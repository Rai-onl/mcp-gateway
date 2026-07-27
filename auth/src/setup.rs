//! Startup construction of the authentication runtime from
//! configuration.
//!
//! Turns an [`AuthenticationConfig`] into a ready [`AuthState`]: it
//! fetches the issuer's discovery document (applying any configured
//! trust anchors), then assembles the configured validation strategy,
//! JWT or introspection. The discovery fetch is the cold-start
//! dependency: its failure is fatal to gateway startup. For
//! introspection, the client secret is resolved here too, so a
//! misconfigured credential fails at startup rather than per request.

use std::collections::HashSet;
use std::time::Duration;

use mcp_gateway_config::{AuthenticationConfig, IntrospectionOutagePolicy, ValidationStrategy};
use mcp_gateway_credentials::CredentialResolver;

use crate::authorise::ScopePolicy;
use crate::discovery::{
	DiscoveryClient, DiscoveryDocument, DiscoveryError, emit_discovery_warnings, well_known_url,
};
use crate::introspection::{IntrospectionPolicy, IntrospectionValidator, OutagePolicy};
use crate::jwks::JwksCache;
use crate::middleware::AuthState;
use crate::strategy::Validator;
use crate::validator::{ClaimChecks, JwtValidator};

/// The `.well-known` suffix at which the gateway serves (and challenges
/// point clients at) its RFC 9728 protected-resource metadata.
const PROTECTED_RESOURCE_METADATA_SUFFIX: &str = "oauth-protected-resource";

/// Build the authentication state from configuration.
///
/// Fetches the discovery document, then assembles the configured
/// validation strategy. The `resolver` resolves the introspection
/// client secret through the established credential chain; it is unused
/// when JWT validation is configured.
///
/// # Errors
///
/// Returns [`AuthSetupError::Discovery`] if the cold discovery fetch
/// fails, and the introspection-setup variants when introspection is
/// configured but its endpoint, client identity, or secret cannot be
/// established. All are fatal at startup.
pub async fn build_auth_state(
	config: &AuthenticationConfig,
	resolver: &dyn CredentialResolver,
) -> Result<AuthState, AuthSetupError> {
	let document = fetch_discovery(config).await?;
	emit_discovery_warnings(&document);
	assemble_auth_state(config, &document, resolver).await
}

/// Fetch the issuer's discovery document, applying any configured trust
/// anchors.
///
/// The background discovery-refresh loop calls this on its cadence to
/// detect a change at the authorisation server. It builds the client
/// from the configuration each call, so a reload that changes the issuer
/// or trust anchors is honoured on the next fetch.
///
/// # Errors
///
/// Returns [`AuthSetupError::NoIssuer`] if the issuer list is empty and
/// [`AuthSetupError::Discovery`] if the fetch fails.
pub async fn fetch_discovery(
	config: &AuthenticationConfig,
) -> Result<DiscoveryDocument, AuthSetupError> {
	let issuer_url = issuer_url(config)?;
	discovery_client(config, &issuer_url)
		.fetch()
		.await
		.map_err(AuthSetupError::Discovery)
}

/// Assemble the authentication state from an already-fetched discovery
/// document, without performing the fetch.
///
/// This is the half of [`build_auth_state`] that runs after discovery:
/// the background discovery-refresh loop re-fetches the document on its
/// own cadence and calls this to rebuild the validator from it, so a
/// changed document does not pay for a second fetch.
///
/// # Errors
///
/// Returns the introspection-setup variants when introspection is
/// configured but its endpoint, client identity, or secret cannot be
/// established, and [`AuthSetupError::NoIssuer`] if the issuer list is
/// empty.
pub async fn assemble_auth_state(
	config: &AuthenticationConfig,
	document: &DiscoveryDocument,
	resolver: &dyn CredentialResolver,
) -> Result<AuthState, AuthSetupError> {
	let issuer_url = issuer_url(config)?;
	let validator = match config.validation {
		ValidationStrategy::Jwt => Validator::Jwt(jwt_validator(config, &issuer_url, document)),
		ValidationStrategy::Introspection => Validator::Introspection(
			introspection_validator(config, &issuer_url, document, resolver).await?,
		),
	};

	let resource_metadata_url =
		well_known_url(&config.resource, PROTECTED_RESOURCE_METADATA_SUFFIX);
	Ok(AuthState::new(
		validator,
		config.resource.clone(),
		resource_metadata_url,
		ScopePolicy::new(&config.server_scopes),
	))
}

/// The configured issuer URL, or [`AuthSetupError::NoIssuer`] when the
/// issuer list is empty. Configuration validation rejects an empty list
/// earlier; the guard keeps these constructors total.
fn issuer_url(config: &AuthenticationConfig) -> Result<String, AuthSetupError> {
	config
		.issuer
		.first()
		.map(|issuer| issuer.url.clone())
		.ok_or(AuthSetupError::NoIssuer)
}

/// Build a discovery client for the configured issuer, applying any
/// configured trust anchors (document hash pin, certificate SPKI pins).
fn discovery_client(config: &AuthenticationConfig, issuer_url: &str) -> DiscoveryClient {
	let mut client = DiscoveryClient::new(issuer_url.to_owned());
	if let Some(anchors) = &config.trust_anchors {
		if let Some(pin) = &anchors.discovery_document_sha256 {
			client = client.with_discovery_document_sha256(pin.clone());
		}
		if !anchors
			.authorization_server_certificate_spki_pins
			.is_empty()
		{
			client = client.with_spki_pins(&anchors.authorization_server_certificate_spki_pins);
		}
	}
	client
}

/// Build the HTTP client the JWKS and introspection fetches use, pinned
/// to the authorisation server's certificate when SPKI pins are
/// configured. This gives those fetches the same TLS posture as the
/// discovery client, so a compromised certificate authority cannot
/// substitute the signing keys or the introspection responses.
fn auth_http_client(config: &AuthenticationConfig) -> reqwest::Client {
	match &config.trust_anchors {
		Some(anchors)
			if !anchors
				.authorization_server_certificate_spki_pins
				.is_empty() =>
		{
			crate::trust::pinned_http_client(&anchors.authorization_server_certificate_spki_pins)
		}
		_ => crate::trust::default_http_client(),
	}
}

/// The claim checks both strategies validate against.
fn claim_checks(config: &AuthenticationConfig, issuer_url: &str) -> ClaimChecks {
	ClaimChecks::new(
		issuer_url.to_owned(),
		config.resource.clone(),
		config.principal_subjects.iter().cloned().collect(),
		Duration::from_secs(config.clock_skew_seconds),
	)
}

/// Build the JWT validator from the discovery document's JWKS endpoint,
/// applying any configured `kid` pins.
fn jwt_validator(
	config: &AuthenticationConfig,
	issuer_url: &str,
	document: &DiscoveryDocument,
) -> JwtValidator {
	let validator = JwtValidator::new(
		issuer_url.to_owned(),
		config.resource.clone(),
		config.principal_subjects.iter().cloned().collect(),
		Duration::from_secs(config.clock_skew_seconds),
		JwksCache::new(document.jwks_uri.clone()).with_http_client(auth_http_client(config)),
	);
	match &config.trust_anchors {
		Some(anchors) if !anchors.jwks_kid_pins.is_empty() => validator.with_kid_pins(
			anchors
				.jwks_kid_pins
				.iter()
				.cloned()
				.collect::<HashSet<_>>(),
		),
		_ => validator,
	}
}

/// Build the introspection validator, resolving the client secret
/// through the credential chain so a misconfiguration fails here.
async fn introspection_validator(
	config: &AuthenticationConfig,
	issuer_url: &str,
	document: &DiscoveryDocument,
	resolver: &dyn CredentialResolver,
) -> Result<IntrospectionValidator, AuthSetupError> {
	let endpoint = document
		.introspection_endpoint
		.clone()
		.ok_or(AuthSetupError::NoIntrospectionEndpoint)?;
	let client_id = config
		.client_id
		.clone()
		.ok_or(AuthSetupError::MissingClientId)?;
	let credential = config
		.client_secret_credential
		.as_ref()
		.ok_or(AuthSetupError::MissingClientSecret)?;
	let secret =
		resolver
			.resolve(credential)
			.await
			.map_err(|reason| AuthSetupError::Credential {
				credential: credential.clone(),
				reason,
			})?;

	let policy = IntrospectionPolicy {
		cache_ttl: Duration::from_secs(config.introspection_cache_seconds),
		outage: match config.introspection_outage_policy {
			IntrospectionOutagePolicy::FailClosed => OutagePolicy::FailClosed,
			IntrospectionOutagePolicy::ServeCached => OutagePolicy::ServeCached,
		},
		max_stale: Duration::from_secs(config.introspection_max_stale_seconds),
	};

	Ok(IntrospectionValidator::new(
		endpoint,
		client_id,
		secret,
		claim_checks(config, issuer_url),
		policy,
	)
	.with_http_client(auth_http_client(config)))
}

/// A failure assembling the authentication state at startup.
#[derive(Debug, thiserror::Error)]
pub enum AuthSetupError {
	/// The configured issuer list was empty. Configuration validation
	/// rejects this earlier; the guard keeps the constructor total.
	#[error("authentication configuration names no issuer")]
	NoIssuer,

	/// The issuer's discovery document could not be fetched at
	/// startup. Fatal: without it the gateway has no keys to validate
	/// tokens against.
	#[error("could not fetch the issuer's discovery document: {0}")]
	Discovery(#[source] DiscoveryError),

	/// Introspection is configured but the discovery document
	/// advertises no introspection endpoint.
	#[error("the discovery document advertises no introspection endpoint")]
	NoIntrospectionEndpoint,

	/// Introspection is configured without a `client_id`. Configuration
	/// validation rejects this earlier; the guard keeps the constructor
	/// total.
	#[error("introspection requires a client_id")]
	MissingClientId,

	/// Introspection is configured without a client-secret credential.
	#[error("introspection requires a client_secret_credential")]
	MissingClientSecret,

	/// The introspection client secret could not be resolved through
	/// the credential chain.
	#[error("could not resolve introspection client secret '{credential}': {reason}")]
	Credential {
		/// The credential name that could not be resolved.
		credential: String,
		/// Why the credential could not be resolved.
		reason: String,
	},
}
