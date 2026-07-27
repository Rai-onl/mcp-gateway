//! Inbound authentication configuration.
//!
//! The gateway becomes an OAuth 2.1 resource server when the
//! top-level `authentication` section is present. The section
//! names the configured authorisation server, the resource URL the
//! gateway answers for, the principals it is willing to admit, and
//! the policy that maps backend servers to required scopes.
//!
//! The types here describe the configuration shape; the runtime
//! behaviour lives in the `mcp-gateway-auth` crate.

use std::collections::HashMap;
use std::hash::BuildHasher;

use serde::{Deserialize, Deserializer, Serialize};

/// The inbound authentication configuration section.
///
/// Absent in local-loopback deployments, present when the gateway
/// is exposed to the network. When present, every request to
/// `/servers/*` requires a valid bearer token bound to the
/// configured resource URL whose `sub` claim is in the configured
/// `principal_subjects` allowlist.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticationConfig {
	/// The OAuth 2.1 / OIDC authorisation server(s) the gateway
	/// federates to. Accepted as a string or as an array of
	/// strings; the internal representation is always a list so
	/// future multi-issuer support is a parser change rather than
	/// a config-shape change. v0 enforces exactly one entry at
	/// validation time.
	#[serde(deserialize_with = "deserialize_issuer")]
	pub issuer: Vec<IssuerConfig>,

	/// The canonical public URL clients reach this instance at.
	/// Validated as the `aud` claim on every inbound token and
	/// published as the `resource` field of the protected
	/// resource metadata document.
	pub resource: String,

	/// Optional human-facing documentation URL for this resource. When
	/// set, it is published as the `resource_documentation` field of
	/// the protected resource metadata document (RFC 9728 §2).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub resource_documentation_url: Option<String>,

	/// OAuth client identifier the gateway presents at the
	/// authorisation server's introspection endpoint. Required
	/// when `validation` is `introspection`; optional otherwise.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub client_id: Option<String>,

	/// Name of a static credential (resolved through the existing
	/// chain) holding the OAuth `client_secret` the gateway uses
	/// to authenticate to the introspection endpoint. Required
	/// when `validation` is `introspection`; optional otherwise.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub client_secret_credential: Option<String>,

	/// The `sub` claim values the gateway is willing to admit.
	/// Tokens whose `sub` is not in this list are rejected even
	/// when their signature, audience, and scope are otherwise
	/// valid. Closes the single-tenancy gap where a misbehaving
	/// authorisation server could issue a token with the correct
	/// `aud` but the wrong identity.
	pub principal_subjects: Vec<String>,

	/// Whether to validate tokens locally as JWTs against the
	/// JWKS, or remotely via RFC 7662 introspection. Defaults to
	/// JWT validation.
	#[serde(default)]
	pub validation: ValidationStrategy,

	/// Clock skew tolerance applied to `exp` and `nbf` checks.
	/// Defaults to 30 seconds. Validation rejects values above
	/// 300 seconds: the replay window grows linearly with skew.
	#[serde(default = "default_clock_skew_seconds")]
	pub clock_skew_seconds: u64,

	/// Lifetime of the cached JWKS document before background
	/// refresh. Refresh on signature failure with an unknown
	/// `kid` happens independent of this TTL.
	#[serde(default = "default_jwks_cache_seconds")]
	pub jwks_cache_seconds: u64,

	/// Lifetime of the cached discovery document before
	/// background refresh.
	#[serde(default = "default_discovery_cache_seconds")]
	pub discovery_cache_seconds: u64,

	/// Lifetime of cached introspection responses. Shorter values
	/// reduce revocation latency at the cost of more network
	/// round-trips to the introspection endpoint.
	#[serde(default = "default_introspection_cache_seconds")]
	pub introspection_cache_seconds: u64,

	/// Behaviour when the introspection endpoint is unreachable.
	/// `FailClosed` (default) rejects requests; `ServeCached`
	/// continues to honour cached positive results up to
	/// `introspection_max_stale_seconds`.
	#[serde(default)]
	pub introspection_outage_policy: IntrospectionOutagePolicy,

	/// Maximum staleness tolerated by `ServeCached` mode, in
	/// seconds. Default 0, effectively disabled until the
	/// operator opts in by raising it.
	#[serde(default)]
	pub introspection_max_stale_seconds: u64,

	/// Pinning of the authorisation server's discovery document,
	/// JWKS keys, and TLS certificate. Recommended for hosted
	/// deployments; HTTPS alone is insufficient against a
	/// compromised certificate authority. Absence is permitted
	/// (a warning is emitted at load time) so local-loopback and
	/// experimental deployments can run without pinning.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub trust_anchors: Option<TrustAnchorsConfig>,

	/// CORS allow-list configuration for browser-native MCP
	/// clients.
	pub cors: CorsConfig,

	/// Per-server scope policy. A request to `/servers/{name}/mcp`
	/// is authorised if and only if the token's `scope` claim
	/// contains at least one of the scopes mapped to `{name}`.
	/// Every server in the top-level `servers` map must have an
	/// entry here; validation rejects configurations that omit a
	/// server.
	#[serde(default)]
	pub server_scopes: HashMap<String, Vec<String>>,
}

/// A single authorisation server entry.
///
/// v0 carries only the issuer URL. The struct exists so future
/// versions can add per-issuer fields (federation weights, JWKS
/// override URLs, audience overrides) without changing the
/// configuration's public shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IssuerConfig {
	/// The issuer URL. Cross-checked against the `iss` claim of
	/// every inbound token and used as the base for discovery
	/// document retrieval.
	pub url: String,
}

/// Optional pins on the authorisation server's discovery
/// document, JWKS, and TLS certificate.
///
/// Each field is independently optional. When any is set, the
/// gateway enforces it on every fetch and on every validation;
/// mismatches fail closed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TrustAnchorsConfig {
	/// Expected SHA-256 of the discovery document body, hex-
	/// encoded. A mismatched body fails the fetch, which defends
	/// against a substituted discovery document that points the
	/// gateway at an attacker-controlled JWKS.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub discovery_document_sha256: Option<String>,

	/// JWKS `kid` values the gateway is willing to accept.
	/// Tokens signed with a key whose `kid` is not in this list
	/// are rejected even when the signature would otherwise
	/// verify against an unpinned JWKS entry.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub jwks_kid_pins: Vec<String>,

	/// SHA-256 SPKI pins for the authorisation server's TLS
	/// certificate, base64-encoded per RFC 7469. Applied to
	/// discovery, JWKS, and introspection calls.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub authorization_server_certificate_spki_pins: Vec<String>,
}

impl TrustAnchorsConfig {
	/// Whether any pin field is set. Absence of all fields is the
	/// signal for a load-time warning, since pinning is the only
	/// mitigation against discovery substitution attacks.
	#[must_use]
	pub fn is_empty(&self) -> bool {
		self.discovery_document_sha256.is_none()
			&& self.jwks_kid_pins.is_empty()
			&& self.authorization_server_certificate_spki_pins.is_empty()
	}
}

/// CORS allow-list configuration for browser-native MCP clients.
///
/// Wildcard origins are rejected at validation; operators must
/// list every origin explicitly. Defaults are conservative:
/// 60-second max-age, the minimum header set browser MCP clients
/// need.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CorsConfig {
	/// Origins permitted to call the gateway from a browser.
	/// Wildcard `*` is rejected. Each origin must be a fully-
	/// qualified URL with scheme and host.
	#[serde(default)]
	pub allowed_origins: Vec<String>,

	/// HTTP request headers browsers are permitted to send.
	/// Operators may extend the default set; they cannot
	/// restrict it below the minimum needed for the bearer
	/// token, session header, and content type.
	#[serde(default = "default_allowed_headers")]
	pub allowed_headers: Vec<String>,

	/// `Access-Control-Max-Age` value, in seconds. Defaults to
	/// 60, short enough that operator-side origin revocation
	/// propagates quickly to browser caches.
	#[serde(default = "default_max_age_seconds")]
	pub max_age_seconds: u64,
}

impl Default for CorsConfig {
	fn default() -> Self {
		Self {
			allowed_origins: Vec::new(),
			allowed_headers: default_allowed_headers(),
			max_age_seconds: default_max_age_seconds(),
		}
	}
}

/// Whether to validate inbound tokens locally (JWT against JWKS)
/// or remotely (RFC 7662 introspection).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ValidationStrategy {
	/// JWT validation against the cached JWKS. No network round
	/// trip per request after the JWKS is fetched.
	#[default]
	Jwt,
	/// RFC 7662 token introspection. One round trip per
	/// uncached token to the introspection endpoint.
	Introspection,
}

/// Behaviour when introspection is configured and the endpoint
/// is unreachable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IntrospectionOutagePolicy {
	/// Reject the request with `invalid_token`. Conservative
	/// default: outages do not silently weaken validation.
	#[default]
	FailClosed,
	/// Honour cached positive responses up to
	/// `introspection_max_stale_seconds`, then transition to
	/// rejection. Opt-in for deployments that prefer
	/// availability over freshness during AS outages.
	ServeCached,
}

/// Validate the inbound authentication configuration against the
/// rules defined in Arai Architecture RFC-0014.
///
/// Returns the list of error messages; an empty list means the
/// configuration is acceptable. Soft warnings (which do not
/// reject the configuration) are emitted via tracing by
/// [`emit_load_time_warnings`].
///
/// `servers` is the top-level `servers` map from the surrounding
/// [`GatewayConfig`](crate::GatewayConfig); it is consulted by
/// the `server_scopes` cross-reference rule. The hasher
/// parameter is generic so callers may use any [`HashMap`]
/// instantiation without an explicit conversion.
#[must_use]
pub fn validate<S: BuildHasher>(
	authentication: &AuthenticationConfig,
	servers: &HashMap<String, crate::ServerDefinition, S>,
) -> Vec<String> {
	let mut errors = Vec::new();
	validate_issuer(authentication, &mut errors);
	validate_resource(authentication, &mut errors);
	validate_principal_subjects(authentication, &mut errors);
	validate_introspection_requirements(authentication, &mut errors);
	validate_clock_skew(authentication, &mut errors);
	validate_introspection_max_stale(authentication, &mut errors);
	validate_cors(authentication, &mut errors);
	validate_server_scope_cross_references(authentication, servers, &mut errors);
	errors
}

/// Enforce the v0 single-issuer rule and reject empty issuer
/// lists. Multi-issuer instances are reserved for a future RFC.
fn validate_issuer(authentication: &AuthenticationConfig, errors: &mut Vec<String>) {
	if authentication.issuer.is_empty() {
		errors.push("authentication.issuer: at least one entry is required".to_owned());
	} else if authentication.issuer.len() > 1 {
		errors.push(format!(
			"authentication.issuer: v0 accepts exactly one entry, found {}",
			authentication.issuer.len()
		));
	}
}

/// Reject configurations where the resource URL is empty. The
/// resource URL is load-bearing on every inbound token's `aud`
/// validation.
fn validate_resource(authentication: &AuthenticationConfig, errors: &mut Vec<String>) {
	if authentication.resource.is_empty() {
		errors.push("authentication.resource: must not be empty".to_owned());
	}
}

/// Reject empty principal allowlists. Without at least one
/// principal, no token's `sub` claim can match, and the gateway
/// would refuse every authenticated request.
fn validate_principal_subjects(authentication: &AuthenticationConfig, errors: &mut Vec<String>) {
	if authentication.principal_subjects.is_empty() {
		errors.push(
			"authentication.principal_subjects: at least one principal is required".to_owned(),
		);
	}
}

/// When introspection is selected, the gateway must be able to
/// authenticate to the introspection endpoint. Both `client_id`
/// and the named client-secret credential are mandatory.
fn validate_introspection_requirements(
	authentication: &AuthenticationConfig,
	errors: &mut Vec<String>,
) {
	if authentication.validation != ValidationStrategy::Introspection {
		return;
	}
	if authentication.client_id.is_none() {
		errors
			.push("authentication.client_id: required when validation is introspection".to_owned());
	}
	if authentication.client_secret_credential.is_none() {
		errors.push(
			"authentication.client_secret_credential: required when validation is introspection"
				.to_owned(),
		);
	}
}

/// Enforce the 300-second ceiling on clock skew. The replay
/// window scales linearly with skew and 300 seconds is the
/// upper bound the project recognises as defensible.
fn validate_clock_skew(authentication: &AuthenticationConfig, errors: &mut Vec<String>) {
	if authentication.clock_skew_seconds > MAXIMUM_CLOCK_SKEW_SECONDS {
		errors.push(format!(
			"authentication.clock_skew_seconds: {} exceeds the {}s ceiling",
			authentication.clock_skew_seconds, MAXIMUM_CLOCK_SKEW_SECONDS,
		));
	}
}

/// Enforce the ceiling on the `serve_cached` staleness window. While the
/// introspection endpoint is unreachable, `serve_cached` keeps honouring
/// a cached positive for up to `introspection_cache_seconds` plus this
/// value, so the window bounds how long a token revoked at the
/// authorisation server can still be served. The ceiling keeps that
/// revocation latency defensibly short.
fn validate_introspection_max_stale(
	authentication: &AuthenticationConfig,
	errors: &mut Vec<String>,
) {
	if authentication.introspection_max_stale_seconds > MAXIMUM_INTROSPECTION_MAX_STALE_SECONDS {
		errors.push(format!(
			"authentication.introspection_max_stale_seconds: {} exceeds the {}s ceiling",
			authentication.introspection_max_stale_seconds, MAXIMUM_INTROSPECTION_MAX_STALE_SECONDS,
		));
	}
}

/// Reject wildcard CORS origins. Browser-origin access is
/// security-sensitive enough that operators must enumerate
/// every permitted origin explicitly.
fn validate_cors(authentication: &AuthenticationConfig, errors: &mut Vec<String>) {
	if authentication
		.cors
		.allowed_origins
		.iter()
		.any(|origin| origin == "*")
	{
		errors.push(
			"authentication.cors.allowed_origins: wildcard \"*\" is rejected; list origins explicitly"
				.to_owned(),
		);
	}
}

/// Cross-check `server_scopes` against the surrounding
/// [`servers`](crate::GatewayConfig::servers) map. Every scope
/// entry must name an existing server, and every server must
/// have at least one scope entry.
fn validate_server_scope_cross_references<S: BuildHasher>(
	authentication: &AuthenticationConfig,
	servers: &HashMap<String, crate::ServerDefinition, S>,
	errors: &mut Vec<String>,
) {
	for scoped_server in authentication.server_scopes.keys() {
		if !servers.contains_key(scoped_server) {
			errors.push(format!(
				"authentication.server_scopes: \"{scoped_server}\" is not present in the servers map"
			));
		}
	}

	for server_name in servers.keys() {
		if !authentication.server_scopes.contains_key(server_name) {
			errors.push(format!(
				"authentication.server_scopes: missing entry for server \"{server_name}\"; \
				 every server requires at least one scope when authentication is configured"
			));
		}
	}
}

/// Emit any soft warnings about the authentication configuration
/// via `tracing` at the `warn` level.
///
/// Soft warnings do not reject the configuration but signal that
/// the deployment is missing a defence the project recommends.
/// Currently the only soft warning is the absence of trust
/// anchors, which leaves the discovery document protected only
/// by HTTPS certificate validation.
pub fn emit_load_time_warnings(authentication: &AuthenticationConfig) {
	let pinning_absent = authentication
		.trust_anchors
		.as_ref()
		.is_none_or(TrustAnchorsConfig::is_empty);

	if pinning_absent {
		tracing::warn!(
			"authentication.trust_anchors is absent; the discovery document and JWKS \
			 are protected only by HTTPS certificate validation. Hosted deployments \
			 should pin discovery_document_sha256, jwks_kid_pins, or \
			 authorization_server_certificate_spki_pins."
		);
	}
}

/// Maximum value accepted for `clock_skew_seconds`. The replay
/// window grows linearly with skew, and 300 seconds is the upper
/// bound this RFC recognises as defensible.
const MAXIMUM_CLOCK_SKEW_SECONDS: u64 = 300;

/// Maximum value accepted for `introspection_max_stale_seconds`. The
/// `serve_cached` outage policy keeps honouring a cached positive for
/// up to the cache lifetime plus this window, so it bounds how long a
/// revoked token can still be served during an authorisation-server
/// outage. 300 seconds keeps revocation latency defensibly short while
/// still tolerating a brief outage; operators wanting more should
/// reconsider the availability-over-freshness tradeoff.
const MAXIMUM_INTROSPECTION_MAX_STALE_SECONDS: u64 = 300;

/// Default value for [`AuthenticationConfig::clock_skew_seconds`].
const fn default_clock_skew_seconds() -> u64 {
	30
}

/// Default value for [`AuthenticationConfig::jwks_cache_seconds`].
const fn default_jwks_cache_seconds() -> u64 {
	600
}

/// Default value for [`AuthenticationConfig::discovery_cache_seconds`].
const fn default_discovery_cache_seconds() -> u64 {
	3600
}

/// Default value for [`AuthenticationConfig::introspection_cache_seconds`].
const fn default_introspection_cache_seconds() -> u64 {
	30
}

/// Default value for [`CorsConfig::max_age_seconds`].
const fn default_max_age_seconds() -> u64 {
	60
}

/// Default value for [`CorsConfig::allowed_headers`].
///
/// Browser MCP clients need these to send authenticated
/// requests with session continuity. Operators may extend the
/// list by configuration but the default set is the minimum
/// usable shape.
fn default_allowed_headers() -> Vec<String> {
	vec![
		"authorization".to_owned(),
		"content-type".to_owned(),
		"mcp-session-id".to_owned(),
		"traceparent".to_owned(),
		"tracestate".to_owned(),
	]
}

/// Deserialize the `issuer` field as either a bare string (`"x"`)
/// or an array of strings (`["x"]` or `["x", "y"]`), producing a
/// [`Vec<IssuerConfig>`] in every case.
fn deserialize_issuer<'de, D>(deserializer: D) -> Result<Vec<IssuerConfig>, D::Error>
where
	D: Deserializer<'de>,
{
	#[derive(Deserialize)]
	#[serde(untagged)]
	enum StringOrList {
		Single(String),
		Many(Vec<String>),
	}

	let raw = StringOrList::deserialize(deserializer)?;
	let urls = match raw {
		StringOrList::Single(url) => vec![url],
		StringOrList::Many(list) => list,
	};

	Ok(urls.into_iter().map(|url| IssuerConfig { url }).collect())
}

#[cfg(test)]
mod tests {
	use std::io;
	use std::sync::{Arc, Mutex};

	use crate::{GatewayConfig, ServerDefinition, Transport};

	use super::*;

	/// A test writer that captures everything written to it into
	/// a shared buffer. Used by [`capture_tracing`] to assert on
	/// emitted warning messages.
	#[derive(Clone, Default)]
	struct CapturingWriter {
		buffer: Arc<Mutex<Vec<u8>>>,
	}

	impl io::Write for CapturingWriter {
		fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
			self.buffer
				.lock()
				.expect("capture buffer poisoned")
				.extend_from_slice(buf);
			Ok(buf.len())
		}
		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}

	impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
		type Writer = Self;
		fn make_writer(&'a self) -> Self::Writer {
			self.clone()
		}
	}

	/// Run `body` inside a tracing subscriber that captures
	/// `warn`-level events; return the captured output as a
	/// string. Used by warning-rule tests to assert that the
	/// expected warning is emitted.
	fn capture_tracing<F: FnOnce()>(body: F) -> String {
		let writer = CapturingWriter::default();
		let captured = Arc::clone(&writer.buffer);
		let subscriber = tracing_subscriber::fmt()
			.with_writer(writer)
			.with_max_level(tracing::Level::WARN)
			.with_ansi(false)
			.with_target(false)
			.finish();
		tracing::subscriber::with_default(subscriber, body);
		String::from_utf8(captured.lock().expect("capture buffer poisoned").clone())
			.expect("captured tracing output should be valid UTF-8")
	}

	/// Build a minimal valid [`AuthenticationConfig`] for tests
	/// that want to mutate a single field without restating the
	/// whole shape.
	fn baseline_authentication() -> AuthenticationConfig {
		AuthenticationConfig {
			issuer: vec![IssuerConfig {
				url: "https://identity.example.coop".to_owned(),
			}],
			resource: "https://alice.gateway.example.coop".to_owned(),
			resource_documentation_url: None,
			client_id: None,
			client_secret_credential: None,
			principal_subjects: vec!["did:arai:example:alice".to_owned()],
			validation: ValidationStrategy::Jwt,
			clock_skew_seconds: 30,
			jwks_cache_seconds: 600,
			discovery_cache_seconds: 3600,
			introspection_cache_seconds: 30,
			introspection_outage_policy: IntrospectionOutagePolicy::FailClosed,
			introspection_max_stale_seconds: 0,
			trust_anchors: Some(TrustAnchorsConfig {
				jwks_kid_pins: vec!["kid-2026-01".to_owned()],
				..TrustAnchorsConfig::default()
			}),
			cors: CorsConfig {
				allowed_origins: vec!["https://app.example.coop".to_owned()],
				..CorsConfig::default()
			},
			server_scopes: HashMap::new(),
		}
	}

	/// Build a single stdio server definition for tests that need
	/// the surrounding [`GatewayConfig`] to contain a server.
	fn stdio_server(command: &str) -> ServerDefinition {
		ServerDefinition {
			enabled: true,
			env: HashMap::new(),
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Stdio {
				command: command.to_owned(),
				args: vec![],
			},
		}
	}

	/// A configuration without an `authentication` section
	/// deserialises with `authentication` unset, preserving the
	/// existing local-loopback behaviour.
	#[test]
	fn config_without_authentication_section_loads() {
		let json = r#"{ "servers": {} }"#;
		let config: GatewayConfig =
			serde_json::from_str(json).expect("local-loopback config should parse");
		assert!(config.authentication.is_none());
	}

	/// The full reference configuration from Arai Architecture
	/// RFC-0014's "Configuration shape" section, used by the
	/// exhaustive field-population test.
	const FULL_AUTHENTICATION_JSON: &str = r#"{
		"servers": {},
		"authentication": {
			"issuer": "https://identity.example.coop",
			"resource": "https://alice.gateway.example.coop",
			"client_id": "gateway-alice",
			"client_secret_credential": "gateway-alice-introspection",
			"principal_subjects": ["did:arai:example:alice"],
			"validation": "jwt",
			"clock_skew_seconds": 30,
			"jwks_cache_seconds": 600,
			"discovery_cache_seconds": 3600,
			"introspection_cache_seconds": 30,
			"introspection_outage_policy": "fail_closed",
			"introspection_max_stale_seconds": 0,
			"trust_anchors": { "jwks_kid_pins": ["kid-2026-01"] },
			"cors": {
				"allowed_origins": ["https://app.example.coop"],
				"allowed_headers": ["authorization", "content-type"],
				"max_age_seconds": 60
			},
			"server_scopes": { "gitlab": ["mcp:invoke:gitlab"] }
		}
	}"#;

	/// Assert the issuer and resource identifiers reflect the
	/// reference configuration.
	fn assert_full_identifiers(authentication: &AuthenticationConfig) {
		assert_eq!(authentication.issuer.len(), 1);
		assert_eq!(
			authentication.issuer[0].url,
			"https://identity.example.coop"
		);
		assert_eq!(
			authentication.resource,
			"https://alice.gateway.example.coop"
		);
	}

	/// Assert the OAuth client identity fields reflect the
	/// reference configuration.
	fn assert_full_client_identity(authentication: &AuthenticationConfig) {
		assert_eq!(authentication.client_id.as_deref(), Some("gateway-alice"));
		assert_eq!(
			authentication.client_secret_credential.as_deref(),
			Some("gateway-alice-introspection")
		);
		assert_eq!(
			authentication.principal_subjects,
			vec!["did:arai:example:alice"]
		);
	}

	/// Assert the validation-strategy, cache-lifetime, and
	/// outage-policy fields reflect the reference configuration.
	fn assert_full_validation_fields(authentication: &AuthenticationConfig) {
		assert_eq!(authentication.validation, ValidationStrategy::Jwt);
		assert_eq!(authentication.clock_skew_seconds, 30);
		assert_eq!(authentication.jwks_cache_seconds, 600);
		assert_eq!(authentication.discovery_cache_seconds, 3600);
		assert_eq!(authentication.introspection_cache_seconds, 30);
		assert_eq!(
			authentication.introspection_outage_policy,
			IntrospectionOutagePolicy::FailClosed
		);
		assert_eq!(authentication.introspection_max_stale_seconds, 0);
	}

	/// Assert the trust-anchor, CORS, and per-server scope
	/// configuration reflects the reference configuration.
	fn assert_full_policy_fields(authentication: &AuthenticationConfig) {
		let trust = authentication
			.trust_anchors
			.as_ref()
			.expect("trust_anchors should be present");
		assert_eq!(trust.jwks_kid_pins, vec!["kid-2026-01"]);
		assert_eq!(
			authentication.cors.allowed_origins,
			vec!["https://app.example.coop"]
		);
		assert_eq!(
			authentication.cors.allowed_headers,
			vec!["authorization".to_owned(), "content-type".to_owned()]
		);
		assert_eq!(authentication.cors.max_age_seconds, 60);
		assert_eq!(
			authentication
				.server_scopes
				.get("gitlab")
				.expect("gitlab scope mapping should be present"),
			&vec!["mcp:invoke:gitlab".to_owned()]
		);
	}

	/// A fully-populated `authentication` section deserialises
	/// with every field present. The shape mirrors the example
	/// in Arai Architecture RFC-0014's "Configuration shape"
	/// section; per-section assertions live in helpers above so
	/// the test reads as a manifest of the public shape.
	#[test]
	fn full_authentication_section_populates_every_field() {
		let config: GatewayConfig =
			serde_json::from_str(FULL_AUTHENTICATION_JSON).expect("full config should parse");
		let authentication = config
			.authentication
			.expect("authentication section should be present");

		assert_full_identifiers(&authentication);
		assert_full_client_identity(&authentication);
		assert_full_validation_fields(&authentication);
		assert_full_policy_fields(&authentication);
	}

	/// The `issuer` field accepts a bare string for operator
	/// convenience; the internal representation is still a list.
	#[test]
	fn issuer_accepts_string_form() {
		let json = r#"{
			"issuer": "https://identity.example.coop",
			"resource": "https://alice.gateway.example.coop",
			"principal_subjects": ["did:arai:alice"],
			"cors": { "allowed_origins": ["https://app.example.coop"] }
		}"#;
		let authentication: AuthenticationConfig =
			serde_json::from_str(json).expect("string-form issuer should parse");
		assert_eq!(authentication.issuer.len(), 1);
		assert_eq!(
			authentication.issuer[0].url,
			"https://identity.example.coop"
		);
	}

	/// The `issuer` field accepts a single-element array; future
	/// multi-issuer support extends this without a config-shape
	/// change for operators.
	#[test]
	fn issuer_accepts_array_form() {
		let json = r#"{
			"issuer": ["https://identity.example.coop"],
			"resource": "https://alice.gateway.example.coop",
			"principal_subjects": ["did:arai:alice"],
			"cors": { "allowed_origins": ["https://app.example.coop"] }
		}"#;
		let authentication: AuthenticationConfig =
			serde_json::from_str(json).expect("array-form issuer should parse");
		assert_eq!(authentication.issuer.len(), 1);
	}

	/// The optional `resource_documentation_url` deserialises when
	/// present and defaults to `None` when omitted, so the metadata
	/// document publishes `resource_documentation` only when the
	/// operator sets it.
	#[test]
	fn resource_documentation_url_is_optional() {
		let without: AuthenticationConfig = serde_json::from_str(
			r#"{
				"issuer": "https://identity.example.coop",
				"resource": "https://alice.gateway.example.coop",
				"principal_subjects": ["did:arai:alice"],
				"cors": { "allowed_origins": ["https://app.example.coop"] }
			}"#,
		)
		.expect("config without the documentation URL should parse");
		assert!(without.resource_documentation_url.is_none());

		let with: AuthenticationConfig = serde_json::from_str(
			r#"{
				"issuer": "https://identity.example.coop",
				"resource": "https://alice.gateway.example.coop",
				"resource_documentation_url": "https://gateway.example.coop/docs",
				"principal_subjects": ["did:arai:alice"],
				"cors": { "allowed_origins": ["https://app.example.coop"] }
			}"#,
		)
		.expect("config with the documentation URL should parse");
		assert_eq!(
			with.resource_documentation_url.as_deref(),
			Some("https://gateway.example.coop/docs"),
		);
	}

	/// Omitted optional fields fall back to their defaults: JWT
	/// validation, 30-second skew, fail-closed outage policy,
	/// 60-second CORS max-age.
	#[test]
	fn omitted_optional_fields_use_defaults() {
		let json = r#"{
			"issuer": "https://identity.example.coop",
			"resource": "https://alice.gateway.example.coop",
			"principal_subjects": ["did:arai:alice"],
			"cors": { "allowed_origins": ["https://app.example.coop"] }
		}"#;
		let authentication: AuthenticationConfig =
			serde_json::from_str(json).expect("minimal config should parse");
		assert_eq!(authentication.validation, ValidationStrategy::Jwt);
		assert_eq!(authentication.clock_skew_seconds, 30);
		assert_eq!(
			authentication.introspection_outage_policy,
			IntrospectionOutagePolicy::FailClosed
		);
		assert_eq!(authentication.cors.max_age_seconds, 60);
		assert!(authentication.client_id.is_none());
		assert!(authentication.client_secret_credential.is_none());
	}

	/// A baseline configuration paired with an empty servers map
	/// validates without errors.
	#[test]
	fn baseline_configuration_validates() {
		let authentication = baseline_authentication();
		let servers = HashMap::new();
		assert!(validate(&authentication, &servers).is_empty());
	}

	/// Introspection validation strategy requires both
	/// `client_id` and `client_secret_credential`. Configurations
	/// missing either are rejected with a precise error.
	#[test]
	fn introspection_without_client_id_rejects() {
		let mut authentication = baseline_authentication();
		authentication.validation = ValidationStrategy::Introspection;
		authentication.client_id = None;
		authentication.client_secret_credential = Some("secret".to_owned());

		let errors = validate(&authentication, &HashMap::new());
		assert!(
			errors.iter().any(|message| message.contains("client_id")),
			"expected client_id error, got {errors:?}"
		);
	}

	/// Introspection validation strategy requires the client
	/// secret credential to be named; absence is rejected.
	#[test]
	fn introspection_without_client_secret_credential_rejects() {
		let mut authentication = baseline_authentication();
		authentication.validation = ValidationStrategy::Introspection;
		authentication.client_id = Some("gateway-alice".to_owned());
		authentication.client_secret_credential = None;

		let errors = validate(&authentication, &HashMap::new());
		assert!(
			errors
				.iter()
				.any(|message| message.contains("client_secret_credential")),
			"expected client_secret_credential error, got {errors:?}"
		);
	}

	/// The 300-second clock-skew ceiling is enforced at the
	/// inclusive boundary: 300 accepts, 301 rejects.
	#[test]
	fn clock_skew_above_ceiling_rejects() {
		let mut authentication = baseline_authentication();
		authentication.clock_skew_seconds = 301;
		let errors = validate(&authentication, &HashMap::new());
		assert!(
			errors
				.iter()
				.any(|message| message.contains("clock_skew_seconds")),
			"expected clock_skew_seconds error, got {errors:?}"
		);
	}

	/// The clock-skew ceiling itself is accepted; the rejection
	/// threshold is strictly above 300.
	#[test]
	fn clock_skew_at_ceiling_accepts() {
		let mut authentication = baseline_authentication();
		authentication.clock_skew_seconds = 300;
		assert!(validate(&authentication, &HashMap::new()).is_empty());
	}

	/// The serve-cached staleness window is bounded: a value above the
	/// ceiling is rejected, because a long stale window keeps serving a
	/// revoked token during an authorisation-server outage. The ceiling
	/// bounds that revocation latency.
	#[test]
	fn introspection_max_stale_above_ceiling_rejects() {
		let mut authentication = baseline_authentication();
		authentication.introspection_max_stale_seconds =
			MAXIMUM_INTROSPECTION_MAX_STALE_SECONDS + 1;
		let errors = validate(&authentication, &HashMap::new());
		assert!(
			errors
				.iter()
				.any(|message| message.contains("introspection_max_stale_seconds")),
			"expected introspection_max_stale_seconds error, got {errors:?}",
		);
	}

	/// The staleness ceiling itself is accepted; the rejection threshold
	/// is strictly above it.
	#[test]
	fn introspection_max_stale_at_ceiling_accepts() {
		let mut authentication = baseline_authentication();
		authentication.introspection_max_stale_seconds = MAXIMUM_INTROSPECTION_MAX_STALE_SECONDS;
		assert!(validate(&authentication, &HashMap::new()).is_empty());
	}

	/// v0 accepts exactly one issuer entry. Two or more is a
	/// validation error pointing at the count.
	#[test]
	fn multi_issuer_rejects_in_v0() {
		let mut authentication = baseline_authentication();
		authentication.issuer = vec![
			IssuerConfig {
				url: "https://one.example.coop".to_owned(),
			},
			IssuerConfig {
				url: "https://two.example.coop".to_owned(),
			},
		];

		let errors = validate(&authentication, &HashMap::new());
		assert!(
			errors.iter().any(|message| message.contains("issuer")),
			"expected issuer error, got {errors:?}"
		);
	}

	/// An empty issuer list is rejected as missing required
	/// information, distinct from the v0 single-issuer rule.
	#[test]
	fn empty_issuer_rejects() {
		let mut authentication = baseline_authentication();
		authentication.issuer.clear();
		let errors = validate(&authentication, &HashMap::new());
		assert!(errors.iter().any(|message| message.contains("issuer")));
	}

	/// An empty `principal_subjects` list is rejected; the
	/// allowlist is the gateway's only check on which identities
	/// it admits.
	#[test]
	fn empty_principal_subjects_rejects() {
		let mut authentication = baseline_authentication();
		authentication.principal_subjects.clear();
		let errors = validate(&authentication, &HashMap::new());
		assert!(
			errors
				.iter()
				.any(|message| message.contains("principal_subjects")),
			"expected principal_subjects error, got {errors:?}"
		);
	}

	/// Wildcard CORS origins are rejected: operators must list
	/// every browser origin explicitly.
	#[test]
	fn cors_wildcard_origin_rejects() {
		let mut authentication = baseline_authentication();
		authentication.cors.allowed_origins.push("*".to_owned());
		let errors = validate(&authentication, &HashMap::new());
		assert!(
			errors
				.iter()
				.any(|message| message.contains("allowed_origins") && message.contains("wildcard")),
			"expected wildcard CORS error, got {errors:?}"
		);
	}

	/// A `server_scopes` entry that names a server absent from
	/// the surrounding `servers` map is rejected as a typo or
	/// stale reference.
	#[test]
	fn server_scopes_referencing_unknown_server_rejects() {
		let mut authentication = baseline_authentication();
		authentication
			.server_scopes
			.insert("missing".to_owned(), vec!["mcp:invoke:missing".to_owned()]);
		let servers = HashMap::new();

		let errors = validate(&authentication, &servers);
		assert!(
			errors
				.iter()
				.any(|message| message.contains("server_scopes") && message.contains("missing")),
			"expected server_scopes/unknown-server error, got {errors:?}"
		);
	}

	/// Every server in the surrounding `servers` map must have an
	/// entry in `server_scopes` when authentication is configured.
	/// Omission is treated as an error: a silently-unreachable
	/// server is a worse failure mode than a startup rejection.
	#[test]
	fn server_in_servers_without_scope_entry_rejects() {
		let authentication = baseline_authentication();
		let mut servers = HashMap::new();
		servers.insert("gitlab".to_owned(), stdio_server("/bin/gitlab"));

		let errors = validate(&authentication, &servers);
		assert!(
			errors
				.iter()
				.any(|message| message.contains("gitlab") && message.contains("scope")),
			"expected missing-scope error for gitlab, got {errors:?}"
		);
	}

	/// A server present in both maps validates without errors.
	#[test]
	fn matched_server_and_scope_validates() {
		let mut authentication = baseline_authentication();
		authentication
			.server_scopes
			.insert("gitlab".to_owned(), vec!["mcp:invoke:gitlab".to_owned()]);

		let mut servers = HashMap::new();
		servers.insert("gitlab".to_owned(), stdio_server("/bin/gitlab"));

		assert!(validate(&authentication, &servers).is_empty());
	}

	/// Absent `trust_anchors` emits a `warn`-level tracing event
	/// at load time. The configuration still loads; pinning is
	/// recommended, not required.
	#[test]
	fn warning_emitted_when_trust_anchors_absent() {
		let mut authentication = baseline_authentication();
		authentication.trust_anchors = None;

		let captured = capture_tracing(|| emit_load_time_warnings(&authentication));
		assert!(
			captured.contains("trust_anchors"),
			"expected trust_anchors warning in tracing output, got: {captured}"
		);
	}

	/// An empty `trust_anchors` object (all pin fields unset) is
	/// equivalent to absence and triggers the same warning.
	#[test]
	fn warning_emitted_when_trust_anchors_empty() {
		let mut authentication = baseline_authentication();
		authentication.trust_anchors = Some(TrustAnchorsConfig::default());

		let captured = capture_tracing(|| emit_load_time_warnings(&authentication));
		assert!(captured.contains("trust_anchors"));
	}

	/// Trust anchors with at least one pin set suppress the
	/// warning; the deployment is no longer relying on HTTPS
	/// certificate validation alone.
	#[test]
	fn no_warning_emitted_when_any_pin_set() {
		let authentication = baseline_authentication();
		let captured = capture_tracing(|| emit_load_time_warnings(&authentication));
		assert!(
			!captured.contains("trust_anchors"),
			"unexpected trust_anchors warning when a pin is set: {captured}"
		);
	}
}
