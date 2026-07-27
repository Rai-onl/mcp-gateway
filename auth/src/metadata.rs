//! The OAuth 2.0 Protected Resource Metadata document (RFC 9728).
//!
//! A hosted gateway publishes this document at
//! `/.well-known/oauth-protected-resource` so a browser-native client,
//! starting from the gateway URL alone, can discover the authorisation
//! server to obtain a token from and the scopes the gateway recognises.

use std::collections::BTreeSet;

use mcp_gateway_config::AuthenticationConfig;
use serde::Serialize;

/// The bearer-token presentation methods the gateway accepts. The
/// gateway reads tokens from the `Authorization` header only (RFC 6750
/// §2.1), never from a query parameter or form body.
const BEARER_METHODS: [&str; 1] = ["header"];

/// An RFC 9728 §2 Protected Resource Metadata document.
///
/// `resource_documentation` is omitted from the serialised output when
/// the operator has not configured a documentation URL.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
	/// The resource identifier: the gateway instance's canonical URL.
	pub resource: String,
	/// The authorisation servers that issue tokens for this resource.
	/// v0 publishes exactly one; the array shape accommodates future
	/// multi-issuer instances.
	pub authorization_servers: Vec<String>,
	/// Every scope the gateway recognises, the sorted unique union of
	/// the per-server scope sets.
	pub scopes_supported: Vec<String>,
	/// How a client may present a bearer token: header only.
	pub bearer_methods_supported: Vec<String>,
	/// A human-facing documentation URL, present only when configured.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub resource_documentation: Option<String>,
}

/// Build the protected-resource metadata document from the
/// authentication configuration.
#[must_use]
pub fn protected_resource_metadata(config: &AuthenticationConfig) -> ProtectedResourceMetadata {
	// A `BTreeSet` yields the scopes sorted and de-duplicated, so a
	// scope listed for several servers appears once and the document is
	// deterministic.
	let scopes_supported: Vec<String> = config
		.server_scopes
		.values()
		.flatten()
		.cloned()
		.collect::<BTreeSet<String>>()
		.into_iter()
		.collect();

	ProtectedResourceMetadata {
		resource: config.resource.clone(),
		authorization_servers: config
			.issuer
			.iter()
			.map(|issuer| issuer.url.clone())
			.collect(),
		scopes_supported,
		bearer_methods_supported: BEARER_METHODS
			.iter()
			.map(|method| (*method).to_owned())
			.collect(),
		resource_documentation: config.resource_documentation_url.clone(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Build an authentication config from JSON, stating only the
	/// fields a test cares about and inheriting documented defaults for
	/// the rest.
	fn config_from(value: serde_json::Value) -> AuthenticationConfig {
		serde_json::from_value(value).expect("authentication config should deserialise")
	}

	/// The document carries every field the gateway publishes: the
	/// resource, the authorisation server as a single-element array,
	/// header-only bearer methods, and the accepted algorithms.
	#[test]
	fn publishes_required_fields() {
		let config = config_from(serde_json::json!({
			"issuer": "https://identity.example.coop",
			"resource": "https://alice.gateway.example.coop",
			"principal_subjects": ["did:arai:alice"],
			"cors": { "allowed_origins": ["https://app.example.coop"] },
		}));
		let metadata = protected_resource_metadata(&config);

		assert_eq!(metadata.resource, "https://alice.gateway.example.coop");
		assert_eq!(
			metadata.authorization_servers,
			vec!["https://identity.example.coop".to_owned()],
		);
		assert_eq!(metadata.bearer_methods_supported, vec!["header".to_owned()]);

		// RFC 9728 §2 defines `resource_signing_alg_values_supported` as
		// the algorithms the resource signs its own responses with, not
		// the algorithms it accepts on inbound tokens. The gateway does
		// not sign responses, so the field must not appear.
		let serialised = serde_json::to_value(&metadata).expect("serialises");
		assert!(
			serialised
				.get("resource_signing_alg_values_supported")
				.is_none(),
			"the gateway must not publish resource_signing_alg_values_supported: {serialised}",
		);
	}

	/// `scopes_supported` is the sorted, de-duplicated union of every
	/// server's scope set, so a scope shared across servers appears
	/// once.
	#[test]
	fn scopes_supported_is_the_sorted_union() {
		let config = config_from(serde_json::json!({
			"issuer": "https://identity.example.coop",
			"resource": "https://alice.gateway.example.coop",
			"principal_subjects": ["did:arai:alice"],
			"cors": { "allowed_origins": ["https://app.example.coop"] },
			"server_scopes": {
				"gitlab": ["mcp:invoke:gitlab", "mcp:invoke:shared"],
				"github": ["mcp:invoke:shared", "mcp:invoke:github"],
			},
		}));
		let metadata = protected_resource_metadata(&config);

		assert_eq!(
			metadata.scopes_supported,
			vec![
				"mcp:invoke:github".to_owned(),
				"mcp:invoke:gitlab".to_owned(),
				"mcp:invoke:shared".to_owned(),
			],
		);
	}

	/// `resource_documentation` is present and serialised only when the
	/// operator configures a documentation URL.
	#[test]
	fn resource_documentation_only_when_configured() {
		let without = protected_resource_metadata(&config_from(serde_json::json!({
			"issuer": "https://identity.example.coop",
			"resource": "https://alice.gateway.example.coop",
			"principal_subjects": ["did:arai:alice"],
			"cors": { "allowed_origins": ["https://app.example.coop"] },
		})));
		assert!(without.resource_documentation.is_none());
		let serialised = serde_json::to_value(&without).expect("serialises");
		assert!(serialised.get("resource_documentation").is_none());

		let with = protected_resource_metadata(&config_from(serde_json::json!({
			"issuer": "https://identity.example.coop",
			"resource": "https://alice.gateway.example.coop",
			"resource_documentation_url": "https://gateway.example.coop/docs",
			"principal_subjects": ["did:arai:alice"],
			"cors": { "allowed_origins": ["https://app.example.coop"] },
		})));
		assert_eq!(
			with.resource_documentation.as_deref(),
			Some("https://gateway.example.coop/docs"),
		);
	}
}
