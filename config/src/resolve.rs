//! Configuration resolution: inject credentials into server
//! definitions before the router sees them.
//!
//! This module transforms a `GatewayConfig` with named credential
//! references into one where credential values have been resolved
//! and injected into the appropriate transport fields (headers for
//! HTTP, environment variables for stdio). The router and runtimes
//! never know about credentials; they receive fully populated
//! headers and env maps.

use std::collections::HashMap;

use crate::{CredentialInjection, GatewayConfig, ServerDefinition, Transport};

/// Translate every server's credential reference into use-time
/// injection metadata.
///
/// For each server whose `credential` field is set, this produces a
/// [`CredentialInjection`] describing *how* the value will be applied
/// to outgoing traffic (as an HTTP header for HTTP and SSE
/// upstreams, or as the `MCP_CREDENTIAL` environment variable for
/// stdio servers) and stores it on
/// [`ServerDefinition::credential_injection`]. The credential value
/// itself is **not** fetched here; that happens at use time through
/// the resolver carried by the proxy and bridge runtimes. Operator
/// supplied headers and environment entries are passed through
/// untouched.
///
/// Servers without a credential reference are returned unchanged.
/// The function is infallible: producing metadata cannot fail, and
/// any resolution errors that *would* surface at use time are
/// reported by the resolver itself when the request is dispatched.
#[must_use]
pub fn resolve_credentials(config: &GatewayConfig) -> GatewayConfig {
	let mut resolved_servers = HashMap::with_capacity(config.servers.len());

	for (name, definition) in &config.servers {
		resolved_servers.insert(name.clone(), populate_injection(definition));
	}

	GatewayConfig {
		servers: resolved_servers,
		oauth: config.oauth.clone(),
		trusted_proxies: config.trusted_proxies.clone(),
		client_identity_headers: config.client_identity_headers.clone(),
		max_body_bytes: config.max_body_bytes,
		authentication: config.authentication.clone(),
	}
}

/// Populate a server's `credential_injection` from its `credential`
/// reference and clear the now-redundant marker.
///
/// The choice of injection variant follows the transport: HTTP and
/// SSE upstreams take a `Header` injection (carrying the resolved
/// header name and prefix so the proxy doesn't have to re-derive
/// them at request time), and stdio servers take an `Env` injection.
fn populate_injection(definition: &ServerDefinition) -> ServerDefinition {
	let Some(credential_name) = &definition.credential else {
		return definition.clone();
	};

	let injection = match &definition.transport {
		Transport::Http { .. } => CredentialInjection::Header {
			credential_name: credential_name.clone(),
			header_name: definition.resolved_credential_header().to_owned(),
			header_prefix: definition.resolved_credential_prefix().to_owned(),
		},
		#[cfg(feature = "sse")]
		Transport::Sse { .. } => CredentialInjection::Header {
			credential_name: credential_name.clone(),
			header_name: definition.resolved_credential_header().to_owned(),
			header_prefix: definition.resolved_credential_prefix().to_owned(),
		},
		Transport::Stdio { .. } => CredentialInjection::Env {
			credential_name: credential_name.clone(),
		},
	};

	let mut populated = definition.clone();
	populated.credential_injection = Some(injection);
	// `credential_injection` is the canonical post-resolution view;
	// clear the input marker so downstream code cannot accidentally
	// re-read it.
	populated.credential = None;
	populated
}

/// A credential referenced by a server could not be resolved.
#[derive(Debug, thiserror::Error)]
#[error("credential '{credential}' for server '{server}' could not be resolved: {reason}")]
pub struct CredentialResolutionError {
	/// The server that referenced the credential.
	pub server: String,
	/// The credential name that could not be resolved.
	pub credential: String,
	/// Why the credential could not be resolved.
	pub reason: String,
}

#[cfg(test)]
mod tests {
	use mcp_gateway_credentials::Secret;

	use crate::CredentialInjection;

	use super::*;

	/// An HTTP server's credential is materialised as `Header`
	/// injection metadata using the default `Authorization`/`Bearer `
	/// settings. The headers map is left untouched; eager value
	/// baking has been replaced by use-time resolution.
	#[test]
	fn http_credential_produces_header_injection_with_defaults() {
		let config = GatewayConfig {
			servers: [(
				"github".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("github-token".to_owned()),
					credential_header: None,
					credential_prefix: None,
					request_timeout_seconds: None,
					credential_injection: None,
					transport: Transport::Http {
						url: "https://api.github.com/mcp/".to_owned(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config);
		let server = &resolved.servers["github"];

		assert_eq!(
			server.credential_injection,
			Some(CredentialInjection::Header {
				credential_name: "github-token".to_owned(),
				header_name: "Authorization".to_owned(),
				header_prefix: "Bearer ".to_owned(),
			}),
		);

		let Transport::Http { headers, .. } = &server.transport else {
			panic!("expected HTTP transport");
		};
		assert!(
			headers.is_empty(),
			"resolve_credentials must no longer eager-inject headers",
		);

		assert!(
			server.credential.is_none(),
			"the credential reference is consumed by resolution",
		);
	}

	/// A server's `credential_header` and `credential_prefix` flow
	/// into the `Header` injection metadata so the use-time consumer
	/// applies the operator-chosen header and prefix.
	#[test]
	fn http_credential_carries_custom_header_and_prefix() {
		let config = GatewayConfig {
			servers: [(
				"custom".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("api-key".to_owned()),
					credential_header: Some("X-Api-Key".to_owned()),
					credential_prefix: Some(String::new()),
					request_timeout_seconds: None,
					credential_injection: None,
					transport: Transport::Http {
						url: "https://api.example.com/mcp/".to_owned(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config);
		let server = &resolved.servers["custom"];

		assert_eq!(
			server.credential_injection,
			Some(CredentialInjection::Header {
				credential_name: "api-key".to_owned(),
				header_name: "X-Api-Key".to_owned(),
				header_prefix: String::new(),
			}),
		);
	}

	/// A stdio server's credential is materialised as `Env`
	/// injection metadata. The `env` map is left untouched; the
	/// bridge resolves the value at spawn time.
	#[test]
	fn stdio_credential_produces_env_injection() {
		let config = GatewayConfig {
			servers: [(
				"local-server".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("github-token".to_owned()),
					credential_header: None,
					credential_prefix: None,
					request_timeout_seconds: None,
					credential_injection: None,
					transport: Transport::Stdio {
						command: "mcp-server".to_owned(),
						args: vec![],
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config);
		let server = &resolved.servers["local-server"];

		assert_eq!(
			server.credential_injection,
			Some(CredentialInjection::Env {
				credential_name: "github-token".to_owned(),
			}),
		);
		assert!(
			!server.env.contains_key("MCP_CREDENTIAL"),
			"resolve_credentials must no longer eager-inject env vars",
		);
	}

	/// Operator-supplied headers and env entries pass through
	/// untouched; resolution only annotates injection metadata.
	#[test]
	fn operator_supplied_headers_and_env_pass_through_unchanged() {
		let mut headers = HashMap::new();
		headers.insert("X-Custom".to_owned(), Secret::new("preserved".to_owned()));

		let mut env = HashMap::new();
		env.insert("LOG_LEVEL".to_owned(), Secret::new("debug".to_owned()));

		let config = GatewayConfig {
			servers: [(
				"mixed".to_owned(),
				ServerDefinition {
					enabled: true,
					env,
					credential: Some("github-token".to_owned()),
					credential_header: None,
					credential_prefix: None,
					request_timeout_seconds: None,
					credential_injection: None,
					transport: Transport::Http {
						url: "https://api.example.com/mcp/".to_owned(),
						headers,
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config);
		let server = &resolved.servers["mixed"];

		let Transport::Http { headers, .. } = &server.transport else {
			panic!("expected HTTP transport");
		};
		assert_eq!(
			headers.get("X-Custom").map(Secret::expose),
			Some("preserved"),
		);
		assert_eq!(headers.len(), 1, "no eager Authorization injection");

		assert_eq!(
			server.env.get("LOG_LEVEL").map(Secret::expose),
			Some("debug"),
		);
	}

	/// Servers without a credential reference receive `None`
	/// injection metadata and are otherwise untouched.
	#[test]
	fn server_without_credential_has_no_injection() {
		let config = GatewayConfig {
			servers: [(
				"public".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					request_timeout_seconds: None,
					credential_injection: None,
					transport: Transport::Http {
						url: "https://public.example.com/mcp/".to_owned(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config);
		let server = &resolved.servers["public"];

		assert_eq!(server.credential_injection, None);
		let Transport::Http { headers, .. } = &server.transport else {
			panic!("expected HTTP transport");
		};
		assert!(headers.is_empty());
	}

	/// Servers are resolved independently; each one's transport
	/// kind drives its own injection variant.
	#[test]
	fn multiple_servers_each_get_their_own_injection() {
		let config = GatewayConfig {
			servers: [
				(
					"github".to_owned(),
					ServerDefinition {
						enabled: true,
						env: HashMap::new(),
						credential: Some("github-token".to_owned()),
						credential_header: None,
						credential_prefix: None,
						request_timeout_seconds: None,
						credential_injection: None,
						transport: Transport::Http {
							url: "https://api.github.com/mcp/".to_owned(),
							headers: HashMap::new(),
						},
					},
				),
				(
					"local".to_owned(),
					ServerDefinition {
						enabled: true,
						env: HashMap::new(),
						credential: Some("local-token".to_owned()),
						credential_header: None,
						credential_prefix: None,
						request_timeout_seconds: None,
						credential_injection: None,
						transport: Transport::Stdio {
							command: "mcp-local".to_owned(),
							args: vec![],
						},
					},
				),
			]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config);

		assert_eq!(
			resolved.servers["github"].credential_injection,
			Some(CredentialInjection::Header {
				credential_name: "github-token".to_owned(),
				header_name: "Authorization".to_owned(),
				header_prefix: "Bearer ".to_owned(),
			}),
		);
		assert_eq!(
			resolved.servers["local"].credential_injection,
			Some(CredentialInjection::Env {
				credential_name: "local-token".to_owned(),
			}),
		);
	}

	/// An SSE server's credential is materialised as `Header`
	/// injection metadata, mirroring the HTTP path.
	#[cfg(feature = "sse")]
	#[test]
	fn sse_credential_produces_header_injection() {
		let config = GatewayConfig {
			servers: [(
				"streaming".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("sse-token".to_owned()),
					credential_header: None,
					credential_prefix: None,
					request_timeout_seconds: None,
					credential_injection: None,
					transport: Transport::Sse {
						url: "https://stream.example.com/mcp/".to_owned(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config);
		let server = &resolved.servers["streaming"];

		assert_eq!(
			server.credential_injection,
			Some(CredentialInjection::Header {
				credential_name: "sse-token".to_owned(),
				header_name: "Authorization".to_owned(),
				header_prefix: "Bearer ".to_owned(),
			}),
		);
	}
}
