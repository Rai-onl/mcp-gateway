//! Configuration resolution — inject credentials into server
//! definitions before the router sees them.
//!
//! This module transforms a `GatewayConfig` with named credential
//! references into one where credential values have been resolved
//! and injected into the appropriate transport fields (headers for
//! HTTP, environment variables for stdio). The router and runtimes
//! never know about credentials — they receive fully populated
//! headers and env maps.

use std::collections::HashMap;

use crate::{GatewayConfig, ServerDefinition, Transport};

/// A function that resolves a credential name to its secret value.
///
/// This is the only coupling point between the credential system
/// and configuration. The daemon provides a closure that calls the
/// credential provider; the config crate does not depend on the
/// credentials crate.
pub type CredentialResolver = Box<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// Resolve all credential references in a gateway configuration.
///
/// For each server with a `credential` field:
/// - **HTTP servers**: the resolved value is injected as a header
///   using `credential_header` and `credential_prefix`
/// - **Stdio servers**: the resolved value is injected as the
///   `MCP_CREDENTIAL` environment variable
///
/// Returns a new config with credentials resolved and injected.
/// Server definitions that have no credential are passed through
/// unchanged.
///
/// # Errors
///
/// Returns an error if any referenced credential cannot be resolved.
pub fn resolve_credentials(
	config: &GatewayConfig,
	resolver: &CredentialResolver,
) -> Result<GatewayConfig, CredentialResolutionError> {
	let mut resolved_servers = HashMap::with_capacity(config.servers.len());

	for (name, definition) in &config.servers {
		let populated = resolve_server_credentials(name, definition, resolver)?;
		resolved_servers.insert(name.clone(), populated);
	}

	Ok(GatewayConfig {
		servers: resolved_servers,
		trusted_proxies: config.trusted_proxies.clone(),
		client_identity_headers: config.client_identity_headers.clone(),
		max_body_bytes: config.max_body_bytes,
	})
}

fn resolve_server_credentials(
	server_name: &str,
	definition: &ServerDefinition,
	resolver: &CredentialResolver,
) -> Result<ServerDefinition, CredentialResolutionError> {
	let Some(credential_name) = &definition.credential else {
		return Ok(definition.clone());
	};

	let secret_value = resolver(credential_name).map_err(|reason| CredentialResolutionError {
		server: server_name.to_owned(),
		credential: credential_name.clone(),
		reason,
	})?;

	let mut populated = definition.clone();

	match &mut populated.transport {
		Transport::Http { headers, .. } => {
			let header_name = definition.resolved_credential_header().to_owned();
			let header_value = format!(
				"{}{}",
				definition.resolved_credential_prefix(),
				secret_value
			);
			headers.insert(header_name, header_value);
		}
		#[cfg(feature = "sse")]
		Transport::Sse { headers, .. } => {
			let header_name = definition.resolved_credential_header().to_owned();
			let header_value = format!(
				"{}{}",
				definition.resolved_credential_prefix(),
				secret_value
			);
			headers.insert(header_name, header_value);
		}
		Transport::Stdio { .. } => {
			populated
				.env
				.insert("MCP_CREDENTIAL".to_owned(), secret_value);
		}
	}

	// Clear the credential reference — it has been resolved.
	populated.credential = None;

	Ok(populated)
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
	use super::*;

	fn test_resolver() -> CredentialResolver {
		Box::new(|name| match name {
			"github-token" => Ok("ghp_test123".to_owned()),
			"api-key" => Ok("sk-test456".to_owned()),
			_ => Err(format!("not found: {name}")),
		})
	}

	/// An HTTP server's credential is injected as an Authorization
	/// header with Bearer prefix by default.
	#[test]
	fn http_credential_injected_as_bearer_header() {
		let config = GatewayConfig {
			servers: [(
				"github".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("github-token".to_owned()),
					credential_header: None,
					credential_prefix: None,
					transport: Transport::Http {
						url: "https://api.github.com/mcp/".to_owned(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config, &test_resolver()).unwrap();
		let server = &resolved.servers["github"];

		match &server.transport {
			Transport::Http { headers, .. } => {
				assert_eq!(
					headers.get("Authorization").map(String::as_str),
					Some("Bearer ghp_test123")
				);
			}
			Transport::Stdio { .. } => panic!("expected HTTP transport"),
		}

		// Credential reference is cleared after resolution.
		assert!(server.credential.is_none());
	}

	/// A custom credential header and empty prefix override the
	/// default Authorization/Bearer behaviour.
	#[test]
	fn custom_header_and_prefix() {
		let config = GatewayConfig {
			servers: [(
				"custom".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("api-key".to_owned()),
					credential_header: Some("X-Api-Key".to_owned()),
					credential_prefix: Some(String::new()),
					transport: Transport::Http {
						url: "https://api.example.com/mcp/".to_owned(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config, &test_resolver()).unwrap();
		let server = &resolved.servers["custom"];

		match &server.transport {
			Transport::Http { headers, .. } => {
				assert_eq!(
					headers.get("X-Api-Key").map(String::as_str),
					Some("sk-test456")
				);
			}
			Transport::Stdio { .. } => panic!("expected HTTP transport"),
		}
	}

	/// A stdio server's credential is injected as the
	/// `MCP_CREDENTIAL` environment variable.
	#[test]
	fn stdio_credential_injected_as_env_var() {
		let config = GatewayConfig {
			servers: [(
				"local-server".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("github-token".to_owned()),
					credential_header: None,
					credential_prefix: None,
					transport: Transport::Stdio {
						command: "mcp-server".to_owned(),
						args: vec![],
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config, &test_resolver()).unwrap();
		let server = &resolved.servers["local-server"];

		assert_eq!(
			server.env.get("MCP_CREDENTIAL").map(String::as_str),
			Some("ghp_test123")
		);
	}

	/// Existing headers are preserved when a credential is injected.
	#[test]
	fn existing_headers_preserved() {
		let mut headers = HashMap::new();
		headers.insert("X-Custom".to_owned(), "preserved".to_owned());

		let config = GatewayConfig {
			servers: [(
				"mixed".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("github-token".to_owned()),
					credential_header: None,
					credential_prefix: None,
					transport: Transport::Http {
						url: "https://api.example.com/mcp/".to_owned(),
						headers,
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config, &test_resolver()).unwrap();
		let server = &resolved.servers["mixed"];

		match &server.transport {
			Transport::Http { headers, .. } => {
				assert_eq!(
					headers.get("X-Custom").map(String::as_str),
					Some("preserved")
				);
				assert_eq!(
					headers.get("Authorization").map(String::as_str),
					Some("Bearer ghp_test123")
				);
			}
			Transport::Stdio { .. } => panic!("expected HTTP transport"),
		}
	}

	/// Servers without credentials pass through unchanged.
	#[test]
	fn no_credential_passes_through() {
		let config = GatewayConfig {
			servers: [(
				"public".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					transport: Transport::Http {
						url: "https://public.example.com/mcp/".to_owned(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config, &test_resolver()).unwrap();
		let server = &resolved.servers["public"];

		match &server.transport {
			Transport::Http { headers, .. } => {
				assert!(headers.is_empty());
			}
			Transport::Stdio { .. } => panic!("expected HTTP transport"),
		}
	}

	/// Multiple servers resolve their credentials independently.
	#[test]
	fn multiple_servers_resolve_independently() {
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
						transport: Transport::Http {
							url: "https://api.github.com/mcp/".to_owned(),
							headers: HashMap::new(),
						},
					},
				),
				(
					"custom".to_owned(),
					ServerDefinition {
						enabled: true,
						env: HashMap::new(),
						credential: Some("api-key".to_owned()),
						credential_header: Some("X-Api-Key".to_owned()),
						credential_prefix: Some(String::new()),
						transport: Transport::Http {
							url: "https://api.example.com/mcp/".to_owned(),
							headers: HashMap::new(),
						},
					},
				),
			]
			.into(),
			..Default::default()
		};

		let resolved = resolve_credentials(&config, &test_resolver()).unwrap();

		match &resolved.servers["github"].transport {
			Transport::Http { headers, .. } => {
				assert_eq!(
					headers.get("Authorization").map(String::as_str),
					Some("Bearer ghp_test123")
				);
			}
			Transport::Stdio { .. } => panic!("expected HTTP"),
		}

		match &resolved.servers["custom"].transport {
			Transport::Http { headers, .. } => {
				assert_eq!(
					headers.get("X-Api-Key").map(String::as_str),
					Some("sk-test456")
				);
			}
			Transport::Stdio { .. } => panic!("expected HTTP"),
		}
	}

	/// An unresolvable credential produces a clear error
	/// identifying the server and credential name.
	#[test]
	fn unresolvable_credential_returns_error() {
		let config = GatewayConfig {
			servers: [(
				"broken".to_owned(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: Some("missing-token".to_owned()),
					credential_header: None,
					credential_prefix: None,
					transport: Transport::Http {
						url: "https://api.example.com/mcp/".to_owned(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let error = resolve_credentials(&config, &test_resolver()).unwrap_err();
		assert_eq!(error.server, "broken");
		assert_eq!(error.credential, "missing-token");
	}
}
