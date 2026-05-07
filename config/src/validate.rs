//! Configuration validation.
//!
//! Checks that a loaded configuration is operationally valid
//! before the gateway starts. Catches problems that are
//! structurally valid JSON but would fail at runtime — missing
//! binaries, malformed URLs, empty commands.

use crate::{GatewayConfig, Transport};

/// Validate a gateway configuration and return all errors found.
///
/// Returns an empty list if the configuration is valid. Disabled
/// servers are skipped since they are not started by the gateway.
/// All errors are collected rather than failing on the first, so
/// operators can fix everything in one pass.
#[must_use]
pub fn validate(config: &GatewayConfig) -> Vec<String> {
	let mut errors = Vec::new();

	for (name, definition) in &config.servers {
		if !definition.enabled {
			continue;
		}

		match &definition.transport {
			Transport::Stdio { command, .. } => {
				if command.is_empty() {
					errors.push(format!("server '{name}': stdio command is empty"));
				}
			}
			Transport::Http { url, .. } => {
				if url.is_empty() {
					errors.push(format!("server '{name}': http url is empty"));
				} else if !url.starts_with("http://") && !url.starts_with("https://") {
					errors.push(format!(
						"server '{name}': http url must start with http:// or https://"
					));
				}
			}
			#[cfg(feature = "sse")]
			Transport::Sse { url, .. } => {
				if url.is_empty() {
					errors.push(format!("server '{name}': sse url is empty"));
				} else if !url.starts_with("http://") && !url.starts_with("https://") {
					errors.push(format!(
						"server '{name}': sse url must start with http:// or https://"
					));
				}
			}
		}
	}

	errors
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use crate::{GatewayConfig, ServerDefinition, Transport};

	use super::*;

	/// A config with valid stdio and HTTP servers passes validation.
	#[test]
	fn valid_config_passes() {
		let config = GatewayConfig {
			servers: [
				(
					"echo".into(),
					ServerDefinition {
						enabled: true,
						env: HashMap::new(),
						credential: None,
						credential_header: None,
						credential_prefix: None,
						credential_injection: None,
						transport: Transport::Stdio {
							command: "echo".into(),
							args: vec![],
						},
					},
				),
				(
					"remote".into(),
					ServerDefinition {
						enabled: true,
						env: HashMap::new(),
						credential: None,
						credential_header: None,
						credential_prefix: None,
						credential_injection: None,
						transport: Transport::Http {
							url: "https://api.example.com/mcp/".into(),
							headers: HashMap::new(),
						},
					},
				),
			]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
	}

	/// An empty config is valid — no servers means nothing to validate.
	#[test]
	fn empty_config_passes() {
		let config = GatewayConfig {
			servers: HashMap::new(),
			..Default::default()
		};

		let errors = validate(&config);
		assert!(errors.is_empty());
	}

	/// A stdio server with an empty command string is invalid.
	#[test]
	fn empty_stdio_command_is_invalid() {
		let config = GatewayConfig {
			servers: [(
				"bad".into(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					credential_injection: None,
					transport: Transport::Stdio {
						command: String::new(),
						args: vec![],
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert_eq!(errors.len(), 1);
		assert!(errors[0].contains("bad"));
		assert!(errors[0].contains("command"));
	}

	/// An HTTP server with an empty URL is invalid.
	#[test]
	fn empty_http_url_is_invalid() {
		let config = GatewayConfig {
			servers: [(
				"broken".into(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					credential_injection: None,
					transport: Transport::Http {
						url: String::new(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert_eq!(errors.len(), 1);
		assert!(errors[0].contains("broken"));
		assert!(errors[0].contains("url"));
	}

	/// An HTTP server with a URL missing a scheme is invalid.
	#[test]
	fn http_url_without_scheme_is_invalid() {
		let config = GatewayConfig {
			servers: [(
				"no-scheme".into(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					credential_injection: None,
					transport: Transport::Http {
						url: "api.example.com/mcp/".into(),
						headers: HashMap::new(),
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert!(!errors.is_empty());
		assert!(errors[0].contains("no-scheme"));
	}

	/// Disabled servers are not validated — they are not started
	/// so their configuration does not need to be operational.
	#[test]
	fn disabled_servers_are_skipped() {
		let config = GatewayConfig {
			servers: [(
				"disabled".into(),
				ServerDefinition {
					enabled: false,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					credential_injection: None,
					transport: Transport::Stdio {
						command: String::new(),
						args: vec![],
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert!(errors.is_empty());
	}

	/// Multiple validation errors are collected and returned
	/// together, not just the first.
	#[test]
	fn multiple_errors_collected() {
		let config = GatewayConfig {
			servers: [
				(
					"bad-stdio".into(),
					ServerDefinition {
						enabled: true,
						env: HashMap::new(),
						credential: None,
						credential_header: None,
						credential_prefix: None,
						credential_injection: None,
						transport: Transport::Stdio {
							command: String::new(),
							args: vec![],
						},
					},
				),
				(
					"bad-http".into(),
					ServerDefinition {
						enabled: true,
						env: HashMap::new(),
						credential: None,
						credential_header: None,
						credential_prefix: None,
						credential_injection: None,
						transport: Transport::Http {
							url: String::new(),
							headers: HashMap::new(),
						},
					},
				),
			]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert_eq!(errors.len(), 2);
	}
}
