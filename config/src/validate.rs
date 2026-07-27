//! Configuration validation.
//!
//! Checks that a loaded configuration is operationally valid
//! before the gateway starts. Catches problems that are
//! structurally valid JSON but would fail at runtime: missing
//! binaries, malformed URLs, empty commands, unsafe inbound
//! authentication shapes.

use crate::server::MAX_REQUEST_TIMEOUT_SECONDS;
use crate::{GatewayConfig, Transport, authentication};

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

		// A configured per-request timeout of zero elapses on the first
		// poll, so every request fails instantly and the router tears the
		// bridge down and respawns it in a tight loop. An absurdly large
		// value is almost always a units mistake and defeats the bound the
		// feature exists to provide. Reject both; an unset value takes the
		// default and is always fine.
		if let Some(seconds) = definition.request_timeout_seconds {
			if seconds == 0 {
				errors.push(format!(
					"server '{name}': request_timeout_seconds must be greater than zero"
				));
			} else if seconds > MAX_REQUEST_TIMEOUT_SECONDS {
				errors.push(format!(
					"server '{name}': request_timeout_seconds must not exceed {MAX_REQUEST_TIMEOUT_SECONDS}"
				));
			}
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

	if let Some(auth) = &config.authentication {
		errors.extend(authentication::validate(auth, &config.servers));
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
						request_timeout_seconds: None,
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
						request_timeout_seconds: None,
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

	/// An empty config is valid: no servers means nothing to validate.
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
					request_timeout_seconds: None,
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
					request_timeout_seconds: None,
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
					request_timeout_seconds: None,
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

	/// Disabled servers are not validated: they are not started
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
					request_timeout_seconds: None,
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
						request_timeout_seconds: None,
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
						request_timeout_seconds: None,
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

	/// A server whose `request_timeout_seconds` is zero is invalid: a
	/// zero timeout would make every request fail instantly and churn the
	/// bridge in a respawn loop.
	#[test]
	fn zero_request_timeout_is_invalid() {
		let config = GatewayConfig {
			servers: [(
				"instant".into(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					request_timeout_seconds: Some(0),
					credential_injection: None,
					transport: Transport::Stdio {
						command: "cat".into(),
						args: vec![],
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert_eq!(errors.len(), 1);
		assert!(errors[0].contains("instant"));
		assert!(errors[0].contains("request_timeout_seconds"));
	}

	/// A server whose `request_timeout_seconds` exceeds the ceiling is
	/// invalid: such a value is almost always a units mistake and would
	/// let a wedged request hang its client far longer than intended.
	#[test]
	fn excessive_request_timeout_is_invalid() {
		let config = GatewayConfig {
			servers: [(
				"day-long".into(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					request_timeout_seconds: Some(86_400),
					credential_injection: None,
					transport: Transport::Stdio {
						command: "cat".into(),
						args: vec![],
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert_eq!(errors.len(), 1);
		assert!(errors[0].contains("day-long"));
		assert!(errors[0].contains("request_timeout_seconds"));
	}

	/// A server with a positive, in-bounds `request_timeout_seconds`
	/// passes: the guard rejects only zero and out-of-range values.
	#[test]
	fn in_bounds_request_timeout_passes() {
		let config = GatewayConfig {
			servers: [(
				"patient".into(),
				ServerDefinition {
					enabled: true,
					env: HashMap::new(),
					credential: None,
					credential_header: None,
					credential_prefix: None,
					request_timeout_seconds: Some(120),
					credential_injection: None,
					transport: Transport::Stdio {
						command: "cat".into(),
						args: vec![],
					},
				},
			)]
			.into(),
			..Default::default()
		};

		let errors = validate(&config);
		assert!(errors.is_empty(), "expected no errors, got: {errors:?}");
	}
}
