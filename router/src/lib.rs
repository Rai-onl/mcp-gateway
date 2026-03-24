//! Request routing for the MCP gateway.
//!
//! The router maps server names to their runtime backends
//! (stdio bridge or HTTP proxy) and dispatches incoming MCP
//! messages to the correct one. It owns the runtime lifecycle
//! — starting bridges and proxies from configuration.

mod dispatch;

pub use dispatch::{Router, RouterError, RouterResponse};

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use mcp_gateway_config::{GatewayConfig, ServerDefinition, Transport};

	use super::*;

	fn test_config() -> GatewayConfig {
		let mut servers = HashMap::new();

		servers.insert(
			"filesystem".into(),
			ServerDefinition {
				enabled: true,
				env: HashMap::new(),
				credential: None,
				credential_header: None,
				credential_prefix: None,
				transport: Transport::Stdio {
					command: "cat".into(),
					args: vec![],
				},
			},
		);

		servers.insert(
			"remote-tools".into(),
			ServerDefinition {
				enabled: true,
				env: HashMap::new(),
				credential: None,
				credential_header: None,
				credential_prefix: None,
				transport: Transport::Http {
					url: "https://api.example.com/mcp/".into(),
					headers: HashMap::new(),
				},
			},
		);

		servers.insert(
			"disabled-server".into(),
			ServerDefinition {
				enabled: false,
				env: HashMap::new(),
				credential: None,
				credential_header: None,
				credential_prefix: None,
				transport: Transport::Stdio {
					command: "echo".into(),
					args: vec![],
				},
			},
		);

		GatewayConfig {
			servers,
			..Default::default()
		}
	}

	/// The router identifies which servers are available from
	/// the configuration, excluding disabled servers.
	#[test]
	fn router_lists_enabled_servers() {
		let config = test_config();
		let router = Router::from_config(&config).unwrap();

		let names = router.server_names();
		assert!(names.contains(&"filesystem"));
		assert!(names.contains(&"remote-tools"));
		assert!(!names.contains(&"disabled-server"));
	}

	/// Requesting an unknown server name returns a not-found error.
	#[tokio::test]
	async fn unknown_server_returns_not_found() {
		let config = test_config();
		let router = Router::from_config(&config).unwrap();

		let message = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "tools/list"
		});

		let error = router
			.dispatch("nonexistent", &message)
			.await
			.expect_err("unknown server should return not-found");
		assert!(matches!(error, RouterError::ServerNotFound(_)));
	}

	/// Requesting a disabled server returns a not-found error
	/// rather than attempting to connect.
	#[tokio::test]
	async fn disabled_server_returns_not_found() {
		let config = test_config();
		let router = Router::from_config(&config).unwrap();

		let message = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "tools/list"
		});

		let error = router
			.dispatch("disabled-server", &message)
			.await
			.expect_err("disabled server should return not-found");
		assert!(matches!(error, RouterError::ServerNotFound(_)));
	}
}
