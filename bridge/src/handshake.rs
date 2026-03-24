//! MCP initialize handshake for stdio bridge processes.
//!
//! When the gateway spawns a stdio MCP server, it must perform
//! the protocol handshake before forwarding any client requests.
//! The handshake consists of:
//!
//! 1. Send an `initialize` request with the gateway's capabilities
//! 2. Read the server's `initialize` response with its capabilities
//! 3. Send a `notifications/initialized` notification

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP protocol version the gateway advertises.
const PROTOCOL_VERSION: &str = "2025-03-26";

/// Gateway client info sent during handshake.
const CLIENT_NAME: &str = "mcp-gateway";
const CLIENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Result of a successful MCP handshake.
#[derive(Debug, Clone)]
pub struct Handshake {
	/// The protocol version agreed upon.
	pub protocol_version: String,

	/// Server capabilities returned in the initialize response.
	pub capabilities: Value,

	/// Server info returned in the initialize response.
	pub server_info: Option<ServerInfo>,
}

/// Server identity from the initialize response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
	pub name: String,
	#[serde(default)]
	pub version: Option<String>,
}

/// Build the JSON-RPC `initialize` request to send to a new
/// stdio server process.
pub fn initialize_request() -> Value {
	serde_json::json!({
		"jsonrpc": "2.0",
		"id": 0,
		"method": "initialize",
		"params": {
			"protocolVersion": PROTOCOL_VERSION,
			"capabilities": {},
			"clientInfo": {
				"name": CLIENT_NAME,
				"version": CLIENT_VERSION,
			}
		}
	})
}

/// Build the `notifications/initialized` notification sent after
/// a successful initialize response.
pub fn initialized_notification() -> Value {
	serde_json::json!({
		"jsonrpc": "2.0",
		"method": "notifications/initialized"
	})
}

/// Parse an initialize response and extract the handshake result.
///
/// # Errors
///
/// Returns an error if the response is not a valid JSON-RPC
/// response or lacks the expected `result` fields.
pub fn parse_initialize_response(response: &Value) -> Result<Handshake, HandshakeError> {
	let result = response
		.get("result")
		.ok_or(HandshakeError::MissingResult)?;

	let protocol_version = result
		.get("protocolVersion")
		.and_then(Value::as_str)
		.ok_or(HandshakeError::MissingProtocolVersion)?
		.to_owned();

	let capabilities = result
		.get("capabilities")
		.cloned()
		.unwrap_or(Value::Object(serde_json::Map::new()));

	let server_info = result
		.get("serverInfo")
		.and_then(|v| serde_json::from_value(v.clone()).ok());

	Ok(Handshake {
		protocol_version,
		capabilities,
		server_info,
	})
}

/// Errors during the MCP handshake.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
	/// The initialize response did not contain a `result` field.
	#[error("initialize response missing result field")]
	MissingResult,

	/// The initialize response did not contain a protocol version.
	#[error("initialize response missing protocolVersion")]
	MissingProtocolVersion,
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The initialize request has the correct JSON-RPC structure
	/// with method, id, and protocol version.
	#[test]
	fn initialize_request_has_correct_structure() {
		let req = initialize_request();
		assert_eq!(req["jsonrpc"], "2.0");
		assert_eq!(req["id"], 0);
		assert_eq!(req["method"], "initialize");
		assert_eq!(req["params"]["protocolVersion"], PROTOCOL_VERSION);
		assert_eq!(req["params"]["clientInfo"]["name"], CLIENT_NAME);
	}

	/// The initialized notification has no `id` field, making it
	/// a fire-and-forget notification per JSON-RPC 2.0.
	#[test]
	fn initialized_notification_has_no_id() {
		let notif = initialized_notification();
		assert_eq!(notif["jsonrpc"], "2.0");
		assert_eq!(notif["method"], "notifications/initialized");
		assert!(notif.get("id").is_none());
	}

	/// A valid initialize response is parsed into a handshake
	/// with protocol version, capabilities, and server info.
	#[test]
	fn valid_response_parses_to_handshake() {
		let response = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 0,
			"result": {
				"protocolVersion": "2025-03-26",
				"capabilities": {
					"tools": {"listChanged": true}
				},
				"serverInfo": {
					"name": "test-server",
					"version": "1.0.0"
				}
			}
		});

		let handshake = parse_initialize_response(&response).unwrap();
		assert_eq!(handshake.protocol_version, "2025-03-26");
		assert_eq!(handshake.capabilities["tools"]["listChanged"], true);
		let info = handshake.server_info.unwrap();
		assert_eq!(info.name, "test-server");
		assert_eq!(info.version.as_deref(), Some("1.0.0"));
	}

	/// A response without a `result` field is an error.
	#[test]
	fn response_without_result_fails() {
		let response = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 0,
			"error": {"code": -1, "message": "failed"}
		});

		let err = parse_initialize_response(&response).unwrap_err();
		assert!(matches!(err, HandshakeError::MissingResult));
	}

	/// A response with a result but no protocol version is an error.
	#[test]
	fn response_without_protocol_version_fails() {
		let response = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 0,
			"result": {
				"capabilities": {}
			}
		});

		let err = parse_initialize_response(&response).unwrap_err();
		assert!(matches!(err, HandshakeError::MissingProtocolVersion));
	}

	/// Missing capabilities defaults to an empty object rather
	/// than failing, since some servers omit this field.
	#[test]
	fn missing_capabilities_defaults_to_empty() {
		let response = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 0,
			"result": {
				"protocolVersion": "2025-03-26"
			}
		});

		let handshake = parse_initialize_response(&response).unwrap();
		assert!(handshake.capabilities.as_object().unwrap().is_empty());
		assert!(handshake.server_info.is_none());
	}
}
