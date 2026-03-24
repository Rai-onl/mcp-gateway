//! MCP message types and JSON-RPC 2.0 detection.
//!
//! The gateway needs to distinguish between JSON-RPC requests
//! (which have an `id` field and expect a response) and
//! notifications (which lack an `id` field and receive HTTP 202
//! Accepted). This crate provides the types and detection logic
//! for that classification.

mod message;

pub use message::{MessageKind, classify, classify_str};

#[cfg(test)]
mod tests {
	use super::*;

	/// A JSON-RPC message with an `id` field is a request that
	/// expects a response from the backend server.
	#[test]
	fn message_with_id_is_request() {
		let value = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}});
		assert_eq!(classify(&value), MessageKind::Request);
	}

	/// A JSON-RPC message without an `id` field is a notification
	/// that should receive HTTP 202 Accepted with no body.
	#[test]
	fn message_without_id_is_notification() {
		let value = serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"});
		assert_eq!(classify(&value), MessageKind::Notification);
	}

	/// A message with a null `id` is still a request — the JSON-RPC
	/// spec allows null IDs for requests that the client does not
	/// need to correlate with a specific response.
	#[test]
	fn message_with_null_id_is_request() {
		let value = serde_json::json!({"jsonrpc":"2.0","id":null,"method":"ping"});
		assert_eq!(classify(&value), MessageKind::Request);
	}

	/// A message with a string `id` is a request — the JSON-RPC
	/// spec allows both integer and string IDs.
	#[test]
	fn message_with_string_id_is_request() {
		let value =
			serde_json::json!({"jsonrpc":"2.0","id":"abc-123","method":"tools/call","params":{}});
		assert_eq!(classify(&value), MessageKind::Request);
	}

	/// Invalid JSON classified via the string path is malformed.
	#[test]
	fn invalid_json_is_malformed() {
		assert_eq!(classify_str("not json at all"), MessageKind::Malformed);
	}

	/// An empty JSON object is malformed — it lacks the required
	/// `jsonrpc` and `method` fields.
	#[test]
	fn empty_object_is_malformed() {
		let value = serde_json::json!({});
		assert_eq!(classify(&value), MessageKind::Malformed);
	}

	/// A message without `jsonrpc: "2.0"` is malformed.
	#[test]
	fn missing_jsonrpc_version_is_malformed() {
		let value = serde_json::json!({"id":1,"method":"ping"});
		assert_eq!(classify(&value), MessageKind::Malformed);
	}

	/// A message with the wrong `jsonrpc` version is malformed.
	#[test]
	fn wrong_jsonrpc_version_is_malformed() {
		let value = serde_json::json!({"jsonrpc":"1.0","id":1,"method":"ping"});
		assert_eq!(classify(&value), MessageKind::Malformed);
	}

	/// A JSON array is classified as a batch request.
	#[test]
	fn array_is_batch() {
		let value = serde_json::json!([
			{"jsonrpc":"2.0","id":1,"method":"ping"},
			{"jsonrpc":"2.0","id":2,"method":"ping"}
		]);
		assert_eq!(classify(&value), MessageKind::Batch);
	}

	/// An empty JSON array is still a batch.
	#[test]
	fn empty_array_is_batch() {
		let value = serde_json::json!([]);
		assert_eq!(classify(&value), MessageKind::Batch);
	}
}
