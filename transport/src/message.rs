//! JSON-RPC 2.0 message classification.
//!
//! MCP uses JSON-RPC 2.0 as its wire format. The gateway needs to
//! classify incoming messages without fully parsing their contents
//! — it only needs to know whether a message is a request (has an
//! `id` field, expects a response) or a notification (no `id`,
//! fire-and-forget).

use serde_json::Value;

/// The kind of JSON-RPC 2.0 message received by the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
	/// A request with an `id` field that expects a response.
	Request,
	/// A notification without an `id` field — fire-and-forget.
	Notification,
	/// The message could not be parsed as valid JSON, lacks
	/// the required fields for a JSON-RPC message, or is a
	/// batch (array) which the gateway does not support.
	Malformed,
	/// The message is a JSON array — a batch request per
	/// JSON-RPC 2.0 section 6. The gateway does not support
	/// batch processing.
	Batch,
}

/// Classify a parsed JSON value as a request, notification,
/// batch, or malformed.
///
/// Checks for the presence of an `id` field, a `method` field,
/// and the `jsonrpc: "2.0"` version marker. The `id` field
/// determines request vs notification; the `method` field and
/// version confirm this is a valid JSON-RPC 2.0 message.
#[must_use]
pub fn classify(value: &Value) -> MessageKind {
	// JSON-RPC 2.0 batch requests are JSON arrays.
	if value.is_array() {
		return MessageKind::Batch;
	}

	let Some(object) = value.as_object() else {
		return MessageKind::Malformed;
	};

	// A valid JSON-RPC 2.0 message must have `jsonrpc: "2.0"`.
	if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
		return MessageKind::Malformed;
	}

	// A valid JSON-RPC message must have a `method` field.
	if !object.contains_key("method") {
		return MessageKind::Malformed;
	}

	if object.contains_key("id") {
		MessageKind::Request
	} else {
		MessageKind::Notification
	}
}

/// Classify a raw JSON string as a request, notification,
/// batch, or malformed.
///
/// Parses the string to a `Value` first, then delegates to
/// [`classify`]. Prefer calling `classify` directly when the
/// message has already been parsed.
#[must_use]
pub fn classify_str(body: &str) -> MessageKind {
	let Ok(value) = serde_json::from_str::<Value>(body) else {
		return MessageKind::Malformed;
	};

	classify(&value)
}
