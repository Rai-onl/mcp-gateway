//! Legacy HTTP+SSE transport runtime for the MCP gateway.
//!
//! Connects to upstream MCP servers that implement the older
//! HTTP+SSE transport (MCP specification 2024-11-05). The client
//! establishes an SSE event stream via GET to receive the message
//! endpoint URL, then forwards MCP requests to that endpoint via
//! POST.
//!
//! This transport is deprecated in favour of Streamable HTTP but
//! remains in use by older servers. The crate exists behind a
//! feature flag so it can be excluded from builds and removed
//! once the legacy transport is fully retired.

mod client;

pub use client::{SseClient, SseError, SseResponse};

#[cfg(test)]
mod tests {
	use super::*;

	/// An SSE client stores the configured SSE endpoint URL.
	#[test]
	fn client_stores_sse_url() {
		mcp_gateway_crypto::install();
		let client = SseClient::new(
			"https://old.example.com/sse".into(),
			std::collections::HashMap::new(),
		);
		assert_eq!(client.sse_url(), "https://old.example.com/sse");
	}

	/// An SSE client with headers stores them for injection
	/// into both the SSE connection and POST requests.
	#[test]
	fn client_stores_headers() {
		let mut headers = std::collections::HashMap::new();
		headers.insert("Authorization".into(), "Bearer token".into());

		mcp_gateway_crypto::install();
		let client = SseClient::new("https://old.example.com/sse".into(), headers);
		assert_eq!(client.sse_url(), "https://old.example.com/sse");
	}

	/// Connecting to an unreachable SSE endpoint produces an error.
	#[tokio::test]
	async fn connect_to_unreachable_host_fails() {
		mcp_gateway_crypto::install();
		let client = SseClient::new(
			"http://192.0.2.1:1/sse".into(),
			std::collections::HashMap::new(),
		);

		let error = client
			.connect()
			.await
			.expect_err("unreachable host should fail");
		assert!(matches!(error, SseError::Connection(_)));
	}

	/// Forwarding to a server that hasn't provided a message
	/// endpoint yet produces a not-connected error.
	#[tokio::test]
	async fn forward_without_connect_fails() {
		mcp_gateway_crypto::install();
		let client = SseClient::new(
			"http://192.0.2.1:1/sse".into(),
			std::collections::HashMap::new(),
		);

		let message = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "ping"
		});

		let error = client
			.forward(&message)
			.await
			.expect_err("forward without connect should fail");
		assert!(matches!(error, SseError::NotConnected));
	}
}
