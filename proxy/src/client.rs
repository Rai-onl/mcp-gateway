//! HTTP client for proxying MCP requests to upstream servers.
//!
//! The proxy sends JSON-RPC message bodies to a configured
//! upstream URL via HTTP POST, injects configured headers, and
//! returns the upstream response body and status.

use std::collections::HashMap;

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;

/// Default timeout for upstream HTTP requests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// An HTTP proxy to a remote MCP server.
#[derive(Debug)]
pub struct Proxy {
	client: Client,
	url: String,
	headers: HashMap<String, String>,
}

/// The response from an upstream MCP server.
#[derive(Debug)]
pub struct ProxyResponse {
	/// The HTTP status code from the upstream server.
	pub status: u16,

	/// The response body parsed as JSON.
	pub body: Value,

	/// The `Mcp-Session-Id` header from the upstream, if present.
	pub session_id: Option<String>,
}

impl Proxy {
	/// Create a new proxy targeting the given upstream URL.
	///
	/// Headers are injected into every request to the upstream
	/// server. Values may contain `${VAR}` references but the
	/// proxy does not resolve them — the caller is responsible
	/// for interpolation before constructing the proxy.
	///
	/// # Errors
	///
	/// Returns an error if the underlying HTTP client cannot be
	/// constructed (TLS backend misconfiguration).
	pub fn new(url: String, headers: HashMap<String, String>) -> Result<Self, ProxyError> {
		let client = Client::builder()
			.timeout(DEFAULT_TIMEOUT)
			.connect_timeout(Duration::from_secs(10))
			.build()
			.map_err(ProxyError::ClientBuild)?;

		Ok(Self {
			client,
			url,
			headers,
		})
	}

	/// Forward a JSON-RPC message to the upstream server.
	///
	/// The message body is sent as-is via HTTP POST with
	/// `Content-Type: application/json`. Configured headers are
	/// injected into the request. The upstream response is
	/// returned with its status code, body, and any
	/// `Mcp-Session-Id` header.
	///
	/// # Errors
	///
	/// Returns an error if the HTTP request fails (network error,
	/// DNS failure, TLS error) or the response body is not valid
	/// JSON.
	pub async fn forward(&self, message: &Value) -> Result<ProxyResponse, ProxyError> {
		let mut request = self
			.client
			.post(&self.url)
			.header("Content-Type", "application/json");

		for (name, value) in &self.headers {
			request = request.header(name, value);
		}

		let response = request
			.json(message)
			.send()
			.await
			.map_err(ProxyError::Request)?;

		let status = response.status().as_u16();

		let session_id = response
			.headers()
			.get("mcp-session-id")
			.and_then(|value| value.to_str().ok())
			.map(String::from);

		let body = response
			.json::<Value>()
			.await
			.map_err(ProxyError::ResponseBody)?;

		Ok(ProxyResponse {
			status,
			body,
			session_id,
		})
	}

	/// The upstream URL this proxy targets.
	#[must_use]
	pub fn url(&self) -> &str {
		&self.url
	}
}

/// Errors from the HTTP proxy.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
	/// The HTTP client could not be constructed.
	#[error("failed to build HTTP client: {0}")]
	ClientBuild(reqwest::Error),

	/// The HTTP request to the upstream server failed.
	#[error("upstream request failed: {0}")]
	Request(reqwest::Error),

	/// The upstream response body could not be parsed as JSON.
	#[error("invalid upstream response body: {0}")]
	ResponseBody(reqwest::Error),
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A proxy stores the configured URL and headers.
	#[test]
	fn proxy_stores_configuration() {
		let mut headers = HashMap::new();
		headers.insert("Authorization".into(), "Bearer test-token".into());

		let proxy = Proxy::new("https://api.example.com/mcp/".into(), headers).unwrap();
		assert_eq!(proxy.url(), "https://api.example.com/mcp/");
	}

	/// A proxy with no headers can be created — headers are
	/// optional for upstream servers that do not require auth.
	#[test]
	fn proxy_without_headers() {
		let proxy = Proxy::new("https://api.example.com/mcp/".into(), HashMap::new()).unwrap();
		assert_eq!(proxy.url(), "https://api.example.com/mcp/");
	}

	/// Forwarding to a nonexistent host produces a request error.
	#[tokio::test]
	async fn forward_to_unreachable_host_fails() {
		let client = Client::builder()
			.connect_timeout(Duration::from_secs(1))
			.build()
			.unwrap();

		let proxy = Proxy {
			client,
			url: "http://192.0.2.1:1/mcp/".into(),
			headers: HashMap::new(),
		};

		let message = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "tools/list",
			"params": {}
		});

		let error = proxy
			.forward(&message)
			.await
			.expect_err("request to unreachable host should fail");
		assert!(matches!(error, ProxyError::Request(_)));
	}
}
