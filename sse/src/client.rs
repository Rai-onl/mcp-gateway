//! SSE client for the legacy HTTP+SSE MCP transport.
//!
//! The older MCP transport works by establishing a Server-Sent
//! Events stream via GET. The server sends an `endpoint` event
//! containing the URL where the client should POST MCP messages.
//! Responses come back as HTTP response bodies from the POST.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use reqwest_eventsource::{Event, EventSource};
use serde_json::Value;
use tokio::sync::RwLock;
use tokio_stream::StreamExt;

/// Timeout for establishing the SSE connection and receiving
/// the endpoint event.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for individual POST requests to the message endpoint.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Client for upstream MCP servers using the legacy HTTP+SSE transport.
#[derive(Debug)]
pub struct SseClient {
	sse_url: String,
	headers: HashMap<String, String>,
	http_client: Client,
	message_endpoint: Arc<RwLock<Option<String>>>,
}

/// Response from an SSE-transport MCP server.
#[derive(Debug)]
pub struct SseResponse {
	/// HTTP status code from the POST request.
	pub status: u16,

	/// Response body parsed as JSON.
	pub body: Value,
}

impl SseClient {
	/// Create a new SSE client targeting the given SSE endpoint URL.
	///
	/// Headers are injected into both the SSE connection request
	/// and POST requests to the message endpoint.
	///
	/// # Panics
	///
	/// Panics if the HTTP client cannot be built, which indicates
	/// a TLS configuration error on the platform.
	#[must_use]
	pub fn new(sse_url: String, headers: HashMap<String, String>) -> Self {
		let http_client = Client::builder()
			.timeout(REQUEST_TIMEOUT)
			.connect_timeout(Duration::from_secs(10))
			.build()
			.expect("failed to build HTTP client");

		Self {
			sse_url,
			headers,
			http_client,
			message_endpoint: Arc::new(RwLock::new(None)),
		}
	}

	/// The SSE endpoint URL this client connects to.
	#[must_use]
	pub fn sse_url(&self) -> &str {
		&self.sse_url
	}

	/// Whether the client has received the message endpoint from
	/// the SSE stream.
	pub async fn is_connected(&self) -> bool {
		self.message_endpoint.read().await.is_some()
	}

	/// Connect to the SSE endpoint and wait for the server to
	/// send the message endpoint URL.
	///
	/// The server sends an `endpoint` event containing the URL
	/// where the client should POST MCP messages. This method
	/// waits for that event before returning.
	///
	/// # Errors
	///
	/// Returns an error if the SSE connection fails, times out,
	/// or the server does not send an endpoint event.
	pub async fn connect(&self) -> Result<(), SseError> {
		let mut request = self.http_client.get(&self.sse_url);
		for (name, value) in &self.headers {
			request = request.header(name, value);
		}

		let mut event_source =
			EventSource::new(request).map_err(|error| SseError::Connection(error.to_string()))?;

		let endpoint = tokio::time::timeout(CONNECT_TIMEOUT, async {
			loop {
				match event_source.next().await {
					Some(Ok(Event::Open)) => {
						tracing::debug!(url = %self.sse_url, "SSE connection opened");
					}
					Some(Ok(Event::Message(message))) => {
						if message.event == "endpoint" {
							event_source.close();
							return Ok(message.data);
						}
					}
					Some(Err(error)) => {
						return Err(SseError::Connection(error.to_string()));
					}
					None => {
						return Err(SseError::Connection(
							"SSE stream ended before endpoint event".into(),
						));
					}
				}
			}
		})
		.await
		.map_err(|_| SseError::Connection("timed out waiting for endpoint event".into()))??;

		tracing::info!(
			sse_url = %self.sse_url,
			message_endpoint = %endpoint,
			"received message endpoint from SSE stream"
		);

		*self.message_endpoint.write().await = Some(endpoint);
		Ok(())
	}

	/// Forward an MCP message to the upstream server via POST.
	///
	/// The message is sent to the message endpoint URL received
	/// from the SSE stream during `connect()`.
	///
	/// # Errors
	///
	/// Returns an error if the client has not connected yet,
	/// or the POST request fails.
	pub async fn forward(&self, message: &Value) -> Result<SseResponse, SseError> {
		let endpoint = self
			.message_endpoint
			.read()
			.await
			.clone()
			.ok_or(SseError::NotConnected)?;

		let mut request = self
			.http_client
			.post(&endpoint)
			.header("Content-Type", "application/json");

		for (name, value) in &self.headers {
			request = request.header(name, value);
		}

		let response = request
			.json(message)
			.send()
			.await
			.map_err(|error| SseError::Request(error.to_string()))?;

		let status = response.status().as_u16();

		let body = response
			.json::<Value>()
			.await
			.map_err(|error| SseError::ResponseBody(error.to_string()))?;

		Ok(SseResponse { status, body })
	}
}

/// Errors from the SSE transport.
#[derive(Debug, thiserror::Error)]
pub enum SseError {
	/// Failed to establish the SSE connection or receive the
	/// endpoint event.
	#[error("SSE connection failed: {0}")]
	Connection(String),

	/// The client has not connected yet—call `connect()` first.
	#[error("not connected—call connect() before forwarding")]
	NotConnected,

	/// The POST request to the message endpoint failed.
	#[error("request to message endpoint failed: {0}")]
	Request(String),

	/// The response body from the message endpoint was not valid JSON.
	#[error("invalid response body: {0}")]
	ResponseBody(String),
}
