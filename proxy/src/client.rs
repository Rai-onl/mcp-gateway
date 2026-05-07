//! HTTP client for proxying MCP requests to upstream servers.
//!
//! The proxy sends JSON-RPC message bodies to a configured
//! upstream URL via HTTP POST, injects configured headers, and
//! returns the upstream response body and status.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_gateway_config::CredentialInjection;
use mcp_gateway_credentials::{CredentialResolver, Secret};
use reqwest::Client;
use serde_json::Value;

/// Default timeout for upstream HTTP requests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// `Accept` value advertised on every outgoing request.
///
/// MCP's Streamable HTTP transport allows servers to respond with
/// either a plain JSON body or a Server-Sent Events stream. Servers
/// that follow the spec strictly (notably GitHub's hosted MCP) reject
/// requests whose `Accept` header does not list both forms, so we
/// always advertise both and adapt to whichever the upstream returns.
const STREAMABLE_HTTP_ACCEPT: &str = "application/json, text/event-stream";

/// An HTTP proxy to a remote MCP server.
pub struct Proxy {
	client: Client,
	url: String,
	headers: HashMap<String, Secret>,
	resolver: Arc<dyn CredentialResolver>,
	/// Optional credential injection metadata. Populated by
	/// [`mcp_gateway_config::resolve_credentials`] from a server's
	/// `credential` field; consumed at every `forward` call so the
	/// header value reflects the resolver's current view of the
	/// credential.
	injection: Option<HeaderInjection>,
}

impl std::fmt::Debug for Proxy {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		// The resolver behind the trait object has no useful Debug
		// representation and may close over operator-supplied state
		// we don't want to log; render only the fields a developer
		// would actually need when inspecting a router snapshot.
		formatter
			.debug_struct("Proxy")
			.field("url", &self.url)
			.field("header_count", &self.headers.len())
			.field("injection", &self.injection)
			.finish_non_exhaustive()
	}
}

/// Narrowed view of [`CredentialInjection::Header`] held by a proxy.
///
/// Stored separately from the full enum so the proxy never has to
/// interpret a `CredentialInjection::Env` value at runtime — the
/// router pattern-matches at construction time and a wrong-variant
/// programming error surfaces there.
#[derive(Debug, Clone)]
struct HeaderInjection {
	credential_name: String,
	header_name: String,
	header_prefix: String,
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
	/// Operator-supplied headers are injected verbatim into every
	/// outgoing request. The optional injection describes how to
	/// resolve and add a credential header at request time; passing
	/// [`CredentialInjection::Env`] is a router-side programming
	/// error and is rejected up-front so a stdio injection never
	/// reaches the HTTP path.
	///
	/// # Errors
	///
	/// Returns [`ProxyError::ClientBuild`] if the underlying HTTP
	/// client cannot be constructed (TLS backend misconfiguration).
	/// Returns [`ProxyError::InvalidInjection`] if the injection
	/// metadata describes a stdio-only variant.
	pub fn new(
		url: String,
		headers: HashMap<String, Secret>,
		resolver: Arc<dyn CredentialResolver>,
		injection: Option<CredentialInjection>,
	) -> Result<Self, ProxyError> {
		let client = Client::builder()
			.timeout(DEFAULT_TIMEOUT)
			.connect_timeout(Duration::from_secs(10))
			.build()
			.map_err(ProxyError::ClientBuild)?;

		let injection = match injection {
			None => None,
			Some(CredentialInjection::Header {
				credential_name,
				header_name,
				header_prefix,
			}) => Some(HeaderInjection {
				credential_name,
				header_name,
				header_prefix,
			}),
			Some(CredentialInjection::Env { .. }) => {
				return Err(ProxyError::InvalidInjection(
					"stdio env-variable injection is not valid for an HTTP proxy".to_owned(),
				));
			}
		};

		Ok(Self {
			client,
			url,
			headers,
			resolver,
			injection,
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
			.header("Content-Type", "application/json")
			.header("Accept", STREAMABLE_HTTP_ACCEPT);

		for (name, value) in &self.headers {
			request = request.header(name, value.expose());
		}

		if let Some(injection) = &self.injection {
			let secret = self
				.resolver
				.resolve(&injection.credential_name)
				.await
				.map_err(|reason| ProxyError::CredentialResolution {
					credential: injection.credential_name.clone(),
					reason,
				})?;
			let header_value = format!("{}{}", injection.header_prefix, secret.expose());
			request = request.header(&injection.header_name, header_value);
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

		let content_type = response
			.headers()
			.get("content-type")
			.and_then(|value| value.to_str().ok())
			.unwrap_or("")
			.to_owned();
		let raw_body = response.text().await.map_err(ProxyError::Request)?;
		let body = parse_response_body(&content_type, &raw_body)?;

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

/// Decode the upstream's response body into a JSON value, choosing
/// the parser by `Content-Type`.
///
/// Streamable HTTP servers may answer a single JSON-RPC request with
/// either a plain `application/json` body or a `text/event-stream`
/// frame containing a `data: <json>` line. Both shapes are valid,
/// so the proxy must accept either. Anything else (or a
/// content-type-less response) falls back to a JSON parse, which
/// keeps lenient upstreams working at the cost of a slightly worse
/// error message when the upstream is genuinely broken.
fn parse_response_body(content_type: &str, body: &str) -> Result<Value, ProxyError> {
	if content_type
		.split(';')
		.next()
		.map(str::trim)
		.is_some_and(|head| head.eq_ignore_ascii_case("text/event-stream"))
	{
		let payload = extract_sse_data(body).ok_or_else(|| {
			ProxyError::SseDecode("upstream SSE response carried no `data:` line".to_owned())
		})?;
		return serde_json::from_str(&payload)
			.map_err(|error| ProxyError::SseDecode(error.to_string()));
	}
	serde_json::from_str(body).map_err(ProxyError::JsonDecode)
}

/// Pull the JSON payload out of an SSE event stream that carries
/// exactly one event (the shape MCP uses for non-streaming
/// responses).
///
/// The SSE spec joins consecutive `data:` lines with `\n` to form
/// the event's payload, so a multi-line JSON body across several
/// `data:` lines reassembles cleanly. Returns `None` when the
/// stream contained no `data:` line at all.
fn extract_sse_data(body: &str) -> Option<String> {
	let mut payload = String::new();
	let mut found = false;
	for line in body.lines() {
		if let Some(rest) = line.strip_prefix("data:") {
			if found {
				payload.push('\n');
			}
			payload.push_str(rest.strip_prefix(' ').unwrap_or(rest));
			found = true;
		}
	}
	if found { Some(payload) } else { None }
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
	#[error("invalid upstream JSON response body: {0}")]
	JsonDecode(serde_json::Error),

	/// The upstream returned an SSE event stream that did not
	/// decode into a JSON-RPC payload (no `data:` line, or a
	/// `data:` line whose contents were not valid JSON).
	#[error("invalid upstream SSE response: {0}")]
	SseDecode(String),

	/// The named credential could not be resolved at request time.
	/// Carries the credential name and the resolver's reason so a
	/// dispatch error log can attribute the failure precisely.
	#[error("credential '{credential}' could not be resolved: {reason}")]
	CredentialResolution {
		/// The name of the credential whose resolution failed.
		credential: String,
		/// Human-readable reason produced by the resolver.
		reason: String,
	},

	/// The router constructed a proxy with injection metadata that
	/// only applies to stdio servers. Surfaces a programming error
	/// at construction time rather than silently no-ing.
	#[error("invalid injection for HTTP proxy: {0}")]
	InvalidInjection(String),
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};

	use async_trait::async_trait;
	use mcp_gateway_config::CredentialInjection;
	use mcp_gateway_credentials::CredentialResolver;

	use super::*;

	/// Test resolver that records every `resolve` call by name and
	/// always returns a fixed `Secret`. Use the call log to assert
	/// the proxy resolved at request time and against the right name.
	struct CountingResolver {
		calls: std::sync::Mutex<Vec<String>>,
		value: String,
	}

	#[async_trait]
	impl CredentialResolver for CountingResolver {
		async fn resolve(&self, name: &str) -> Result<Secret, String> {
			self.calls.lock().unwrap().push(name.to_owned());
			Ok(Secret::new(self.value.clone()))
		}
	}

	/// Test resolver that always fails — used to verify
	/// resolution-failure surfaces as [`ProxyError::CredentialResolution`]
	/// without an outbound HTTP request being attempted.
	struct FailingResolver {
		called: AtomicUsize,
	}

	#[async_trait]
	impl CredentialResolver for FailingResolver {
		async fn resolve(&self, _name: &str) -> Result<Secret, String> {
			self.called.fetch_add(1, Ordering::SeqCst);
			Err("resolver always fails".to_owned())
		}
	}

	/// A proxy stores the configured URL and headers.
	#[test]
	fn proxy_stores_configuration() {
		let mut headers = HashMap::new();
		headers.insert(
			"Authorization".into(),
			Secret::new("Bearer test-token".into()),
		);

		let resolver: Arc<dyn CredentialResolver> = Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "unused".to_owned(),
		});
		let proxy = Proxy::new(
			"https://api.example.com/mcp/".into(),
			headers,
			resolver,
			None,
		)
		.unwrap();
		assert_eq!(proxy.url(), "https://api.example.com/mcp/");
	}

	/// A proxy with no headers can be created — headers are
	/// optional for upstream servers that do not require auth.
	#[test]
	fn proxy_without_headers() {
		let resolver: Arc<dyn CredentialResolver> = Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "unused".to_owned(),
		});
		let proxy = Proxy::new(
			"https://api.example.com/mcp/".into(),
			HashMap::new(),
			resolver,
			None,
		)
		.unwrap();
		assert_eq!(proxy.url(), "https://api.example.com/mcp/");
	}

	/// `forward` resolves the credential through the resolver every
	/// time it dispatches — this is what makes the resolver model
	/// tolerate rotation, OAuth refresh, and revocation. The
	/// outbound request will fail because the upstream is
	/// unreachable, but resolution must already have happened by
	/// then; the call log proves it.
	#[tokio::test]
	async fn forward_resolves_credential_at_request_time() {
		let resolver = Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "tok-abc".to_owned(),
		});
		let resolver_handle: Arc<dyn CredentialResolver> = Arc::clone(&resolver) as _;

		let proxy = Proxy::new(
			"http://192.0.2.1:1/mcp/".into(),
			HashMap::new(),
			resolver_handle,
			Some(CredentialInjection::Header {
				credential_name: "github-token".to_owned(),
				header_name: "Authorization".to_owned(),
				header_prefix: "Bearer ".to_owned(),
			}),
		)
		.unwrap();

		let message = serde_json::json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "tools/list",
			"params": {}
		});
		let _outcome = proxy.forward(&message).await;

		let calls = resolver.calls.lock().unwrap().clone();
		assert_eq!(
			calls,
			vec!["github-token".to_owned()],
			"forward must resolve through the resolver exactly once at request time",
		);
	}

	/// When a server has no credential injection (operator did not
	/// set `credential`), the resolver is never called.
	#[tokio::test]
	async fn forward_without_injection_skips_resolver() {
		let resolver = Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "unused".to_owned(),
		});
		let resolver_handle: Arc<dyn CredentialResolver> = Arc::clone(&resolver) as _;

		let proxy = Proxy::new(
			"http://192.0.2.1:1/mcp/".into(),
			HashMap::new(),
			resolver_handle,
			None,
		)
		.unwrap();

		let message = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
		let _outcome = proxy.forward(&message).await;

		assert!(
			resolver.calls.lock().unwrap().is_empty(),
			"resolver must not be invoked when there is no injection metadata",
		);
	}

	/// A resolver failure short-circuits before the HTTP request is
	/// attempted and surfaces as a typed proxy error so the router
	/// can report it back to the client with the credential name
	/// that failed.
	#[tokio::test]
	async fn forward_resolution_failure_returns_proxy_error_without_dispatch() {
		let resolver = Arc::new(FailingResolver {
			called: AtomicUsize::new(0),
		});
		let resolver_handle: Arc<dyn CredentialResolver> = Arc::clone(&resolver) as _;

		let proxy = Proxy::new(
			"http://192.0.2.1:1/mcp/".into(),
			HashMap::new(),
			resolver_handle,
			Some(CredentialInjection::Header {
				credential_name: "missing".to_owned(),
				header_name: "Authorization".to_owned(),
				header_prefix: "Bearer ".to_owned(),
			}),
		)
		.unwrap();

		let message = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
		let error = proxy
			.forward(&message)
			.await
			.expect_err("resolver failure must surface");

		match error {
			ProxyError::CredentialResolution {
				credential,
				ref reason,
			} => {
				assert_eq!(credential, "missing");
				assert!(
					reason.contains("always fails"),
					"the resolver's error message must propagate, got {reason:?}",
				);
			}
			other => panic!("expected CredentialResolution error, got {other:?}"),
		}
		assert_eq!(
			resolver.called.load(Ordering::SeqCst),
			1,
			"the resolver is consulted once and the request is never dispatched",
		);
	}

	/// Forwarding to a nonexistent host produces a request error.
	/// This locks in the existing transport-error behaviour while
	/// the credential pathway is being added.
	#[tokio::test]
	async fn forward_to_unreachable_host_fails() {
		let resolver: Arc<dyn CredentialResolver> = Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "unused".to_owned(),
		});
		let proxy = Proxy::new(
			"http://192.0.2.1:1/mcp/".into(),
			HashMap::new(),
			resolver,
			None,
		)
		.unwrap();

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

	/// Helper that boots a single-route axum mock on a random port,
	/// driving each test's content-negotiation expectation. The
	/// handler closure receives the request's `Accept` header and
	/// returns whatever `Response` the test wants.
	async fn spawn_upstream<F>(handler: F) -> String
	where
		F: Fn(Option<String>) -> axum::response::Response + Clone + Send + Sync + 'static,
	{
		use axum::Router;
		use axum::http::HeaderMap;
		use axum::routing::post;
		use tokio::net::TcpListener;

		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		let address = listener.local_addr().expect("address");
		let app = Router::new().route(
			"/mcp",
			post(move |headers: HeaderMap| {
				let handler = handler.clone();
				async move {
					let accept = headers
						.get("accept")
						.and_then(|value| value.to_str().ok())
						.map(str::to_owned);
					handler(accept)
				}
			}),
		);
		tokio::spawn(async move {
			axum::serve(listener, app).await.expect("mock server runs");
		});
		format!("http://{address}/mcp")
	}

	fn unused_resolver() -> Arc<dyn CredentialResolver> {
		Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "unused".to_owned(),
		})
	}

	/// MCP servers that follow the Streamable HTTP spec strictly
	/// (GitHub's hosted MCP is one) reject requests whose `Accept`
	/// header does not advertise both `application/json` and
	/// `text/event-stream`. The proxy must send both.
	#[tokio::test]
	async fn forward_advertises_streamable_http_accept_header() {
		use std::sync::Mutex as StdMutex;
		let captured: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
		let captured_in_handler = Arc::clone(&captured);
		let url = spawn_upstream(move |accept| {
			*captured_in_handler.lock().unwrap() = accept;
			axum::response::Response::builder()
				.status(200)
				.header("content-type", "application/json")
				.body(axum::body::Body::from(r#"{"ok":true}"#))
				.unwrap()
		})
		.await;

		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let _outcome = proxy.forward(&serde_json::json!({})).await;

		let accept = captured.lock().unwrap().clone().expect("Accept captured");
		assert!(
			accept.contains("application/json") && accept.contains("text/event-stream"),
			"Accept must advertise both content types, got {accept:?}",
		);
	}

	/// An upstream that follows the Streamable HTTP spec wraps a
	/// JSON-RPC response in an SSE `event: message / data: <json>`
	/// frame. The proxy must extract the JSON payload from the
	/// `data:` line rather than trying to parse the whole envelope.
	#[tokio::test]
	async fn forward_decodes_sse_response_into_json() {
		let url = spawn_upstream(|_accept| {
			axum::response::Response::builder()
				.status(200)
				.header("content-type", "text/event-stream")
				.body(axum::body::Body::from(
					"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\n",
				))
				.unwrap()
		})
		.await;

		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let response = proxy
			.forward(&serde_json::json!({}))
			.await
			.expect("SSE response decodes");

		assert_eq!(response.status, 200);
		assert_eq!(response.body["id"], 1);
		assert!(response.body["result"]["tools"].is_array());
	}

	/// A multi-line `data:` event gathers the lines into one JSON
	/// payload joined by `\n`, per the SSE spec. The proxy must
	/// honour that join so multi-line JSON in a single event still
	/// parses.
	#[tokio::test]
	async fn forward_decodes_multiline_sse_data_into_json() {
		let url = spawn_upstream(|_accept| {
			axum::response::Response::builder()
				.status(200)
				.header("content-type", "text/event-stream")
				.body(axum::body::Body::from(
					"event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":7}\n\n",
				))
				.unwrap()
		})
		.await;

		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let response = proxy
			.forward(&serde_json::json!({}))
			.await
			.expect("multi-line SSE response decodes");
		assert_eq!(response.body["id"], 7);
	}

	/// A plain `application/json` response (the simplest happy path,
	/// servers that don't bother with SSE wrapping) must still parse
	/// correctly. Locks the existing JSON behaviour in place across
	/// the new content-negotiation logic.
	#[tokio::test]
	async fn forward_decodes_plain_json_response() {
		let url = spawn_upstream(|_accept| {
			axum::response::Response::builder()
				.status(200)
				.header("content-type", "application/json")
				.body(axum::body::Body::from(
					r#"{"jsonrpc":"2.0","id":42,"result":{"ok":true}}"#,
				))
				.unwrap()
		})
		.await;

		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let response = proxy
			.forward(&serde_json::json!({}))
			.await
			.expect("JSON response decodes");
		assert_eq!(response.body["id"], 42);
	}
}
