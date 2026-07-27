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
/// interpret a `CredentialInjection::Env` value at runtime: the
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
	/// Returns [`ProxyError::ClientBuild`] if reqwest cannot construct
	/// the client. The process-wide crypto provider must already be
	/// installed (see `mcp_gateway_crypto::install`); reqwest panics, it
	/// does not return an error, if none is set, so that case is a
	/// startup-ordering bug rather than a recoverable condition. Returns
	/// [`ProxyError::InvalidInjection`] if the injection metadata
	/// describes a stdio-only variant.
	pub fn new(
		url: String,
		headers: HashMap<String, Secret>,
		resolver: Arc<dyn CredentialResolver>,
		injection: Option<CredentialInjection>,
	) -> Result<Self, ProxyError> {
		Self::with_request_timeout(url, headers, resolver, injection, DEFAULT_TIMEOUT)
	}

	/// Construct a proxy whose HTTP client bounds each request by
	/// `request_timeout`, the per-server value from its
	/// [`request_timeout_seconds`](mcp_gateway_config::ServerDefinition)
	/// so an HTTP server honours the same timeout control as a stdio one.
	///
	/// # Errors
	///
	/// As [`Proxy::new`]: [`ProxyError::ClientBuild`] if the client
	/// cannot be built, or [`ProxyError::InvalidInjection`] for a
	/// stdio-only injection variant.
	pub fn with_request_timeout(
		url: String,
		headers: HashMap<String, Secret>,
		resolver: Arc<dyn CredentialResolver>,
		injection: Option<CredentialInjection>,
		request_timeout: Duration,
	) -> Result<Self, ProxyError> {
		let client = Client::builder()
			.timeout(request_timeout)
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

		read_response(response).await
	}

	/// The upstream URL this proxy targets.
	#[must_use]
	pub fn url(&self) -> &str {
		&self.url
	}
}

/// Whether an HTTP status code is in the 2xx success range.
///
/// `forward` uses this to decide how to read an empty response body.
/// An empty body is only meaningful as a deliberate no-content reply
/// when the upstream reports success: a notification draws a `202
/// Accepted` with nothing to parse. On a non-2xx status an empty body
/// is a different condition entirely (an upstream that rejected the
/// request without a diagnostic), so this gate keeps the no-content
/// shortcut from masking failures. Classifying those non-2xx
/// responses precisely is the separate concern tracked in the
/// upstream transport resilience programme; here we only need to know
/// whether the status is a success so the notification path does not
/// trip over the JSON parser.
fn is_success(status: u16) -> bool {
	(200..300).contains(&status)
}

/// Read an upstream HTTP response into a [`ProxyResponse`], or the typed
/// error its status and body warrant.
///
/// A non-2xx status becomes [`ProxyError::UpstreamStatus`] carrying the
/// status, a bounded body preview, and any `Retry-After` value, rather
/// than a parse of a body that is often not JSON. A success status with
/// an empty body resolves to a JSON null no-content sentinel, the correct
/// reply to a notification (the `notifications/initialized` handshake
/// message answered with `202 Accepted`); the dispatch layer discards it
/// on the notification path. Any other success body is parsed as
/// JSON-RPC.
///
/// # Errors
///
/// Returns [`ProxyError::Request`] if the body cannot be read,
/// [`ProxyError::UpstreamStatus`] on a non-2xx status, or a parse error
/// from [`parse_response_body`] on a malformed success body.
async fn read_response(response: reqwest::Response) -> Result<ProxyResponse, ProxyError> {
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
	// A back-pressure signal on a rate-limited or unavailable upstream
	// (429 or 503). Captured verbatim so the daemon can relay it to the
	// client, which honours it for precise retry timing.
	let retry_after = response
		.headers()
		.get(reqwest::header::RETRY_AFTER)
		.and_then(|value| value.to_str().ok())
		.map(str::to_owned);
	let raw_body = response.text().await.map_err(ProxyError::Request)?;

	// A non-2xx status is an upstream failure, not a response to parse.
	// Its body is frequently not JSON at all (an HTML error page from a
	// proxy, a plain-text "Unauthorized" from an auth layer), so parsing
	// it would surface the real failure as a misleading JSON decode
	// error. Capture the status and a bounded body preview instead, so
	// the daemon can log a precise diagnostic and return a meaningful
	// error. The most common trigger is a rejected upstream credential
	// (401 or 403).
	if !is_success(status) {
		return Err(ProxyError::UpstreamStatus {
			status,
			content_type,
			body_preview: truncate_preview(&raw_body),
			retry_after,
		});
	}

	let body = if raw_body.trim().is_empty() {
		// A success status with an empty body carries no response to
		// parse, so it resolves to a JSON null no-content sentinel rather
		// than running the empty string through `parse_response_body`,
		// which fails at end of input (`EOF while parsing a value`) and
		// would otherwise abort the handshake for every HTTP upstream.
		// The `trim` covers servers that pad the body with a stray
		// newline or other whitespace rather than a strictly zero-length
		// body.
		Value::Null
	} else {
		parse_response_body(&content_type, &raw_body)?
	};

	Ok(ProxyResponse {
		status,
		body,
		session_id,
	})
}

/// The maximum number of body bytes retained in an
/// [`ProxyError::UpstreamStatus`] preview, bounding how much of an
/// upstream error body is carried into logs.
const MAX_BODY_PREVIEW_BYTES: usize = 300;

/// Truncate an upstream response body to a bounded,
/// character-boundary-safe preview for diagnostics, appending an
/// ellipsis marker when truncated.
fn truncate_preview(body: &str) -> String {
	if body.len() <= MAX_BODY_PREVIEW_BYTES {
		return body.to_owned();
	}
	let mut end = MAX_BODY_PREVIEW_BYTES;
	while !body.is_char_boundary(end) {
		end -= 1;
	}
	format!("{}...", &body[..end])
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

	/// The upstream returned a non-2xx HTTP status. Carries the status,
	/// the response content type, and a bounded preview of the body so
	/// the daemon can log a precise diagnostic and return a meaningful
	/// error to the client instead of a generic parse failure. The most
	/// common trigger is a rejected upstream credential (401 or 403).
	#[error("upstream returned HTTP status {status}")]
	UpstreamStatus {
		/// The non-2xx HTTP status code.
		status: u16,
		/// The response `Content-Type`, retained for diagnostics.
		content_type: String,
		/// A bounded preview of the response body, for logging only.
		body_preview: String,
		/// The upstream's `Retry-After` header value, when it sent one
		/// (typically on a 429 or 503). Relayed to the client so it can
		/// honour the requested back-off.
		retry_after: Option<String>,
	},

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

	/// Test resolver that always fails. It verifies a resolution
	/// failure surfaces as [`ProxyError::CredentialResolution`] without
	/// an outbound HTTP request being attempted.
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
		mcp_gateway_crypto::install();
		let proxy = Proxy::new(
			"https://api.example.com/mcp/".into(),
			headers,
			resolver,
			None,
		)
		.unwrap();
		assert_eq!(proxy.url(), "https://api.example.com/mcp/");
	}

	/// A proxy with no headers can be created; headers are optional for
	/// upstream servers that do not require auth.
	#[test]
	fn proxy_without_headers() {
		let resolver: Arc<dyn CredentialResolver> = Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "unused".to_owned(),
		});
		mcp_gateway_crypto::install();
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
	/// time it dispatches. That is what makes the resolver model
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

		mcp_gateway_crypto::install();
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

		mcp_gateway_crypto::install();
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

		mcp_gateway_crypto::install();
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
		mcp_gateway_crypto::install();
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

	/// A mock upstream handler that sleeps well past any test timeout
	/// before answering, so a proxy's request timeout is what ends the
	/// request rather than the response.
	async fn slow_upstream_handler() -> axum::http::StatusCode {
		tokio::time::sleep(Duration::from_secs(5)).await;
		axum::http::StatusCode::OK
	}

	/// A per-server request timeout bounds a slow HTTP upstream: a proxy
	/// built with a short timeout fails fast rather than waiting the
	/// default, so an operator's `request_timeout_seconds` takes effect
	/// on an HTTP server just as it does on a stdio one.
	#[tokio::test]
	async fn with_request_timeout_bounds_a_slow_upstream() {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.expect("bind mock upstream");
		let address = listener.local_addr().expect("mock upstream address");
		let app = axum::Router::new().route("/mcp", axum::routing::post(slow_upstream_handler));
		tokio::spawn(async move {
			axum::serve(listener, app).await.expect("mock upstream runs");
		});

		mcp_gateway_crypto::install();
		let proxy = Proxy::with_request_timeout(
			format!("http://{address}/mcp"),
			HashMap::new(),
			unused_resolver(),
			None,
			Duration::from_millis(150),
		)
		.unwrap();

		let started = std::time::Instant::now();
		let error = proxy
			.forward(&serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
			.await
			.expect_err("a request exceeding the timeout must fail");

		assert!(
			started.elapsed() < Duration::from_secs(2),
			"the request should fail fast, took {:?}",
			started.elapsed(),
		);
		assert!(
			matches!(error, ProxyError::Request(ref inner) if inner.is_timeout()),
			"expected a timeout error, got {error:?}",
		);
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

		mcp_gateway_crypto::install();
		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let _outcome = proxy.forward(&serde_json::json!({})).await;

		let accept = captured.lock().unwrap().clone().expect("Accept captured");
		assert!(
			accept.contains("application/json") && accept.contains("text/event-stream"),
			"Accept must advertise both content types, got {accept:?}",
		);
	}

	/// A JSON-RPC notification is a message with no `id`, such as the
	/// `notifications/initialized` that completes the MCP handshake. A
	/// notification expects no response, so a spec-compliant Streamable
	/// HTTP upstream answers it with `202 Accepted` and an empty body.
	/// The proxy must treat an empty body on a success status as
	/// no-content. Parsing it as JSON instead fails with an
	/// end-of-input error and aborts the connection, which breaks the
	/// handshake for every HTTP upstream, because every handshake ends
	/// with this notification.
	#[tokio::test]
	async fn forward_treats_empty_success_body_as_no_content() {
		let url = spawn_upstream(|_accept| {
			axum::response::Response::builder()
				.status(202)
				.body(axum::body::Body::empty())
				.unwrap()
		})
		.await;

		mcp_gateway_crypto::install();
		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let response = proxy
			.forward(&serde_json::json!({
				"jsonrpc": "2.0",
				"method": "notifications/initialized"
			}))
			.await
			.expect("an empty 202 body must resolve to no-content, not a parse error");

		assert_eq!(response.status, 202);
		assert!(
			response.body.is_null(),
			"an empty success body must resolve to a JSON null no-content sentinel, got {:?}",
			response.body,
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

		mcp_gateway_crypto::install();
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

		mcp_gateway_crypto::install();
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

		mcp_gateway_crypto::install();
		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let response = proxy
			.forward(&serde_json::json!({}))
			.await
			.expect("JSON response decodes");
		assert_eq!(response.body["id"], 42);
	}

	/// Regression guard: a 2xx response whose body is not valid JSON
	/// still surfaces as `JsonDecode`. The status-before-parse gate must
	/// not accidentally swallow a malformed success body.
	#[tokio::test]
	async fn forward_2xx_with_malformed_json_still_yields_json_decode() {
		let url = spawn_upstream(|_accept| {
			axum::response::Response::builder()
				.status(200)
				.header("content-type", "application/json")
				.body(axum::body::Body::from("not valid json"))
				.unwrap()
		})
		.await;

		mcp_gateway_crypto::install();
		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let error = proxy
			.forward(&serde_json::json!({}))
			.await
			.expect_err("a malformed 2xx body must fail to parse");
		assert!(
			matches!(error, ProxyError::JsonDecode(_)),
			"expected JsonDecode, got {error:?}"
		);
	}

	/// A non-2xx response whose body is not JSON (an auth layer's HTML
	/// or plain-text rejection) surfaces as a typed `UpstreamStatus`
	/// error carrying the status, not a misleading JSON decode error.
	#[tokio::test]
	async fn forward_non_2xx_with_non_json_body_yields_upstream_status() {
		let url = spawn_upstream(|_accept| {
			axum::response::Response::builder()
				.status(401)
				.header("content-type", "text/html")
				.body(axum::body::Body::from("<html><body>Unauthorized</body></html>"))
				.unwrap()
		})
		.await;

		mcp_gateway_crypto::install();
		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let error = proxy
			.forward(&serde_json::json!({}))
			.await
			.expect_err("a 401 must surface as an error");

		match error {
			ProxyError::UpstreamStatus {
				status,
				ref content_type,
				ref body_preview,
				..
			} => {
				assert_eq!(status, 401);
				assert!(content_type.starts_with("text/html"), "got {content_type:?}");
				assert!(body_preview.contains("Unauthorized"), "got {body_preview:?}");
			}
			other => panic!("expected UpstreamStatus, got {other:?}"),
		}
	}

	/// A non-2xx response with an empty body is still an upstream
	/// failure, not the no-content notification reply that an empty 2xx
	/// body represents.
	#[tokio::test]
	async fn forward_non_2xx_with_empty_body_yields_upstream_status() {
		let url = spawn_upstream(|_accept| {
			axum::response::Response::builder()
				.status(503)
				.body(axum::body::Body::empty())
				.unwrap()
		})
		.await;

		mcp_gateway_crypto::install();
		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let error = proxy
			.forward(&serde_json::json!({}))
			.await
			.expect_err("a 503 must surface as an error");

		assert!(
			matches!(error, ProxyError::UpstreamStatus { status: 503, .. }),
			"expected UpstreamStatus 503, got {error:?}"
		);
	}

	/// A large upstream error body is truncated to the preview bound so
	/// a chatty upstream cannot flood the diagnostic log.
	#[tokio::test]
	async fn forward_upstream_status_preview_is_truncated() {
		let url = spawn_upstream(|_accept| {
			axum::response::Response::builder()
				.status(500)
				.header("content-type", "text/plain")
				.body(axum::body::Body::from("x".repeat(5_000)))
				.unwrap()
		})
		.await;

		mcp_gateway_crypto::install();
		let proxy = Proxy::new(url, HashMap::new(), unused_resolver(), None).unwrap();
		let error = proxy
			.forward(&serde_json::json!({}))
			.await
			.expect_err("a 500 must surface as an error");

		match error {
			ProxyError::UpstreamStatus { body_preview, .. } => {
				// The preview keeps at most the bound plus the short
				// ellipsis marker.
				assert!(
					body_preview.len() <= MAX_BODY_PREVIEW_BYTES + 3,
					"preview should be truncated, got {} bytes",
					body_preview.len(),
				);
				assert!(body_preview.ends_with("..."), "expected truncation marker");
			}
			other => panic!("expected UpstreamStatus, got {other:?}"),
		}
	}

	/// The preview cut lands on a character boundary, never splitting a
	/// multi-byte codepoint that straddles the byte limit.
	#[test]
	fn truncate_preview_respects_char_boundaries() {
		// The 3-byte euro sign begins at byte 299, so the 300-byte cut
		// falls inside it; the walk-back must drop the whole codepoint
		// rather than panic on a mid-codepoint slice.
		let body = format!("{}\u{20ac}tail", "a".repeat(299));
		let preview = truncate_preview(&body);
		assert!(preview.ends_with("..."), "expected truncation marker");
		assert!(!preview.contains('\u{20ac}'), "must not keep a split codepoint");
		assert!(preview.starts_with(&"a".repeat(299)));
	}
}
