//! Axum server setup and HTTP handlers.
//!
//! Builds the axum router with MCP message and health endpoints,
//! wiring them to the gateway's router for dispatch.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::Value;

use mcp_gateway_config::{
	CredentialResolutionError, CredentialResolver, GatewayConfig, resolve_credentials,
};
use mcp_gateway_router::{self as gateway_router, RouterError, RouterResponse};

use crate::identity::{TrustedProxyConfig, extract_client_identity};

/// The `Mcp-Session-Id` header name.
const SESSION_HEADER: &str = "mcp-session-id";

/// Errors that can occur when building application state.
#[derive(Debug, thiserror::Error)]
pub enum AppStateError {
	/// A credential referenced by a server could not be resolved.
	#[error(transparent)]
	Credential(#[from] CredentialResolutionError),

	/// A server runtime could not be initialised.
	#[error(transparent)]
	Router(#[from] RouterError),
}

/// Shared application state passed to all handlers.
pub struct AppState {
	router: gateway_router::Router,
	/// The original configuration before credential resolution.
	/// Intentionally stores the unresolved config so that health
	/// and server card endpoints never expose resolved secrets.
	config: GatewayConfig,
	/// Session IDs issued by this gateway instance. Client-supplied
	/// session IDs are only accepted if they appear in this set;
	/// unknown IDs are replaced with a fresh one.
	sessions: RwLock<HashSet<String>>,
}

impl AppState {
	/// Create application state from a gateway configuration.
	///
	/// If a credential resolver is provided, all credential
	/// references in server definitions are resolved and injected
	/// into headers (HTTP) or environment variables (stdio) before
	/// the router is built. The router and runtimes never see
	/// credential names — only resolved values.
	///
	/// # Errors
	///
	/// Returns an error if any referenced credential cannot be
	/// resolved, or if a server runtime cannot be initialised.
	pub fn new(
		config: GatewayConfig,
		credential_resolver: Option<&CredentialResolver>,
	) -> Result<Self, AppStateError> {
		let resolved_config = match credential_resolver {
			Some(resolver) => resolve_credentials(&config, resolver)?,
			None => config.clone(),
		};

		let router = gateway_router::Router::from_config(&resolved_config)?;
		Ok(Self {
			router,
			config,
			sessions: RwLock::new(HashSet::new()),
		})
	}

	/// Check all active stdio bridge processes and log any that
	/// have exited. Call this periodically from a background task
	/// so that crashes are detected promptly.
	pub async fn check_bridge_health(&self) {
		self.router.check_bridge_health().await;
	}
}

/// Build the axum application with all routes.
///
/// When the configuration includes `trusted_proxies`, the identity
/// extraction middleware is applied. It reads client certificate
/// headers from trusted proxy requests and strips them from
/// untrusted sources.
pub fn build_app(state: &Arc<AppState>) -> Router {
	let application = Router::new()
		.route("/servers/{name}/mcp", post(handle_mcp))
		.route("/health", get(handle_health))
		.route("/ready", get(handle_ready))
		.route("/.well-known/mcp-server-card", get(handle_server_card))
		.with_state(Arc::clone(state))
		.layer(DefaultBodyLimit::max(state.config.max_body_bytes))
		.layer(middleware::from_fn(set_security_headers));

	// Always install the identity middleware to strip forwarded
	// identity headers from untrusted sources. When trusted proxies
	// are configured, the middleware also extracts client identity
	// from requests originating within those networks.
	let proxy_config = Arc::new(TrustedProxyConfig {
		trusted_networks: state.config.trusted_proxies.clone(),
		identity_headers: state
			.config
			.client_identity_headers
			.clone()
			.unwrap_or_default(),
	});

	if !state.config.trusted_proxies.is_empty() {
		tracing::info!(
			networks = ?state.config.trusted_proxies,
			certificate_header = %proxy_config.identity_headers.certificate,
			chain_header = %proxy_config.identity_headers.certificate_chain,
			"trusted proxy identity extraction enabled"
		);
	}

	application
		.layer(middleware::from_fn(extract_client_identity))
		.layer(axum::extract::Extension(proxy_config))
}

/// Middleware that adds security headers to all responses.
async fn set_security_headers(request: axum::extract::Request, next: middleware::Next) -> Response {
	let mut response = next.run(request).await;
	response
		.headers_mut()
		.insert("x-content-type-options", "nosniff".parse().unwrap());
	response
}

/// Check whether a server name contains only valid characters:
/// alphanumeric, hyphens, and underscores.
fn is_valid_server_name(name: &str) -> bool {
	!name.is_empty()
		&& name.len() <= 128
		&& name
			.bytes()
			.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Check whether a traceparent header value matches the W3C
/// Trace Context format: `{version}-{trace-id}-{parent-id}-{flags}`
/// where version is 2 hex chars, trace-id is 32 hex chars,
/// parent-id is 16 hex chars, and flags is 2 hex chars.
fn is_valid_traceparent(value: &str) -> bool {
	let parts: Vec<&str> = value.split('-').collect();
	parts.len() == 4
		&& parts[0].len() == 2
		&& parts[1].len() == 32
		&& parts[2].len() == 16
		&& parts[3].len() == 2
		&& parts
			.iter()
			.all(|part| part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Check whether the Content-Type header indicates JSON.
fn is_json_content_type(headers: &HeaderMap) -> bool {
	headers
		.get("content-type")
		.and_then(|value| value.to_str().ok())
		.is_some_and(|content_type| {
			let media_type = content_type.split(';').next().unwrap_or("").trim();
			media_type.eq_ignore_ascii_case("application/json")
		})
}

/// Handle an MCP message for the named server.
///
/// Validates the server name and content type, reads the
/// `Mcp-Session-Id` header from the request, dispatches the
/// JSON-RPC message, and returns the session ID in the response.
/// Each request is instrumented with a tracing span containing the
/// server name, JSON-RPC method, and request duration.
async fn handle_mcp(
	State(state): State<Arc<AppState>>,
	Path(server_name): Path<String>,
	request_headers: HeaderMap,
	body: String,
) -> Response {
	// Validate server name before any logging or dispatch to
	// prevent log pollution from malicious path parameters.
	if !is_valid_server_name(&server_name) {
		return json_rpc_error(
			StatusCode::BAD_REQUEST,
			-32600,
			"Invalid server name",
			None,
			"",
			&TraceContext::empty(),
		);
	}

	// Reject requests without a JSON content type.
	if !is_json_content_type(&request_headers) {
		return json_rpc_error(
			StatusCode::UNSUPPORTED_MEDIA_TYPE,
			-32600,
			"Content-Type must be application/json",
			None,
			"",
			&TraceContext::empty(),
		);
	}

	let started_at = Instant::now();

	let session_id = resolve_session_id(&request_headers, &state.sessions);

	// Propagate W3C trace context for distributed tracing.
	// Only accept values matching the traceparent format
	// (version-traceid-parentid-traceflags).
	let traceparent = request_headers
		.get("traceparent")
		.and_then(|value| value.to_str().ok())
		.filter(|value| is_valid_traceparent(value))
		.map(String::from);

	// Propagate tracestate alongside traceparent per W3C Trace
	// Context. Only forward tracestate when traceparent is present.
	let tracestate = traceparent.as_ref().and_then(|_| {
		request_headers
			.get("tracestate")
			.and_then(|value| value.to_str().ok())
			.map(String::from)
	});

	let trace = TraceContext {
		traceparent,
		tracestate,
	};

	let message: Value = if let Ok(value) = serde_json::from_str(&body) {
		value
	} else {
		tracing::warn!(
			server = %server_name,
			session = %session_id,
			"received malformed JSON"
		);
		return json_rpc_error(
			StatusCode::BAD_REQUEST,
			-32700,
			"Parse error",
			None,
			&session_id,
			&trace,
		);
	};

	// Reject batch requests (JSON arrays) explicitly.
	if message.is_array() {
		return json_rpc_error(
			StatusCode::BAD_REQUEST,
			-32600,
			"Batch requests are not supported",
			None,
			&session_id,
			&trace,
		);
	}

	let method = message
		.get("method")
		.and_then(Value::as_str)
		.unwrap_or("unknown");

	let span = tracing::info_span!(
		"mcp_request",
		server = %server_name,
		method = %method,
		session = %session_id,
		transport = tracing::field::Empty,
	);
	let _guard = span.enter();

	tracing::debug!("dispatching request");

	let result = state.router.dispatch(&server_name, &message).await;
	let duration = started_at.elapsed();

	let request_id = message.get("id");

	dispatch_response(
		result,
		duration,
		&server_name,
		request_id,
		&session_id,
		&trace,
	)
}

/// Convert a dispatch result into an HTTP response with appropriate
/// status codes, JSON-RPC formatting, and tracing.
fn dispatch_response(
	result: Result<RouterResponse, gateway_router::RouterError>,
	duration: std::time::Duration,
	server_name: &str,
	request_id: Option<&Value>,
	session_id: &str,
	trace: &TraceContext,
) -> Response {
	let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);

	match result {
		Ok(RouterResponse::Reply(response)) => {
			tracing::info!(duration_ms, "request completed");
			json_rpc_response(StatusCode::OK, &response, session_id, trace)
		}
		Ok(RouterResponse::Accepted) => {
			tracing::info!(duration_ms, "notification accepted");
			let mut response = StatusCode::ACCEPTED.into_response();
			response
				.headers_mut()
				.insert(SESSION_HEADER, session_id.parse().unwrap());
			response
		}
		Err(gateway_router::RouterError::ServerNotFound(_)) => {
			tracing::warn!(duration_ms, "server not found");
			json_rpc_error(
				StatusCode::NOT_FOUND,
				-32001,
				&format!("Server not found: {server_name}"),
				request_id,
				session_id,
				trace,
			)
		}
		Err(gateway_router::RouterError::MalformedMessage) => {
			tracing::warn!(duration_ms, "malformed message");
			json_rpc_error(
				StatusCode::BAD_REQUEST,
				-32600,
				"Invalid request — missing method field",
				request_id,
				session_id,
				trace,
			)
		}
		Err(error) => {
			tracing::error!(duration_ms, error = %error, "dispatch failed");
			json_rpc_error(
				StatusCode::INTERNAL_SERVER_ERROR,
				-32603,
				"Internal error",
				request_id,
				session_id,
				trace,
			)
		}
	}
}

/// MCP Server Card endpoint.
///
/// Returns structured metadata about all enabled MCP servers
/// hosted by this gateway, including their transport type and
/// endpoint path. Follows the MCP Server Card convention for
/// server discovery via `.well-known` URLs.
async fn handle_server_card(State(state): State<Arc<AppState>>) -> Response {
	let servers: Vec<Value> = state
		.config
		.servers
		.iter()
		.filter(|(_, definition)| definition.enabled)
		.map(|(name, definition)| {
			let transport = match &definition.transport {
				mcp_gateway_config::Transport::Stdio { .. } => "stdio",
				mcp_gateway_config::Transport::Http { .. } => "http",
				#[cfg(feature = "sse")]
				mcp_gateway_config::Transport::Sse { .. } => "sse",
			};
			serde_json::json!({
				"name": name,
				"transport": transport,
				"endpoint": format!("/servers/{name}/mcp")
			})
		})
		.collect();

	let body = serde_json::json!({
		"servers": servers
	});

	(
		StatusCode::OK,
		[("content-type", "application/json")],
		serde_json::to_string(&body).unwrap(),
	)
		.into_response()
}

/// Liveness check endpoint.
///
/// Returns 200 if the gateway process is running. Does not
/// verify backend server reachability — use `/ready` for that.
async fn handle_health() -> Response {
	let body = serde_json::json!({"status": "healthy"});

	(
		StatusCode::OK,
		[("content-type", "application/json")],
		serde_json::to_string(&body).unwrap(),
	)
		.into_response()
}

/// Readiness check endpoint.
///
/// Returns 200 with details about each configured server when
/// the gateway has at least one enabled server. Returns 503
/// when no servers are configured or all are disabled.
async fn handle_ready(State(state): State<Arc<AppState>>) -> Response {
	let servers: serde_json::Map<String, Value> = state
		.config
		.servers
		.iter()
		.filter(|(_, definition)| definition.enabled)
		.map(|(name, definition)| {
			let runtime = match &definition.transport {
				mcp_gateway_config::Transport::Stdio { .. } => "stdio",
				mcp_gateway_config::Transport::Http { .. } => "http",
				#[cfg(feature = "sse")]
				mcp_gateway_config::Transport::Sse { .. } => "sse",
			};
			(name.clone(), serde_json::json!({"runtime": runtime}))
		})
		.collect();

	let has_servers = !servers.is_empty();
	let status_code = if has_servers {
		StatusCode::OK
	} else {
		StatusCode::SERVICE_UNAVAILABLE
	};

	let body = serde_json::json!({
		"ready": has_servers,
		"servers": servers
	});

	(
		status_code,
		[("content-type", "application/json")],
		serde_json::to_string(&body).unwrap(),
	)
		.into_response()
}

/// W3C Trace Context headers extracted from the request.
struct TraceContext {
	traceparent: Option<String>,
	tracestate: Option<String>,
}

impl TraceContext {
	/// An empty trace context for responses before tracing is
	/// extracted (early validation errors).
	const fn empty() -> Self {
		Self {
			traceparent: None,
			tracestate: None,
		}
	}
}

/// Build a JSON-RPC response with session and trace headers.
fn json_rpc_response(
	status: StatusCode,
	body: &Value,
	session_id: &str,
	trace: &TraceContext,
) -> Response {
	let mut response = (
		status,
		[("content-type", "application/json")],
		serde_json::to_string(body).unwrap_or_default(),
	)
		.into_response();

	response
		.headers_mut()
		.insert(SESSION_HEADER, session_id.parse().unwrap());

	if let Some(trace_value) = &trace.traceparent
		&& let Ok(header_value) = trace_value.parse()
	{
		response.headers_mut().insert("traceparent", header_value);
	}

	if let Some(state_value) = &trace.tracestate
		&& let Ok(header_value) = state_value.parse()
	{
		response.headers_mut().insert("tracestate", header_value);
	}

	response
}

/// Build a JSON-RPC error response with session and trace headers.
///
/// When the request `id` is known (parsed successfully), it is
/// echoed in the error response per JSON-RPC 2.0 section 5.1.
/// When the `id` cannot be determined (parse error), pass `None`.
fn json_rpc_error(
	status: StatusCode,
	code: i32,
	message: &str,
	request_id: Option<&Value>,
	session_id: &str,
	trace: &TraceContext,
) -> Response {
	let id = request_id.unwrap_or(&Value::Null);
	let body = serde_json::json!({
		"jsonrpc": "2.0",
		"error": {
			"code": code,
			"message": message
		},
		"id": id
	});

	json_rpc_response(status, &body, session_id, trace)
}

/// Accept a client-supplied session ID only if it was previously
/// issued by this gateway. Unknown IDs are replaced with a fresh
/// one to prevent session adoption attacks.
fn resolve_session_id(headers: &HeaderMap, sessions: &RwLock<HashSet<String>>) -> String {
	if let Some(candidate) = headers
		.get(SESSION_HEADER)
		.and_then(|value| value.to_str().ok())
		&& sessions
			.read()
			.expect("session lock poisoned")
			.contains(candidate)
	{
		return candidate.to_owned();
	}

	let new_id = generate_session_id();
	sessions
		.write()
		.expect("session lock poisoned")
		.insert(new_id.clone());
	new_id
}

/// Generate a cryptographically random session ID.
///
/// Produces 128 bits of randomness from the operating system's
/// CSPRNG, formatted as 32 lowercase hexadecimal characters.
/// This satisfies the MCP requirement that session IDs be
/// globally unique and unguessable.
fn generate_session_id() -> String {
	use rand::Rng;
	let bytes: [u8; 16] = rand::rng().random();
	hex_encode(&bytes)
}

/// Encode a byte slice as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
	let mut output = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		use std::fmt::Write;
		write!(output, "{byte:02x}").unwrap();
	}
	output
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use axum::body::Body;
	use axum::http::Request;
	use http_body_util::BodyExt;
	use tower::ServiceExt;

	use mcp_gateway_config::{GatewayConfig, ServerDefinition, Transport};

	use super::*;

	fn test_state() -> Arc<AppState> {
		let mut servers = HashMap::new();

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

		Arc::new(
			AppState::new(
				GatewayConfig {
					servers,
					..Default::default()
				},
				None,
			)
			.unwrap(),
		)
	}

	/// The health endpoint returns 200 as a liveness check.
	#[tokio::test]
	async fn health_returns_ok() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.uri("/health")
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);

		let body = response.into_body().collect().await.unwrap().to_bytes();
		let json: Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(json["status"], "healthy");
	}

	/// The ready endpoint returns 200 with server details when
	/// servers are configured.
	#[tokio::test]
	async fn ready_returns_ok_with_servers() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.uri("/ready")
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);

		let body = response.into_body().collect().await.unwrap().to_bytes();
		let json: Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(json["ready"], true);
		assert!(json["servers"]["remote-tools"].is_object());
	}

	/// Posting to an unknown server returns 404 with a JSON-RPC error.
	#[tokio::test]
	async fn unknown_server_returns_404() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/nonexistent/mcp")
			.header("content-type", "application/json")
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::NOT_FOUND);

		let body = response.into_body().collect().await.unwrap().to_bytes();
		let json: Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(json["error"]["code"], -32001);
	}

	/// Posting invalid JSON returns 400 with a parse error.
	#[tokio::test]
	async fn invalid_json_returns_400() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/remote-tools/mcp")
			.header("content-type", "application/json")
			.body(Body::from("not json"))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::BAD_REQUEST);

		let body = response.into_body().collect().await.unwrap().to_bytes();
		let json: Value = serde_json::from_slice(&body).unwrap();
		assert_eq!(json["error"]["code"], -32700);
	}

	/// Responses include the Mcp-Session-Id header.
	#[tokio::test]
	async fn response_includes_session_header() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/nonexistent/mcp")
			.header("content-type", "application/json")
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert!(response.headers().contains_key(SESSION_HEADER));
	}

	/// The server card endpoint returns metadata about all
	/// enabled servers, including their transport type and
	/// MCP endpoint path.
	#[tokio::test]
	async fn server_card_returns_server_metadata() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.uri("/.well-known/mcp-server-card")
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);

		let body = response.into_body().collect().await.unwrap().to_bytes();
		let json: Value = serde_json::from_slice(&body).unwrap();

		// The response lists each server with its transport and endpoint.
		let servers = json["servers"].as_array().unwrap();
		assert_eq!(servers.len(), 1);
		assert_eq!(servers[0]["name"], "remote-tools");
		assert_eq!(servers[0]["transport"], "http");
		assert!(
			servers[0]["endpoint"]
				.as_str()
				.unwrap()
				.contains("/servers/remote-tools/mcp")
		);
	}

	/// A traceparent header from the client is echoed in the response
	/// for distributed tracing continuity.
	#[tokio::test]
	async fn traceparent_header_echoed() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/nonexistent/mcp")
			.header("content-type", "application/json")
			.header(
				"traceparent",
				"00-abcdef1234567890abcdef1234567890-1234567890abcdef-01",
			)
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		let traceparent = response
			.headers()
			.get("traceparent")
			.and_then(|value| value.to_str().ok());
		assert_eq!(
			traceparent,
			Some("00-abcdef1234567890abcdef1234567890-1234567890abcdef-01")
		);
	}

	/// A gateway-issued session ID is echoed back when the client
	/// sends it on a subsequent request.
	#[tokio::test]
	async fn gateway_issued_session_id_echoed() {
		let state = test_state();

		// First request — get a session ID from the gateway.
		let first_application = build_app(&state);
		let first_request = Request::builder()
			.method("POST")
			.uri("/servers/nonexistent/mcp")
			.header("content-type", "application/json")
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let first_response = first_application.oneshot(first_request).await.unwrap();
		let issued_session = first_response
			.headers()
			.get(SESSION_HEADER)
			.unwrap()
			.to_str()
			.unwrap()
			.to_owned();

		// Second request — send the issued session ID back.
		let second_application = build_app(&state);
		let second_request = Request::builder()
			.method("POST")
			.uri("/servers/nonexistent/mcp")
			.header("content-type", "application/json")
			.header(SESSION_HEADER, &issued_session)
			.body(Body::from(r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#))
			.unwrap();

		let second_response = second_application.oneshot(second_request).await.unwrap();
		let echoed_session = second_response
			.headers()
			.get(SESSION_HEADER)
			.unwrap()
			.to_str()
			.unwrap();
		assert_eq!(echoed_session, issued_session);
	}

	/// An unknown client-supplied session ID is replaced with
	/// a fresh gateway-issued one.
	#[tokio::test]
	async fn unknown_session_id_replaced() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/nonexistent/mcp")
			.header("content-type", "application/json")
			.header(SESSION_HEADER, "forged-session-id")
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		let session = response
			.headers()
			.get(SESSION_HEADER)
			.unwrap()
			.to_str()
			.unwrap();
		// The gateway must not adopt the forged ID.
		assert_ne!(session, "forged-session-id");
		// The replacement must be a valid 32-char hex string.
		assert_eq!(session.len(), 32);
		assert!(
			session
				.chars()
				.all(|character| character.is_ascii_hexdigit())
		);
	}

	/// Requests without a JSON content type are rejected with 415.
	#[tokio::test]
	async fn wrong_content_type_returns_415() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/remote-tools/mcp")
			.header("content-type", "text/plain")
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
	}

	/// Requests with no content type header are rejected with 415.
	#[tokio::test]
	async fn missing_content_type_returns_415() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/remote-tools/mcp")
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
	}

	/// Content-Type with charset parameter is accepted.
	#[tokio::test]
	async fn json_content_type_with_charset_accepted() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/remote-tools/mcp")
			.header("content-type", "application/json; charset=utf-8")
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		// Should get past content-type validation (may be 502 from
		// unreachable upstream, but not 415).
		assert_ne!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
	}

	/// Server names with invalid characters are rejected with 400.
	#[tokio::test]
	async fn invalid_server_name_returns_400() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/bad%20name!/mcp")
			.header("content-type", "application/json")
			.body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::BAD_REQUEST);
	}

	/// Responses include the X-Content-Type-Options security header.
	#[tokio::test]
	async fn responses_include_security_headers() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.uri("/health")
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(
			response
				.headers()
				.get("x-content-type-options")
				.and_then(|value| value.to_str().ok()),
			Some("nosniff")
		);
	}

	/// Internal errors do not leak implementation details.
	#[tokio::test]
	async fn internal_errors_are_generic() {
		let application = build_app(&test_state());
		let request = Request::builder()
			.method("POST")
			.uri("/servers/remote-tools/mcp")
			.header("content-type", "application/json")
			.body(Body::from(
				r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
			))
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		if response.status() == StatusCode::INTERNAL_SERVER_ERROR {
			let body = response.into_body().collect().await.unwrap().to_bytes();
			let json: Value = serde_json::from_slice(&body).unwrap();
			let message = json["error"]["message"].as_str().unwrap_or("");
			// The error message must not contain paths or URLs.
			assert_eq!(message, "Internal error");
		}
	}
}
