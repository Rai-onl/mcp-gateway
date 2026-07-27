//! Axum server setup and HTTP handlers.
//!
//! Builds the axum router with MCP message and health endpoints,
//! wiring them to the gateway's router for dispatch.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use arc_swap::{ArcSwap, ArcSwapOption};
use axum::Router;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use mcp_gateway_auth::middleware::AuthState;
use serde_json::Value;

use mcp_gateway_config::{CredentialResolutionError, GatewayConfig, resolve_credentials};
use mcp_gateway_credentials::CredentialResolver;
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

/// The swappable portion of `AppState`.
///
/// Reload replaces this whole struct atomically via [`ArcSwap`] so
/// in-flight requests holding the previous `Arc<AppStateInner>`
/// finish on it while new requests load the new one. The unresolved
/// configuration kept here drives `/ready` and the server-card
/// endpoint; they reflect the post-reload server set.
pub struct AppStateInner {
	router: gateway_router::Router,
	/// The original configuration before credential resolution.
	/// Intentionally stores the unresolved config so that health
	/// and server card endpoints never expose resolved secrets.
	pub(crate) config: GatewayConfig,
	/// The credential resolver this inner was built with, retained so
	/// the background refresh can rebuild the validator from the live
	/// configuration (which may have changed under a reload) rather than
	/// a frozen startup copy. The router holds its own clone of this.
	pub(crate) resolver: Arc<dyn CredentialResolver>,
}

/// Shared application state passed to all handlers.
///
/// Holds an [`ArcSwap`] of the swappable [`AppStateInner`] so the
/// gateway's router and configuration can be replaced atomically
/// without dropping `AppState` itself. Sessions persist across
/// reloads: clients keep their issued session IDs even when the
/// configuration changes underneath.
///
/// Note: certain top-level fields are read once when the axum
/// application is built and remain frozen for the process lifetime.
/// Reload picks up changes to `servers` and credential references;
/// changes to `max_body_bytes`, `trusted_proxies`, and
/// `client_identity_headers` require a process restart.
pub struct AppState {
	inner: ArcSwap<AppStateInner>,
	/// Session IDs issued by this gateway instance. Client-supplied
	/// session IDs are only accepted if they appear in this store;
	/// unknown IDs are replaced with a fresh one. Persists across
	/// reloads so reload does not log clients out. Bounded with
	/// first-in, first-out eviction so a flood of unrecognised IDs
	/// cannot grow it without limit.
	sessions: RwLock<SessionStore>,
	/// The authentication state the middleware validates tokens
	/// against, present only when the `authentication` section is
	/// configured. Held behind an [`ArcSwapOption`] so a `SIGHUP`
	/// reload can rebuild and swap it without dropping `AppState`;
	/// each request loads the current value.
	auth: ArcSwapOption<AuthState>,
	/// Serialises the two writers that rebuild and swap the validator:
	/// the `SIGHUP` reload and the background discovery refresh. Without
	/// it, a discovery refresh that began before a reload could store a
	/// validator built from the pre-reload configuration after the
	/// reload installed the new one, silently reverting it. Both writers
	/// take this lock around their read-config, build, and `set_auth`
	/// sequence so each sees a configuration consistent with what it
	/// installs.
	auth_rebuild_lock: tokio::sync::Mutex<()>,
	/// Whether the `authentication` section was present when the axum
	/// application was built. The authentication middleware is mounted
	/// once at that point and frozen for the process lifetime, so a
	/// reload cannot turn it on or off. Reload compares against this to
	/// refuse a configuration that would toggle it, rather than swapping
	/// the validator while the middleware layer stays as it was built.
	authentication_configured_at_startup: bool,
}

impl AppState {
	/// Create application state from a gateway configuration.
	///
	/// If a credential resolver is provided, all credential
	/// references in server definitions are resolved and injected
	/// into headers (HTTP) or environment variables (stdio) before
	/// the router is built. The router and runtimes never see
	/// credential names, only resolved values.
	///
	/// # Errors
	///
	/// Returns an error if any referenced credential cannot be
	/// resolved, or if a server runtime cannot be initialised.
	pub fn new(
		config: GatewayConfig,
		credential_resolver: Option<Arc<dyn CredentialResolver>>,
	) -> Result<Self, AppStateError> {
		let authentication_configured_at_startup = config.authentication.is_some();
		let inner = build_inner(config, credential_resolver)?;
		Ok(Self {
			inner: ArcSwap::from_pointee(inner),
			sessions: RwLock::new(SessionStore::new(MAX_RETAINED_SESSIONS)),
			auth: ArcSwapOption::empty(),
			auth_rebuild_lock: tokio::sync::Mutex::new(()),
			authentication_configured_at_startup,
		})
	}

	/// Whether inbound authentication was configured when this state was
	/// built, and therefore whether the authentication middleware is
	/// mounted. Reload consults this to refuse a configuration that would
	/// toggle authentication, which the frozen middleware cannot honour
	/// without a restart.
	#[must_use]
	pub fn authentication_configured_at_startup(&self) -> bool {
		self.authentication_configured_at_startup
	}

	/// Acquire the lock that serialises validator rebuilds.
	///
	/// The reload handler and the background discovery refresh both hold
	/// this across their read-configuration, build, and [`set_auth`]
	/// sequence, so the two cannot interleave and revert each other.
	///
	/// [`set_auth`]: AppState::set_auth
	pub async fn lock_auth_rebuild(&self) -> tokio::sync::MutexGuard<'_, ()> {
		self.auth_rebuild_lock.lock().await
	}

	/// Install (or replace) the authentication state. Called once at
	/// startup after the discovery fetch builds the validator, and
	/// again on reload. New requests load the swapped-in value; those
	/// in flight finish against the previous one.
	pub fn set_auth(&self, auth: Arc<AuthState>) {
		self.auth.store(Some(auth));
	}

	/// The current authentication state, or `None` when the gateway
	/// runs without inbound authentication.
	#[must_use]
	pub fn auth(&self) -> Option<Arc<AuthState>> {
		self.auth.load_full()
	}

	/// Atomically replace the router and resolved configuration in
	/// place. In-flight requests holding the previous inner finish
	/// on it; subsequent requests load the new inner. On failure no
	/// swap happens and the previous inner stays installed.
	///
	/// # Errors
	///
	/// Returns the same errors as [`AppState::new`] if the new
	/// configuration cannot be resolved or the router cannot be
	/// built. The state is unchanged on error.
	pub fn replace_inner(
		&self,
		config: GatewayConfig,
		credential_resolver: Option<Arc<dyn CredentialResolver>>,
	) -> Result<(), AppStateError> {
		let inner = build_inner(config, credential_resolver)?;
		self.inner.store(Arc::new(inner));
		Ok(())
	}

	/// Snapshot the current inner. Calls within a single request
	/// should reuse this snapshot rather than calling `current` more
	/// than once, so all dispatch decisions stay consistent even if
	/// reload swaps the inner mid-request.
	pub fn current(&self) -> Arc<AppStateInner> {
		self.inner.load_full()
	}

	/// Check all active stdio bridge processes and log any that
	/// have exited. Call this periodically from a background task
	/// so that crashes are detected promptly.
	pub async fn check_bridge_health(&self) {
		self.inner.load().router.check_bridge_health().await;
	}
}

/// Translate credential references into use-time injection metadata,
/// build the router (handing it the resolver so the proxy and bridge
/// runtimes can fetch values per-use), and bundle the result into an
/// `AppStateInner` ready to install via `ArcSwap`.
///
/// `None` for the resolver substitutes a [`StaticResolver`] holding
/// no entries: any server with a credential reference will surface a
/// lookup error at use time, which matches the previous "no resolver
/// available" behaviour and keeps server-less test fixtures working.
fn build_inner(
	config: GatewayConfig,
	credential_resolver: Option<Arc<dyn CredentialResolver>>,
) -> Result<AppStateInner, AppStateError> {
	let resolved_config = resolve_credentials(&config);
	let resolver = credential_resolver.unwrap_or_else(|| {
		Arc::new(mcp_gateway_credentials::StaticResolver::default()) as Arc<dyn CredentialResolver>
	});
	let router = gateway_router::Router::from_config(&resolved_config, Arc::clone(&resolver))?;
	Ok(AppStateInner {
		router,
		config,
		resolver,
	})
}

/// Build the axum application with all routes.
///
/// When the configuration includes `trusted_proxies`, the identity
/// extraction middleware is applied. It reads client certificate
/// headers from trusted proxy requests and strips them from
/// untrusted sources.
pub fn build_app(state: &Arc<AppState>) -> Router {
	// Snapshot the configuration once at app-build time. Top-level
	// fields like `max_body_bytes`, `trusted_proxies`,
	// `client_identity_headers`, and the `authentication` section are
	// wired into middleware here and stay frozen for the process
	// lifetime. Reload picks up `servers` and credential references
	// (and swaps the auth state in place), but not these.
	let initial = state.inner.load();
	let authentication_configured = initial.config.authentication.is_some();

	// Routes split by whether they require a bearer token. The MCP
	// dispatch route always does; `mcp-server-card` joins the
	// protected set only when authentication is configured (it leaks
	// the server inventory, which maps to scopes), otherwise it stays
	// public as it is in local-loopback mode. `health` and `ready`
	// are always public.
	let mut protected = Router::new().route("/servers/{name}/mcp", post(handle_mcp));
	let mut public = Router::new()
		.route("/health", get(handle_health))
		.route("/ready", get(handle_ready))
		.route(
			"/.well-known/oauth-protected-resource",
			get(handle_protected_resource_metadata),
		);

	if authentication_configured {
		protected = protected
			.route("/.well-known/mcp-server-card", get(handle_server_card))
			// `route_layer` applies authentication only to the routes
			// above, never to the public routes merged in below.
			.route_layer(middleware::from_fn_with_state(
				Arc::clone(state),
				require_authentication,
			));
	} else {
		public = public.route("/.well-known/mcp-server-card", get(handle_server_card));
	}

	let mut application = protected
		.merge(public)
		.with_state(Arc::clone(state))
		.layer(DefaultBodyLimit::max(initial.config.max_body_bytes))
		.layer(middleware::from_fn(set_security_headers));

	// Always install the identity middleware to strip forwarded
	// identity headers from untrusted sources. When trusted proxies
	// are configured, the middleware also extracts client identity
	// from requests originating within those networks. It is applied
	// outside the authentication layer so forged identity headers are
	// scrubbed before authentication runs.
	let proxy_config = Arc::new(TrustedProxyConfig {
		trusted_networks: initial.config.trusted_proxies.clone(),
		identity_headers: initial
			.config
			.client_identity_headers
			.clone()
			.unwrap_or_default(),
	});

	if !initial.config.trusted_proxies.is_empty() {
		tracing::info!(
			networks = ?initial.config.trusted_proxies,
			certificate_header = %proxy_config.identity_headers.certificate,
			chain_header = %proxy_config.identity_headers.certificate_chain,
			"trusted proxy identity extraction enabled"
		);
	}

	application = application
		.layer(middleware::from_fn(extract_client_identity))
		.layer(axum::extract::Extension(proxy_config));

	// The CORS layer is outermost so a preflight `OPTIONS` is answered
	// before the trusted-proxy and authentication layers run. It is
	// mounted only when authentication is configured: browser clients
	// only reach a hosted instance, and an unconfigured `cors` section
	// permits no origin.
	if let Some(authentication) = initial.config.authentication.as_ref() {
		application = application.layer(mcp_gateway_auth::cors::cors_layer(&authentication.cors));
	}

	application
}

/// Authentication gate for the protected routes.
///
/// Loads the current authentication state, swapped in place on reload,
/// and delegates to the auth crate's middleware. This layer is mounted
/// only when authentication is configured, so a missing validator means
/// the state is configured but not yet installed (the brief startup
/// window before the cold discovery fetch, or a wiring mistake). The gate
/// fails closed in that case with `500` rather than passing the request
/// through, so the authentication layer can never default to open.
async fn require_authentication(
	State(state): State<Arc<AppState>>,
	request: axum::extract::Request,
	next: middleware::Next,
) -> Response {
	let Some(auth) = state.auth() else {
		tracing::error!(
			"protected route reached with no authentication validator installed; \
			 failing closed"
		);
		return StatusCode::INTERNAL_SERVER_ERROR.into_response();
	};
	mcp_gateway_auth::middleware::authenticate(&auth, request, next).await
}

/// Middleware that adds security headers to all responses.
async fn set_security_headers(request: axum::extract::Request, next: middleware::Next) -> Response {
	let mut response = next.run(request).await;
	response.headers_mut().insert(
		"x-content-type-options",
		axum::http::HeaderValue::from_static("nosniff"),
	);
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
	if let Some(early) = check_request_preconditions(&server_name, &request_headers) {
		return early;
	}

	let started_at = Instant::now();
	let session_id = resolve_session_id(&request_headers, &state.sessions);
	let trace = extract_trace_context(&request_headers);

	let message = match parse_request_body(&body, &server_name, &session_id, &trace) {
		Ok(value) => value,
		Err(response) => return *response,
	};

	if message.is_array() {
		let context = RequestContext {
			request_id: None,
			session_id: &session_id,
			trace: &trace,
		};
		return json_rpc_error(
			StatusCode::BAD_REQUEST,
			-32600,
			"Batch requests are not supported",
			&context,
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

	// Snapshot the inner once so an in-flight reload swap does not
	// surface a half-changed view to this request.
	let inner = state.current();
	let result = inner.router.dispatch(&server_name, &message).await;
	let duration = started_at.elapsed();
	let context = RequestContext {
		request_id: message.get("id"),
		session_id: &session_id,
		trace: &trace,
	};

	dispatch_response(result, duration, &server_name, &context)
}

/// Reject requests with invalid server names or non-JSON bodies
/// before any logging, parsing, or dispatch happens.
///
/// Returns `Some(response)` when the request must be rejected and
/// `None` to indicate the caller should proceed.
fn check_request_preconditions(server_name: &str, headers: &HeaderMap) -> Option<Response> {
	let empty_trace = TraceContext::empty();
	let context = RequestContext::for_early_failure(&empty_trace);

	if !is_valid_server_name(server_name) {
		return Some(json_rpc_error(
			StatusCode::BAD_REQUEST,
			-32600,
			"Invalid server name",
			&context,
		));
	}
	if !is_json_content_type(headers) {
		return Some(json_rpc_error(
			StatusCode::UNSUPPORTED_MEDIA_TYPE,
			-32600,
			"Content-Type must be application/json",
			&context,
		));
	}
	None
}

/// Parse the request body as JSON, producing a JSON-RPC parse-error
/// response if it is malformed. Mirrors JSON-RPC 2.0 section 4.2.
///
/// The error variant is boxed because `axum::Response` exceeds the
/// `result_large_err` size budget; parse failures are the rare path,
/// so the extra allocation is acceptable in exchange for the
/// shallower call-site logic.
fn parse_request_body(
	body: &str,
	server_name: &str,
	session_id: &str,
	trace: &TraceContext,
) -> Result<Value, Box<Response>> {
	serde_json::from_str(body).map_err(|_| {
		tracing::warn!(
			server = %server_name,
			session = %session_id,
			"received malformed JSON"
		);
		let context = RequestContext {
			request_id: None,
			session_id,
			trace,
		};
		Box::new(json_rpc_error(
			StatusCode::BAD_REQUEST,
			-32700,
			"Parse error",
			&context,
		))
	})
}

/// Convert a dispatch result into an HTTP response with appropriate
/// status codes, JSON-RPC formatting, and tracing.
fn dispatch_response(
	result: Result<RouterResponse, gateway_router::RouterError>,
	duration: std::time::Duration,
	server_name: &str,
	context: &RequestContext<'_>,
) -> Response {
	let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);

	match result {
		Ok(RouterResponse::Reply(response)) => {
			tracing::info!(duration_ms, "request completed");
			json_rpc_response(StatusCode::OK, &response, context.session_id, context.trace)
		}
		Ok(RouterResponse::Accepted) => {
			tracing::info!(duration_ms, "notification accepted");
			let mut response = StatusCode::ACCEPTED.into_response();
			response
				.headers_mut()
				.insert(SESSION_HEADER, session_id_header(context.session_id));
			response
		}
		Err(error) => dispatch_error_response(&error, duration_ms, server_name, context),
	}
}

/// Map a router dispatch error to its client response, logging at the
/// severity the failure warrants. Split out of [`dispatch_response`] so
/// each keeps to one concern: success shaping there, error shaping here.
fn dispatch_error_response(
	error: &gateway_router::RouterError,
	duration_ms: u64,
	server_name: &str,
	context: &RequestContext<'_>,
) -> Response {
	match error {
		gateway_router::RouterError::ServerNotFound(_) => {
			tracing::warn!(duration_ms, "server not found");
			json_rpc_error(
				StatusCode::NOT_FOUND,
				-32004,
				&format!("Server not found: {server_name}"),
				context,
			)
		}
		gateway_router::RouterError::MalformedMessage => {
			tracing::warn!(duration_ms, "malformed message");
			json_rpc_error(
				StatusCode::BAD_REQUEST,
				-32600,
				"Invalid request: missing method field",
				context,
			)
		}
		gateway_router::RouterError::BridgeCooldown(_) => {
			tracing::warn!(duration_ms, "bridge cooling down after a recent respawn");
			let mut response = json_rpc_error(
				StatusCode::SERVICE_UNAVAILABLE,
				-32003,
				"Server temporarily unavailable; retry shortly",
				context,
			);
			// The spawn backoff is sub-second, and `Retry-After` is granular
			// to whole seconds, so advertise the one-second ceiling rather
			// than round down to zero and invite an immediate retry.
			response.headers_mut().insert(
				axum::http::header::RETRY_AFTER,
				axum::http::HeaderValue::from_static("1"),
			);
			response
		}
		gateway_router::RouterError::EmptyUpstreamReply(_) => {
			tracing::error!(duration_ms, "upstream returned an empty response to a request");
			json_rpc_error(
				StatusCode::BAD_GATEWAY,
				-32002,
				"Upstream server error",
				context,
			)
		}
		gateway_router::RouterError::Bridge(_) => bridge_error_response(error, duration_ms, context),
		error => {
			if let Some(failure) = error.upstream_failure() {
				return upstream_error_response(&failure, duration_ms, context);
			}
			tracing::error!(duration_ms, error = %error, "dispatch failed");
			json_rpc_error(
				StatusCode::INTERNAL_SERVER_ERROR,
				-32603,
				"Internal error",
				context,
			)
		}
	}
}

/// Map a stdio bridge failure to its client response. A wedged backend
/// (a request or handshake that timed out) becomes 504 Gateway Timeout;
/// any other bridge failure (a dead or unwritable child) becomes 502 Bad
/// Gateway. A bridge failure is an upstream failure, not a gateway
/// internal error.
fn bridge_error_response(
	error: &gateway_router::RouterError,
	duration_ms: u64,
	context: &RequestContext<'_>,
) -> Response {
	let status = if error.is_bridge_timeout() {
		StatusCode::GATEWAY_TIMEOUT
	} else {
		StatusCode::BAD_GATEWAY
	};
	tracing::error!(duration_ms, error = %error, "stdio bridge failed");
	json_rpc_error(status, -32002, "Upstream server error", context)
}

/// Build the client response for a failure originating in an HTTP
/// upstream. The upstream status and content type go into the JSON-RPC
/// error `data`; the body preview is never returned to the client, since
/// an upstream error body can reflect secrets and must not be echoed
/// onward.
///
/// A rate-limited or unavailable upstream (429 or 503) is a transient
/// condition, so it maps to a retryable 503 Service Unavailable and its
/// `Retry-After` value, when present, is relayed both as a response
/// header and in `data` so the client can honour the requested back-off.
/// Every other upstream status maps to 502 Bad Gateway.
fn upstream_error_response(
	failure: &gateway_router::UpstreamFailure,
	duration_ms: u64,
	context: &RequestContext<'_>,
) -> Response {
	let upstream_status = failure.status;
	// Status and content type are always safe to log and are enough to
	// diagnose the common case (a rejected upstream credential).
	tracing::error!(
		duration_ms,
		upstream_status,
		content_type = failure.content_type,
		retry_after = ?failure.retry_after,
		"upstream returned a non-2xx status"
	);
	// The body itself can echo a secret (an upstream that reflects the
	// rejected credential in its error message), so it is emitted only
	// at DEBUG, which is off under the default `info` filter. Operators
	// opt in explicitly when they need it.
	tracing::debug!(
		upstream_status,
		body_preview = failure.body_preview,
		"upstream error body preview"
	);

	// A rate-limited or unavailable upstream should be retried, so surface
	// it as a retryable 503; every other upstream status is a bad-gateway
	// condition the client cannot simply retry into.
	let client_status = if matches!(upstream_status, 429 | 503) {
		StatusCode::SERVICE_UNAVAILABLE
	} else {
		StatusCode::BAD_GATEWAY
	};

	let mut data = serde_json::json!({
		"status": upstream_status,
		"contentType": failure.content_type,
	});
	if let Some(retry_after) = failure.retry_after {
		data["retryAfter"] = Value::from(retry_after);
	}

	let mut response =
		json_rpc_error_with_data(client_status, -32002, "Upstream server error", &data, context);

	// Relay the back-off as a real `Retry-After` header too, the standard
	// mechanism a client honours without parsing the JSON-RPC error data.
	// A value the upstream sent that is not a valid header value is
	// dropped rather than passed through.
	if let Some(retry_after) = failure.retry_after
		&& let Ok(header_value) = axum::http::HeaderValue::from_str(retry_after)
	{
		response
			.headers_mut()
			.insert(axum::http::header::RETRY_AFTER, header_value);
	}

	response
}

/// MCP Server Card endpoint.
///
/// Returns structured metadata about all enabled MCP servers
/// hosted by this gateway, including their transport type and
/// endpoint path. Follows the MCP Server Card convention for
/// server discovery via `.well-known` URLs.
async fn handle_server_card(State(state): State<Arc<AppState>>) -> Response {
	let inner = state.current();
	let servers: Vec<Value> = inner
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

/// Protected resource metadata endpoint (RFC 9728).
///
/// Always public, so a client can discover the authorisation server
/// before authenticating. Serves the metadata document when the
/// gateway is configured as a resource server, and `404` otherwise: in
/// local-loopback mode the document has no meaning, and a `404` tells a
/// client this instance is not a protected resource.
async fn handle_protected_resource_metadata(State(state): State<Arc<AppState>>) -> Response {
	let inner = state.current();
	match &inner.config.authentication {
		Some(authentication) => {
			let document = mcp_gateway_auth::metadata::protected_resource_metadata(authentication);
			(StatusCode::OK, axum::Json(document)).into_response()
		}
		None => StatusCode::NOT_FOUND.into_response(),
	}
}

/// Liveness check endpoint.
///
/// Returns 200 if the gateway process is running. Does not
/// verify backend server reachability; use `/ready` for that.
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
	let inner = state.current();
	let servers: serde_json::Map<String, Value> = inner
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

/// Per-request identifying information passed to response builders.
///
/// Bundles the JSON-RPC request id, MCP session id, and W3C trace
/// context so response-building functions can stay below the
/// workspace's `too-many-arguments-threshold`.
struct RequestContext<'request> {
	request_id: Option<&'request Value>,
	session_id: &'request str,
	trace: &'request TraceContext,
}

impl RequestContext<'_> {
	/// A context with no JSON-RPC id, empty session, and no trace.
	/// Used for very early validation failures before any of those
	/// values can be extracted from the request.
	const fn for_early_failure(trace: &TraceContext) -> RequestContext<'_> {
		RequestContext {
			request_id: None,
			session_id: "",
			trace,
		}
	}
}

/// Extract the W3C Trace Context from request headers.
///
/// Returns an empty context when `traceparent` is missing or
/// malformed; `tracestate` is only forwarded when `traceparent` is
/// present, per the W3C Trace Context specification.
fn extract_trace_context(headers: &HeaderMap) -> TraceContext {
	let traceparent = headers
		.get("traceparent")
		.and_then(|value| value.to_str().ok())
		.filter(|value| is_valid_traceparent(value))
		.map(String::from);

	let tracestate = traceparent.as_ref().and_then(|_| {
		headers
			.get("tracestate")
			.and_then(|value| value.to_str().ok())
			.map(String::from)
	});

	TraceContext {
		traceparent,
		tracestate,
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
		.insert(SESSION_HEADER, session_id_header(session_id));

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
/// When the `id` cannot be determined (parse error), the context's
/// `request_id` is `None` and the response carries `null`.
fn json_rpc_error(
	status: StatusCode,
	code: i32,
	message: &str,
	context: &RequestContext<'_>,
) -> Response {
	let id = context.request_id.unwrap_or(&Value::Null);
	let body = serde_json::json!({
		"jsonrpc": "2.0",
		"error": {
			"code": code,
			"message": message
		},
		"id": id
	});

	json_rpc_response(status, &body, context.session_id, context.trace)
}

/// Build a JSON-RPC error response that carries a structured `data`
/// field, for errors where the client benefits from machine-readable
/// detail (such as an upstream status code) alongside the message.
fn json_rpc_error_with_data(
	status: StatusCode,
	code: i32,
	message: &str,
	data: &Value,
	context: &RequestContext<'_>,
) -> Response {
	let id = context.request_id.unwrap_or(&Value::Null);
	let body = serde_json::json!({
		"jsonrpc": "2.0",
		"error": {
			"code": code,
			"message": message,
			"data": data
		},
		"id": id
	});

	json_rpc_response(status, &body, context.session_id, context.trace)
}

/// The most issued session IDs the gateway retains. Beyond this the
/// oldest are evicted, bounding the store's memory: a flood of requests
/// with no or forged session IDs cannot grow it without limit. A client
/// whose session is evicted simply receives a fresh one on its next
/// request, the same as an unrecognised ID.
const MAX_RETAINED_SESSIONS: usize = 100_000;

/// A bounded set of issued session IDs with first-in, first-out
/// eviction.
///
/// Lookups go through the `ids` set; the `order` queue records insertion
/// order so the oldest ID can be evicted when the store is at capacity.
/// The two always hold the same set of IDs.
struct SessionStore {
	/// The issued session IDs, for constant-time membership checks on
	/// the request path.
	ids: HashSet<String>,
	/// The same IDs in insertion order, so the oldest can be found and
	/// evicted in constant time when the store reaches capacity.
	order: VecDeque<String>,
	/// The maximum number of IDs retained before the oldest is evicted.
	capacity: usize,
}

impl SessionStore {
	/// Create an empty store retaining at most `capacity` session IDs.
	fn new(capacity: usize) -> Self {
		Self {
			ids: HashSet::new(),
			order: VecDeque::new(),
			capacity,
		}
	}

	/// Whether the store holds the given session ID.
	fn contains(&self, id: &str) -> bool {
		self.ids.contains(id)
	}

	/// Record a freshly issued session ID, evicting the oldest if the
	/// store is at capacity. A duplicate is ignored, so the insertion
	/// order is not disturbed by a re-insert.
	fn insert(&mut self, id: String) {
		if self.ids.contains(&id) {
			return;
		}
		if self.ids.len() >= self.capacity
			&& let Some(oldest) = self.order.pop_front()
		{
			self.ids.remove(&oldest);
		}
		self.order.push_back(id.clone());
		self.ids.insert(id);
	}

	/// The number of session IDs currently retained.
	#[cfg(test)]
	fn len(&self) -> usize {
		self.ids.len()
	}
}

/// Accept a client-supplied session ID only if it was previously
/// issued by this gateway. Unknown IDs are replaced with a fresh
/// one to prevent session adoption attacks.
fn resolve_session_id(headers: &HeaderMap, sessions: &RwLock<SessionStore>) -> String {
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
	use std::fmt::Write as _;

	let mut output = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		// Writing into a `String` is infallible.
		let _ = write!(output, "{byte:02x}");
	}
	output
}

/// Build the `Mcp-Session-Id` header value from a session ID.
///
/// Session IDs are gateway-issued (or client-supplied but accepted only
/// when previously issued), so they are always 32 lowercase hexadecimal
/// characters: a valid header value. The conversion cannot fail.
fn session_id_header(session_id: &str) -> axum::http::HeaderValue {
	axum::http::HeaderValue::from_str(session_id)
		.expect("a gateway session ID is a valid header value")
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

	/// Build an [`AppState`] with a single HTTP-transport server, the
	/// fixture the server-handler unit tests dispatch against.
	fn test_state() -> Arc<AppState> {
		// Proxying to an HTTPS upstream builds a reqwest client with no
		// bundled provider, so install the process default first.
		mcp_gateway_crypto::install();

		let mut servers = HashMap::new();

		servers.insert(
			"remote-tools".into(),
			ServerDefinition {
				enabled: true,
				env: HashMap::new(),
				credential: None,
				credential_header: None,
				credential_prefix: None,
				request_timeout_seconds: None,
				credential_injection: None,
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
		assert_eq!(json["error"]["code"], -32004);
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

		// First request: get a session ID from the gateway.
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

		// Second request: send the issued session ID back.
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
		// Should get past content-type validation (an unreachable
		// upstream yields a 500 dispatch error, but not a 415).
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

	/// The session store is bounded: inserting beyond its capacity evicts
	/// the oldest ID, so a flood of unrecognised session IDs cannot grow
	/// it without limit, while the most recent IDs are retained.
	#[test]
	fn session_store_evicts_the_oldest_at_capacity() {
		let mut store = SessionStore::new(3);
		store.insert("a".to_owned());
		store.insert("b".to_owned());
		store.insert("c".to_owned());
		assert_eq!(store.len(), 3);
		assert!(store.contains("a"));

		// A fourth insertion evicts the oldest entry, "a".
		store.insert("d".to_owned());
		assert_eq!(store.len(), 3, "the store must stay at capacity");
		assert!(!store.contains("a"), "the oldest ID must be evicted");
		assert!(store.contains("b") && store.contains("c") && store.contains("d"));
	}

	/// Re-inserting an ID already present does not disturb the eviction
	/// order or grow the store, so a repeated ID cannot push others out.
	#[test]
	fn session_store_ignores_a_duplicate_insert() {
		let mut store = SessionStore::new(2);
		store.insert("a".to_owned());
		store.insert("b".to_owned());
		store.insert("a".to_owned());
		assert_eq!(store.len(), 2);

		// "a" was the oldest and a duplicate insert did not refresh it, so
		// the next new ID still evicts "a".
		store.insert("c".to_owned());
		assert!(!store.contains("a"));
		assert!(store.contains("b") && store.contains("c"));
	}
}
