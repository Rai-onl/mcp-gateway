//! Integration tests using the test MCP server fixture.
//!
//! These tests build a full gateway application with the test
//! server configured as a stdio bridge, and send HTTP requests
//! to verify end-to-end behaviour.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use mcp_gateway_config::{GatewayConfig, ServerDefinition, Transport};
use mcp_gateway_credentials::{CredentialResolver, Secret};
use mcp_gateway_daemon::{AppState, build_app};

/// Path to the test MCP server binary built from tests/fixture/.
///
/// # Panics
///
/// Panics with a descriptive message if the fixture binary has
/// not been built. Build it first with:
/// `cd tests/fixture && cargo build`
fn test_server_path() -> String {
	let manifest_dir = env!("CARGO_MANIFEST_DIR");
	let path = format!("{manifest_dir}/../tests/fixture/target/debug/mcp-test-server");
	assert!(
		std::path::Path::new(&path).exists(),
		"test fixture not built; run: cd tests/fixture && cargo build"
	);
	path
}

fn test_config() -> GatewayConfig {
	let mut servers = HashMap::new();

	servers.insert(
		"test-server".into(),
		ServerDefinition {
			enabled: true,
			env: HashMap::new(),
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Stdio {
				command: test_server_path(),
				args: vec![],
			},
		},
	);

	GatewayConfig {
		servers,
		..Default::default()
	}
}

fn test_app() -> axum::Router {
	let state = Arc::new(AppState::new(test_config(), None).expect("failed to create app state"));
	build_app(&state)
}

/// The gateway can route a tools/list request through the stdio
/// bridge to the test server and return the response.
#[tokio::test]
async fn tools_list_through_bridge() {
	let application = test_app();

	let request = Request::builder()
		.method("POST")
		.uri("/servers/test-server/mcp")
		.header("content-type", "application/json")
		.body(Body::from(
			r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
		))
		.unwrap();

	let response = application.oneshot(request).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);

	let body = response.into_body().collect().await.unwrap().to_bytes();
	let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

	assert_eq!(json["id"], 1);
	assert!(json["result"]["tools"].is_array());
	assert_eq!(json["result"]["tools"][0]["name"], "echo");
}

/// The gateway can route a tools/call request and return the
/// tool's result through the bridge.
#[tokio::test]
async fn tools_call_through_bridge() {
	let application = test_app();

	let request = Request::builder()
		.method("POST")
		.uri("/servers/test-server/mcp")
		.header("content-type", "application/json")
		.body(Body::from(
			r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello world"}}}"#,
		))
		.unwrap();

	let response = application.oneshot(request).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);

	let body = response.into_body().collect().await.unwrap().to_bytes();
	let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

	assert_eq!(json["id"], 2);
	assert_eq!(json["result"]["content"][0]["text"], "hello world");
}

/// A notification (no id field) receives 202 Accepted with no body.
#[tokio::test]
async fn notification_returns_accepted() {
	let application = test_app();

	let request = Request::builder()
		.method("POST")
		.uri("/servers/test-server/mcp")
		.header("content-type", "application/json")
		.body(Body::from(
			r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
		))
		.unwrap();

	let response = application.oneshot(request).await.unwrap();
	assert_eq!(response.status(), StatusCode::ACCEPTED);
}

/// The Mcp-Session-Id header is present in responses from
/// bridge-backed servers.
#[tokio::test]
async fn bridge_response_includes_session_header() {
	let application = test_app();

	let request = Request::builder()
		.method("POST")
		.uri("/servers/test-server/mcp")
		.header("content-type", "application/json")
		.body(Body::from(r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#))
		.unwrap();

	let response = application.oneshot(request).await.unwrap();
	assert!(response.headers().contains_key("mcp-session-id"));
}

/// The readiness endpoint lists the test server with its runtime type.
#[tokio::test]
async fn ready_lists_test_server() {
	let application = test_app();

	let request = Request::builder()
		.uri("/ready")
		.body(Body::empty())
		.unwrap();

	let response = application.oneshot(request).await.unwrap();
	assert_eq!(response.status(), StatusCode::OK);

	let body = response.into_body().collect().await.unwrap().to_bytes();
	let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

	assert_eq!(json["ready"], true);
	assert_eq!(json["servers"]["test-server"]["runtime"], "stdio");
}

/// Build a configuration that lists a single HTTP server with the
/// given name. The URL is intentionally unreachable: these tests
/// exercise the routing surface, not actual upstream behaviour.
fn config_with_http_server(name: &str) -> GatewayConfig {
	// Dispatching to an HTTP server builds a reqwest client with no
	// bundled provider, so install the process default first.
	mcp_gateway_crypto::install();

	let mut servers = HashMap::new();
	servers.insert(
		name.to_owned(),
		ServerDefinition {
			enabled: true,
			env: HashMap::new(),
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Http {
				url: "https://upstream.invalid/mcp/".to_owned(),
				headers: HashMap::new(),
			},
		},
	);
	GatewayConfig {
		servers,
		..Default::default()
	}
}

/// `AppState::replace_inner` atomically installs a new router and
/// configuration. After the swap, observable surfaces (the `/ready`
/// endpoint, dispatch routing) reflect the new server set without
/// the gateway process restarting and without rebuilding the axum
/// application.
#[tokio::test]
async fn replace_inner_updates_ready_endpoint() {
	let state =
		Arc::new(AppState::new(config_with_http_server("alpha"), None).expect("initial state"));
	let application = build_app(&state);

	let response = application
		.clone()
		.oneshot(
			Request::builder()
				.uri("/ready")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	let body = response.into_body().collect().await.unwrap().to_bytes();
	let pre_swap: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert!(pre_swap["servers"]["alpha"].is_object());
	assert!(pre_swap["servers"]["beta"].is_null());

	state
		.replace_inner(config_with_http_server("beta"), None)
		.expect("swap succeeds");

	let response = application
		.oneshot(
			Request::builder()
				.uri("/ready")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	let body = response.into_body().collect().await.unwrap().to_bytes();
	let post_swap: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert!(post_swap["servers"]["beta"].is_object());
	assert!(
		post_swap["servers"]["alpha"].is_null(),
		"old server set must be gone after swap, got {post_swap:?}",
	);
}

/// Resolver fixture that always fails. Use-time use confirms the
/// failure surfaces back to the caller as a 5xx without tearing
/// down the application. `replace_inner` no longer fails on bad
/// credentials, but a request that reaches the proxy will.
struct AlwaysFailingResolver;

#[async_trait]
impl CredentialResolver for AlwaysFailingResolver {
	async fn resolve(&self, name: &str) -> Result<Secret, String> {
		Err(format!("forced failure for {name}"))
	}
}

/// A request to a server whose credential cannot be resolved at
/// use time returns a 5xx response, while the gateway itself keeps
/// serving: the failure does not crash the process or tear down
/// other servers.
#[tokio::test]
async fn use_time_credential_failure_returns_error_response() {
	let resolver: Arc<dyn CredentialResolver> = Arc::new(AlwaysFailingResolver);

	let mut config = config_with_http_server("beta");
	if let Some(definition) = config.servers.get_mut("beta") {
		definition.credential = Some("missing-token".to_owned());
	}

	let state =
		Arc::new(AppState::new(config, Some(Arc::clone(&resolver))).expect("AppState builds"));
	let application = build_app(&state);

	let response = application
		.clone()
		.oneshot(
			Request::builder()
				.method("POST")
				.uri("/servers/beta/mcp")
				.header("content-type", "application/json")
				.body(Body::from(
					r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
				))
				.unwrap(),
		)
		.await
		.unwrap();
	assert!(
		response.status().is_server_error(),
		"use-time credential failure should surface as a 5xx, got {}",
		response.status(),
	);

	// The gateway is still up; `/ready` still answers.
	let ready = application
		.oneshot(
			Request::builder()
				.uri("/ready")
				.body(Body::empty())
				.unwrap(),
		)
		.await
		.unwrap();
	assert_eq!(ready.status(), StatusCode::OK);
}

/// Build a configuration with a single HTTP server pointed at the
/// given URL.
fn config_with_http_url(name: &str, url: String) -> GatewayConfig {
	// Dispatching to an HTTP server builds a reqwest client with no
	// bundled provider, so install the process default first.
	mcp_gateway_crypto::install();

	let mut servers = HashMap::new();
	servers.insert(
		name.to_owned(),
		ServerDefinition {
			enabled: true,
			env: HashMap::new(),
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Http {
				url,
				headers: HashMap::new(),
			},
		},
	);
	GatewayConfig {
		servers,
		..Default::default()
	}
}

/// A non-2xx response from an HTTP upstream surfaces to the client as
/// HTTP 502 Bad Gateway with JSON-RPC error code -32002 carrying the
/// upstream status, and the upstream's error body is not echoed onward
/// to the client (it stays in the gateway's logs only).
#[tokio::test]
async fn upstream_non_2xx_maps_to_bad_gateway_without_leaking_body() {
	// A local upstream that always rejects with 401 and a body that
	// would be sensitive if leaked.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind mock upstream");
	let address = listener.local_addr().expect("mock upstream address");
	tokio::spawn(async move {
		let app = axum::Router::new().route(
			"/mcp",
			axum::routing::post(|| async {
				axum::response::Response::builder()
					.status(401)
					.header("content-type", "text/html")
					.body(axum::body::Body::from(
						"<html>upstream-secret-marker</html>",
					))
					.unwrap()
			}),
		);
		axum::serve(listener, app).await.expect("mock upstream runs");
	});

	let config = config_with_http_url("up", format!("http://{address}/mcp"));
	let state = Arc::new(AppState::new(config, None).expect("AppState builds"));
	let application = build_app(&state);

	let response = application
		.oneshot(
			Request::builder()
				.method("POST")
				.uri("/servers/up/mcp")
				.header("content-type", "application/json")
				.body(Body::from(
					r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
				))
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

	let body = response.into_body().collect().await.unwrap().to_bytes();
	let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert_eq!(json["error"]["code"], -32002);
	assert_eq!(json["error"]["data"]["status"], 401);

	let rendered = String::from_utf8_lossy(&body);
	assert!(
		!rendered.contains("upstream-secret-marker"),
		"the upstream error body must not be echoed to the client, got {rendered}",
	);
}

/// An HTTP upstream that answers a request with a success status but an
/// empty body surfaces to the client as HTTP 502 Bad Gateway rather than
/// a bare JSON-RPC `null`: an empty body is a valid notification
/// acknowledgement but not a valid reply to a request.
#[tokio::test]
async fn upstream_empty_2xx_to_request_maps_to_bad_gateway() {
	// A local upstream that answers every request 200 OK with no body.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind mock upstream");
	let address = listener.local_addr().expect("mock upstream address");
	tokio::spawn(async move {
		let app = axum::Router::new().route(
			"/mcp",
			axum::routing::post(|| async { axum::http::StatusCode::OK }),
		);
		axum::serve(listener, app).await.expect("mock upstream runs");
	});

	let config = config_with_http_url("up", format!("http://{address}/mcp"));
	let state = Arc::new(AppState::new(config, None).expect("AppState builds"));
	let application = build_app(&state);

	let response = application
		.oneshot(
			Request::builder()
				.method("POST")
				.uri("/servers/up/mcp")
				.header("content-type", "application/json")
				.body(Body::from(
					r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
				))
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

	let body = response.into_body().collect().await.unwrap().to_bytes();
	let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert_eq!(json["error"]["code"], -32002);
}

/// A rate-limited or unavailable upstream (a 503 carrying `Retry-After`)
/// surfaces to the client as a retryable 503 Service Unavailable with the
/// upstream's back-off relayed both as a `Retry-After` header and in the
/// JSON-RPC error `data`, so the client can honour the requested wait.
#[tokio::test]
async fn upstream_503_relays_retry_after_as_retryable_503() {
	// A local upstream that rejects with 503 and a Retry-After of 12s.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("bind mock upstream");
	let address = listener.local_addr().expect("mock upstream address");
	tokio::spawn(async move {
		let app = axum::Router::new().route(
			"/mcp",
			axum::routing::post(|| async {
				axum::response::Response::builder()
					.status(503)
					.header("retry-after", "12")
					.body(axum::body::Body::from("upstream busy"))
					.unwrap()
			}),
		);
		axum::serve(listener, app).await.expect("mock upstream runs");
	});

	let config = config_with_http_url("up", format!("http://{address}/mcp"));
	let state = Arc::new(AppState::new(config, None).expect("AppState builds"));
	let application = build_app(&state);

	let response = application
		.oneshot(
			Request::builder()
				.method("POST")
				.uri("/servers/up/mcp")
				.header("content-type", "application/json")
				.body(Body::from(
					r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
				))
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(
		response
			.headers()
			.get("retry-after")
			.and_then(|value| value.to_str().ok()),
		Some("12"),
	);

	let body = response.into_body().collect().await.unwrap().to_bytes();
	let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert_eq!(json["error"]["code"], -32002);
	assert_eq!(json["error"]["data"]["status"], 503);
	assert_eq!(json["error"]["data"]["retryAfter"], "12");
}

/// A dead stdio backend (a command that cannot be spawned) surfaces to
/// the client as HTTP 502 Bad Gateway, an upstream failure, rather than a
/// 500 Internal Server Error: the gateway itself is healthy, the backend
/// is not.
#[tokio::test]
async fn dead_stdio_bridge_maps_to_bad_gateway() {
	let mut servers = HashMap::new();
	servers.insert(
		"broken".to_owned(),
		ServerDefinition {
			enabled: true,
			env: HashMap::new(),
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Stdio {
				command: "/nonexistent/mcp-server-binary".to_owned(),
				args: vec![],
			},
		},
	);
	let config = GatewayConfig {
		servers,
		..Default::default()
	};
	let state = Arc::new(AppState::new(config, None).expect("AppState builds"));
	let application = build_app(&state);

	let response = application
		.oneshot(
			Request::builder()
				.method("POST")
				.uri("/servers/broken/mcp")
				.header("content-type", "application/json")
				.body(Body::from(
					r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
				))
				.unwrap(),
		)
		.await
		.unwrap();

	assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

	let body = response.into_body().collect().await.unwrap().to_bytes();
	let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
	assert_eq!(json["error"]["code"], -32002);
}
