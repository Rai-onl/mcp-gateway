//! Integration tests using the test MCP server fixture.
//!
//! These tests build a full gateway application with the test
//! server configured as a stdio bridge, and send HTTP requests
//! to verify end-to-end behaviour.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use mcp_gateway_config::{GatewayConfig, ServerDefinition, Transport};
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
		"test fixture not built — run: cd tests/fixture && cargo build"
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
