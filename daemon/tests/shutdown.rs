//! Graceful shutdown integration tests.
//!
//! These tests verify that the gateway handles shutdown correctly:
//! it responds to requests while running, exits cleanly when a
//! shutdown signal is received, and refuses new connections after
//! shutdown has been triggered. Each test starts a real TCP server
//! on a random port and communicates with it over HTTP.
//!
//! The shutdown signal is simulated using a `oneshot` channel
//! rather than an actual OS signal, which allows the tests to run
//! without elevated privileges and without interfering with other
//! processes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_gateway_config::{GatewayConfig, ServerDefinition, Transport};
use mcp_gateway_daemon::{AppState, build_app};

/// Start a gateway on a random available port.
///
/// Returns the bound address, a oneshot sender that triggers
/// graceful shutdown when sent, and the join handle for the
/// server task. The server is ready to accept connections when
/// this function returns.
async fn start_gateway(
	config: GatewayConfig,
) -> (
	std::net::SocketAddr,
	tokio::sync::oneshot::Sender<()>,
	tokio::task::JoinHandle<()>,
) {
	// The tests connect with a reqwest client that carries no bundled
	// crypto provider, so install the process default first.
	mcp_gateway_crypto::install();

	let state = Arc::new(AppState::new(config, None).unwrap());
	let application = build_app(&state);

	// Bind to port 0 so the OS assigns a random available port.
	// This avoids port conflicts when running tests in parallel.
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let address = listener.local_addr().unwrap();

	// The oneshot channel simulates SIGTERM/SIGINT. Sending a
	// value triggers axum's graceful shutdown, which stops
	// accepting new connections and drains in-flight requests.
	let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel::<()>();

	let server_handle = tokio::spawn(async move {
		axum::serve(listener, application)
			.with_graceful_shutdown(async {
				// Wait until the shutdown signal is sent. The
				// channel closing (sender dropped) also triggers
				// shutdown, which is the correct fallback if the
				// test panics before sending the signal.
				shutdown_receiver.await.ok();
			})
			.await
			.unwrap();
	});

	// Allow the server time to start accepting connections.
	// Without this, the first HTTP request may arrive before
	// the listener is ready, causing a spurious connection
	// refused error.
	tokio::time::sleep(Duration::from_millis(50)).await;

	(address, shutdown_sender, server_handle)
}

/// Build a test configuration that uses the test MCP server
/// fixture as a stdio bridge. The fixture binary must be built
/// before running these tests (see tests/fixture/).
fn test_config() -> GatewayConfig {
	let manifest_directory = env!("CARGO_MANIFEST_DIR");
	let test_server_path =
		format!("{manifest_directory}/../tests/fixture/target/debug/mcp-test-server");

	GatewayConfig {
		servers: [(
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
					command: test_server_path,
					args: vec![],
				},
			},
		)]
		.into(),
		..Default::default()
	}
}

/// The gateway responds normally to MCP requests while running.
/// This establishes the baseline that the server is operational
/// before we test shutdown behaviour.
#[tokio::test]
async fn gateway_responds_before_shutdown() {
	let (address, shutdown_sender, server_handle) = start_gateway(test_config()).await;

	// Send an MCP ping request and verify the response.
	let client = reqwest::Client::new();
	let response = client
		.post(format!("http://{address}/servers/test-server/mcp"))
		.header("content-type", "application/json")
		.body(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#)
		.send()
		.await
		.unwrap();

	assert_eq!(response.status(), 200);

	// Trigger shutdown and wait for the server to stop so we
	// don't leave orphaned tasks.
	let _ = shutdown_sender.send(());
	let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
}

/// After the shutdown signal is sent, the server task completes
/// within a reasonable time. This verifies that graceful shutdown
/// actually terminates the server rather than hanging indefinitely.
#[tokio::test]
async fn gateway_exits_after_shutdown_signal() {
	let (address, shutdown_sender, server_handle) = start_gateway(test_config()).await;

	// Confirm the server is running by checking the health endpoint.
	let client = reqwest::Client::new();
	let response = client
		.get(format!("http://{address}/health"))
		.send()
		.await
		.unwrap();
	assert_eq!(response.status(), 200);

	// Send the shutdown signal.
	shutdown_sender.send(()).unwrap();

	// The server should complete its shutdown and the task should
	// finish within 5 seconds. If it takes longer, the graceful
	// shutdown mechanism is broken or hanging on a resource.
	let result = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
	assert!(result.is_ok(), "gateway did not shut down within 5 seconds");
}

/// After shutdown completes, new connections to the server's
/// address are refused. This verifies that the listener is
/// actually closed and the port is released.
#[tokio::test]
async fn gateway_refuses_connections_after_shutdown() {
	let (address, shutdown_sender, server_handle) = start_gateway(test_config()).await;

	// Send the shutdown signal and wait for the server to stop.
	shutdown_sender.send(()).unwrap();
	let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;

	// Attempt to connect to the now-stopped server. The TCP
	// connection should be refused since the listener is closed.
	let client = reqwest::Client::builder()
		.connect_timeout(Duration::from_secs(1))
		.build()
		.unwrap();

	let result = client.get(format!("http://{address}/health")).send().await;

	assert!(
		result.is_err(),
		"expected connection to be refused after shutdown"
	);
}
