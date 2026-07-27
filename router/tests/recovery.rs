//! Recovery integration tests for the stdio bridge runtime.
//!
//! These spawn the real MCP test fixture as a stdio bridge and drive
//! the router directly with a short request timeout, so the
//! timeout-and-respawn path can be exercised without waiting the full
//! production request timeout.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_gateway_config::{GatewayConfig, ServerDefinition, Transport};
use mcp_gateway_credentials::{CredentialResolver, Secret, StaticResolver};
use mcp_gateway_router::{Router, RouterError, RouterResponse};
use serde_json::{Value, json};

/// Path to the test MCP server binary built from tests/fixture/.
///
/// # Panics
///
/// Panics if the fixture binary has not been built. Build it with:
/// `cd tests/fixture && cargo build`.
fn fixture_path() -> String {
	let manifest_dir = env!("CARGO_MANIFEST_DIR");
	let path = format!("{manifest_dir}/../tests/fixture/target/debug/mcp-test-server");
	assert!(
		std::path::Path::new(&path).exists(),
		"test fixture not built; run: cd tests/fixture && cargo build"
	);
	path
}

/// Build a router with a single stdio server pointed at the fixture,
/// carrying the given environment and a short per-request timeout.
fn router_with_env(env: HashMap<String, Secret>, request_timeout: Duration) -> Router {
	let mut servers = HashMap::new();
	servers.insert(
		"wedge".to_owned(),
		ServerDefinition {
			enabled: true,
			env,
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Stdio {
				command: fixture_path(),
				args: vec![],
			},
		},
	);
	let config = GatewayConfig {
		servers,
		..Default::default()
	};
	let resolver: Arc<dyn CredentialResolver> = Arc::new(StaticResolver::default());
	Router::from_config(&config, resolver)
		.expect("router builds from fixture config")
		.with_request_timeout(request_timeout)
}

/// A `tools/call` echo request used across the recovery assertions.
fn echo_call() -> Value {
	json!({
		"jsonrpc": "2.0",
		"id": 1,
		"method": "tools/call",
		"params": {"name": "echo", "arguments": {"message": "hi"}},
	})
}

/// A request to a wedged-but-alive child times out and the bridge is
/// dropped from the slot. An immediate retry is refused with a cooldown
/// error (respawn rate-limiting), but once the backoff window passes,
/// the next request spawns a fresh child that answers normally. No
/// retry is attempted for the timed-out call, so the wedged child
/// receives exactly one `tools/call`.
#[tokio::test]
async fn wedged_request_times_out_then_bridge_respawns_after_backoff() {
	let marker = std::env::temp_dir().join(format!("mcp-wedge-{}.marker", std::process::id()));
	// Ensure a clean slate so the first spawned child is the one that
	// wedges.
	let _ = std::fs::remove_file(&marker);

	let mut env = HashMap::new();
	env.insert(
		"MCP_FIXTURE_WEDGE_TOOLS_CALL_ONCE".to_owned(),
		Secret::new(marker.to_string_lossy().into_owned()),
	);
	// A short request timeout keeps the first call's failure well
	// inside the spawn-backoff window, so the immediate retry
	// deterministically observes the cooldown.
	let router = router_with_env(env, Duration::from_millis(100));

	// First call reaches the wedged child and times out.
	let first = router.dispatch("wedge", &echo_call()).await;
	assert!(
		matches!(first, Err(RouterError::Bridge(_))),
		"wedged call should fail, got {first:?}"
	);

	// An immediate retry is inside the respawn backoff window and is
	// refused rather than relaunching the child straight away.
	let immediate = router.dispatch("wedge", &echo_call()).await;
	assert!(
		matches!(immediate, Err(RouterError::BridgeCooldown(_))),
		"immediate retry should be cooled down, got {immediate:?}"
	);

	// After the backoff window elapses, the next call spawns a fresh,
	// healthy child and succeeds.
	tokio::time::sleep(Duration::from_millis(600)).await;
	let recovered = router
		.dispatch("wedge", &echo_call())
		.await
		.expect("respawned call should succeed");
	match recovered {
		RouterResponse::Reply(value) => {
			assert_eq!(value["result"]["content"][0]["text"], "hi");
		}
		RouterResponse::Accepted => panic!("expected a reply from the respawned child, got Accepted"),
	}

	let _ = std::fs::remove_file(&marker);
}

/// An idle child that stays alive but stops answering the liveness
/// probe is reaped after repeated probe failures, while a single
/// failure is tolerated.
#[tokio::test]
async fn idle_wedged_bridge_is_reaped_by_health_probe() {
	let mut env = HashMap::new();
	env.insert(
		"MCP_FIXTURE_IGNORE_PING".to_owned(),
		Secret::new("1".to_owned()),
	);
	let router = router_with_env(env, Duration::from_secs(5))
		.with_health_probe_timeout(Duration::from_millis(200));

	// A successful real request spawns the bridge and proves liveness.
	let listed = router
		.dispatch(
			"wedge",
			&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
		)
		.await;
	assert!(listed.is_ok(), "tools/list should succeed, got {listed:?}");
	assert!(router.is_bridge_active("wedge").await);

	// The child ignores ping; the first probe failure is tolerated.
	router.check_bridge_health().await;
	assert!(
		router.is_bridge_active("wedge").await,
		"a single ping failure should be tolerated"
	);

	// A second consecutive probe failure reaps the wedged bridge.
	router.check_bridge_health().await;
	assert!(
		!router.is_bridge_active("wedge").await,
		"two consecutive ping failures should reap the bridge"
	);
}

/// A server that answers the liveness probe with a JSON-RPC error
/// rather than a result is alive (it correlated and replied) and must
/// not be reaped, even when idle across several probes.
#[tokio::test]
async fn ping_erroring_server_is_not_reaped() {
	let mut env = HashMap::new();
	env.insert(
		"MCP_FIXTURE_PING_ERROR".to_owned(),
		Secret::new("1".to_owned()),
	);
	let router = router_with_env(env, Duration::from_secs(5))
		.with_health_probe_timeout(Duration::from_millis(200));

	let listed = router
		.dispatch(
			"wedge",
			&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
		)
		.await;
	assert!(listed.is_ok(), "tools/list should succeed, got {listed:?}");

	// Several probes, all answered with an error, must not condemn the
	// bridge: an error reply still proves the child is alive.
	for _ in 0..4 {
		router.check_bridge_health().await;
	}
	assert!(
		router.is_bridge_active("wedge").await,
		"a ping-erroring but alive server must not be reaped"
	);
}

/// A per-server `request_timeout_seconds` drives the dispatch timeout,
/// not the 30-second default. Without any test-only override, a wedged
/// call must fail within the configured window.
#[tokio::test]
async fn per_server_request_timeout_is_honoured() {
	let marker =
		std::env::temp_dir().join(format!("mcp-timeout-{}.marker", std::process::id()));
	let _ = std::fs::remove_file(&marker);

	let mut env = HashMap::new();
	env.insert(
		"MCP_FIXTURE_WEDGE_TOOLS_CALL_ONCE".to_owned(),
		Secret::new(marker.to_string_lossy().into_owned()),
	);

	// Build the router straight from config, with the server's own
	// one-second timeout and no `with_request_timeout` override.
	let mut servers = HashMap::new();
	servers.insert(
		"wedge".to_owned(),
		ServerDefinition {
			enabled: true,
			env,
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: Some(1),
			credential_injection: None,
			transport: Transport::Stdio {
				command: fixture_path(),
				args: vec![],
			},
		},
	);
	let config = GatewayConfig {
		servers,
		..Default::default()
	};
	let resolver: Arc<dyn CredentialResolver> = Arc::new(StaticResolver::default());
	let router = Router::from_config(&config, resolver).expect("router builds");

	// The dispatch must resolve well before the 30-second default. The
	// outer 5-second bound fails the test if the configured 1-second
	// timeout was not applied.
	let outcome = tokio::time::timeout(Duration::from_secs(5), router.dispatch("wedge", &echo_call()))
		.await
		.expect("dispatch must complete within the configured 1-second timeout");
	assert!(
		matches!(outcome, Err(RouterError::Bridge(_))),
		"the wedged call should fail, got {outcome:?}"
	);

	let _ = std::fs::remove_file(&marker);
}
