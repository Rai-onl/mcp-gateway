//! Integration test for the daemon's background key-refresh loop (the
//! #31 daemon-mount follow-up). The loop reads the current, reload-
//! swappable auth state each tick and refreshes its signing keys on the
//! configured cadence; the fixture's request counter observes the
//! resulting JWKS fetches.

use std::sync::Arc;
use std::time::Duration;

use mcp_gateway_auth::setup::build_auth_state;
use mcp_gateway_config::{AuthenticationConfig, GatewayConfig};
use mcp_gateway_credentials::StaticResolver;
use mcp_gateway_daemon::{AppState, run_key_refresh};
use mockoidc_kit::{Endpoint, MockIssuer, SigningAlgorithm};
use serde_json::{Value, json};

/// The resource URL the test gateway answers for.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// Build a JWT-validation `authentication` section pointed at the fixture.
fn jwt_section(issuer: &MockIssuer) -> Value {
	json!({
		"issuer": issuer.issuer(),
		"resource": RESOURCE,
		"principal_subjects": ["did:arai:example:alice"],
		"cors": { "allowed_origins": ["https://app.example.test"] },
	})
}

/// The background key-refresh loop refreshes the current validator's JWKS
/// on its cadence: the cache is fetched lazily, so nothing touches the
/// JWKS until the first tick drives a proactive refresh.
#[tokio::test]
async fn key_refresh_loop_refreshes_the_current_validator_jwks() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let section = jwt_section(&issuer);

	let config: GatewayConfig =
		serde_json::from_value(json!({ "servers": {}, "authentication": section }))
			.expect("gateway config should deserialise");
	let state = Arc::new(AppState::new(config, None).expect("app state should build"));

	let auth_config: AuthenticationConfig =
		serde_json::from_value(jwt_section(&issuer)).expect("authentication section should parse");
	let auth = build_auth_state(&auth_config, &StaticResolver::default())
		.await
		.expect("jwt auth state should build against the fixture");
	state.set_auth(Arc::new(auth));

	// The JWKS is fetched lazily, so nothing has touched it yet.
	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		0,
		"no JWKS fetch should have happened before the refresh loop runs",
	);

	// Drive the loop with a short cadence so the test does not wait long.
	let task = tokio::spawn(run_key_refresh(
		Arc::clone(&state),
		Duration::from_millis(50),
	));

	// Wait for the first proactive refresh, polling up to roughly two
	// seconds so the assertion does not race the loop's first tick.
	let mut refreshed = false;
	for _ in 0..40 {
		if issuer.request_count(Endpoint::Jwks) >= 1 {
			refreshed = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	task.abort();

	assert!(
		refreshed,
		"the background refresh loop must proactively fetch the JWKS on its cadence",
	);
}
