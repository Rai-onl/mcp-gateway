//! Integration tests for the daemon's background discovery-refresh loop
//! (the #31 daemon-mount follow-up, hardened under issue #52). The loop
//! re-fetches the discovery document on its cadence, reading the live
//! configuration, and rebuilds the validator when the document changes.
//! A fetch failure keeps the previous validator, and crucially a rebuild
//! reads the post-reload configuration so it cannot revert a reload.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{StatusCode, header};
use mcp_gateway_auth::middleware::AuthState;
use mcp_gateway_auth::setup::build_auth_state;
use mcp_gateway_config::{AuthenticationConfig, GatewayConfig};
use mcp_gateway_credentials::StaticResolver;
use mcp_gateway_daemon::{AppState, build_app, run_discovery_refresh};
use mockoidc_kit::{Endpoint, FaultResponse, MockIssuer, SigningAlgorithm};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// The resource URL the test gateway answers for.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// Principals used across the reload-does-not-revert case.
const ALICE: &str = "did:arai:example:alice";
const BOB: &str = "did:arai:example:bob";

/// A short cadence so the tests do not wait long for a tick.
const TICK: Duration = Duration::from_millis(50);

/// Build a JWT-validation `authentication` section admitting `principals`.
fn jwt_section(issuer: &MockIssuer, principals: &[&str]) -> Value {
	json!({
		"issuer": issuer.issuer(),
		"resource": RESOURCE,
		"principal_subjects": principals,
		"cors": { "allowed_origins": ["https://app.example.test"] },
	})
}

/// Build a gateway configuration wrapping the given authentication section.
fn gateway_config(section: &Value) -> GatewayConfig {
	serde_json::from_value(json!({ "servers": {}, "authentication": section }))
		.expect("gateway config should deserialise")
}

/// Build the validator admitting `principals`, the production way.
async fn build_jwt_auth(issuer: &MockIssuer, principals: &[&str]) -> Arc<AuthState> {
	let section: AuthenticationConfig = serde_json::from_value(jwt_section(issuer, principals))
		.expect("authentication section should deserialise");
	Arc::new(
		build_auth_state(&section, &StaticResolver::default())
			.await
			.expect("jwt auth state should build against the fixture"),
	)
}

/// Build the app state with the validator installed, admitting
/// `principals`. The configuration is stored in the state, so the refresh
/// loop reads it live.
async fn state_admitting(issuer: &MockIssuer, principals: &[&str]) -> Arc<AppState> {
	let state =
		Arc::new(AppState::new(gateway_config(&jwt_section(issuer, principals)), None).unwrap());
	state.set_auth(build_jwt_auth(issuer, principals).await);
	state
}

/// A bearer token for `subject`, audience-bound to the resource.
fn token_for(issuer: &MockIssuer, subject: &str) -> String {
	issuer
		.subject(subject)
		.audience(RESOURCE)
		.claim("scope", "mcp:invoke:gitlab")
		.mint_id_token()
}

/// `GET /.well-known/mcp-server-card` with a bearer token, returning the
/// status. The card endpoint is protected but scope-free, so it reflects
/// the authentication and principal-admission decision alone.
async fn card_status(app: axum::Router, bearer: &str) -> StatusCode {
	let request = axum::http::Request::builder()
		.method("GET")
		.uri("/.well-known/mcp-server-card")
		.header(header::AUTHORIZATION, format!("Bearer {bearer}"))
		.body(Body::empty())
		.expect("request should build");
	app.oneshot(request)
		.await
		.expect("app should respond")
		.status()
}

/// The discovery-refresh loop leaves the validator untouched while the
/// document is unchanged, then rebuilds and swaps it once it changes.
#[tokio::test]
async fn discovery_change_rebuilds_the_validator() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let state = state_admitting(&issuer, &[ALICE]).await;
	let auth_before = state.auth().expect("auth is installed");

	let task = tokio::spawn(run_discovery_refresh(Arc::clone(&state), TICK));

	// Several ticks with no change must not rebuild the validator.
	tokio::time::sleep(Duration::from_millis(200)).await;
	assert!(
		Arc::ptr_eq(&auth_before, &state.auth().expect("auth is installed")),
		"an unchanged discovery document must not rebuild the validator",
	);

	// Change the document; the next tick that observes it rebuilds.
	issuer.tamper_discovery(|document| {
		document["scopes_supported"] = json!(["openid", "mcp:invoke:gitlab"]);
	});

	let mut rebuilt = false;
	for _ in 0..40 {
		if !Arc::ptr_eq(&auth_before, &state.auth().expect("auth is installed")) {
			rebuilt = true;
			break;
		}
		tokio::time::sleep(TICK).await;
	}
	task.abort();
	assert!(
		rebuilt,
		"a changed discovery document must rebuild and swap the validator",
	);
}

/// A discovery fetch that fails keeps the previously installed validator.
#[tokio::test]
async fn discovery_fetch_failure_keeps_the_validator() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let state = state_admitting(&issuer, &[ALICE]).await;
	let auth_before = state.auth().expect("auth is installed");

	let task = tokio::spawn(run_discovery_refresh(Arc::clone(&state), TICK));

	tokio::time::sleep(Duration::from_millis(150)).await;
	issuer.fail(Endpoint::OidcDiscovery, FaultResponse::new(503));
	tokio::time::sleep(Duration::from_millis(300)).await;
	task.abort();

	assert!(
		Arc::ptr_eq(&auth_before, &state.auth().expect("auth is installed")),
		"a discovery outage must keep the previously installed validator",
	);
}

/// The regression test for issue #52: a discovery change must rebuild from
/// the live (post-reload) configuration, so it cannot revert a reload that
/// narrowed the principal allowlist. With the old frozen-config loop, the
/// rebuild would re-admit a principal the reload had removed.
#[tokio::test]
async fn discovery_change_does_not_revert_a_reloaded_allowlist() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	// Start admitting both alice and bob.
	let state = state_admitting(&issuer, &[ALICE, BOB]).await;
	let app = build_app(&state);
	let bob = token_for(&issuer, BOB);
	assert_eq!(
		card_status(app.clone(), &bob).await,
		StatusCode::OK,
		"bob is admitted before the reload",
	);

	let task = tokio::spawn(run_discovery_refresh(Arc::clone(&state), TICK));
	// Let the loop establish its baseline document.
	tokio::time::sleep(Duration::from_millis(150)).await;

	// Reload narrows the allowlist to alice only: swap the live config and
	// install the narrowed validator, as the reload handler does.
	state
		.replace_inner(gateway_config(&jwt_section(&issuer, &[ALICE])), None)
		.expect("router rebuilds");
	state.set_auth(build_jwt_auth(&issuer, &[ALICE]).await);
	let after_reload = state.auth().expect("auth is installed");
	assert_eq!(
		card_status(app.clone(), &bob).await,
		StatusCode::FORBIDDEN,
		"the reload removed bob",
	);

	// The authorisation server rotates its discovery document, triggering
	// a background rebuild. That rebuild must read the narrowed config.
	issuer.tamper_discovery(|document| {
		document["scopes_supported"] = json!(["openid", "mcp:invoke:gitlab"]);
	});

	// Wait for the rebuild to land (the validator Arc changes).
	let mut rebuilt = false;
	for _ in 0..40 {
		if !Arc::ptr_eq(&after_reload, &state.auth().expect("auth is installed")) {
			rebuilt = true;
			break;
		}
		tokio::time::sleep(TICK).await;
	}
	task.abort();
	assert!(rebuilt, "the discovery change must trigger a rebuild");

	// The rebuilt validator must still reject bob: the discovery refresh
	// rebuilt from the narrowed allowlist, not the startup one.
	assert_eq!(
		card_status(app, &bob).await,
		StatusCode::FORBIDDEN,
		"a discovery change must not revert the reload that removed bob",
	);
}
