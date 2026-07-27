//! Integration tests for how the daemon mounts inbound authentication
//! and CORS (issue #31): which endpoints require a token, which stay
//! public, and how the CORS preflight behaves. The auth state is built
//! the production way, from the `mockoidc-kit` fixture's discovery
//! document.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{StatusCode, header};
use http_body_util::BodyExt as _;
use mcp_gateway_auth::setup::build_auth_state;
use mcp_gateway_config::GatewayConfig;
use mcp_gateway_daemon::{AppState, build_app};
use mockoidc_kit::{MockIssuer, SigningAlgorithm};
use serde_json::json;
use tower::ServiceExt as _;

/// The resource URL the test gateway answers for.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// An origin the test gateway's CORS policy admits.
const ALLOWED_ORIGIN: &str = "https://app.example.test";

/// Build a gateway with no `authentication` section: the local-loopback
/// posture, where every endpoint is public.
fn unauthenticated_app() -> axum::Router {
	let config: GatewayConfig =
		serde_json::from_value(json!({ "servers": {} })).expect("config should deserialise");
	let state = Arc::new(AppState::new(config, None).expect("state should build"));
	build_app(&state)
}

/// Build a gateway with `authentication` configured against the
/// fixture, mounting the validator the daemon would use in production.
async fn authenticated_app(issuer: &MockIssuer) -> axum::Router {
	let config: GatewayConfig = serde_json::from_value(json!({
		"servers": {},
		"authentication": {
			"issuer": issuer.issuer(),
			"resource": RESOURCE,
			"principal_subjects": ["did:arai:example:alice"],
			"cors": { "allowed_origins": [ALLOWED_ORIGIN] },
		},
	}))
	.expect("config should deserialise");

	let authentication = config
		.authentication
		.clone()
		.expect("authentication section is present");
	let state = Arc::new(AppState::new(config, None).expect("state should build"));
	let auth = build_auth_state(
		&authentication,
		&mcp_gateway_credentials::StaticResolver::default(),
	)
	.await
	.expect("auth state should build against the fixture");
	state.set_auth(Arc::new(auth));
	build_app(&state)
}

/// `GET` a path with no credentials and return the response status.
async fn get_status(app: axum::Router, path: &str) -> StatusCode {
	let request = axum::http::Request::builder()
		.method("GET")
		.uri(path)
		.body(Body::empty())
		.expect("request should build");
	app.oneshot(request)
		.await
		.expect("app should respond")
		.status()
}

/// `GET` a path with no credentials and return the response status and
/// JSON body, for endpoints whose body the assertions inspect.
async fn get_json(app: axum::Router, path: &str) -> (StatusCode, serde_json::Value) {
	let request = axum::http::Request::builder()
		.method("GET")
		.uri(path)
		.body(Body::empty())
		.expect("request should build");
	let response = app.oneshot(request).await.expect("app should respond");
	let status = response.status();
	let bytes = response
		.into_body()
		.collect()
		.await
		.expect("body should read")
		.to_bytes();
	let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
	(status, body)
}

/// Without `authentication`, the gateway is not a protected resource:
/// the metadata endpoint answers `404`, telling a client there is
/// nothing to authenticate against here.
#[tokio::test]
async fn metadata_endpoint_is_404_without_authentication() {
	let status = get_status(
		unauthenticated_app(),
		"/.well-known/oauth-protected-resource",
	)
	.await;
	assert_eq!(status, StatusCode::NOT_FOUND);
}

/// When authentication is configured, the metadata endpoint serves the
/// RFC 9728 document without requiring a token, so a client can begin
/// discovery before authenticating.
#[tokio::test]
async fn metadata_endpoint_serves_document_when_configured() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let (status, body) = get_json(
		authenticated_app(&issuer).await,
		"/.well-known/oauth-protected-resource",
	)
	.await;

	assert_eq!(status, StatusCode::OK);
	assert_eq!(body["resource"], serde_json::json!(RESOURCE));
	assert_eq!(
		body["authorization_servers"],
		serde_json::json!([issuer.issuer()]),
	);
	assert_eq!(
		body["bearer_methods_supported"],
		serde_json::json!(["header"])
	);
}

/// When authentication is configured but no validator has been installed
/// yet (the brief window between building the state and the cold discovery
/// fetch, or a future wiring mistake), a protected route fails closed with
/// `500` rather than passing the request through unauthenticated. The
/// authentication layer must never default to open.
#[tokio::test]
async fn protected_route_fails_closed_without_a_validator() {
	let config: GatewayConfig = serde_json::from_value(json!({
		"servers": {},
		"authentication": {
			"issuer": "https://identity.example.test",
			"resource": RESOURCE,
			"principal_subjects": ["did:arai:example:alice"],
			"cors": { "allowed_origins": [ALLOWED_ORIGIN] },
		},
	}))
	.expect("config should deserialise");
	// Routing reflects the authentication section, but `set_auth` is never
	// called, so the validator is absent.
	let state = Arc::new(AppState::new(config, None).expect("state should build"));

	let status = get_status(build_app(&state), "/.well-known/mcp-server-card").await;
	assert_eq!(
		status,
		StatusCode::INTERNAL_SERVER_ERROR,
		"a protected route must fail closed when no validator is installed",
	);
}

/// With no `authentication` configured, the server-card endpoint stays
/// public and serves its inventory, exactly as in local-loopback mode.
#[tokio::test]
async fn server_card_is_public_without_authentication() {
	let status = get_status(unauthenticated_app(), "/.well-known/mcp-server-card").await;
	assert_eq!(status, StatusCode::OK);
}

/// `/health` and `/ready` never require a token, even when
/// authentication is configured.
///
/// `/health` answers `200`. `/ready` answers its readiness status,
/// which is `503` here because the test config defines no servers; the
/// point is that it is reached at all, never an authentication `401`.
#[tokio::test]
async fn health_and_ready_stay_public_with_authentication() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let app = authenticated_app(&issuer).await;

	assert_eq!(get_status(app.clone(), "/health").await, StatusCode::OK);
	assert_ne!(
		get_status(app, "/ready").await,
		StatusCode::UNAUTHORIZED,
		"/ready must be reachable without authentication",
	);
}

/// When authentication is configured, the server-card endpoint moves
/// behind it: an unauthenticated request is rejected, so the server
/// inventory is not leaked to unauthenticated callers.
#[tokio::test]
async fn server_card_requires_authentication_when_configured() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let app = authenticated_app(&issuer).await;

	let status = get_status(app, "/.well-known/mcp-server-card").await;
	assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A CORS preflight from an allowed origin is answered by the CORS
/// layer, before authentication, with an `Access-Control-Allow-Origin`
/// echoing the origin.
#[tokio::test]
async fn cors_preflight_from_allowed_origin_is_permitted() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let app = authenticated_app(&issuer).await;

	let request = axum::http::Request::builder()
		.method("OPTIONS")
		.uri("/servers/gitlab/mcp")
		.header(header::ORIGIN, ALLOWED_ORIGIN)
		.header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
		.body(Body::empty())
		.expect("request should build");
	let response = app.oneshot(request).await.expect("app should respond");

	let allow_origin = response
		.headers()
		.get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
		.and_then(|value| value.to_str().ok());
	assert_eq!(
		allow_origin,
		Some(ALLOWED_ORIGIN),
		"the preflight must echo the allowed origin",
	);
}

/// A CORS preflight from a disallowed origin carries no
/// `Access-Control-Allow-Origin`, so a browser refuses the
/// cross-origin call.
#[tokio::test]
async fn cors_preflight_from_disallowed_origin_is_refused() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let app = authenticated_app(&issuer).await;

	let request = axum::http::Request::builder()
		.method("OPTIONS")
		.uri("/servers/gitlab/mcp")
		.header(header::ORIGIN, "https://evil.example.test")
		.header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
		.body(Body::empty())
		.expect("request should build");
	let response = app.oneshot(request).await.expect("app should respond");

	assert!(
		response
			.headers()
			.get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
			.is_none(),
		"a disallowed origin must receive no Access-Control-Allow-Origin",
	);
}
