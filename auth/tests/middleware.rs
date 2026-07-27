//! Integration tests for the authentication middleware (issue #31),
//! driven through a minimal axum app against the `mockoidc-kit`
//! fixture.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use http_body_util::BodyExt as _;
use mcp_gateway_auth::claims::ValidatedClaims;
use mcp_gateway_auth::middleware::{AuthState, authenticate};
use mcp_gateway_auth::setup::build_auth_state;
use mcp_gateway_config::AuthenticationConfig;
use mcp_gateway_credentials::{Secret, StaticResolver};
use mockoidc_kit::{MockIssuer, SigningAlgorithm};
use serde_json::json;
use std::collections::HashMap;
use tower::ServiceExt as _;

/// The resource URL the test gateway answers for.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// A principal the test gateway admits.
const PRINCIPAL: &str = "did:arai:example:alice";

/// Build the full authentication state the way the daemon does at
/// startup, pointed at the running fixture.
///
/// The fixture binds to an ephemeral port, so its issuer URL is only
/// known once it is running. We feed that URL into an
/// [`AuthenticationConfig`], built from JSON so the test states only
/// the fields it cares about and inherits the documented defaults for
/// the rest, and hand it to [`build_auth_state`]. That call performs
/// the real cold-start sequence: fetch the discovery document, derive
/// the JWKS endpoint, assemble the validator. These tests therefore
/// exercise the same wiring production uses, not a hand-built
/// stand-in.
async fn auth_state(issuer: &MockIssuer) -> Arc<AuthState> {
	let config: AuthenticationConfig = serde_json::from_value(json!({
		"issuer": issuer.issuer(),
		"resource": RESOURCE,
		"principal_subjects": [PRINCIPAL],
		"server_scopes": { "gitlab": ["mcp:invoke:gitlab"] },
		"cors": { "allowed_origins": ["https://app.example.test"] },
	}))
	.expect("authentication config should deserialise");
	Arc::new(
		build_auth_state(&config, &mcp_gateway_credentials::StaticResolver::default())
			.await
			.expect("auth state should build against the fixture"),
	)
}

/// The middleware gate mounted in the test app.
///
/// The auth crate's [`authenticate`] takes the [`AuthState`] by
/// reference, so the daemon can load its current, reload-swappable
/// value per request. axum middleware cannot take a bare reference, so
/// this thin wrapper receives the state through `from_fn_with_state`
/// and forwards a borrow. It mirrors the daemon's own wrapper.
async fn gate(State(state): State<Arc<AuthState>>, request: Request, next: Next) -> Response {
	authenticate(&state, request, next).await
}

/// Stand-in protected handler that proves authentication ran and
/// attached the claims.
///
/// On a request that passed the gate, the middleware inserts a
/// [`ValidatedClaims`] request extension. This handler reads it back
/// and echoes the subject, so a `200` whose body is the subject proves
/// the extension propagated to the handler. Its absence yields a `500`,
/// which would mean the middleware let the request through without
/// attaching claims: a bug.
async fn echo_subject(request: Request) -> Response {
	match request.extensions().get::<ValidatedClaims>() {
		Some(claims) => (StatusCode::OK, claims.subject().to_owned()).into_response(),
		None => (
			StatusCode::INTERNAL_SERVER_ERROR,
			"claims extension missing",
		)
			.into_response(),
	}
}

/// Assemble the test app: a single MCP route guarded by the
/// authentication gate, mirroring how the daemon mounts the layer on
/// `/servers/*`.
fn app(state: Arc<AuthState>) -> Router {
	Router::new()
		.route("/servers/gitlab/mcp", post(echo_subject))
		.layer(from_fn_with_state(state, gate))
}

/// Drive one request through the app and return what the assertions
/// need to inspect.
///
/// Sends a `POST` to the protected route carrying the given
/// `Authorization` header, or none, then returns the response status,
/// the body as a string, and the `WWW-Authenticate` challenge value
/// when present. Bundling the three keeps each test to a single call
/// plus its assertions.
async fn post_with_authorization(
	state: Arc<AuthState>,
	authorization: Option<&str>,
) -> (StatusCode, String, Option<String>) {
	let mut builder = Request::builder().method("POST").uri("/servers/gitlab/mcp");
	if let Some(value) = authorization {
		builder = builder.header(header::AUTHORIZATION, value);
	}
	let request = builder.body(Body::empty()).expect("request should build");

	let response = app(state)
		.oneshot(request)
		.await
		.expect("the app should respond");
	let status = response.status();
	let challenge = response
		.headers()
		.get(header::WWW_AUTHENTICATE)
		.and_then(|value| value.to_str().ok())
		.map(str::to_owned);
	let body = response
		.into_body()
		.collect()
		.await
		.expect("body should read")
		.to_bytes();
	(
		status,
		String::from_utf8_lossy(&body).into_owned(),
		challenge,
	)
}

/// A bearer token for the given subject, audience-bound to the
/// resource.
fn token_for(issuer: &MockIssuer, subject: &str) -> String {
	issuer
		.subject(subject)
		.audience(RESOURCE)
		.claim("scope", "mcp:invoke:gitlab")
		.mint_id_token()
}

/// A request with no `Authorization` header is rejected with 401 and a
/// challenge pointing clients at the protected-resource metadata URL.
#[tokio::test]
async fn missing_authorization_is_rejected_with_challenge() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let (status, _body, challenge) = post_with_authorization(auth_state(&issuer).await, None).await;

	assert_eq!(status, StatusCode::UNAUTHORIZED);
	let challenge = challenge.expect("a 401 must carry a WWW-Authenticate challenge");
	assert!(challenge.starts_with("Bearer "), "{challenge}");
	assert!(
		challenge.contains("/.well-known/oauth-protected-resource"),
		"the challenge must point at the metadata URL: {challenge}",
	);
}

/// A valid bearer token reaches the handler with the validated claims
/// attached as a request extension.
#[tokio::test]
async fn valid_token_reaches_handler_with_claims() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = token_for(&issuer, PRINCIPAL);
	let (status, body, _) =
		post_with_authorization(auth_state(&issuer).await, Some(&format!("Bearer {token}"))).await;

	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		body, PRINCIPAL,
		"the handler should see the validated subject"
	);
}

/// A non-Bearer scheme is rejected with 401, and the challenge
/// advertises only Bearer.
#[tokio::test]
async fn unsupported_scheme_is_rejected_advertising_bearer() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let (status, _body, challenge) =
		post_with_authorization(auth_state(&issuer).await, Some("Negotiate abc123")).await;

	assert_eq!(status, StatusCode::UNAUTHORIZED);
	let challenge = challenge.expect("a 401 must carry a challenge");
	assert!(challenge.starts_with("Bearer "), "{challenge}");
	assert!(!challenge.contains("Negotiate"), "{challenge}");
}

/// A cryptographically valid token whose subject is not an admitted
/// principal is rejected with 403 `insufficient_scope`, distinct from
/// an unauthenticated 401.
#[tokio::test]
async fn unknown_principal_is_forbidden() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = token_for(&issuer, "did:arai:example:mallory");
	let (status, _body, challenge) =
		post_with_authorization(auth_state(&issuer).await, Some(&format!("Bearer {token}"))).await;

	assert_eq!(status, StatusCode::FORBIDDEN);
	let challenge = challenge.expect("a 403 must carry a challenge");
	assert!(
		challenge.contains(r#"error="insufficient_scope""#),
		"{challenge}"
	);
}

/// A valid token whose scopes do not authorise the route's server is
/// rejected with 403 `insufficient_scope`, even though the token is
/// authentic and the principal admitted.
#[tokio::test]
async fn token_without_required_scope_is_forbidden() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = issuer
		.subject(PRINCIPAL)
		.audience(RESOURCE)
		.claim("scope", "mcp:invoke:other")
		.mint_id_token();
	let (status, _body, challenge) =
		post_with_authorization(auth_state(&issuer).await, Some(&format!("Bearer {token}"))).await;

	assert_eq!(status, StatusCode::FORBIDDEN);
	let challenge = challenge.expect("a 403 must carry a challenge");
	assert!(
		challenge.contains(r#"error="insufficient_scope""#),
		"{challenge}",
	);
}

/// A valid token carrying no scope claim authorises nothing and is
/// rejected with 403.
#[tokio::test]
async fn token_with_no_scope_is_forbidden() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = issuer.subject(PRINCIPAL).audience(RESOURCE).mint_id_token();
	let (status, _body, _) =
		post_with_authorization(auth_state(&issuer).await, Some(&format!("Bearer {token}"))).await;

	assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Seconds since the Unix epoch, for crafting a future `exp`.
fn now_unix() -> i64 {
	i64::try_from(
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.expect("system clock is after the epoch")
			.as_secs(),
	)
	.expect("the current time fits in an i64")
}

/// A resolver holding the introspection client secret under the
/// configured credential name.
fn resolver_with_secret() -> StaticResolver {
	let mut secrets = HashMap::new();
	secrets.insert(
		"introspection-secret".to_owned(),
		Secret::new("gateway-secret".to_owned()),
	);
	StaticResolver::new(secrets)
}

/// The `authentication` section configured to validate by introspection
/// against the fixture.
fn introspection_config(issuer: &MockIssuer) -> serde_json::Value {
	json!({
		"issuer": issuer.issuer(),
		"resource": RESOURCE,
		"principal_subjects": [PRINCIPAL],
		"validation": "introspection",
		"client_id": "gateway-client",
		"client_secret_credential": "introspection-secret",
		"server_scopes": { "gitlab": ["mcp:invoke:gitlab"] },
		"cors": { "allowed_origins": ["https://app.example.test"] },
	})
}

/// With the introspection strategy configured, an active token reaches
/// the handler with the same [`ValidatedClaims`] shape a JWT yields:
/// switching `validation` does not change what the handler sees.
#[tokio::test]
async fn introspection_strategy_reaches_handler_with_claims() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	issuer.set_introspection(
		"opaque-handler",
		json!({
			"active": true,
			"iss": issuer.issuer(),
			"sub": PRINCIPAL,
			"aud": RESOURCE,
			"exp": now_unix() + 3600,
			"scope": "mcp:invoke:gitlab",
		}),
	);

	let config: AuthenticationConfig = serde_json::from_value(introspection_config(&issuer))
		.expect("introspection config should deserialise");
	let state = Arc::new(
		build_auth_state(&config, &resolver_with_secret())
			.await
			.expect("introspection auth state should build"),
	);

	let (status, body, _) = post_with_authorization(state, Some("Bearer opaque-handler")).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(
		body, PRINCIPAL,
		"the handler should see the validated subject"
	);
}

/// A misconfigured `client_secret_credential` fails when the
/// authentication state is built at startup, not later at request time.
#[tokio::test]
async fn misconfigured_introspection_secret_fails_at_startup() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let config: AuthenticationConfig = serde_json::from_value(introspection_config(&issuer))
		.expect("introspection config should deserialise");

	// An empty resolver cannot resolve the named secret.
	let result = build_auth_state(&config, &StaticResolver::new(HashMap::new())).await;
	assert!(
		result.is_err(),
		"building the auth state must fail when the client secret cannot be resolved",
	);
}
