//! Integration tests for inbound-authentication reload, rotation, and
//! request-entry snapshot semantics (issue #36).
//!
//! Reload rebuilds the validator from the (possibly changed) discovery
//! document, credential, and principal allowlist, then swaps it into the
//! daemon's [`AppState`] exactly as `SIGHUP` does in production through
//! `console::reload::ReloadHandle::rebuild_auth`. These tests drive that
//! swap directly, building a fresh [`AuthState`] with
//! [`build_auth_state`] and installing it with [`AppState::set_auth`]
//! (the same two calls the reload handler makes), then assert the
//! observable consequences against the running `mockoidc-kit` fixture.
//!
//! The auth state is built the production way, from the fixture's
//! discovery document, so the wiring under test is the wiring that ships.
//! The `control` feature on the fixture supplies key rotation, fault
//! injection, and introspection programming.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use axum::routing::get;
use mcp_gateway_auth::authorise::ScopePolicy;
use mcp_gateway_auth::jwks::JwksCache;
use mcp_gateway_auth::middleware::{AuthState, authenticate};
use mcp_gateway_auth::setup::build_auth_state;
use mcp_gateway_auth::strategy::Validator;
use mcp_gateway_auth::validator::JwtValidator;
use mcp_gateway_config::{AuthenticationConfig, GatewayConfig};
use mcp_gateway_credentials::{Secret, StaticResolver};
use mcp_gateway_daemon::{AppState, build_app};
use mockoidc_kit::{MockIssuer, SigningAlgorithm};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// The resource URL the test gateway answers for, and the audience every
/// minted token binds to.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// An origin the test gateway's CORS policy admits. Present only because
/// the configuration shape requires it; these tests do not exercise CORS.
const ALLOWED_ORIGIN: &str = "https://app.example.test";

/// A principal subject used across the admit and deny cases.
const ALICE: &str = "did:arai:example:alice";

/// A second principal, used by the narrow and broaden allowlist cases.
const BOB: &str = "did:arai:example:bob";

/// The opaque bearer the introspection cache-flush case programmes at the
/// fixture and replays across a reload.
const OPAQUE_TOKEN: &str = "opaque-reload-token";

/// Build the JSON for a JWT-validation `authentication` section pointed at
/// the running fixture and admitting exactly `principals`.
///
/// The fixture binds to an ephemeral port, so its issuer URL is only known
/// once it is running; it is read here and fed into the section the same
/// way the daemon reads it from a configuration file.
fn jwt_section_value(issuer: &MockIssuer, principals: &[&str]) -> Value {
	json!({
		"issuer": issuer.issuer(),
		"resource": RESOURCE,
		"principal_subjects": principals,
		"cors": { "allowed_origins": [ALLOWED_ORIGIN] },
	})
}

/// Build the JSON for an introspection-validation `authentication`
/// section: the JWT shape plus the OAuth client identity the gateway
/// presents at the introspection endpoint.
fn introspection_section_value(issuer: &MockIssuer, principals: &[&str]) -> Value {
	let mut section = jwt_section_value(issuer, principals);
	section["validation"] = json!("introspection");
	section["client_id"] = json!("gateway-client");
	section["client_secret_credential"] = json!("introspection-secret");
	section
}

/// A resolver holding the introspection client secret under the
/// credential name the introspection section references.
fn resolver_with_secret() -> StaticResolver {
	let mut secrets = HashMap::new();
	secrets.insert(
		"introspection-secret".to_owned(),
		Secret::new("gateway-secret".to_owned()),
	);
	StaticResolver::new(secrets)
}

/// Build an [`AppState`] whose routing reflects `section`: with an
/// `authentication` section present, `build_app` mounts the server-card
/// endpoint behind the authentication layer. The validator itself is
/// installed separately with [`AppState::set_auth`], mirroring the daemon,
/// which builds routing once at startup and swaps the validator on reload.
fn state_with_routing(section: &Value) -> Arc<AppState> {
	let config: GatewayConfig =
		serde_json::from_value(json!({ "servers": {}, "authentication": section }))
			.expect("gateway config should deserialise");
	Arc::new(AppState::new(config, None).expect("app state should build"))
}

/// Build the JWT auth state the production way: fetch the fixture's
/// discovery document, derive the JWKS endpoint, assemble the validator
/// admitting `principals`. This is the call `rebuild_auth` makes on
/// reload, so invoking it again is a faithful reload of the validator.
async fn build_jwt_auth(issuer: &MockIssuer, principals: &[&str]) -> Arc<AuthState> {
	let section: AuthenticationConfig =
		serde_json::from_value(jwt_section_value(issuer, principals))
			.expect("authentication section should deserialise");
	Arc::new(
		build_auth_state(&section, &StaticResolver::default())
			.await
			.expect("jwt auth state should build against the fixture"),
	)
}

/// Build the introspection auth state the production way, resolving the
/// client secret through the credential chain. A fresh build carries an
/// empty response cache, which is what makes reload flush prior decisions.
async fn build_introspection_auth(issuer: &MockIssuer, principals: &[&str]) -> Arc<AuthState> {
	let section: AuthenticationConfig =
		serde_json::from_value(introspection_section_value(issuer, principals))
			.expect("introspection section should deserialise");
	Arc::new(
		build_auth_state(&section, &resolver_with_secret())
			.await
			.expect("introspection auth state should build against the fixture"),
	)
}

/// A bearer token for `subject`, audience-bound to the resource and
/// carrying the gitlab invoke scope. The token is signed by the fixture's
/// current key, so minting after a rotation yields a token under the new
/// `kid`.
fn token_for(issuer: &MockIssuer, subject: &str) -> String {
	issuer
		.subject(subject)
		.audience(RESOURCE)
		.claim("scope", "mcp:invoke:gitlab")
		.mint_id_token()
}

/// Issue `GET /.well-known/mcp-server-card` through `app` with an optional
/// bearer token and return the response status and `WWW-Authenticate`
/// challenge.
///
/// The server-card endpoint is protected when authentication is configured
/// but carries no per-server scope requirement, so it isolates the
/// authentication and principal-admission decision the reload cases turn
/// on from the separate scope-authorisation seam.
async fn card_status(app: Router, bearer: Option<&str>) -> (StatusCode, Option<String>) {
	let mut builder = Request::builder()
		.method("GET")
		.uri("/.well-known/mcp-server-card");
	if let Some(token) = bearer {
		builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let response = app
		.oneshot(builder.body(Body::empty()).expect("request should build"))
		.await
		.expect("app should respond");
	let status = response.status();
	let challenge = response
		.headers()
		.get(header::WWW_AUTHENTICATE)
		.and_then(|value| value.to_str().ok())
		.map(str::to_owned);
	(status, challenge)
}

/// Seconds since the Unix epoch, for crafting an introspection `exp` in
/// the future.
fn now_unix() -> i64 {
	i64::try_from(
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.expect("system clock is after the epoch")
			.as_secs(),
	)
	.expect("the current time fits in an i64")
}

/// Reload re-fetches discovery and the JWKS: a token signed by a key the
/// issuer rotated in between reloads validates afterwards.
///
/// The validator is rebuilt from scratch on reload, so it carries a fresh
/// JWKS cache that fetches the post-rotation key set on first lookup.
#[tokio::test]
async fn reload_refetches_jwks_so_a_new_key_validates() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let state = state_with_routing(&jwt_section_value(&issuer, &[ALICE]));
	state.set_auth(build_jwt_auth(&issuer, &[ALICE]).await);
	let app = build_app(&state);

	// The issuer rotates to a new signing key, then reload rebuilds the
	// validator against the refreshed discovery and JWKS.
	issuer.rotate().expect("rotate to a new signing key");
	state.set_auth(build_jwt_auth(&issuer, &[ALICE]).await);

	// A token signed by the new current key validates.
	let token = token_for(&issuer, ALICE);
	let (status, _) = card_status(app, Some(&token)).await;
	assert_eq!(
		status,
		StatusCode::OK,
		"a token from the post-rotation key must validate after reload",
	);
}

/// Without any reload, a token signed by a freshly-rotated key still
/// validates: an unknown `kid` triggers a single JWKS refresh, and a
/// subsequent token under that `kid` is then served from the warmed cache.
#[tokio::test]
async fn unknown_kid_triggers_jwks_refresh_then_serves_from_cache() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let state = state_with_routing(&jwt_section_value(&issuer, &[ALICE]));
	state.set_auth(build_jwt_auth(&issuer, &[ALICE]).await);
	let app = build_app(&state);

	// First token warms the cache with the original key.
	let first = token_for(&issuer, ALICE);
	assert_eq!(
		card_status(app.clone(), Some(&first)).await.0,
		StatusCode::OK,
	);

	// Rotate, then a token under the new kid is unknown to the cache and
	// drives a single refresh before validating.
	issuer.rotate().expect("rotate to a new signing key");
	let second = token_for(&issuer, ALICE);
	assert_eq!(
		card_status(app.clone(), Some(&second)).await.0,
		StatusCode::OK,
		"a token under a newly rotated kid must validate via a JWKS refresh",
	);

	// The retiring key is still published during the overlap, so the
	// first token continues to validate, now from the warmed cache.
	assert_eq!(
		card_status(app, Some(&first)).await.0,
		StatusCode::OK,
		"a token under the retiring kid must still validate during the overlap",
	);
}

/// Narrowing the principal allowlist on reload causes a previously-valid
/// token whose `sub` is no longer admitted to be rejected on the next
/// request, with the authentic-but-unauthorised 403 rather than a 401.
#[tokio::test]
async fn narrowing_principals_rejects_a_dropped_subject() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let state = state_with_routing(&jwt_section_value(&issuer, &[ALICE, BOB]));
	state.set_auth(build_jwt_auth(&issuer, &[ALICE, BOB]).await);
	let app = build_app(&state);

	let alice = token_for(&issuer, ALICE);
	assert_eq!(
		card_status(app.clone(), Some(&alice)).await.0,
		StatusCode::OK,
		"alice is admitted before the allowlist narrows",
	);

	// Reload narrows the allowlist to bob only.
	state.set_auth(build_jwt_auth(&issuer, &[BOB]).await);

	let (status, challenge) = card_status(app, Some(&alice)).await;
	assert_eq!(
		status,
		StatusCode::FORBIDDEN,
		"alice's token must be rejected once she is no longer an admitted principal",
	);
	let challenge = challenge.expect("a 403 must carry a challenge");
	assert!(
		challenge.contains(r#"error="insufficient_scope""#),
		"an unknown principal renders as insufficient_scope: {challenge}",
	);
}

/// Broadening the principal allowlist on reload admits a new principal
/// without any process restart: a token rejected before the reload
/// validates afterwards.
#[tokio::test]
async fn broadening_principals_admits_a_new_subject() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let state = state_with_routing(&jwt_section_value(&issuer, &[ALICE]));
	state.set_auth(build_jwt_auth(&issuer, &[ALICE]).await);
	let app = build_app(&state);

	let bob = token_for(&issuer, BOB);
	assert_eq!(
		card_status(app.clone(), Some(&bob)).await.0,
		StatusCode::FORBIDDEN,
		"bob is not admitted before the allowlist broadens",
	);

	// Reload broadens the allowlist to include bob.
	state.set_auth(build_jwt_auth(&issuer, &[ALICE, BOB]).await);

	assert_eq!(
		card_status(app, Some(&bob)).await.0,
		StatusCode::OK,
		"bob's token must validate once he is an admitted principal",
	);
}

/// The middleware gate for the request-entry-snapshot harness. It mirrors
/// the daemon's own `require_authentication`: load the current auth state
/// once and hand a borrow to [`authenticate`].
async fn gate(State(state): State<Arc<AuthState>>, request: Request, next: Next) -> Response {
	authenticate(&state, request, next).await
}

/// Drive a bearer token through a one-route app guarded by `auth`, using a
/// route with no `/servers/` prefix so the per-server scope seam does not
/// apply and the status reflects authentication and principal admission
/// alone. Returns the response status.
async fn protected_through(auth: Arc<AuthState>, bearer: &str) -> StatusCode {
	let app = Router::new()
		.route("/protected", get(|| async { "ok" }))
		.layer(from_fn_with_state(auth, gate));
	let request = Request::builder()
		.method("GET")
		.uri("/protected")
		.header(header::AUTHORIZATION, format!("Bearer {bearer}"))
		.body(Body::empty())
		.expect("request should build");
	app.oneshot(request)
		.await
		.expect("app should respond")
		.status()
}

/// A request takes its auth state once at entry and uses that snapshot for
/// its whole lifetime: a reload that lands mid-request does not change the
/// validator the request was admitted by.
///
/// The daemon loads the auth state once in `require_authentication` and
/// holds the `Arc` across the request; this test reproduces that by
/// capturing the snapshot, swapping a narrower validator into the shared
/// state, and showing the captured snapshot still admits the original
/// principal while a freshly-loaded validator rejects it.
#[tokio::test]
async fn request_uses_its_entry_time_validator_across_a_reload() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let state = state_with_routing(&jwt_section_value(&issuer, &[ALICE]));
	state.set_auth(build_jwt_auth(&issuer, &[ALICE]).await);

	// The snapshot a request takes at entry, while alice is admitted.
	let entry_snapshot = state.auth().expect("auth state is installed");

	// A reload lands, narrowing the allowlist to bob only.
	state.set_auth(build_jwt_auth(&issuer, &[BOB]).await);

	let alice = token_for(&issuer, ALICE);
	assert_eq!(
		protected_through(entry_snapshot, &alice).await,
		StatusCode::OK,
		"the in-flight request must complete against its entry-time validator",
	);
	let current = state.auth().expect("auth state is installed");
	assert_eq!(
		protected_through(current, &alice).await,
		StatusCode::FORBIDDEN,
		"a request entering after the reload sees the narrowed validator",
	);
}

/// Reload flushes the introspection response cache entirely: a token whose
/// previously-cached positive would still be valid by TTL is
/// re-introspected against the live endpoint, so a revocation that lands
/// between caching and reload takes effect immediately on reload.
#[tokio::test]
async fn reload_flushes_the_introspection_cache() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	// The token is active at the authorisation server.
	issuer.set_introspection(
		OPAQUE_TOKEN,
		json!({
			"active": true,
			"iss": issuer.issuer(),
			"sub": ALICE,
			"aud": RESOURCE,
			"exp": now_unix() + 3600,
			"scope": "mcp:invoke:gitlab",
		}),
	);

	let state = state_with_routing(&introspection_section_value(&issuer, &[ALICE]));
	state.set_auth(build_introspection_auth(&issuer, &[ALICE]).await);
	let app = build_app(&state);

	// First request introspects and caches the positive result.
	assert_eq!(
		card_status(app.clone(), Some(OPAQUE_TOKEN)).await.0,
		StatusCode::OK,
		"the active token validates and its positive result is cached",
	);

	// The token is revoked at the authorisation server. Within the cache
	// TTL (30s default) and with no reload, the cached positive is still
	// served, proving the cache is in effect.
	issuer.set_introspection(OPAQUE_TOKEN, json!({ "active": false }));
	assert_eq!(
		card_status(app.clone(), Some(OPAQUE_TOKEN)).await.0,
		StatusCode::OK,
		"the cached positive is served before reload, within its TTL",
	);

	// Reload rebuilds the validator with an empty cache, forcing a fresh
	// introspection that now sees the revocation.
	state.set_auth(build_introspection_auth(&issuer, &[ALICE]).await);
	let (status, challenge) = card_status(app, Some(OPAQUE_TOKEN)).await;
	assert_eq!(
		status,
		StatusCode::UNAUTHORIZED,
		"after reload the revoked token is re-introspected and rejected",
	);
	let challenge = challenge.expect("a 401 must carry a challenge");
	assert!(
		challenge.contains(r#"error="invalid_token""#),
		"an inactive token renders as invalid_token: {challenge}",
	);
}

/// A static `authentication` section with a placeholder issuer, for the
/// no-leak stress case. Building [`AppState`] does not fetch discovery, so
/// the issuer URL need not be reachable.
fn static_section() -> Value {
	json!({
		"issuer": "https://issuer.example.test",
		"resource": RESOURCE,
		"principal_subjects": [ALICE],
		"cors": { "allowed_origins": [ALLOWED_ORIGIN] },
	})
}

/// Build a validator cheaply, without any network round trip: the JWKS
/// cache is constructed empty and never fetched, since the stress case
/// never validates a token through it. Used only to exercise the swap
/// machinery's drop semantics.
fn cheap_auth(principal: &str) -> Arc<AuthState> {
	let mut subjects = HashSet::new();
	subjects.insert(principal.to_owned());
	let validator = JwtValidator::new(
		"https://issuer.example.test".to_owned(),
		RESOURCE.to_owned(),
		subjects,
		Duration::from_secs(30),
		JwksCache::new("https://issuer.example.test/jwks".to_owned()),
	);
	Arc::new(AuthState::new(
		Validator::Jwt(validator),
		RESOURCE,
		format!("{RESOURCE}/.well-known/oauth-protected-resource"),
		ScopePolicy::new(&HashMap::new()),
	))
}

/// Repeated reloads do not retain prior auth states: after a thousand swap
/// cycles, the validator installed before them all has been dropped.
///
/// A weak reference to the first validator must be dead once later swaps
/// have replaced it: a deterministic check on the [`arc_swap`] drop
/// semantics that stands in for the issue's memory-growth sanity test
/// without depending on a flaky resident-set measurement.
#[tokio::test]
async fn reload_cycles_do_not_retain_previous_auth_states() {
	let state = state_with_routing(&static_section());

	let first = cheap_auth(ALICE);
	let first_weak = Arc::downgrade(&first);
	state.set_auth(first);

	for index in 0..1000 {
		state.set_auth(cheap_auth(&format!("did:arai:example:p{index}")));
	}

	assert!(
		first_weak.upgrade().is_none(),
		"an auth state from an earlier reload was retained across 1000 cycles",
	);
}
