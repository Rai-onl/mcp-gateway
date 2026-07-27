//! Integration tests for proactive background refresh of the JWKS
//! (the #31 daemon-mount follow-up), driven against the `mockoidc-kit`
//! fixture. The fixture's per-endpoint request counter lets these tests
//! prove that a proactive refresh populates the cache ahead of any lazy
//! refresh-on-unknown-`kid`, and that a failed refresh retains the
//! last-good keys.

use std::collections::HashMap;

use mcp_gateway_auth::jwks::JwksCache;
use mcp_gateway_auth::setup::build_auth_state;
use mcp_gateway_config::AuthenticationConfig;
use mcp_gateway_credentials::{Secret, StaticResolver};
use mockoidc_kit::{Endpoint, FaultResponse, MockIssuer, SigningAlgorithm, StartOptions};
use serde_json::json;

/// The resource URL the test gateway answers for.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// A principal the test gateway admits.
const PRINCIPAL: &str = "did:arai:example:alice";

/// Boot an ES256 issuer whose single key carries a known `kid`, so tests
/// can look the key up by name without first fetching the JWKS themselves
/// (which would pollute the request counter).
async fn issuer_with_kid(kid: &str) -> MockIssuer {
	MockIssuer::start_with(StartOptions::new(SigningAlgorithm::Es256).with_kid(kid))
		.await
		.expect("fixture should boot")
}

/// A proactive refresh fetches the current key set and populates the
/// cache, so a token signed by a key rotated in before the refresh is
/// then served from cache without the lazy refresh-on-unknown-`kid` path
/// reaching the network a second time.
#[tokio::test]
async fn refresh_populates_the_cache_ahead_of_a_lazy_lookup() {
	let issuer = issuer_with_kid("test-key-1").await;
	let cache = JwksCache::new(format!("{}/jwks", issuer.issuer()));

	// Warm the cache with the original key.
	assert!(
		cache
			.key_for_kid("test-key-1")
			.await
			.expect("lookup should succeed")
			.is_some(),
	);
	assert_eq!(issuer.request_count(Endpoint::Jwks), 1);

	// Rotate in a key the cache has never seen, then proactively refresh.
	issuer
		.rotate_with_kid("test-key-2")
		.expect("rotation should succeed");
	cache.refresh().await.expect("refresh should succeed");
	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		2,
		"the proactive refresh performs exactly one fetch",
	);

	// The rotated key is now served from the proactively refreshed cache:
	// the lookup finds it without a further fetch, so the lazy
	// refresh-on-unknown-kid path never runs.
	assert!(
		cache
			.key_for_kid("test-key-2")
			.await
			.expect("lookup should succeed")
			.is_some(),
		"the rotated key must be present after a proactive refresh",
	);
	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		2,
		"a proactively cached key must not trigger a further fetch",
	);
}

/// A refresh whose fetch fails retains the previously cached keys: the
/// cache keeps serving the last-good key set rather than emptying, so a
/// transient JWKS outage does not break validation between ticks.
#[tokio::test]
async fn refresh_failure_retains_the_last_good_keys() {
	let issuer = issuer_with_kid("test-key-1").await;
	let cache = JwksCache::new(format!("{}/jwks", issuer.issuer()));

	// Warm the cache, then make the JWKS endpoint fail.
	assert!(
		cache
			.key_for_kid("test-key-1")
			.await
			.expect("lookup should succeed")
			.is_some(),
	);
	issuer.fail(Endpoint::Jwks, FaultResponse::new(503));

	// The refresh fails, but the cached key set is retained.
	assert!(
		cache.refresh().await.is_err(),
		"a refresh against a failing endpoint must surface the error",
	);
	assert!(
		cache
			.key_for_kid("test-key-1")
			.await
			.expect("a retained key is served without a network call")
			.is_some(),
		"a failed refresh must keep serving the last-good keys",
	);
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

/// Build a JWT-validation authentication config pointed at the fixture.
fn jwt_config(issuer: &MockIssuer) -> AuthenticationConfig {
	serde_json::from_value(json!({
		"issuer": issuer.issuer(),
		"resource": RESOURCE,
		"principal_subjects": [PRINCIPAL],
		"cors": { "allowed_origins": ["https://app.example.test"] },
	}))
	.expect("jwt config should deserialise")
}

/// Build an introspection-validation authentication config pointed at the
/// fixture.
fn introspection_config(issuer: &MockIssuer) -> AuthenticationConfig {
	serde_json::from_value(json!({
		"issuer": issuer.issuer(),
		"resource": RESOURCE,
		"principal_subjects": [PRINCIPAL],
		"validation": "introspection",
		"client_id": "gateway-client",
		"client_secret_credential": "introspection-secret",
		"cors": { "allowed_origins": ["https://app.example.test"] },
	}))
	.expect("introspection config should deserialise")
}

/// Refreshing a JWT-strategy auth state proactively fetches the JWKS: the
/// validator's cache is empty after build (keys are fetched lazily), and
/// the refresh fills it, which the request counter observes.
#[tokio::test]
async fn refreshing_jwt_auth_state_fetches_the_jwks() {
	let issuer = issuer_with_kid("test-key-1").await;
	let auth = build_auth_state(&jwt_config(&issuer), &StaticResolver::default())
		.await
		.expect("jwt auth state should build against the fixture");

	// The JWKS is fetched lazily, so nothing has touched it at build time.
	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		0,
		"building the auth state must not eagerly fetch the JWKS",
	);

	auth.refresh_keys().await;
	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		1,
		"refreshing a JWT auth state must proactively fetch the JWKS",
	);
}

/// Refreshing an introspection-strategy auth state is a no-op: the
/// introspection validator holds no JWKS, so the refresh touches no
/// endpoint and does not error.
#[tokio::test]
async fn refreshing_introspection_auth_state_is_a_noop() {
	let issuer = issuer_with_kid("test-key-1").await;
	let auth = build_auth_state(&introspection_config(&issuer), &resolver_with_secret())
		.await
		.expect("introspection auth state should build against the fixture");

	auth.refresh_keys().await;
	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		0,
		"an introspection auth state has no JWKS to refresh",
	);
}
