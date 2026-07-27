//! Integration tests for token introspection (issue #35), driven
//! against the `mockoidc-kit` fixture's `/introspect` endpoint and its
//! response-arming controls.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mcp_gateway_auth::introspection::{IntrospectionPolicy, IntrospectionValidator, OutagePolicy};
use mcp_gateway_auth::validator::{ClaimChecks, FailureReason};
use mcp_gateway_credentials::Secret;
use mockoidc_kit::{Endpoint, FaultResponse, MockIssuer, SigningAlgorithm};
use serde_json::json;

/// The resource URL the test gateway answers for.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// A principal the test gateway admits.
const PRINCIPAL: &str = "did:arai:example:alice";

/// Seconds since the Unix epoch, for crafting an `exp` in the future.
fn now_seconds() -> i64 {
	i64::try_from(
		SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.expect("system clock is after the epoch")
			.as_secs(),
	)
	.expect("the current time fits in an i64")
}

/// Build an introspection validator pointed at the fixture's endpoint,
/// admitting the single test principal and resource, under the given
/// cache and outage policy.
fn validator(issuer: &MockIssuer, policy: IntrospectionPolicy) -> IntrospectionValidator {
	IntrospectionValidator::new(
		format!("{}/introspect", issuer.issuer()),
		"gateway-client".to_owned(),
		Secret::new("gateway-secret".to_owned()),
		ClaimChecks::new(
			issuer.issuer(),
			RESOURCE.to_owned(),
			HashSet::from([PRINCIPAL.to_owned()]),
			Duration::from_secs(30),
		),
		policy,
	)
}

/// A fail-closed policy with a half-minute positive cache and no stale
/// serving: the defaults the configuration documents.
fn default_policy() -> IntrospectionPolicy {
	IntrospectionPolicy {
		cache_ttl: Duration::from_secs(30),
		outage: OutagePolicy::FailClosed,
		max_stale: Duration::ZERO,
	}
}

/// Arm the fixture to report `token` active with valid claims and a
/// far-future expiry.
fn arm_active(issuer: &MockIssuer, token: &str) {
	issuer.set_introspection(
		token,
		json!({
			"active": true,
			"iss": issuer.issuer(),
			"sub": PRINCIPAL,
			"aud": RESOURCE,
			"exp": now_seconds() + 3600,
			"scope": "mcp:invoke:gitlab",
		}),
	);
}

/// An `active: true` response carrying valid claims authenticates the
/// request, and the claims reach the caller.
#[tokio::test]
async fn active_token_authenticates() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	issuer.set_introspection(
		"opaque-active",
		json!({
			"active": true,
			"iss": issuer.issuer(),
			"sub": PRINCIPAL,
			"aud": RESOURCE,
			"exp": now_seconds() + 3600,
			"scope": "mcp:invoke:gitlab",
		}),
	);

	let claims = validator(&issuer, default_policy())
		.validate("Bearer opaque-active")
		.await
		.expect("an active token with valid claims should authenticate");
	assert_eq!(claims.subject(), PRINCIPAL);
	assert!(claims.scopes().contains("mcp:invoke:gitlab"));
}

/// An `active: false` response rejects the token as inactive, which the
/// middleware renders as `invalid_token`.
#[tokio::test]
async fn inactive_token_is_rejected() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	issuer.set_introspection("opaque-revoked", json!({ "active": false }));

	let reason = validator(&issuer, default_policy())
		.validate("Bearer opaque-revoked")
		.await
		.expect_err("an inactive token must be rejected");
	assert_eq!(reason, FailureReason::Inactive);
}

/// The same claim checks as JWT validation apply to an introspection
/// response: an active token bound to the wrong audience is rejected.
#[tokio::test]
async fn active_token_with_wrong_audience_is_rejected() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	issuer.set_introspection(
		"opaque-wrong-aud",
		json!({
			"active": true,
			"iss": issuer.issuer(),
			"sub": PRINCIPAL,
			"aud": "https://someone-else.example.test",
			"exp": now_seconds() + 3600,
		}),
	);

	let reason = validator(&issuer, default_policy())
		.validate("Bearer opaque-wrong-aud")
		.await
		.expect_err("a wrong audience must be rejected");
	assert_eq!(reason, FailureReason::InvalidAudience);
}

/// A second request for the same token within the cache window is
/// served from cache, with no second network round-trip.
#[tokio::test]
async fn cache_hit_avoids_second_introspection() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	arm_active(&issuer, "opaque-cached");
	let validator = validator(&issuer, default_policy());

	assert!(validator.validate("Bearer opaque-cached").await.is_ok());
	assert!(validator.validate("Bearer opaque-cached").await.is_ok());

	assert_eq!(
		issuer.request_count(Endpoint::Introspect),
		1,
		"the second request must be served from cache",
	);
}

/// Once a cached entry is past its time-to-live, the token is
/// introspected afresh rather than served stale.
#[tokio::test]
async fn entry_past_ttl_is_reintrospected() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	arm_active(&issuer, "opaque-ttl");
	let policy = IntrospectionPolicy {
		cache_ttl: Duration::ZERO,
		outage: OutagePolicy::FailClosed,
		max_stale: Duration::ZERO,
	};
	let validator = validator(&issuer, policy);

	assert!(validator.validate("Bearer opaque-ttl").await.is_ok());
	assert!(validator.validate("Bearer opaque-ttl").await.is_ok());

	assert_eq!(
		issuer.request_count(Endpoint::Introspect),
		2,
		"a past-TTL entry must be re-introspected",
	);
}

/// Under the fail-closed policy, an introspection endpoint returning
/// 503 rejects the request.
#[tokio::test]
async fn fail_closed_rejects_on_outage() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	issuer.fail(Endpoint::Introspect, FaultResponse::new(503));

	let reason = validator(&issuer, default_policy())
		.validate("Bearer opaque-unanswerable")
		.await
		.expect_err("a fail-closed outage must reject");
	assert_eq!(reason, FailureReason::Inactive);
}

/// Under the serve-cached policy, a positive outcome still inside the
/// staleness bound is served while the endpoint is down.
#[tokio::test]
async fn serve_cached_serves_stale_positive_during_outage() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	arm_active(&issuer, "opaque-stale");
	let policy = IntrospectionPolicy {
		cache_ttl: Duration::ZERO,
		outage: OutagePolicy::ServeCached,
		max_stale: Duration::from_mins(1),
	};
	let validator = validator(&issuer, policy);

	// Prime the cache with a positive outcome, then take the endpoint
	// down.
	assert!(validator.validate("Bearer opaque-stale").await.is_ok());
	issuer.fail(Endpoint::Introspect, FaultResponse::new(503));

	assert!(
		validator.validate("Bearer opaque-stale").await.is_ok(),
		"a stale positive outcome must be served during an outage",
	);
}

/// Under the serve-cached policy with no staleness allowance, an
/// outage rejects rather than serving the cached outcome.
#[tokio::test]
async fn serve_cached_rejects_when_stale_window_exhausted() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	arm_active(&issuer, "opaque-exhausted");
	let policy = IntrospectionPolicy {
		cache_ttl: Duration::ZERO,
		outage: OutagePolicy::ServeCached,
		max_stale: Duration::ZERO,
	};
	let validator = validator(&issuer, policy);

	assert!(validator.validate("Bearer opaque-exhausted").await.is_ok());
	issuer.fail(Endpoint::Introspect, FaultResponse::new(503));

	let reason = validator
		.validate("Bearer opaque-exhausted")
		.await
		.expect_err("past the staleness bound the request must be rejected");
	assert_eq!(reason, FailureReason::Inactive);
}

/// Under serve-cached, a token whose own `exp` has passed is still
/// rejected during an outage. The staleness window serves a cached
/// positive when the endpoint cannot answer, but the per-request claim
/// check still enforces expiry, so an expired token is never resurrected
/// from cache: the availability tradeoff covers revocation latency, not
/// serving tokens past their own lifetime.
#[tokio::test]
async fn serve_cached_does_not_serve_an_expired_token() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	// The endpoint reports the token active, but its claims are already
	// expired (an hour ago).
	issuer.set_introspection(
		"opaque-expired",
		json!({
			"active": true,
			"iss": issuer.issuer(),
			"sub": PRINCIPAL,
			"aud": RESOURCE,
			"exp": now_seconds() - 3600,
			"scope": "mcp:invoke:gitlab",
		}),
	);
	// No fresh window, so the second call always re-introspects and, on
	// the outage, falls to the serve-cached path.
	let policy = IntrospectionPolicy {
		cache_ttl: Duration::ZERO,
		outage: OutagePolicy::ServeCached,
		max_stale: Duration::from_mins(5),
	};
	let validator = validator(&issuer, policy);

	// The first call introspects, caches the active-but-expired outcome,
	// and rejects it for being expired.
	let first = validator
		.validate("Bearer opaque-expired")
		.await
		.expect_err("an expired token is rejected even when introspection reports it active");
	assert_eq!(first, FailureReason::Expired);

	// The endpoint goes down. Serve-cached would serve the cached
	// positive, but the expiry check still rejects it.
	issuer.fail(Endpoint::Introspect, FaultResponse::new(503));
	let second = validator
		.validate("Bearer opaque-expired")
		.await
		.expect_err("serve-cached must not resurrect a token past its own expiry");
	assert_eq!(second, FailureReason::Expired);
}
