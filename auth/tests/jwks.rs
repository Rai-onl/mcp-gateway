//! Integration tests for the JWKS cache (issue #29), driven against
//! the `mockoidc-kit` fixture. The fixture's per-endpoint request
//! counter lets these tests assert exactly how many times the cache
//! reached the network.

use mcp_gateway_auth::jwks::JwksCache;
use mockoidc_kit::{Endpoint, MockIssuer, SigningAlgorithm, StartOptions};

/// Boot an ES256 issuer whose single key carries a known `kid`, so
/// tests can look the key up by name without first fetching the JWKS
/// themselves (which would pollute the request counter).
async fn issuer_with_kid(kid: &str) -> MockIssuer {
	MockIssuer::start_with(StartOptions::new(SigningAlgorithm::Es256).with_kid(kid))
		.await
		.expect("fixture should boot")
}

/// Once the JWKS is fetched, a second lookup of the same `kid` is
/// served from cache without a second network fetch.
#[tokio::test]
async fn serves_known_kid_from_cache_without_refetching() {
	let issuer = issuer_with_kid("test-key-1").await;
	let cache = JwksCache::new(format!("{}/jwks", issuer.issuer()));

	let first = cache
		.key_for_kid("test-key-1")
		.await
		.expect("lookup should succeed");
	assert!(first.is_some(), "the published key should be found");

	let second = cache
		.key_for_kid("test-key-1")
		.await
		.expect("lookup should succeed");
	assert!(second.is_some(), "the cached key should still be found");

	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		1,
		"a known kid must be served from cache without re-fetching",
	);
}

/// A lookup for a `kid` the cache has not seen triggers exactly one
/// JWKS refresh, which then finds the freshly rotated key. This is the
/// path the validator takes when a token is signed by a key minted
/// after the last fetch.
#[tokio::test]
async fn refreshes_when_kid_is_unknown() {
	let issuer = issuer_with_kid("test-key-1").await;
	let cache = JwksCache::new(format!("{}/jwks", issuer.issuer()));

	// Populate the cache with the original key.
	assert!(
		cache
			.key_for_kid("test-key-1")
			.await
			.expect("lookup should succeed")
			.is_some(),
	);
	assert_eq!(issuer.request_count(Endpoint::Jwks), 1);

	// Rotate in a key the cache has never seen.
	issuer
		.rotate_with_kid("test-key-2")
		.expect("rotation should succeed");

	let rotated = cache
		.key_for_kid("test-key-2")
		.await
		.expect("lookup should succeed");
	assert!(
		rotated.is_some(),
		"an unknown kid must trigger a refresh that finds the rotated key",
	);
	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		2,
		"exactly one refresh should occur for the unknown kid",
	);
}

/// A burst of concurrent lookups for the same unknown `kid` collapses to
/// a single JWKS fetch. The forced refresh is single-flighted, so an
/// unauthenticated caller (a `kid` is read before any signature check)
/// cannot fan one request out into many outbound fetches against the
/// authorisation server.
#[tokio::test]
async fn concurrent_unknown_kid_lookups_collapse_to_one_fetch() {
	let issuer = issuer_with_kid("test-key-1").await;
	let cache = std::sync::Arc::new(JwksCache::new(format!("{}/jwks", issuer.issuer())));

	let mut handles = Vec::new();
	for _ in 0..16 {
		let cache = std::sync::Arc::clone(&cache);
		handles.push(tokio::spawn(
			async move { cache.key_for_kid("never-published").await },
		));
	}
	for handle in handles {
		let found = handle
			.await
			.expect("task should not panic")
			.expect("lookup should succeed");
		assert!(found.is_none(), "an unpublished kid must not resolve to a key");
	}

	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		1,
		"concurrent unknown-kid lookups must share a single forced refresh",
	);
}

/// A repeated unknown `kid` does not re-fetch within the cooldown. The
/// first miss arms it, and subsequent unknown-kid lookups report the key
/// absent without touching the network, so a sequential flood of forged
/// `kid`s cannot drive unbounded outbound fetches.
#[tokio::test]
async fn repeated_unknown_kid_is_throttled_after_a_miss() {
	let issuer = issuer_with_kid("test-key-1").await;
	let cache = JwksCache::new(format!("{}/jwks", issuer.issuer()));

	for _ in 0..5 {
		let found = cache
			.key_for_kid("never-published")
			.await
			.expect("lookup should succeed");
		assert!(found.is_none());
	}

	assert_eq!(
		issuer.request_count(Endpoint::Jwks),
		1,
		"after the first miss, further unknown-kid lookups must be served \
		 from the cooldown without re-fetching",
	);
}
