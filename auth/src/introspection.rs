//! RFC 7662 token introspection.
//!
//! For deployments issuing opaque (reference) tokens, or needing
//! sub-token-lifetime revocation, the gateway validates a token by
//! asking the authorisation server whether it is active rather than
//! verifying a signature locally. The introspection response carries
//! the same claims a JWT would, validated through the shared
//! [`check_claims`] so both strategies reach the same contract.
//!
//! Responses are cached by token hash for a bounded time so a busy
//! token does not introspect on every request, and an outage policy
//! governs what happens when the endpoint cannot answer.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use mcp_gateway_credentials::Secret;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::claims::ValidatedClaims;
use crate::validator::{
	Audience, ClaimChecks, FailureReason, RawClaims, bearer_token, check_claims,
};

/// How long a negative (`active: false`) outcome is cached. Short and
/// fixed: a token reported inactive is unlikely to come back, but
/// caching the answer briefly absorbs a burst of replays without
/// re-introspecting each one.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// The default bound on cached entries, evicting the oldest when full
/// so the cache cannot grow without limit under a flood of distinct
/// tokens.
const DEFAULT_CACHE_CAPACITY: usize = 4096;

/// Behaviour when the introspection endpoint cannot answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutagePolicy {
	/// Reject the request: an endpoint that cannot answer must not let
	/// a token through.
	FailClosed,
	/// Serve a cached positive outcome past its time-to-live, up to the
	/// configured staleness bound, then reject.
	ServeCached,
}

/// The cache and outage settings for introspection.
#[derive(Debug, Clone)]
pub struct IntrospectionPolicy {
	/// How long a positive outcome is served from cache.
	pub cache_ttl: Duration,
	/// What to do when the endpoint cannot answer.
	pub outage: OutagePolicy,
	/// How far past `cache_ttl` a positive outcome may be served under
	/// [`OutagePolicy::ServeCached`].
	pub max_stale: Duration,
}

/// Validates opaque tokens against the authorisation server's RFC 7662
/// introspection endpoint, with response caching and an outage policy.
pub struct IntrospectionValidator {
	/// HTTP client used for the introspection call.
	http: reqwest::Client,
	/// The RFC 7662 introspection endpoint URL.
	introspection_endpoint: String,
	/// The OAuth client identifier the gateway authenticates with.
	client_id: String,
	/// The resolved client secret the gateway authenticates with, held
	/// wrapped so it is zeroised on drop and kept out of any `Debug`
	/// output. It is exposed only at the point the introspection request
	/// is signed.
	client_secret: Secret,
	/// The issuer, resource, principal, and skew checks applied to an
	/// active token's claims.
	checks: ClaimChecks,
	/// The cache and outage settings.
	policy: IntrospectionPolicy,
	/// The response cache, keyed by token hash.
	cache: IntrospectionCache,
}

impl IntrospectionValidator {
	/// Construct an introspection validator.
	#[must_use]
	pub fn new(
		introspection_endpoint: String,
		client_id: String,
		client_secret: Secret,
		checks: ClaimChecks,
		policy: IntrospectionPolicy,
	) -> Self {
		Self {
			http: crate::trust::default_http_client(),
			introspection_endpoint,
			client_id,
			client_secret,
			checks,
			policy,
			cache: IntrospectionCache::new(DEFAULT_CACHE_CAPACITY),
		}
	}

	/// Replace the HTTP client used for the introspection call.
	///
	/// The setup path installs the authorisation-server-pinned client
	/// here when SPKI pins are configured, so the introspection call is
	/// protected by the same pins as the discovery fetch rather than
	/// trusting the system certificate store.
	#[must_use]
	pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
		self.http = http;
		self
	}

	/// Validate the token carried in an `Authorization` header value.
	///
	/// A fresh cached outcome is served without a network call.
	/// Otherwise the gateway introspects, caches the outcome, and
	/// applies it. When the endpoint cannot answer, the outage policy
	/// decides: fail closed, or serve a still-acceptable stale positive
	/// outcome.
	///
	/// # Errors
	///
	/// Returns [`FailureReason::Inactive`] for an inactive token or an
	/// unanswerable endpoint under a fail-closed policy,
	/// [`FailureReason::MalformedToken`] for an unusable response, and
	/// any claim [`FailureReason`] from [`check_claims`].
	pub async fn validate(&self, authorization: &str) -> Result<ValidatedClaims, FailureReason> {
		let token = bearer_token(authorization)?;
		let key = token_key(token);

		if let Some((outcome, age)) = self.cache.lookup(&key)
			&& self.is_fresh(&outcome, age)
		{
			return self.finish(outcome);
		}

		match self.introspect(token).await {
			Ok(outcome) => {
				self.cache.insert(key, outcome.clone());
				self.finish(outcome)
			}
			Err(IntrospectError::Malformed) => Err(FailureReason::MalformedToken),
			Err(IntrospectError::Outage) => self.on_outage(&key),
		}
	}

	/// Discard every cached outcome. Called on reload so a rotated
	/// credential or policy does not keep serving stale decisions.
	pub fn flush(&self) {
		self.cache.flush();
	}

	/// Whether a cached outcome is still within its time-to-live: the
	/// configured TTL for a positive outcome, the fixed short TTL for a
	/// negative one.
	fn is_fresh(&self, outcome: &Outcome, age: Duration) -> bool {
		match outcome {
			Outcome::Active(_) => age < self.policy.cache_ttl,
			Outcome::Inactive => age < NEGATIVE_TTL,
		}
	}

	/// Turn a cached or fresh outcome into a validation result.
	fn finish(&self, outcome: Outcome) -> Result<ValidatedClaims, FailureReason> {
		match outcome {
			Outcome::Active(claims) => {
				check_claims(claims, &self.checks, crate::validator::now_unix_seconds())
			}
			Outcome::Inactive => Err(FailureReason::Inactive),
		}
	}

	/// Resolve a request whose introspection call could not be
	/// answered. Under [`OutagePolicy::ServeCached`] a positive outcome
	/// still within the staleness bound is served; otherwise the
	/// request fails closed.
	fn on_outage(&self, key: &[u8; 32]) -> Result<ValidatedClaims, FailureReason> {
		if self.policy.outage == OutagePolicy::ServeCached
			&& let Some((Outcome::Active(claims), age)) = self.cache.lookup(key)
			&& age <= self.policy.cache_ttl + self.policy.max_stale
		{
			return self.finish(Outcome::Active(claims));
		}
		Err(FailureReason::Inactive)
	}

	/// Call the introspection endpoint and classify the response.
	async fn introspect(&self, token: &str) -> Result<Outcome, IntrospectError> {
		// The body is a single `token` form parameter (RFC 7662 §2.1).
		// Bearer tokens are URL-safe (a JWT is base64url with dots; an
		// opaque reference token is drawn from an unreserved alphabet),
		// so no percent-encoding of the value is needed.
		let response = self
			.http
			.post(&self.introspection_endpoint)
			.basic_auth(&self.client_id, Some(self.client_secret.expose()))
			.header(
				reqwest::header::CONTENT_TYPE,
				"application/x-www-form-urlencoded",
			)
			.body(format!("token={token}"))
			.send()
			.await
			.map_err(|_| IntrospectError::Outage)?;

		if response.status().is_server_error() {
			return Err(IntrospectError::Outage);
		}

		let introspection: IntrospectionResponse = response
			.json()
			.await
			.map_err(|_| IntrospectError::Malformed)?;
		if !introspection.active {
			return Ok(Outcome::Inactive);
		}
		introspection
			.into_claims()
			.map(Outcome::Active)
			.map_err(|_| IntrospectError::Malformed)
	}
}

/// The classified result of an introspection call, the value cached
/// per token.
#[derive(Clone)]
enum Outcome {
	/// The token is active; the carried claims are validated per
	/// request.
	Active(RawClaims),
	/// The authorisation server reported the token inactive.
	Inactive,
}

/// Why an introspection call did not yield a usable outcome.
enum IntrospectError {
	/// The endpoint could not be reached or returned a server error.
	/// Subject to the outage policy.
	Outage,
	/// The endpoint answered, but not with a usable introspection
	/// document. Always a hard reject.
	Malformed,
}

/// Hash a token into a fixed-size cache key, so raw token bytes are
/// never stored.
fn token_key(token: &str) -> [u8; 32] {
	Sha256::digest(token.as_bytes()).into()
}

/// A bounded cache of introspection outcomes keyed by token hash.
struct IntrospectionCache {
	/// The cached entries, behind a mutex; the guard is never held
	/// across an `await`.
	entries: Mutex<HashMap<[u8; 32], CacheEntry>>,
	/// The maximum number of entries before the oldest is evicted.
	capacity: usize,
}

/// A cached outcome together with the instant it was stored, against
/// which its age is measured.
struct CacheEntry {
	/// The cached introspection outcome.
	outcome: Outcome,
	/// When the outcome was cached.
	cached_at: Instant,
}

impl IntrospectionCache {
	/// Construct an empty cache bounded to `capacity` entries.
	fn new(capacity: usize) -> Self {
		Self {
			entries: Mutex::new(HashMap::new()),
			capacity,
		}
	}

	/// Return the cached outcome for `key` and its age, if present.
	fn lookup(&self, key: &[u8; 32]) -> Option<(Outcome, Duration)> {
		let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
		entries
			.get(key)
			.map(|entry| (entry.outcome.clone(), entry.cached_at.elapsed()))
	}

	/// Insert an outcome, evicting the oldest entry first when the
	/// cache is at capacity.
	fn insert(&self, key: [u8; 32], outcome: Outcome) {
		let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
		if entries.len() >= self.capacity
			&& !entries.contains_key(&key)
			&& let Some(oldest) = entries
				.iter()
				.min_by_key(|(_, entry)| entry.cached_at)
				.map(|(oldest_key, _)| *oldest_key)
		{
			entries.remove(&oldest);
		}
		entries.insert(
			key,
			CacheEntry {
				outcome,
				cached_at: Instant::now(),
			},
		);
	}

	/// Discard every cached entry.
	fn flush(&self) {
		self.entries
			.lock()
			.unwrap_or_else(PoisonError::into_inner)
			.clear();
	}

	/// The number of cached entries. Used by tests to assert eviction
	/// and flush.
	#[cfg(test)]
	fn len(&self) -> usize {
		self.entries
			.lock()
			.unwrap_or_else(PoisonError::into_inner)
			.len()
	}
}

/// An RFC 7662 §2.2 introspection response. `active` is the only field
/// the authorisation server must return; the claims are present only
/// when the token is active.
#[derive(Debug, Deserialize)]
struct IntrospectionResponse {
	/// Whether the authorisation server considers the token active.
	#[serde(default)]
	active: bool,
	/// The issuer claim, when active.
	iss: Option<String>,
	/// The subject claim, when active.
	sub: Option<String>,
	/// The audience claim, when active.
	#[serde(default)]
	aud: Option<Audience>,
	/// The expiry, as seconds since the Unix epoch, when active.
	exp: Option<i64>,
	/// The not-before, as seconds since the Unix epoch, when present.
	#[serde(default)]
	nbf: Option<i64>,
	/// The space-delimited scope string, when present.
	#[serde(default)]
	scope: Option<String>,
}

impl IntrospectionResponse {
	/// Convert an active response into the claims the shared validator
	/// checks. A response missing a required claim (`iss`, `sub`, or
	/// `exp`) is treated as malformed: the authorisation server marked
	/// the token active but did not describe it completely.
	fn into_claims(self) -> Result<RawClaims, FailureReason> {
		Ok(RawClaims {
			iss: self.iss.ok_or(FailureReason::MalformedToken)?,
			sub: self.sub.ok_or(FailureReason::MalformedToken)?,
			aud: self.aud,
			exp: self.exp.ok_or(FailureReason::MalformedToken)?,
			nbf: self.nbf,
			scope: self.scope,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A bounded cache evicts the oldest entry when a new one would
	/// exceed its capacity, so it never grows past the bound.
	#[test]
	fn cache_evicts_oldest_at_capacity() {
		let cache = IntrospectionCache::new(2);
		cache.insert([1; 32], Outcome::Inactive);
		cache.insert([2; 32], Outcome::Inactive);
		cache.insert([3; 32], Outcome::Inactive);

		assert_eq!(cache.len(), 2, "capacity must be respected");
		assert!(cache.lookup(&[1; 32]).is_none(), "the oldest is evicted");
		assert!(cache.lookup(&[3; 32]).is_some(), "the newest is kept");
	}

	/// Flush discards every cached entry.
	#[test]
	fn flush_clears_the_cache() {
		let cache = IntrospectionCache::new(8);
		cache.insert([1; 32], Outcome::Inactive);
		cache.flush();
		assert_eq!(cache.len(), 0);
	}
}
