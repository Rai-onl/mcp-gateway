//! JSON Web Key Set retrieval and caching.
//!
//! The cache fetches the authorisation server's JWKS lazily on first
//! lookup and serves subsequent lookups of a known `kid` from memory.
//! A lookup for a `kid` the cache has not seen triggers a single
//! refresh before giving up, which is how a token signed by a key
//! rotated in since the last fetch still validates.
//!
//! This slice provides retrieval and caching only. Signature
//! verification and `kid`-pin enforcement live in the validator slice
//! that consumes these keys.

use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;

/// The minimum interval between forced refreshes that fail to find the
/// requested `kid`. An unauthenticated caller can present a token with
/// any `kid` before its signature is checked, so an unknown `kid` must
/// not translate one-to-one into an outbound fetch. A refresh that
/// misses arms this cooldown, during which further unknown-`kid` lookups
/// report the key as absent without touching the network. A refresh that
/// finds its key (a genuine key rotation) does not arm it, so rotated
/// keys are still picked up immediately.
const UNKNOWN_KID_REFRESH_COOLDOWN: Duration = Duration::from_secs(10);

/// A cache over an authorisation server's JSON Web Key Set.
pub struct JwksCache {
	http: reqwest::Client,
	jwks_uri: String,
	/// The cached keys, or `None` until the first successful fetch.
	/// Each entry is the raw JWK object; the validator extracts the
	/// cryptographic material when it builds a verifier.
	keys: Mutex<Option<Vec<Value>>>,
	/// Held across a forced refresh so a burst of concurrent
	/// unknown-`kid` lookups issues one fetch between them rather than
	/// one each. An async lock because it is held over the fetch await.
	refresh_lock: tokio::sync::Mutex<()>,
	/// When the last forced refresh that missed its `kid` happened, if
	/// any. Gates the [`UNKNOWN_KID_REFRESH_COOLDOWN`] so a flood of
	/// unknown keys cannot drive unbounded outbound fetches.
	last_missed_refresh: Mutex<Option<Instant>>,
}

impl JwksCache {
	/// Construct a cache that fetches from the given JWKS URI.
	#[must_use]
	pub fn new(jwks_uri: String) -> Self {
		Self {
			http: crate::trust::default_http_client(),
			jwks_uri,
			keys: Mutex::new(None),
			refresh_lock: tokio::sync::Mutex::new(()),
			last_missed_refresh: Mutex::new(None),
		}
	}

	/// Replace the HTTP client used to fetch the JWKS.
	///
	/// The setup path installs the authorisation-server-pinned client
	/// here when SPKI pins are configured, so the JWKS fetch (which
	/// retrieves the signing keys) is protected by the same pins as the
	/// discovery fetch rather than trusting the system certificate store.
	#[must_use]
	pub fn with_http_client(mut self, http: reqwest::Client) -> Self {
		self.http = http;
		self
	}

	/// Return the JWK with the given `kid`, or `None` if the
	/// authorisation server does not publish one.
	///
	/// A known `kid` already in the cache is returned without a
	/// network call. A `kid` absent from the cache (including the
	/// very first lookup, when the cache is empty) triggers a single
	/// JWKS refresh and is then looked up once more; if it is still
	/// absent the result is `None`.
	///
	/// # Errors
	///
	/// Returns [`JwksError::Request`] if the refresh HTTP request
	/// fails and [`JwksError::Parse`] if the JWKS body is not valid
	/// JSON.
	pub async fn key_for_kid(&self, kid: &str) -> Result<Option<Value>, JwksError> {
		// Serve a cached key without touching the network. The guard
		// is dropped at the end of this block, never held across the
		// refresh `await` below. A poisoned lock is recovered rather
		// than propagated: a panic in an unrelated cache update must
		// not take token validation down.
		if let Some(found) = self.cached_key(kid) {
			return Ok(Some(found));
		}

		// Serialise forced refreshes: only one fetch runs at a time, so a
		// burst of concurrent unknown-`kid` lookups collapses to a single
		// outbound request rather than one per caller.
		let _refresh = self.refresh_lock.lock().await;

		// Re-check the cache: another lookup may have refreshed it while
		// this one waited for the lock.
		if let Some(found) = self.cached_key(kid) {
			return Ok(Some(found));
		}

		// Throttle repeated misses. A recent forced refresh that failed to
		// find its `kid` arms the cooldown, so a flood of unknown keys is
		// reported absent without re-fetching. A genuine rotation is a hit
		// and never arms it, so a rotated key is still fetched at once.
		if let Some(missed_at) = *self
			.last_missed_refresh
			.lock()
			.unwrap_or_else(PoisonError::into_inner)
			&& missed_at.elapsed() < UNKNOWN_KID_REFRESH_COOLDOWN
		{
			return Ok(None);
		}

		// Either the cache is empty or it does not hold this kid.
		// Refresh once and look again.
		let refreshed = self.fetch().await?;
		let found = find_key(&refreshed, kid);
		*self.keys.lock().unwrap_or_else(PoisonError::into_inner) = Some(refreshed);
		if found.is_none() {
			*self
				.last_missed_refresh
				.lock()
				.unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
		}
		Ok(found)
	}

	/// Return a clone of the cached key with the given `kid`, or `None`
	/// if the cache is empty or does not hold it. Never touches the
	/// network; a poisoned lock is recovered rather than propagated so a
	/// panic in an unrelated cache update cannot take validation down.
	fn cached_key(&self, kid: &str) -> Option<Value> {
		let cached = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
		cached.as_ref().and_then(|keys| find_key(keys, kid))
	}

	/// Proactively refresh the cached key set.
	///
	/// Fetches the JWKS and replaces the cached keys on success. On
	/// failure the previously cached keys are retained and a warning is
	/// logged, so a transient outage between background-refresh ticks
	/// does not empty the cache and break validation; the error is still
	/// returned so the caller can observe the failure. This is the
	/// proactive counterpart to the lazy refresh
	/// [`key_for_kid`](Self::key_for_kid) performs on an unknown `kid`.
	///
	/// # Errors
	///
	/// Returns [`JwksError::Request`] if the refresh HTTP request fails
	/// and [`JwksError::Parse`] if the JWKS body is not valid JSON.
	pub async fn refresh(&self) -> Result<(), JwksError> {
		match self.fetch().await {
			Ok(keys) => {
				*self.keys.lock().unwrap_or_else(PoisonError::into_inner) = Some(keys);
				Ok(())
			}
			Err(error) => {
				if self
					.keys
					.lock()
					.unwrap_or_else(PoisonError::into_inner)
					.is_some()
				{
					tracing::warn!(
						%error,
						"JWKS refresh failed; retaining the previously loaded keys"
					);
				}
				Err(error)
			}
		}
	}

	/// Fetch and parse the JWKS, returning its keys.
	async fn fetch(&self) -> Result<Vec<Value>, JwksError> {
		let body = self
			.http
			.get(&self.jwks_uri)
			.send()
			.await
			.map_err(JwksError::Request)?
			.text()
			.await
			.map_err(JwksError::Request)?;
		let jwks: Jwks = serde_json::from_str(&body).map_err(JwksError::Parse)?;
		Ok(jwks.keys)
	}
}

/// The wire shape of a JWKS document: a `keys` array of JWK objects.
#[derive(Debug, Deserialize)]
struct Jwks {
	#[serde(default)]
	keys: Vec<Value>,
}

/// Find the key in `keys` whose `kid` member equals `kid`, returning a
/// clone of the matching JWK object.
fn find_key(keys: &[Value], kid: &str) -> Option<Value> {
	keys.iter()
		.find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
		.cloned()
}

/// Errors that can occur while retrieving a JWKS.
#[derive(Debug, thiserror::Error)]
pub enum JwksError {
	/// The HTTP request to the JWKS endpoint failed.
	#[error("JWKS request failed: {0}")]
	Request(reqwest::Error),

	/// The JWKS response body could not be parsed as JSON.
	#[error("JWKS document is not valid JSON: {0}")]
	Parse(serde_json::Error),
}
