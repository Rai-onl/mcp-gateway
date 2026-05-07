//! In-memory cache of OAuth-issued tokens with single-flight
//! refresh.
//!
//! Tokens obtained from a [`super::oauth::fetch_token`] call carry
//! an `expires_in` lifetime. The cache stores the token alongside
//! its computed expiry instant so callers can reuse the same token
//! across many requests without hitting the authorisation server
//! every time. When a token is close to (or past) expiry, the cache
//! refreshes it. Concurrent callers that arrive during refresh share
//! the result of a single in-flight HTTP call rather than each
//! issuing their own — the single-flight guarantee.
//!
//! The cache is keyed by credential name. Each entry has its own
//! mutex so unrelated credentials never block one another.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::chain::Secret;
use crate::oauth::{OAuthError, TokenRequest, TokenResponse, fetch_token};

/// Default refresh skew: refresh a token this far before the
/// authorisation server's reported expiry. Keeps in-flight requests
/// from racing against expiry on the upstream side.
pub const DEFAULT_REFRESH_SKEW: Duration = Duration::from_secs(30);

/// A token alongside the instant at which it should be considered
/// expired (the authorisation server's `expires_in` minus the
/// configured refresh skew).
#[derive(Clone)]
struct CachedToken {
	access_token: Secret,
	expires_at: Instant,
}

/// Per-credential state inside the cache.
///
/// The mutex serialises refresh attempts so the cache issues at
/// most one in-flight token request per credential. Cached tokens
/// live in an `Option` so a still-warm value can be cloned without
/// acquiring the mutex (only refresh paths take the lock).
struct CacheEntry {
	/// Credential-specific request shape used by every refresh.
	request: TokenRequest,
	/// How long before reported expiry the cache treats a token as
	/// stale.
	refresh_skew: Duration,
	/// The most recently fetched token, if any. Wrapped in
	/// `tokio::sync::Mutex` so callers can `await` while a refresh
	/// is in progress without holding a sync lock across `.await`.
	state: Mutex<Option<CachedToken>>,
}

/// In-memory store of OAuth tokens keyed by credential name.
///
/// Cheap to clone (`Arc` internally) so it can be shared between
/// the proxy request path and any background refresh task. Each
/// credential's entry lives behind its own mutex; serving a token
/// for credential `A` never blocks a token request for credential
/// `B`.
#[derive(Clone)]
pub struct OAuthCache {
	entries: Arc<HashMap<String, Arc<CacheEntry>>>,
	http_client: reqwest::Client,
	/// Source of the current time. Defaults to the real monotonic
	/// clock; tests inject a controlled clock so they can reason
	/// about expiry without sleeping.
	clock: Arc<dyn Clock>,
}

/// A monotonically increasing clock. Production uses `Instant::now`;
/// tests inject a controlled clock so expiry behaviour can be
/// exercised deterministically.
pub trait Clock: Send + Sync + 'static {
	/// Return the current instant.
	fn now(&self) -> Instant;
}

/// Real-time clock backed by [`Instant::now`].
pub struct SystemClock;

impl Clock for SystemClock {
	fn now(&self) -> Instant {
		Instant::now()
	}
}

impl OAuthCache {
	/// Build a cache from a map of credential-name → token request.
	///
	/// Every credential listed in `credentials` becomes a tracked
	/// entry; calls for any name not in this map fail with
	/// [`OAuthError::Request`] (or similar) since the cache cannot
	/// invent a token request.
	#[must_use]
	pub fn new(
		credentials: HashMap<String, TokenRequest>,
		http_client: reqwest::Client,
		refresh_skew: Duration,
	) -> Self {
		Self::with_clock(
			credentials,
			http_client,
			refresh_skew,
			Arc::new(SystemClock),
		)
	}

	/// Build a cache that uses a custom [`Clock`]. Used in tests to
	/// observe expiry without real-world delays.
	#[must_use]
	pub fn with_clock(
		credentials: HashMap<String, TokenRequest>,
		http_client: reqwest::Client,
		refresh_skew: Duration,
		clock: Arc<dyn Clock>,
	) -> Self {
		let entries = credentials
			.into_iter()
			.map(|(name, request)| {
				(
					name,
					Arc::new(CacheEntry {
						request,
						refresh_skew,
						state: Mutex::new(None),
					}),
				)
			})
			.collect();
		Self {
			entries: Arc::new(entries),
			http_client,
			clock,
		}
	}

	/// Fetch a current access token for `credential_name`,
	/// refreshing from the authorisation server when the cached
	/// value is missing or close to expiry.
	///
	/// Concurrent callers for the same credential share a single
	/// in-flight refresh: only the first caller through the per-
	/// entry mutex performs the HTTP call; subsequent callers wait
	/// on the mutex and observe the freshly cached value.
	///
	/// # Errors
	///
	/// Returns [`OAuthError`] if the credential is unknown or the
	/// authorisation server returns an error during refresh.
	pub async fn current_token(&self, credential_name: &str) -> Result<Secret, OAuthError> {
		let entry = self
			.entries
			.get(credential_name)
			.ok_or_else(|| {
				OAuthError::MalformedBody(format!(
					"OAuth credential '{credential_name}' is not configured"
				))
			})?
			.clone();

		let now = self.clock.now();
		let mut state = entry.state.lock().await;
		if let Some(cached) = state.as_ref()
			&& cached.expires_at > now
		{
			return Ok(cached.access_token.clone());
		}

		let response = fetch_token(&self.http_client, &entry.request).await?;
		let cached = build_cached_token(&response, now, entry.refresh_skew);
		let token = cached.access_token.clone();
		*state = Some(cached);
		Ok(token)
	}
}

impl std::fmt::Debug for OAuthCache {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter
			.debug_struct("OAuthCache")
			.field("credentials", &self.entries.keys().collect::<Vec<_>>())
			.finish_non_exhaustive()
	}
}

/// Build a [`CachedToken`] from a freshly-fetched [`TokenResponse`],
/// applying the configured refresh skew to compute the expiry instant.
///
/// `expires_at` is `now + expires_in - skew` saturating to `now` if
/// the skew exceeds the issued lifetime — better to refresh
/// immediately on next call than to compute a past expiry instant.
fn build_cached_token(response: &TokenResponse, now: Instant, skew: Duration) -> CachedToken {
	let lifetime = response.expires_in.saturating_sub(skew).max(Duration::ZERO);
	CachedToken {
		access_token: response.access_token.clone(),
		expires_at: now + lifetime,
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Mutex as StdMutex;

	use axum::Router;
	use axum::extract::State;
	use axum::http::StatusCode;
	use axum::response::Json;
	use axum::routing::post;
	use serde_json::Value;
	use tokio::net::TcpListener;

	use super::*;

	/// A controllable clock that tests can advance manually. Lets
	/// us prove expiry behaviour without sleeping.
	struct TestClock {
		now: StdMutex<Instant>,
	}

	impl TestClock {
		/// Build a clock anchored at the current real instant.
		fn new() -> Arc<Self> {
			Arc::new(Self {
				now: StdMutex::new(Instant::now()),
			})
		}

		/// Advance the clock by `amount`. The next call to
		/// [`Clock::now`] returns the updated instant.
		fn advance(&self, amount: Duration) {
			let mut guard = self.now.lock().expect("test clock lock");
			*guard += amount;
		}
	}

	impl Clock for TestClock {
		fn now(&self) -> Instant {
			*self.now.lock().expect("test clock lock")
		}
	}

	/// Mutable counter so the mock token endpoint can issue a fresh
	/// token value on each refresh, letting tests assert the cache
	/// returned the *new* token after expiry.
	#[derive(Default)]
	struct MockTokenIssuer {
		next_serial: StdMutex<u64>,
		hits: StdMutex<u64>,
	}

	impl MockTokenIssuer {
		/// Issue the next token value (`token-1`, `token-2`, …) and
		/// record the call.
		fn issue(&self) -> String {
			let mut serial = self.next_serial.lock().expect("serial lock");
			*serial += 1;
			let mut hits = self.hits.lock().expect("hits lock");
			*hits += 1;
			format!("token-{serial}", serial = *serial)
		}

		/// Number of token requests served since spawn.
		fn hit_count(&self) -> u64 {
			*self.hits.lock().expect("hits lock")
		}
	}

	/// Spin up a mock token endpoint that serves a fresh token on
	/// every request. Returns the endpoint URL and the issuer so
	/// tests can read the hit count.
	async fn spawn_issuer() -> (String, Arc<MockTokenIssuer>) {
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		let address = listener.local_addr().expect("local address");
		let issuer = Arc::new(MockTokenIssuer::default());
		let app = Router::new()
			.route("/oauth/token", post(handle_issue))
			.with_state(Arc::clone(&issuer));
		tokio::spawn(async move {
			axum::serve(listener, app).await.expect("mock server runs");
		});
		(format!("http://{address}/oauth/token"), issuer)
	}

	/// Mock token endpoint handler that returns a uniquely-numbered
	/// token on each invocation.
	async fn handle_issue(State(issuer): State<Arc<MockTokenIssuer>>) -> (StatusCode, Json<Value>) {
		let token = issuer.issue();
		(
			StatusCode::OK,
			Json(serde_json::json!({
				"access_token": token,
				"expires_in": 3600,
				"token_type": "Bearer"
			})),
		)
	}

	/// Helper that issues one token request against the shared
	/// cache, used by the single-flight test to spawn many
	/// concurrent callers without nesting a closure inside
	/// `tokio::spawn`'s argument expression.
	async fn spawn_token_request(cache: OAuthCache) -> Secret {
		cache.current_token("api").await.expect("token returned")
	}

	/// Build a single-credential cache pointing at `endpoint`.
	fn cache_for(
		credential_name: &str,
		endpoint: String,
		clock: Arc<dyn Clock>,
		skew: Duration,
	) -> OAuthCache {
		let mut credentials = HashMap::new();
		credentials.insert(
			credential_name.to_owned(),
			TokenRequest {
				token_endpoint: endpoint,
				client_id: "client".to_owned(),
				client_secret: Secret::new("secret".to_owned()),
				scope: None,
				audience: None,
			},
		);
		OAuthCache::with_clock(credentials, reqwest::Client::new(), skew, clock)
	}

	/// First call to `current_token` fetches from the upstream and
	/// returns the issued value.
	#[tokio::test]
	async fn cold_cache_fetches_from_upstream() {
		let (endpoint, issuer) = spawn_issuer().await;
		let cache = cache_for("api", endpoint, TestClock::new(), DEFAULT_REFRESH_SKEW);

		let token = cache.current_token("api").await.expect("token returned");
		assert_eq!(token.expose(), "token-1");
		assert_eq!(issuer.hit_count(), 1);
	}

	/// Second call before expiry reuses the cached token without
	/// hitting the upstream.
	#[tokio::test]
	async fn warm_cache_reuses_token() {
		let (endpoint, issuer) = spawn_issuer().await;
		let clock = TestClock::new();
		let cache = cache_for(
			"api",
			endpoint,
			clock.clone() as Arc<dyn Clock>,
			DEFAULT_REFRESH_SKEW,
		);

		let first = cache.current_token("api").await.expect("first");
		// Time advances by less than the issued lifetime minus skew
		// (3600s - 30s = 3570s), so the cached token is still valid.
		clock.advance(Duration::from_mins(1));
		let second = cache.current_token("api").await.expect("second");

		assert_eq!(first.expose(), "token-1");
		assert_eq!(second.expose(), "token-1");
		assert_eq!(
			issuer.hit_count(),
			1,
			"cached token must not trigger a second upstream call"
		);
	}

	/// After advancing past the expiry instant, the next call
	/// triggers a refresh and observes a new token.
	#[tokio::test]
	async fn expired_cache_refreshes_token() {
		let (endpoint, issuer) = spawn_issuer().await;
		let clock = TestClock::new();
		let cache = cache_for(
			"api",
			endpoint,
			clock.clone() as Arc<dyn Clock>,
			DEFAULT_REFRESH_SKEW,
		);

		let _first = cache.current_token("api").await.expect("first");
		// 3600s issued, 30s skew → cached for 3570s. Jump past it.
		clock.advance(Duration::from_hours(1));
		let second = cache.current_token("api").await.expect("second");

		assert_eq!(second.expose(), "token-2");
		assert_eq!(issuer.hit_count(), 2);
	}

	/// Many concurrent callers on a cold cache see exactly one
	/// upstream call. Demonstrates the single-flight guarantee.
	#[tokio::test]
	async fn concurrent_cold_callers_share_a_single_fetch() {
		let (endpoint, issuer) = spawn_issuer().await;
		let cache = cache_for("api", endpoint, TestClock::new(), DEFAULT_REFRESH_SKEW);

		let mut tasks = Vec::new();
		for _ in 0..16 {
			let cache = cache.clone();
			tasks.push(tokio::spawn(spawn_token_request(cache)));
		}
		for task in tasks {
			let token = task.await.expect("task joined");
			assert_eq!(token.expose(), "token-1");
		}

		assert_eq!(
			issuer.hit_count(),
			1,
			"single-flight must coalesce concurrent cold callers"
		);
	}

	/// A request for an unknown credential name fails without
	/// hitting the upstream.
	#[tokio::test]
	async fn unknown_credential_returns_error() {
		let (endpoint, _issuer) = spawn_issuer().await;
		let cache = cache_for("api", endpoint, TestClock::new(), DEFAULT_REFRESH_SKEW);

		let outcome = cache.current_token("unknown").await;
		assert!(outcome.is_err(), "unknown credential must fail");
	}
}
