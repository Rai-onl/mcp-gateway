//! [`OAuthResolver`]: an `Arc<dyn CredentialResolver>` backed by an
//! [`OAuthCache`].
//!
//! The cache holds the per-credential refresh state and single-flight
//! mutex; this resolver is the trait-shaped seam the proxy and bridge
//! consume. A future Vault-backed resolver wraps a different cache
//! the same way without any consumer changes.

use async_trait::async_trait;

use crate::{CredentialResolver, OAuthCache, Secret};

/// Resolver that issues OAuth bearer tokens from a backing
/// [`OAuthCache`]. Each `resolve` call returns the cache's current
/// view of the token, which the cache refreshes lazily as it ages
/// out of its refresh skew window.
pub struct OAuthResolver {
	cache: OAuthCache,
}

impl OAuthResolver {
	/// Build a resolver from a cache that has been preloaded with
	/// every OAuth credential the configuration referenced.
	#[must_use]
	pub fn new(cache: OAuthCache) -> Self {
		Self { cache }
	}
}

#[async_trait]
impl CredentialResolver for OAuthResolver {
	async fn resolve(&self, name: &str) -> Result<Secret, String> {
		self.cache
			.current_token(name)
			.await
			.map_err(|error| error.to_string())
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::sync::Arc;
	use std::sync::Mutex as StdMutex;
	use std::time::Duration;

	use axum::Router;
	use axum::extract::State;
	use axum::http::StatusCode;
	use axum::response::Json;
	use axum::routing::post;
	use serde_json::Value;
	use tokio::net::TcpListener;

	use crate::oauth::TokenRequest;

	use super::*;

	/// Mock token issuer used by the OAuth resolver tests, mirroring
	/// the helper in `oauth_cache.rs` so each test can rebuild a
	/// realistic authorisation server in isolation.
	#[derive(Default)]
	struct MockIssuer {
		serial: StdMutex<u64>,
	}

	impl MockIssuer {
		/// Produce the next sequential token value.
		fn issue(&self) -> String {
			let mut serial = self.serial.lock().expect("serial lock");
			*serial += 1;
			format!("oauth-token-{serial}", serial = *serial)
		}
	}

	/// Boot a mock token endpoint and return its URL and the issuer.
	async fn spawn_issuer() -> (String, Arc<MockIssuer>) {
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		let address = listener.local_addr().expect("address");
		let issuer = Arc::new(MockIssuer::default());
		let app = Router::new()
			.route("/oauth/token", post(handle_issue))
			.with_state(Arc::clone(&issuer));
		tokio::spawn(async move {
			axum::serve(listener, app).await.expect("mock server runs");
		});
		(format!("http://{address}/oauth/token"), issuer)
	}

	/// Mock token-endpoint handler: emits a sequential bearer token
	/// with a long lifetime so a single test rarely exercises refresh
	/// behaviour (refresh has its own coverage in `oauth_cache`).
	async fn handle_issue(State(issuer): State<Arc<MockIssuer>>) -> (StatusCode, Json<Value>) {
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

	/// Build an `OAuthResolver` whose cache knows about a single
	/// `api` credential pointing at the supplied token endpoint.
	fn build_resolver(token_endpoint: String) -> OAuthResolver {
		let mut credentials = HashMap::new();
		credentials.insert(
			"api".to_owned(),
			TokenRequest {
				token_endpoint,
				client_id: "test-client".to_owned(),
				client_secret: Secret::new("test-secret".to_owned()),
				scope: None,
				audience: None,
			},
		);
		let cache = OAuthCache::new(credentials, reqwest::Client::new(), Duration::from_secs(30));
		OAuthResolver::new(cache)
	}

	/// `resolve` returns the token issued by the authorisation
	/// server for a credential the cache knows about.
	#[tokio::test]
	async fn resolve_returns_token_for_known_credential() {
		let (token_endpoint, _issuer) = spawn_issuer().await;
		let resolver = build_resolver(token_endpoint);

		let secret = resolver
			.resolve("api")
			.await
			.expect("known oauth credential resolves");
		assert_eq!(secret.expose(), "oauth-token-1");
	}

	/// A name the cache was not configured for surfaces as a
	/// human-readable error rather than panicking.
	#[tokio::test]
	async fn resolve_returns_error_for_unknown_credential() {
		let (token_endpoint, _issuer) = spawn_issuer().await;
		let resolver = build_resolver(token_endpoint);

		let outcome = resolver.resolve("unknown").await;
		match outcome {
			Err(message) => assert!(
				message.contains("unknown"),
				"unknown credential error must name it, got {message:?}",
			),
			Ok(_) => panic!("an unknown credential must fail through the trait"),
		}
	}
}
