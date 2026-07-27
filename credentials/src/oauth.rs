//! OAuth 2.0 `client_credentials` flow for upstream credential
//! acquisition.
//!
//! The gateway treats OAuth-issued credentials as a fourth source
//! alongside command, file, and environment. Unlike the static
//! sources, OAuth values have an expiry and must be refreshed; this
//! module owns the token-endpoint round-trip and the typed
//! request/response shapes. Higher layers (the cache, the proxy
//! integration) compose on top.
//!
//! Only the `client_credentials` grant is implemented. Other flows
//! (`refresh_token`, `authorization_code`) are out of scope until a
//! use case appears; `client_credentials` covers the
//! server-to-server scenario that is the gateway's focus.

use std::time::Duration;

use serde::Deserialize;

use crate::chain::Secret;

/// A request to a token endpoint using the `client_credentials`
/// grant. Carries the client identity and any scope or audience the
/// authorisation server requires.
///
/// `client_secret` is held as [`Secret`] so it is zeroized after the
/// HTTP body has been built and the request has been sent.
#[derive(Debug)]
pub struct TokenRequest {
	/// Full URL of the OAuth token endpoint.
	pub token_endpoint: String,

	/// OAuth client identifier (the `client_id` registered with the
	/// authorisation server).
	pub client_id: String,

	/// OAuth client secret, held in zeroizing storage.
	pub client_secret: Secret,

	/// Optional `scope` parameter sent as part of the request body.
	pub scope: Option<String>,

	/// Optional `audience` parameter sent as part of the request
	/// body. Some authorisation servers (e.g. Auth0) require it.
	pub audience: Option<String>,
}

/// A successful response from a token endpoint.
///
/// The access token itself is held in zeroizing storage. Other
/// fields (lifetime, token type) are non-secret metadata the cache
/// uses to decide when to refresh.
#[derive(Debug)]
pub struct TokenResponse {
	/// The bearer token to attach to upstream requests.
	pub access_token: Secret,

	/// How long the token remains valid, as reported by the
	/// authorisation server.
	pub expires_in: Duration,

	/// The `token_type` returned by the authorisation server. Almost
	/// always `Bearer`; preserved here so callers that need to honour
	/// a non-default scheme can do so.
	pub token_type: String,
}

/// Errors from the OAuth token-endpoint round-trip.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
	/// The HTTP request itself failed (DNS, connection, timeout).
	#[error("OAuth token request failed: {0}")]
	Request(reqwest::Error),

	/// The authorisation server responded with a non-2xx status.
	#[error("OAuth token endpoint returned status {status}: {body}")]
	BadStatus {
		/// HTTP status code returned by the authorisation server.
		status: u16,
		/// The raw response body, included verbatim so operators can
		/// see provider-specific error messages.
		body: String,
	},

	/// The response body was not a valid JSON token response.
	#[error("OAuth token endpoint returned malformed body: {0}")]
	MalformedBody(String),
}

/// Issue a `client_credentials` token request and parse the
/// response.
///
/// Sends an HTTP POST to `request.token_endpoint` with the
/// authorisation server's expected form encoding, using HTTP Basic
/// authentication for the client identity. Returns the parsed
/// [`TokenResponse`] on success.
///
/// # Errors
///
/// Returns [`OAuthError`] for network, status, or parse failures.
pub async fn fetch_token(
	http_client: &reqwest::Client,
	request: &TokenRequest,
) -> Result<TokenResponse, OAuthError> {
	let body = encode_token_request_body(request);

	let response = http_client
		.post(&request.token_endpoint)
		.basic_auth(&request.client_id, Some(request.client_secret.expose()))
		.header(
			reqwest::header::CONTENT_TYPE,
			"application/x-www-form-urlencoded",
		)
		.body(body)
		.send()
		.await
		.map_err(OAuthError::Request)?;

	let status = response.status();
	if !status.is_success() {
		let body = response.text().await.unwrap_or_default();
		return Err(OAuthError::BadStatus {
			status: status.as_u16(),
			body,
		});
	}

	let payload: TokenResponsePayload = response
		.json()
		.await
		.map_err(|error| OAuthError::MalformedBody(error.to_string()))?;
	Ok(TokenResponse::from(payload))
}

/// Build the `application/x-www-form-urlencoded` body for a
/// `client_credentials` token request. Always includes
/// `grant_type=client_credentials`; conditionally includes
/// `scope` and `audience` when the request supplies them.
fn encode_token_request_body(request: &TokenRequest) -> String {
	let mut body = String::new();
	let mut serializer = url::form_urlencoded::Serializer::new(&mut body);
	serializer.append_pair("grant_type", "client_credentials");
	if let Some(scope) = request.scope.as_deref() {
		serializer.append_pair("scope", scope);
	}
	if let Some(audience) = request.audience.as_deref() {
		serializer.append_pair("audience", audience);
	}
	serializer.finish();
	body
}

/// On-the-wire shape of the token endpoint's success response.
///
/// Kept private and converted into [`TokenResponse`] so the public
/// API holds the access token in [`Secret`] from the moment it is
/// parsed.
#[derive(Deserialize)]
struct TokenResponsePayload {
	access_token: String,
	expires_in: u64,
	#[serde(default = "default_token_type")]
	token_type: String,
}

/// Default `token_type` for parsed responses where the server
/// omits the field. RFC 6749 says `Bearer` is the conventional
/// default, and most implementations rely on that.
fn default_token_type() -> String {
	"Bearer".to_owned()
}

impl From<TokenResponsePayload> for TokenResponse {
	fn from(payload: TokenResponsePayload) -> Self {
		Self {
			access_token: Secret::new(payload.access_token),
			expires_in: Duration::from_secs(payload.expires_in),
			token_type: payload.token_type,
		}
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::sync::{Arc, Mutex};

	use axum::Router;
	use axum::extract::{Form, State};
	use axum::http::HeaderMap;
	use axum::response::Json;
	use axum::routing::post;
	use serde_json::Value;
	use tokio::net::TcpListener;

	use super::*;

	/// Captured request seen by the mock token endpoint, so each
	/// test can assert on the exact bytes the client sent.
	#[derive(Default)]
	struct RecordedRequest {
		authorization: Option<String>,
		form: HashMap<String, String>,
	}

	/// Spin up an in-process mock token endpoint and return its base
	/// URL plus a handle to inspect the most recent request. The
	/// listener is bound to an ephemeral port and the server runs on
	/// a tokio task for the lifetime of the test.
	async fn spawn_mock_token_endpoint(
		response_status: axum::http::StatusCode,
		response_body: Value,
	) -> (String, Arc<Mutex<RecordedRequest>>) {
		let listener = TcpListener::bind("127.0.0.1:0")
			.await
			.expect("bind ephemeral");
		let address = listener.local_addr().expect("local address");
		let recorder: Arc<Mutex<RecordedRequest>> =
			Arc::new(Mutex::new(RecordedRequest::default()));
		let state = MockState {
			recorder: Arc::clone(&recorder),
			status: response_status,
			body: response_body,
		};
		let app = Router::new()
			.route("/oauth/token", post(handle_mock_token))
			.with_state(state);
		tokio::spawn(async move {
			axum::serve(listener, app).await.expect("mock server runs");
		});
		(format!("http://{address}/oauth/token"), recorder)
	}

	/// Shared state passed to the mock token handler.
	#[derive(Clone)]
	struct MockState {
		recorder: Arc<Mutex<RecordedRequest>>,
		status: axum::http::StatusCode,
		body: Value,
	}

	/// Mock token endpoint handler that records the incoming request
	/// and returns the test-configured status and body.
	async fn handle_mock_token(
		State(state): State<MockState>,
		headers: HeaderMap,
		Form(form): Form<HashMap<String, String>>,
	) -> (axum::http::StatusCode, Json<Value>) {
		let mut recorded = state.recorder.lock().expect("recorder lock");
		recorded.authorization = headers
			.get("authorization")
			.and_then(|value| value.to_str().ok())
			.map(str::to_owned);
		recorded.form = form;
		drop(recorded);
		(state.status, Json(state.body.clone()))
	}

	/// `fetch_token` POSTs to the configured endpoint with
	/// `grant_type=client_credentials`, sends the client identity as
	/// HTTP Basic, and parses a successful JSON response into a
	/// `TokenResponse`.
	#[tokio::test]
	async fn fetch_token_sends_basic_auth_and_parses_success_response() {
		let (endpoint, recorder) = spawn_mock_token_endpoint(
			axum::http::StatusCode::OK,
			serde_json::json!({
				"access_token": "the-token",
				"expires_in": 3600,
				"token_type": "Bearer"
			}),
		)
		.await;

		let request = TokenRequest {
			token_endpoint: endpoint,
			client_id: "the-client".to_owned(),
			client_secret: Secret::new("the-secret".to_owned()),
			scope: Some("repo".to_owned()),
			audience: None,
		};

		let http_client = crate::test_http_client();
		let response = fetch_token(&http_client, &request)
			.await
			.expect("token fetch succeeds");

		assert_eq!(response.access_token.expose(), "the-token");
		assert_eq!(response.expires_in, Duration::from_hours(1));
		assert_eq!(response.token_type, "Bearer");

		let captured = recorder.lock().expect("recorder lock");
		assert!(
			captured
				.authorization
				.as_deref()
				.is_some_and(|value| value.starts_with("Basic ")),
			"client identity must be sent as HTTP Basic, got {:?}",
			captured.authorization,
		);
		assert_eq!(
			captured.form.get("grant_type").map(String::as_str),
			Some("client_credentials")
		);
		assert_eq!(captured.form.get("scope").map(String::as_str), Some("repo"));
	}

	/// A non-2xx response from the token endpoint produces a
	/// `BadStatus` error carrying the status code and body.
	#[tokio::test]
	async fn fetch_token_returns_bad_status_on_non_2xx() {
		let (endpoint, _recorder) = spawn_mock_token_endpoint(
			axum::http::StatusCode::UNAUTHORIZED,
			serde_json::json!({"error": "invalid_client"}),
		)
		.await;

		let request = TokenRequest {
			token_endpoint: endpoint,
			client_id: "wrong".to_owned(),
			client_secret: Secret::new("wrong".to_owned()),
			scope: None,
			audience: None,
		};

		let http_client = crate::test_http_client();
		let outcome = fetch_token(&http_client, &request).await;
		match outcome {
			Err(OAuthError::BadStatus { status, body }) => {
				assert_eq!(status, 401);
				assert!(
					body.contains("invalid_client"),
					"body should include provider error, got {body:?}"
				);
			}
			other => panic!("expected BadStatus, got {other:?}"),
		}
	}

	/// A 2xx response with a body that does not parse as the
	/// expected JSON shape produces a `MalformedBody` error rather
	/// than a panic.
	#[tokio::test]
	async fn fetch_token_returns_malformed_body_on_unexpected_payload() {
		let (endpoint, _recorder) = spawn_mock_token_endpoint(
			axum::http::StatusCode::OK,
			serde_json::json!({"unrelated": "payload"}),
		)
		.await;

		let request = TokenRequest {
			token_endpoint: endpoint,
			client_id: "id".to_owned(),
			client_secret: Secret::new("secret".to_owned()),
			scope: None,
			audience: None,
		};

		let http_client = crate::test_http_client();
		let outcome = fetch_token(&http_client, &request).await;
		assert!(matches!(outcome, Err(OAuthError::MalformedBody(_))));
	}

	/// `token_type` defaults to `Bearer` when the authorisation
	/// server omits the field, per RFC 6749's conventional default.
	#[tokio::test]
	async fn fetch_token_defaults_token_type_to_bearer() {
		let (endpoint, _recorder) = spawn_mock_token_endpoint(
			axum::http::StatusCode::OK,
			serde_json::json!({
				"access_token": "no-type-token",
				"expires_in": 60
			}),
		)
		.await;

		let request = TokenRequest {
			token_endpoint: endpoint,
			client_id: "id".to_owned(),
			client_secret: Secret::new("secret".to_owned()),
			scope: None,
			audience: None,
		};

		let http_client = crate::test_http_client();
		let response = fetch_token(&http_client, &request)
			.await
			.expect("token fetch");
		assert_eq!(response.token_type, "Bearer");
	}
}
