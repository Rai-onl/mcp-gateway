//! Pre-resolve credentials at startup so the daemon receives a
//! [`StaticResolver`] backed by an in-memory map of values.
//!
//! Pre-resolution exists because the credential helper command path
//! is async ([`CredentialProvider::resolve`] uses
//! `tokio::process::Command`), but most consumers only learn the
//! credential name. Resolving every reference once at startup and
//! handing the daemon an `Arc<dyn CredentialResolver>` keeps the
//! per-request hot path off the helper-command pipeline and surfaces
//! missing references with server attribution before the gateway
//! starts accepting traffic. Failures flow through the existing
//! [`mcp_gateway_daemon::AppStateError::Credential`] path.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use mcp_gateway_config::{CredentialResolutionError, GatewayConfig, OAuthCredential};
use mcp_gateway_credentials::oauth::TokenRequest;
use mcp_gateway_credentials::{
	CompositeResolver, CredentialProvider, CredentialResolver, DEFAULT_REFRESH_SKEW, OAuthCache,
	OAuthResolver, Secret, StaticResolver,
};

/// Walk the configuration and collect the set of *static* credential
/// references that need resolving at startup.
///
/// Two sources contribute:
///
/// 1. Server `credential` fields whose names are not declared in the
///    top-level `oauth` map. Names that appear in `oauth` are
///    resolved at request time by an [`OAuthResolver`] and are
///    deliberately excluded here so the static provider chain is
///    not asked for them.
/// 2. Every OAuth credential's `client_secret_credential`. The
///    OAuth flow needs a `client_secret` to authenticate to the
///    authorisation server; that value is materialised at startup
///    through the same provider chain as everything else and lives
///    in the static map for the OAuth cache to read once.
///
/// Both enabled and disabled servers contribute references: a typo
/// in a disabled server's credential is caught at startup, not at
/// re-enable time.
///
/// The returned map is keyed by credential name; the value is the
/// first context that referenced it (a server name, or
/// `oauth:<credential>` for OAuth client-secret references). That
/// attribution drives the failure message when a lookup fails.
pub(crate) fn collect_credential_references(config: &GatewayConfig) -> BTreeMap<String, String> {
	let mut references = BTreeMap::new();
	for (server_name, definition) in &config.servers {
		if let Some(credential_name) = &definition.credential
			&& !config.oauth.contains_key(credential_name)
		{
			references
				.entry(credential_name.clone())
				.or_insert_with(|| server_name.clone());
		}
	}
	for (oauth_name, oauth_credential) in &config.oauth {
		references
			.entry(oauth_credential.client_secret_credential.clone())
			.or_insert_with(|| format!("oauth:{oauth_name}"));
	}
	references
}

/// Resolve every referenced credential through the provider chain.
///
/// Resolution is sequential. The first failure short-circuits and is
/// returned as a [`CredentialResolutionError`] attributed to the
/// server that referenced the credential, matching the error shape
/// produced by [`mcp_gateway_config::resolve_credentials`] so the
/// console error path is identical regardless of which crate detected
/// the failure.
///
/// # Errors
///
/// Returns [`CredentialResolutionError`] if any provider lookup
/// fails. Errors carry the server name, credential name, and the
/// underlying [`mcp_gateway_credentials::CredentialError`] message.
pub(crate) async fn resolve_all(
	provider: &CredentialProvider,
	references: &BTreeMap<String, String>,
) -> Result<HashMap<String, Secret>, CredentialResolutionError> {
	tracing::info!(count = references.len(), "pre-resolving credentials");

	let mut secrets = HashMap::with_capacity(references.len());
	for (credential_name, server_name) in references {
		let secret =
			provider
				.resolve(credential_name)
				.await
				.map_err(|error| CredentialResolutionError {
					server: server_name.clone(),
					credential: credential_name.clone(),
					reason: error.to_string(),
				})?;
		tracing::debug!(
			credential = credential_name,
			server = server_name,
			"resolved credential"
		);
		secrets.insert(credential_name.clone(), secret);
	}
	Ok(secrets)
}

/// Build the resolver shared by the daemon, reload handle, proxy,
/// and bridge.
///
/// `static_secrets` carries every credential the static provider
/// chain produced at startup (server credentials plus every OAuth
/// `client_secret_credential`). `oauth_credentials` is the
/// configuration's `oauth` map. When that map is non-empty this
/// builds a [`CompositeResolver`] that routes OAuth-named lookups
/// to an [`OAuthResolver`] and falls back to a [`StaticResolver`]
/// for everything else; otherwise the static resolver is returned
/// directly.
///
/// The returned `Arc<dyn CredentialResolver>` is the seam every
/// runtime consumer holds. `Arc` makes reload cheap: reload rebuilds
/// the composite and swaps in a new `Arc`, while in-flight requests
/// keep dispatching against the previous one until they complete.
pub(crate) fn build_resolver(
	static_secrets: HashMap<String, Secret>,
	oauth_credentials: &HashMap<String, OAuthCredential>,
) -> Arc<dyn CredentialResolver> {
	if oauth_credentials.is_empty() {
		return Arc::new(StaticResolver::new(static_secrets));
	}

	// Extract OAuth client secrets from the static map first, then
	// move what remains into the static resolver. The lookup borrow
	// ends before `static_secrets` is consumed.
	let token_requests = build_token_requests(oauth_credentials, &static_secrets);
	let static_resolver: Arc<dyn CredentialResolver> =
		Arc::new(StaticResolver::new(static_secrets));

	let oauth_cache = OAuthCache::new(token_requests, reqwest::Client::new(), DEFAULT_REFRESH_SKEW);
	let oauth_resolver: Arc<dyn CredentialResolver> = Arc::new(OAuthResolver::new(oauth_cache));

	let mut handlers: HashMap<String, Arc<dyn CredentialResolver>> = HashMap::new();
	for name in oauth_credentials.keys() {
		handlers.insert(name.clone(), Arc::clone(&oauth_resolver));
	}
	Arc::new(CompositeResolver::new(handlers, static_resolver))
}

/// Translate the configuration's `oauth` map into the
/// [`TokenRequest`] map that [`OAuthCache::new`] expects.
///
/// Each `client_secret_credential` is read from `static_secrets` and
/// must be present: [`collect_credential_references`] adds every
/// OAuth client-secret reference to the static set, so any miss here
/// would mean pre-resolution did not run before this builder.
fn build_token_requests(
	oauth_credentials: &HashMap<String, OAuthCredential>,
	static_secrets: &HashMap<String, Secret>,
) -> HashMap<String, TokenRequest> {
	let mut token_requests = HashMap::with_capacity(oauth_credentials.len());
	for (name, credential) in oauth_credentials {
		let client_secret = static_secrets
			.get(&credential.client_secret_credential)
			.cloned()
			.expect(
				"OAuth client_secret_credential must be pre-resolved by \
				 collect_credential_references",
			);
		token_requests.insert(
			name.clone(),
			TokenRequest {
				token_endpoint: credential.token_endpoint.clone(),
				client_id: credential.client_id.clone(),
				client_secret,
				scope: credential.scope.clone(),
				audience: credential.audience.clone(),
			},
		);
	}
	token_requests
}

#[cfg(test)]
mod tests {
	//! Tests for the credential pre-resolution helper. Each test
	//! builds its own runtime and a `tempfile::TempDir`-backed
	//! credential provider, then drives `collect_credential_references`,
	//! `resolve_all`, and `build_resolver` end-to-end.

	use std::collections::HashMap;

	use mcp_gateway_config::{GatewayConfig, ServerDefinition, Transport};
	use mcp_gateway_credentials::CredentialProvider;

	use super::{build_resolver, collect_credential_references, resolve_all};

	/// Build a `ServerDefinition` with a credential reference, used
	/// across multiple tests to keep fixtures terse.
	fn server_definition(credential: Option<&str>, enabled: bool) -> ServerDefinition {
		ServerDefinition {
			enabled,
			env: HashMap::new(),
			credential: credential.map(str::to_owned),
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Http {
				url: "https://example.com/mcp/".to_owned(),
				headers: HashMap::new(),
			},
		}
	}

	/// Mock token issuer that emits sequential bearer tokens. Shared
	/// across the OAuth-routing test so each call returns a fresh
	/// value the assertion can match.
	#[derive(Default)]
	struct MockTokenIssuer {
		serial: std::sync::Mutex<u64>,
	}

	/// Handler for the mock token endpoint: increments the issuer's
	/// counter and returns a JSON `client_credentials` token response
	/// with a long lifetime so the test never trips refresh logic.
	async fn handle_token_issue(
		axum::extract::State(issuer): axum::extract::State<std::sync::Arc<MockTokenIssuer>>,
	) -> (
		axum::http::StatusCode,
		axum::response::Json<serde_json::Value>,
	) {
		let mut serial = issuer.serial.lock().expect("issuer lock");
		*serial += 1;
		(
			axum::http::StatusCode::OK,
			axum::response::Json(serde_json::json!({
				"access_token": format!("oauth-token-{}", *serial),
				"expires_in": 3600,
				"token_type": "Bearer"
			})),
		)
	}

	/// Boot a mock OAuth token endpoint on a random port and return
	/// the URL of the `/oauth/token` route. The server runs on a
	/// detached task; the test only needs to know the URL.
	async fn spawn_mock_token_endpoint() -> String {
		use axum::Router;
		use axum::routing::post;
		use tokio::net::TcpListener;

		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		let address = listener.local_addr().expect("addr");
		let issuer = std::sync::Arc::new(MockTokenIssuer::default());
		let app = Router::new()
			.route("/oauth/token", post(handle_token_issue))
			.with_state(std::sync::Arc::clone(&issuer));
		tokio::spawn(async move {
			axum::serve(listener, app).await.expect("mock server runs");
		});
		format!("http://{address}/oauth/token")
	}

	/// `build_resolver` wraps the pre-resolved secrets in a
	/// [`StaticResolver`] reachable through the
	/// [`CredentialResolver`](mcp_gateway_credentials::CredentialResolver)
	/// trait surface, the same surface the daemon, reload handle,
	/// proxy, and bridge will share. A miss surfaces as a
	/// human-readable error rather than a panic.
	#[test]
	fn pre_resolved_secrets_are_accessible_through_resolver_trait() {
		let temp_dir = tempfile::tempdir().expect("create temp dir");
		std::fs::write(temp_dir.path().join("foo"), "test-value").expect("write credential file");

		let mut servers = HashMap::new();
		servers.insert(
			"service".to_owned(),
			ServerDefinition {
				enabled: true,
				env: HashMap::new(),
				credential: Some("foo".to_owned()),
				credential_header: None,
				credential_prefix: None,
				request_timeout_seconds: None,
				credential_injection: None,
				transport: Transport::Http {
					url: "https://example.com/mcp/".to_owned(),
					headers: HashMap::new(),
				},
			},
		);
		let config = GatewayConfig {
			servers,
			..Default::default()
		};

		let provider = CredentialProvider::builder()
			.with_credentials_dir(temp_dir.path().to_path_buf())
			.build();

		let references = collect_credential_references(&config);
		let runtime = tokio::runtime::Runtime::new().expect("build runtime");
		let trait_object = runtime.block_on(async {
			let secrets = resolve_all(&provider, &references)
				.await
				.expect("pre-resolution succeeds");
			build_resolver(secrets, &config.oauth)
		});

		let known = runtime
			.block_on(trait_object.resolve("foo"))
			.expect("known credential resolves through the trait");
		assert_eq!(known.expose(), "test-value");

		let unknown = runtime.block_on(trait_object.resolve("absent"));
		match unknown {
			Err(message) => assert!(
				message.contains("absent"),
				"missing credential error should name it, got {message:?}",
			),
			Ok(_) => panic!("a credential that was never pre-resolved must fail the trait call"),
		}
	}

	/// A missing credential surfaces a `CredentialResolutionError`
	/// that names the server which referenced it. The error shape
	/// matches the one produced by
	/// `mcp_gateway_config::resolve_credentials`, so the console
	/// error path is identical regardless of where the failure was
	/// detected.
	#[test]
	fn missing_credential_fails_with_server_attribution() {
		let temp_dir = tempfile::tempdir().expect("create temp dir");

		let mut servers = HashMap::new();
		servers.insert(
			"service".to_owned(),
			server_definition(Some("missing"), true),
		);
		let config = GatewayConfig {
			servers,
			..Default::default()
		};

		let provider = CredentialProvider::builder()
			.with_credentials_dir(temp_dir.path().to_path_buf())
			.build();

		let references = collect_credential_references(&config);
		let runtime = tokio::runtime::Runtime::new().expect("build runtime");
		let error = runtime
			.block_on(resolve_all(&provider, &references))
			.expect_err("missing credential must fail pre-resolution");

		assert_eq!(error.server, "service");
		assert_eq!(error.credential, "missing");
		assert!(
			error.reason.contains("not found"),
			"reason should mention the underlying not-found error, got: {}",
			error.reason,
		);
	}

	/// A configuration whose servers reference no credentials yields
	/// an empty reference map, and `resolve_all` produces an empty
	/// secrets map without invoking the provider chain.
	#[test]
	fn servers_without_credentials_skip_resolution() {
		let mut servers = HashMap::new();
		servers.insert("public-a".to_owned(), server_definition(None, true));
		servers.insert("public-b".to_owned(), server_definition(None, true));
		let config = GatewayConfig {
			servers,
			..Default::default()
		};

		let references = collect_credential_references(&config);
		assert!(references.is_empty());

		// A provider with no sources configured would error on any
		// lookup; the empty reference map proves none were attempted.
		let provider = CredentialProvider::builder().build();
		let runtime = tokio::runtime::Runtime::new().expect("build runtime");
		let secrets = runtime
			.block_on(resolve_all(&provider, &references))
			.expect("empty references resolve without error");
		assert!(secrets.is_empty());
	}

	/// A disabled server's credential reference is still pre-resolved
	/// at startup. This locks in the boundary alignment between
	/// `collect_credential_references` and
	/// `mcp_gateway_config::resolve_credentials` (both walk all
	/// servers regardless of enabled state) so a typo in a disabled
	/// server's credential is caught at startup, not at re-enable
	/// time.
	#[test]
	fn disabled_servers_credentials_are_pre_resolved() {
		let temp_dir = tempfile::tempdir().expect("create temp dir");
		std::fs::write(temp_dir.path().join("must-resolve"), "value-for-disabled")
			.expect("write credential file");

		let mut servers = HashMap::new();
		servers.insert(
			"dormant".to_owned(),
			server_definition(Some("must-resolve"), false),
		);
		let config = GatewayConfig {
			servers,
			..Default::default()
		};

		let references = collect_credential_references(&config);
		assert_eq!(
			references.get("must-resolve").map(String::as_str),
			Some("dormant"),
			"disabled server should still appear in references",
		);

		let provider = CredentialProvider::builder()
			.with_credentials_dir(temp_dir.path().to_path_buf())
			.build();
		let runtime = tokio::runtime::Runtime::new().expect("build runtime");
		let secrets = runtime
			.block_on(resolve_all(&provider, &references))
			.expect("disabled server's credential must resolve at startup");
		assert_eq!(
			secrets
				.get("must-resolve")
				.map(mcp_gateway_credentials::Secret::expose),
			Some("value-for-disabled"),
		);
	}

	/// Sentinel value used by the redaction test: high-entropy so
	/// a substring match against any captured tracing field is a
	/// reliable leak detector.
	const REDACTION_SENTINEL: &str = "TOTALLY-SECRET-SENTINEL-VALUE-8675309";

	/// Shared buffer that accumulates every captured tracing field
	/// value and message piece for later assertion.
	#[derive(Default)]
	struct CapturedFields {
		pieces: std::sync::Mutex<Vec<String>>,
	}

	impl CapturedFields {
		fn push(&self, piece: String) {
			self.pieces
				.lock()
				.expect("captured fields mutex must not be poisoned")
				.push(piece);
		}

		fn snapshot(&self) -> Vec<String> {
			self.pieces
				.lock()
				.expect("captured fields mutex must not be poisoned")
				.clone()
		}
	}

	/// Visitor that records every field's debug or string
	/// representation. Both shapes need capturing because tracing
	/// macros may use `%value` (Display, surfacing via
	/// `record_str`-adjacent paths) or `?value` (Debug via
	/// `record_debug`).
	struct CapturingVisitor<'recorder> {
		captured: &'recorder CapturedFields,
	}

	impl tracing::field::Visit for CapturingVisitor<'_> {
		fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
			self.captured.push(format!("{value:?}"));
		}

		fn record_str(&mut self, _field: &tracing::field::Field, value: &str) {
			self.captured.push(value.to_owned());
		}
	}

	/// The buffer the global capturing subscriber writes into while a
	/// capture test runs. A test sets it before resolving and clears it
	/// afterwards; events emitted outside a capture window are dropped.
	static ACTIVE_CAPTURE: std::sync::Mutex<Option<std::sync::Arc<CapturedFields>>> =
		std::sync::Mutex::new(None);

	/// Global tracing layer that copies every event's fields into the
	/// active capture buffer, when one is set.
	///
	/// It is installed as the process-wide default so the resolution
	/// callsites always register as enabled. A thread-local subscriber
	/// cannot guarantee that under parallel tests: a sibling test that
	/// reaches a callsite first, with no subscriber installed, has its
	/// interest cached as disabled for the rest of the process, after
	/// which the events never arrive and the capture buffer stays empty.
	struct GlobalCapturingLayer;

	impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for GlobalCapturingLayer {
		fn on_event(
			&self,
			event: &tracing::Event<'_>,
			_context: tracing_subscriber::layer::Context<'_, S>,
		) {
			let Some(captured) = ACTIVE_CAPTURE
				.lock()
				.expect("active capture mutex must not be poisoned")
				.clone()
			else {
				return;
			};
			let mut visitor = CapturingVisitor {
				captured: &captured,
			};
			event.record(&mut visitor);
		}
	}

	/// Install the global capturing subscriber exactly once for the test
	/// binary. Later calls are no-ops.
	fn install_global_capture() {
		use std::sync::OnceLock;
		use tracing_subscriber::layer::SubscriberExt;

		static INSTALLED: OnceLock<()> = OnceLock::new();
		INSTALLED.get_or_init(|| {
			let subscriber = tracing_subscriber::registry().with(GlobalCapturingLayer);
			tracing::subscriber::set_global_default(subscriber)
				.expect("the test binary installs no other global subscriber");
		});
	}

	/// Build a single-credential `GatewayConfig` and a matching
	/// `CredentialProvider` rooted at a `tempfile::TempDir` whose
	/// `sentinel-token` file holds [`REDACTION_SENTINEL`].
	fn build_sentinel_fixture() -> (tempfile::TempDir, GatewayConfig, CredentialProvider) {
		let temp_dir = tempfile::tempdir().expect("create temp dir");
		std::fs::write(temp_dir.path().join("sentinel-token"), REDACTION_SENTINEL)
			.expect("write credential file");

		let mut servers = HashMap::new();
		servers.insert(
			"sentinel-service".to_owned(),
			ServerDefinition {
				enabled: true,
				env: HashMap::new(),
				credential: Some("sentinel-token".to_owned()),
				credential_header: None,
				credential_prefix: None,
				request_timeout_seconds: None,
				credential_injection: None,
				transport: Transport::Http {
					url: "https://example.com/mcp/".to_owned(),
					headers: HashMap::new(),
				},
			},
		);
		let config = GatewayConfig {
			servers,
			..Default::default()
		};
		let provider = CredentialProvider::builder()
			.with_credentials_dir(temp_dir.path().to_path_buf())
			.build();
		(temp_dir, config, provider)
	}

	/// A captured-tracing test ensures the credential resolution
	/// path never emits a resolved credential value into any
	/// tracing event field or message. Credential names *are*
	/// allowed in events: operators want them for diagnostics.
	#[test]
	fn resolved_values_never_appear_in_tracing_output() {
		install_global_capture();

		let (_temp_dir, config, provider) = build_sentinel_fixture();
		let references = collect_credential_references(&config);
		let captured = std::sync::Arc::new(CapturedFields::default());

		// Route resolution events into this buffer for the duration of
		// the call, then stop capturing. The global subscriber may also
		// record events from other tests running concurrently; that is
		// harmless, since only the sentinel value is asserted against and
		// no other test emits it.
		*ACTIVE_CAPTURE
			.lock()
			.expect("active capture mutex must not be poisoned") = Some(std::sync::Arc::clone(&captured));

		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("build current-thread runtime");
		let secrets = runtime
			.block_on(resolve_all(&provider, &references))
			.expect("resolution succeeds for sentinel credential");

		*ACTIVE_CAPTURE
			.lock()
			.expect("active capture mutex must not be poisoned") = None;

		// Confirm the resolution actually saw the sentinel, otherwise the
		// redaction assertion is vacuous.
		assert_eq!(
			secrets
				.get("sentinel-token")
				.map(mcp_gateway_credentials::Secret::expose),
			Some(REDACTION_SENTINEL),
		);

		let pieces = captured.snapshot();
		assert!(
			!pieces.is_empty(),
			"resolution must emit at least one tracing event for the assertion to be meaningful",
		);
		for piece in &pieces {
			assert!(
				!piece.contains(REDACTION_SENTINEL),
				"sentinel credential value leaked into tracing field: {piece:?}",
			);
		}
	}

	/// Pre-resolution treats an OAuth-named server credential as
	/// *not* a static reference: the OAuth resolver fetches it at
	/// request time. The OAuth credential's `client_secret_credential`,
	/// however, *is* a static reference and must be pre-resolved so
	/// the OAuth cache has a value to use when authenticating to the
	/// authorisation server.
	#[test]
	fn oauth_named_server_credentials_are_skipped_but_their_client_secrets_are_collected() {
		use mcp_gateway_config::OAuthCredential;

		let mut servers = HashMap::new();
		servers.insert(
			"github".to_owned(),
			server_definition(Some("github-oauth"), true),
		);

		let mut oauth = HashMap::new();
		oauth.insert(
			"github-oauth".to_owned(),
			OAuthCredential {
				token_endpoint: "https://github.com/login/oauth/access_token".to_owned(),
				client_id: "client-id".to_owned(),
				client_secret_credential: "github-app-secret".to_owned(),
				scope: None,
				audience: None,
				refresh_skew: None,
			},
		);

		let config = GatewayConfig {
			servers,
			oauth,
			..Default::default()
		};

		let references = collect_credential_references(&config);

		assert!(
			!references.contains_key("github-oauth"),
			"oauth-named server credentials must not appear in the static reference set",
		);
		assert_eq!(
			references.get("github-app-secret").map(String::as_str),
			Some("oauth:github-oauth"),
			"every oauth client_secret_credential must be in the static reference set, attributed to its oauth entry",
		);
	}

	/// `build_resolver` returns the plain `StaticResolver` directly
	/// when the configuration declares no OAuth credentials, so the
	/// non-OAuth code path keeps its zero-overhead character.
	#[tokio::test]
	async fn build_resolver_without_oauth_returns_static_resolver_directly() {
		let mut secrets = HashMap::new();
		secrets.insert(
			"github-token".to_owned(),
			mcp_gateway_credentials::Secret::new("ghp_test".to_owned()),
		);

		let resolver = build_resolver(secrets, &HashMap::new());

		let value = resolver
			.resolve("github-token")
			.await
			.expect("static resolver returns the pre-resolved value");
		assert_eq!(value.expose(), "ghp_test");
	}

	/// When the configuration declares an OAuth credential, the
	/// resolver returned by `build_resolver` routes that name into
	/// the OAuth cache and falls through to the static map for
	/// everything else.
	#[tokio::test]
	async fn build_resolver_routes_oauth_names_to_oauth_resolver() {
		use mcp_gateway_config::OAuthCredential;

		// Building the OAuth cache constructs a reqwest client with no
		// bundled provider, so install the process default first.
		mcp_gateway_crypto::install();

		let token_endpoint = spawn_mock_token_endpoint().await;

		let mut secrets = HashMap::new();
		secrets.insert(
			"static-name".to_owned(),
			mcp_gateway_credentials::Secret::new("static-value".to_owned()),
		);
		secrets.insert(
			"app-secret".to_owned(),
			mcp_gateway_credentials::Secret::new("client-secret-value".to_owned()),
		);

		let mut oauth = HashMap::new();
		oauth.insert(
			"oauth-name".to_owned(),
			OAuthCredential {
				token_endpoint,
				client_id: "client-id".to_owned(),
				client_secret_credential: "app-secret".to_owned(),
				scope: None,
				audience: None,
				refresh_skew: None,
			},
		);

		let resolver = build_resolver(secrets, &oauth);

		let oauth_value = resolver
			.resolve("oauth-name")
			.await
			.expect("oauth credential resolves through the cache");
		assert_eq!(oauth_value.expose(), "oauth-token-1");

		let static_value = resolver
			.resolve("static-name")
			.await
			.expect("static credential still resolves through the fallback");
		assert_eq!(static_value.expose(), "static-value");
	}
}
