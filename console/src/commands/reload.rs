//! In-place reload of the gateway's configuration and credentials.
//!
//! Reload re-runs the same pipeline that runs at startup — load the
//! configuration file, pre-resolve every referenced credential, build
//! a router, and atomically install the result inside `AppState`.
//! Failure leaves the previously installed state untouched and is
//! surfaced through tracing as a `warn`-level event so an operator
//! can diagnose without losing service.
//!
//! This module owns the orchestration; the trigger (SIGHUP, an admin
//! endpoint, a watcher) is wired separately so each trigger can be
//! tested against the same `ReloadHandle::reload` entry point.

use std::path::PathBuf;
use std::sync::Arc;

use mcp_gateway_credentials::CredentialProvider;
use mcp_gateway_daemon::AppState;

use crate::commands::credential_resolution;
use crate::error::ConsoleError;

/// Orchestrates one reload cycle against a running `AppState`.
///
/// Holds everything reload needs: the live state, the configuration
/// file path passed at startup, and the credential provider built
/// from operator-supplied flags. The handle is `Clone` so multiple
/// triggers (signal task, integration tests) can share one instance.
#[derive(Clone)]
pub(crate) struct ReloadHandle {
	state: Arc<AppState>,
	config_path: PathBuf,
	credential_provider: Arc<CredentialProvider>,
}

impl ReloadHandle {
	/// Build a reload handle from the live state and the inputs that
	/// were used to build it at startup. The configuration is always
	/// re-read from `config_path` on each reload — operators who want
	/// to use a different file must restart the gateway.
	pub(crate) fn new(
		state: Arc<AppState>,
		config_path: PathBuf,
		credential_provider: Arc<CredentialProvider>,
	) -> Self {
		Self {
			state,
			config_path,
			credential_provider,
		}
	}

	/// Run one reload cycle.
	///
	/// On success, atomically installs a new router and resolved
	/// configuration. On failure, the previous state stays installed
	/// and the failure is logged. Either way, the running gateway
	/// keeps serving traffic.
	///
	/// # Errors
	///
	/// Returns [`ConsoleError`] if the configuration cannot be loaded
	/// or any referenced credential cannot be resolved. The state is
	/// unchanged on error.
	pub(crate) async fn reload(&self) -> Result<(), ConsoleError> {
		tracing::info!(
			path = %self.config_path.display(),
			"reloading gateway configuration"
		);

		let new_config = match mcp_gateway_config::load(&self.config_path) {
			Ok(config) => config,
			Err(error) => {
				tracing::warn!(
					path = %self.config_path.display(),
					error = %error,
					"reload failed: configuration could not be loaded; keeping previous state"
				);
				return Err(ConsoleError::Config(error));
			}
		};

		let references = credential_resolution::collect_credential_references(&new_config);
		let secrets = match credential_resolution::resolve_all(
			&self.credential_provider,
			&references,
		)
		.await
		{
			Ok(map) => map,
			Err(error) => {
				tracing::warn!(
					server = %error.server,
					credential = %error.credential,
					reason = %error.reason,
					"reload failed: credential could not be resolved; keeping previous state"
				);
				return Err(ConsoleError::AppState(
					mcp_gateway_daemon::AppStateError::from(error),
				));
			}
		};
		let resolver = credential_resolution::build_resolver(secrets, &new_config.oauth);

		match self.state.replace_inner(new_config, Some(resolver)) {
			Ok(()) => {
				tracing::info!("reload completed");
				Ok(())
			}
			Err(error) => {
				tracing::warn!(
					error = %error,
					"reload failed: router could not be built; keeping previous state"
				);
				Err(ConsoleError::AppState(error))
			}
		}
	}
}

#[cfg(test)]
mod tests {
	//! Reload tests build their own runtime, configuration file, and
	//! credentials directory in `tempfile::TempDir` fixtures. Each
	//! test exercises one observable property of reload via the
	//! `/ready` endpoint, which reads from `AppState::current()` and
	//! reflects the post-reload server set without rebuilding the
	//! axum application.

	use std::path::Path;
	use std::sync::Arc;

	use axum::body::Body;
	use axum::http::Request;
	use http_body_util::BodyExt;
	use mcp_gateway_credentials::CredentialProvider;
	use mcp_gateway_daemon::{AppState, build_app};
	use tower::ServiceExt;

	use super::ReloadHandle;
	use crate::commands::credential_resolution;

	/// Write a configuration JSON document to `path`. The document
	/// declares one HTTP server with the given name and an optional
	/// credential reference.
	fn write_config(path: &Path, server_name: &str, credential: Option<&str>) {
		let mut server = serde_json::json!({
			"transport": "http",
			"url": "https://upstream.invalid/mcp/",
		});
		if let Some(name) = credential {
			server["credential"] = serde_json::Value::String(name.to_owned());
		}
		let document = serde_json::json!({
			"servers": { server_name: server },
		});
		std::fs::write(path, serde_json::to_string_pretty(&document).unwrap())
			.expect("write config file");
	}

	/// Build an `AppState` from the configuration at `config_path`,
	/// pre-resolving credentials with the supplied provider.
	fn initial_state(
		runtime: &tokio::runtime::Runtime,
		config_path: &Path,
		provider: &CredentialProvider,
	) -> Arc<AppState> {
		let config = mcp_gateway_config::load(config_path).expect("initial config loads");
		let references = credential_resolution::collect_credential_references(&config);
		let secrets = runtime
			.block_on(credential_resolution::resolve_all(provider, &references))
			.expect("initial credentials resolve");
		let resolver = credential_resolution::build_resolver(secrets, &config.oauth);
		Arc::new(AppState::new(config, Some(resolver)).expect("initial AppState"))
	}

	/// Issue a `GET /ready` against `application` and parse the JSON
	/// body. The application is cloned so the caller can reuse it.
	async fn fetch_ready(application: axum::Router) -> serde_json::Value {
		let response = application
			.oneshot(
				Request::builder()
					.uri("/ready")
					.body(Body::empty())
					.unwrap(),
			)
			.await
			.expect("ready request");
		let bytes = response.into_body().collect().await.unwrap().to_bytes();
		serde_json::from_slice(&bytes).expect("ready body is JSON")
	}

	/// A successful reload picks up server entries added to the
	/// configuration file and exposes them through `/ready` without
	/// rebuilding the axum application.
	#[test]
	fn reload_picks_up_new_server_entries() {
		let config_dir = tempfile::tempdir().expect("config tempdir");
		let credentials_dir = tempfile::tempdir().expect("credentials tempdir");
		let config_path = config_dir.path().join("config.json");

		write_config(&config_path, "alpha", None);

		let provider = Arc::new(
			CredentialProvider::builder()
				.with_credentials_dir(credentials_dir.path().to_path_buf())
				.build(),
		);
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("current-thread runtime");

		let state = initial_state(&runtime, &config_path, &provider);
		let application = build_app(&state);

		let pre = runtime.block_on(fetch_ready(application.clone()));
		assert!(pre["servers"]["alpha"].is_object());
		assert!(pre["servers"]["beta"].is_null());

		write_config(&config_path, "beta", None);
		let handle = ReloadHandle::new(Arc::clone(&state), config_path.clone(), provider);
		runtime.block_on(handle.reload()).expect("reload succeeds");

		let post = runtime.block_on(fetch_ready(application));
		assert!(post["servers"]["beta"].is_object());
		assert!(
			post["servers"]["alpha"].is_null(),
			"old server should be gone after reload, got {post:?}",
		);
	}

	/// A reload referencing a credential that cannot be resolved
	/// returns an error and leaves the previous configuration in
	/// place. The gateway keeps serving traffic.
	#[test]
	fn reload_failure_keeps_previous_state() {
		let config_dir = tempfile::tempdir().expect("config tempdir");
		let credentials_dir = tempfile::tempdir().expect("credentials tempdir");
		let config_path = config_dir.path().join("config.json");

		// Initial credential present, initial config references it.
		std::fs::write(credentials_dir.path().join("token"), "initial-secret")
			.expect("write credential file");
		write_config(&config_path, "alpha", Some("token"));

		let provider = Arc::new(
			CredentialProvider::builder()
				.with_credentials_dir(credentials_dir.path().to_path_buf())
				.build(),
		);
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("current-thread runtime");

		let state = initial_state(&runtime, &config_path, &provider);
		let application = build_app(&state);

		// Rewrite the configuration to reference a credential that
		// the provider chain cannot resolve.
		write_config(&config_path, "beta", Some("missing-token"));

		let handle = ReloadHandle::new(Arc::clone(&state), config_path.clone(), provider);
		let outcome = runtime.block_on(handle.reload());
		assert!(outcome.is_err(), "reload with missing credential must err");

		// Original server set is still serving.
		let after = runtime.block_on(fetch_ready(application));
		assert!(
			after["servers"]["alpha"].is_object(),
			"original server must still be present, got {after:?}",
		);
		assert!(after["servers"]["beta"].is_null());
	}

	/// Reloading after a credential value rotates on disk succeeds
	/// without errors. The resolver picks up the new value through
	/// the same provider used at startup.
	#[test]
	fn reload_succeeds_after_credential_rotation() {
		let config_dir = tempfile::tempdir().expect("config tempdir");
		let credentials_dir = tempfile::tempdir().expect("credentials tempdir");
		let config_path = config_dir.path().join("config.json");

		std::fs::write(credentials_dir.path().join("token"), "initial-secret")
			.expect("write initial credential");
		write_config(&config_path, "alpha", Some("token"));

		let provider = Arc::new(
			CredentialProvider::builder()
				.with_credentials_dir(credentials_dir.path().to_path_buf())
				.build(),
		);
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("current-thread runtime");

		let state = initial_state(&runtime, &config_path, &provider);

		// Rotate the credential file.
		std::fs::write(credentials_dir.path().join("token"), "rotated-secret")
			.expect("rotate credential");

		let handle = ReloadHandle::new(Arc::clone(&state), config_path.clone(), provider);
		runtime
			.block_on(handle.reload())
			.expect("reload after rotation succeeds");
	}
}
