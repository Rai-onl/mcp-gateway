//! Handler for the `mcp serve` subcommand.
//!
//! Loads the gateway configuration, builds the application state,
//! binds the HTTP listener, and runs the axum server. All gateway
//! logic lives in the domain library crates; this handler wires
//! them together.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Args;

use mcp_gateway_credentials::CredentialProvider;
use mcp_gateway_daemon::AppStateError;
use mcp_gateway_output::Renderer;
use mcp_gateway_tls::TlsOptions;

use crate::commands::credential_resolution;
use crate::commands::memory;
use crate::commands::reload::ReloadHandle;
use crate::error::ConsoleError;

/// Arguments for the `mcp serve` subcommand.
#[derive(Args, Debug)]
pub struct ServeArguments {
	/// Path to the JSON configuration file.
	#[arg(long)]
	pub config: PathBuf,

	/// Address and port to listen on.
	#[arg(long, default_value = "127.0.0.1:3000")]
	pub bind: SocketAddr,

	/// Directory containing credential files (one file per
	/// credential, named after the credential).
	#[arg(long)]
	pub credentials_dir: Option<PathBuf>,

	/// Path to a PEM certificate file for TLS.
	#[arg(long, requires = "tls_key", conflicts_with = "tls_self_signed")]
	pub tls_cert: Option<PathBuf>,

	/// Path to a PEM private key file for TLS.
	#[arg(long, requires = "tls_cert", conflicts_with = "tls_self_signed")]
	pub tls_key: Option<PathBuf>,

	/// Generate an ephemeral self-signed certificate for localhost.
	#[arg(long, conflicts_with_all = ["tls_cert", "tls_key"])]
	pub tls_self_signed: bool,

	/// Maximum time to wait for a credential helper command to
	/// produce output. Accepts humantime-style values such as
	/// `30s`, `1m`, or `2m 30s`. When unset, the gateway falls
	/// back to the `MCP_CREDENTIAL_TIMEOUT` environment variable
	/// and finally to the built-in default of thirty seconds.
	#[arg(long, value_parser = parse_humantime_duration)]
	pub credential_timeout: Option<Duration>,

	/// Disable the in-place reload trigger. By default, the gateway
	/// reloads its configuration and re-resolves credentials in
	/// place on receipt of `SIGHUP`. Reload re-reads the original
	/// `--config` file and re-runs the credential provider chain;
	/// if any step fails the previous configuration stays installed
	/// and the failure is logged at `warn`. Stdio bridges restart
	/// eagerly: in-flight requests for changed servers complete on
	/// the previous bridge, new requests spawn fresh children with
	/// the new environment. Top-level fields (`max_body_bytes`,
	/// `trusted_proxies`, `client_identity_headers`) are read once
	/// at startup and a process restart is required to change them.
	/// On non-Unix platforms reload is unavailable regardless of
	/// this flag.
	///
	/// When `--no-reload` is set, `SIGHUP` is logged and ignored.
	/// The gateway does *not* fall through to the default behaviour
	/// (process termination); operators who set this flag get a
	/// gateway that survives accidental hangup signals as well.
	#[arg(long)]
	pub no_reload: bool,

	/// Allow core dumps for the gateway process. By default the
	/// gateway lowers `RLIMIT_CORE` to zero at startup so that a
	/// crash cannot write live secrets to a post-mortem file.
	/// Operators running the gateway under a debugger or against a
	/// crash-reporter that captures cores should pass this flag to
	/// keep the OS default behaviour. Has no effect on platforms
	/// without `RLIMIT_CORE`.
	#[arg(long)]
	pub allow_core_dumps: bool,
}

/// Parse a humantime-style duration string from the command line.
///
/// Used by clap's `value_parser` to validate `--credential-timeout`
/// at parse time so a malformed value fails before any work begins.
fn parse_humantime_duration(input: &str) -> Result<Duration, String> {
	humantime::parse_duration(input).map_err(|error| error.to_string())
}

/// The environment variable that supplies the credential helper
/// command timeout when the command-line flag is absent.
const CREDENTIAL_TIMEOUT_ENVIRONMENT_VARIABLE: &str = "MCP_CREDENTIAL_TIMEOUT";

/// Resolve the credential helper command timeout from the available
/// inputs in precedence order: command-line flag, then the
/// environment variable, then the built-in default.
///
/// Factored as a pure function so the precedence chain can be
/// exercised without mutating the process environment, which is
/// `unsafe` under the workspace's edition 2024 / `forbid(unsafe_code)`
/// policy and would race across parallel tests.
///
/// # Errors
///
/// Returns [`ConsoleError::Environment`] if the environment variable
/// is set to a value that is not a valid humantime duration.
fn resolve_command_timeout(
	command_line_value: Option<Duration>,
	environment_value: Option<&str>,
) -> Result<Duration, ConsoleError> {
	if let Some(duration) = command_line_value {
		return Ok(duration);
	}
	if let Some(raw) = environment_value {
		return humantime::parse_duration(raw).map_err(|error| ConsoleError::Environment {
			variable: CREDENTIAL_TIMEOUT_ENVIRONMENT_VARIABLE.to_owned(),
			reason: error.to_string(),
		});
	}
	Ok(mcp_gateway_credentials::DEFAULT_COMMAND_TIMEOUT)
}

/// Start the gateway daemon.
///
/// Loads configuration, builds the router and HTTP application,
/// then runs the server until interrupted.
///
/// # Errors
///
/// Returns a [`ConsoleError`] if configuration loading, network
/// binding, or the server itself fails.
pub fn run(arguments: &ServeArguments, renderer: &Renderer) -> Result<(), ConsoleError> {
	apply_memory_hardening(arguments);

	let gateway_config = mcp_gateway_config::load(&arguments.config)?;

	report_startup(&gateway_config, arguments, renderer)?;

	// Build the runtime up-front so credential resolution and the
	// serve loop share it. A previous implementation built a
	// credential resolver closure that called `Handle::block_on`
	// before any runtime existed, which surfaced as a "no reactor
	// running" error during `AppState::new`.
	let runtime = tokio::runtime::Runtime::new().map_err(ConsoleError::Serve)?;

	let credential_provider = Arc::new(build_credential_provider(arguments)?);
	let credential_resolver =
		pre_resolve_credentials(&credential_provider, &gateway_config, &runtime)?;

	// Capture the authentication section before the config is moved
	// into the state. When present, the gateway becomes an OAuth 2.1
	// resource server: build the validator from the issuer's discovery
	// document now, so a token can be validated on the first request.
	let authentication = gateway_config.authentication.clone();
	// Keep a handle on the resolver for the introspection client secret
	// before the config-bound resolver moves into the state.
	let auth_resolver = Arc::clone(&credential_resolver);
	let state = Arc::new(mcp_gateway_daemon::AppState::new(
		gateway_config,
		Some(credential_resolver),
	)?);

	// The discovery fetch (and, for introspection, the client-secret
	// resolution) is a cold-start dependency: if it cannot complete at
	// startup the gateway cannot validate any token, so the failure is
	// fatal and exits non-zero. The error names the issuer or credential
	// so an operator can see what failed.
	//
	// When authentication is configured, also assemble the background
	// refresh inputs so the serve loop can keep the cached signing keys
	// and discovery document fresh ahead of expiry, rather than only
	// refreshing lazily on an unknown `kid` or a reload.
	let mut auth_refresh = None;
	if let Some(authentication) = &authentication {
		let auth_state = runtime.block_on(mcp_gateway_auth::setup::build_auth_state(
			authentication,
			auth_resolver.as_ref(),
		))?;
		state.set_auth(Arc::new(auth_state));
		auth_refresh = Some(build_auth_refresh(authentication));
	}

	let application = mcp_gateway_daemon::build_app(&state);

	let reload_handle = (!arguments.no_reload).then(|| {
		ReloadHandle::new(
			Arc::clone(&state),
			arguments.config.clone(),
			Arc::clone(&credential_provider),
		)
	});

	let tls_options = TlsOptions {
		cert_path: arguments.tls_cert.clone(),
		key_path: arguments.tls_key.clone(),
		self_signed: arguments.tls_self_signed,
	};
	let tls_config = mcp_gateway_tls::resolve(&tls_options).map_err(ConsoleError::Tls)?;

	let context = ServeContext {
		tls_config,
		reload_handle,
		auth_refresh,
	};
	runtime.block_on(serve_loop(
		state,
		application,
		arguments.bind,
		renderer,
		context,
	))
}

/// Optional runtime-level wiring passed to [`serve_loop`].
///
/// Bundling these together keeps the `serve_loop` signature inside
/// the workspace's `too-many-arguments-threshold`. Both fields are
/// optional because TLS and reload are deployment-time choices.
struct ServeContext {
	tls_config: Option<mcp_gateway_tls::TlsConfig>,
	reload_handle: Option<ReloadHandle>,
	/// Background refresh inputs, present only when inbound authentication
	/// is configured.
	auth_refresh: Option<AuthRefresh>,
}

/// The background-refresh cadences, present only when inbound
/// authentication is configured. The refresh loops read the live
/// configuration and resolver from the shared state themselves, so only
/// the timer intervals need to be carried here.
struct AuthRefresh {
	/// How often to proactively refresh the cached JWKS, from
	/// `authentication.jwks_cache_seconds`.
	jwks_interval: Duration,
	/// How often to re-fetch the discovery document, from
	/// `authentication.discovery_cache_seconds`.
	discovery_interval: Duration,
}

/// Read the background-refresh cadences from the authentication
/// configuration.
fn build_auth_refresh(authentication: &mcp_gateway_config::AuthenticationConfig) -> AuthRefresh {
	AuthRefresh {
		jwks_interval: Duration::from_secs(authentication.jwks_cache_seconds),
		discovery_interval: Duration::from_secs(authentication.discovery_cache_seconds),
	}
}

/// Apply process-wide memory hardening before any secrets are
/// loaded, unless the operator has opted out.
///
/// Currently this lowers `RLIMIT_CORE` to zero so a crash cannot
/// write live secrets to a post-mortem dump. Failures are logged
/// at `warn` level and not propagated: an environment that already
/// disabled core dumps (typical under `systemd` with
/// `LimitCORE=0`) will refuse the redundant request, and the
/// gateway should still start so the operator can investigate.
fn apply_memory_hardening(arguments: &ServeArguments) {
	if arguments.allow_core_dumps {
		tracing::info!("core dumps left enabled (--allow-core-dumps)");
		return;
	}
	match memory::disable_core_dumps() {
		Ok(()) => tracing::info!("core dumps disabled (RLIMIT_CORE=0)"),
		Err(error) => tracing::warn!(
			error = %error,
			"failed to disable core dumps; continuing startup",
		),
	}
}

/// Render the human-readable and structured startup banner.
fn report_startup(
	gateway_config: &mcp_gateway_config::GatewayConfig,
	arguments: &ServeArguments,
	renderer: &Renderer,
) -> Result<(), ConsoleError> {
	let server_count = gateway_config
		.servers
		.values()
		.filter(|definition| definition.enabled)
		.count();

	renderer.human(|writer| {
		writeln!(
			writer,
			"starting gateway with {server_count} server(s) on {}",
			arguments.bind
		)
	})?;
	tracing::info!(
		servers = server_count,
		address = %arguments.bind,
		"starting gateway"
	);
	Ok(())
}

/// Build the credential provider from operator-supplied flags. The
/// provider is shared between startup pre-resolution and any later
/// reload trigger, so it must be constructed once.
fn build_credential_provider(
	arguments: &ServeArguments,
) -> Result<CredentialProvider, ConsoleError> {
	let environment_timeout = std::env::var(CREDENTIAL_TIMEOUT_ENVIRONMENT_VARIABLE).ok();
	let command_timeout =
		resolve_command_timeout(arguments.credential_timeout, environment_timeout.as_deref())?;

	let mut credential_builder = CredentialProvider::builder()
		.with_env_prefix("MCP_CREDENTIAL_")
		.with_command_timeout(command_timeout);
	if let Some(directory) = &arguments.credentials_dir {
		credential_builder = credential_builder.with_credentials_dir(directory.clone());
	}
	Ok(credential_builder.build())
}

/// Pre-resolve every referenced credential before `AppState` consumes
/// the resolver.
fn pre_resolve_credentials(
	credential_provider: &CredentialProvider,
	gateway_config: &mcp_gateway_config::GatewayConfig,
	runtime: &tokio::runtime::Runtime,
) -> Result<Arc<dyn mcp_gateway_credentials::CredentialResolver>, ConsoleError> {
	let credential_references =
		credential_resolution::collect_credential_references(gateway_config);
	let resolved_secrets = runtime
		.block_on(credential_resolution::resolve_all(
			credential_provider,
			&credential_references,
		))
		.map_err(AppStateError::from)?;
	Ok(credential_resolution::build_resolver(
		resolved_secrets,
		&gateway_config.oauth,
	))
}

/// Drive the gateway's serve loop: spawn the bridge health monitor,
/// bind the listener, and run `axum` (or `tokio-rustls` over `axum`)
/// until a shutdown signal arrives.
async fn serve_loop(
	state: Arc<mcp_gateway_daemon::AppState>,
	application: axum::Router,
	bind: SocketAddr,
	renderer: &Renderer,
	context: ServeContext,
) -> Result<(), ConsoleError> {
	let monitor_state = Arc::clone(&state);
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(Duration::from_secs(5));
		// Skip, not burst: a slow health check must not trigger a burst of
		// catch-up checks on recovery.
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			interval.tick().await;
			monitor_state.check_bridge_health().await;
		}
	});

	// When inbound authentication is configured, keep the cached signing
	// keys and discovery document fresh ahead of expiry on the operator-
	// configured cadences. Both loops read the reload-swappable auth state
	// each tick, so they follow a validator replaced by a reload.
	if let Some(refresh) = context.auth_refresh {
		tokio::spawn(mcp_gateway_daemon::run_key_refresh(
			Arc::clone(&state),
			refresh.jwks_interval,
		));
		tokio::spawn(mcp_gateway_daemon::run_discovery_refresh(
			Arc::clone(&state),
			refresh.discovery_interval,
		));
	}

	spawn_signal_handler(context.reload_handle);

	let listener = tokio::net::TcpListener::bind(bind)
		.await
		.map_err(ConsoleError::Bind)?;

	if let Some(tls) = context.tls_config {
		renderer.human(|writer| {
			writeln!(
				writer,
				"gateway listening on https://{} (TLS: {})",
				bind,
				tls.source()
			)
		})?;
		tracing::info!(
			address = %bind,
			tls_source = %tls.source(),
			"gateway listening with TLS"
		);
		serve_tls(listener, application, tls, shutdown_signal()).await?;
	} else {
		renderer.human(|writer| writeln!(writer, "gateway listening on http://{bind}"))?;
		tracing::info!(address = %bind, "gateway listening");
		axum::serve(listener, application)
			.with_graceful_shutdown(shutdown_signal())
			.await
			.map_err(ConsoleError::Serve)?;
	}

	renderer.human(|writer| writeln!(writer, "gateway shut down"))?;
	tracing::info!("gateway shut down");
	Ok(())
}

/// Install a `SIGHUP` handler.
///
/// When `reload_handle` is `Some`, each `SIGHUP` triggers an
/// in-place reload of the gateway. When `None` (because the operator
/// passed `--no-reload`), `SIGHUP` is logged and ignored: the
/// gateway does *not* fall through to the default termination
/// behaviour, since a hangup signal is rarely an intentional
/// shutdown request for a long-running daemon.
///
/// On non-Unix platforms there is no equivalent signal that can be
/// installed safely from Rust, so reload is simply unavailable.
#[cfg(unix)]
fn spawn_signal_handler(reload_handle: Option<ReloadHandle>) {
	use tokio::signal::unix::{SignalKind, signal};

	tokio::spawn(async move {
		let mut hup = match signal(SignalKind::hangup()) {
			Ok(stream) => stream,
			Err(error) => {
				tracing::error!(error = %error, "failed to install SIGHUP handler");
				return;
			}
		};
		log_reload_trigger_status(reload_handle.is_some());
		while hup.recv().await.is_some() {
			handle_hangup_signal(reload_handle.as_ref()).await;
		}
	});
}

#[cfg(unix)]
fn log_reload_trigger_status(enabled: bool) {
	if enabled {
		tracing::info!("SIGHUP reload trigger active");
	} else {
		tracing::info!("SIGHUP reload trigger disabled (--no-reload); SIGHUP will be ignored");
	}
}

#[cfg(unix)]
async fn handle_hangup_signal(reload_handle: Option<&ReloadHandle>) {
	let Some(handle) = reload_handle else {
		tracing::info!("received SIGHUP, ignoring (--no-reload is set)");
		return;
	};
	tracing::info!("received SIGHUP, beginning reload");
	if let Err(error) = handle.reload().await {
		tracing::warn!(
			error = %error,
			"reload trigger handled with error; previous configuration retained"
		);
	}
}

#[cfg(not(unix))]
fn spawn_signal_handler(_reload_handle: Option<ReloadHandle>) {
	tracing::info!("reload trigger is unavailable on this platform");
}

/// Serve the application over TLS using `tokio-rustls`.
///
/// Accepts TCP connections, upgrades them to TLS, then hands
/// the encrypted stream to axum via the `hyper` service interface.
async fn serve_tls(
	listener: tokio::net::TcpListener,
	application: axum::Router,
	tls_config: mcp_gateway_tls::TlsConfig,
	shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), ConsoleError> {
	use hyper_util::rt::TokioIo;
	use hyper_util::service::TowerToHyperService;
	use tokio_rustls::TlsAcceptor;
	use tower::Service as _;

	let tls_acceptor = TlsAcceptor::from(tls_config.server_config());

	// Pin the shutdown future so we can poll it in the loop.
	tokio::pin!(shutdown);

	loop {
		tokio::select! {
			() = &mut shutdown => {
				tracing::info!("shutting down TLS listener");
				break;
			}
			incoming = listener.accept() => {
				let (tcp_stream, remote_address) = incoming.map_err(ConsoleError::Serve)?;
				let connection_acceptor = tls_acceptor.clone();
				let router = application.clone();

				tokio::spawn(async move {
					// Timeout the TLS handshake to prevent clients
					// from holding connections open indefinitely.
					let handshake = tokio::time::timeout(
						std::time::Duration::from_secs(10),
						connection_acceptor.accept(tcp_stream),
					);

					let Ok(Ok(tls_stream)) = handshake.await else {
						tracing::debug!(
							address = %remote_address,
							"TLS handshake failed or timed out"
						);
						return;
					};

					let transport = TokioIo::new(tls_stream);
					let connection_builder = hyper_util::server::conn::auto::Builder::new(
						hyper_util::rt::TokioExecutor::new(),
					);

					let mut make_service = router
						.into_make_service_with_connect_info::<SocketAddr>();
					let tower_service = make_service
						.call(remote_address)
						.await
						.expect("infallible make_service");
					let hyper_service = TowerToHyperService::new(tower_service);

					if let Err(error) = connection_builder
						.serve_connection(transport, hyper_service)
						.await
					{
						tracing::debug!(
							address = %remote_address,
							error = %error,
							"connection error"
						);
					}
				});
			}
		}
	}

	Ok(())
}

/// Wait for a shutdown signal (SIGINT or SIGTERM).
///
/// On Unix systems, listens for both SIGINT (Ctrl+C from the
/// terminal) and SIGTERM (sent by process managers, container
/// runtimes, and `kill`). On non-Unix systems, only Ctrl+C is
/// supported.
///
/// When either signal is received, this future completes and
/// axum begins its graceful shutdown sequence: it stops accepting
/// new connections and waits for in-flight requests to finish
/// before the server task completes.
async fn shutdown_signal() {
	use tokio::signal;

	let ctrl_c = async {
		signal::ctrl_c()
			.await
			.expect("failed to install SIGINT handler");
	};

	#[cfg(unix)]
	let terminate = async {
		signal::unix::signal(signal::unix::SignalKind::terminate())
			.expect("failed to install SIGTERM handler")
			.recv()
			.await;
	};

	// On non-Unix platforms, SIGTERM is not available so we
	// use a future that never completes, making Ctrl+C the
	// only shutdown mechanism.
	#[cfg(not(unix))]
	let terminate = std::future::pending::<()>();

	tokio::select! {
		() = ctrl_c => {
			tracing::info!("received SIGINT, shutting down");
		}
		() = terminate => {
			tracing::info!("received SIGTERM, shutting down");
		}
	}
}

#[cfg(test)]
mod tests {
	use std::time::Duration;

	use clap::Parser;

	use super::{ServeArguments, resolve_command_timeout};
	use mcp_gateway_credentials::DEFAULT_COMMAND_TIMEOUT;

	/// Test harness wrapping `ServeArguments` so it can be parsed
	/// directly from a `&[&str]` argv slice without having to invoke
	/// the full `Console` parser.
	#[derive(Parser, Debug)]
	struct TestParser {
		#[command(flatten)]
		arguments: ServeArguments,
	}

	/// `--credential-timeout` accepts humantime-style values and
	/// surfaces them as a `Duration`.
	#[test]
	fn credential_timeout_flag_parses_humantime_duration() {
		let parsed = TestParser::try_parse_from([
			"test",
			"--config",
			"/tmp/config.json",
			"--credential-timeout",
			"45s",
		])
		.expect("parses with explicit timeout");
		assert_eq!(
			parsed.arguments.credential_timeout,
			Some(Duration::from_secs(45))
		);
	}

	/// Omitting `--credential-timeout` leaves the field as `None`
	/// so the runtime can apply the env-var or built-in default.
	#[test]
	fn credential_timeout_flag_absent_yields_none() {
		let parsed = TestParser::try_parse_from(["test", "--config", "/tmp/config.json"])
			.expect("parses without timeout");
		assert!(parsed.arguments.credential_timeout.is_none());
	}

	/// A malformed humantime duration is rejected at parse time
	/// rather than silently coerced.
	#[test]
	fn credential_timeout_flag_rejects_invalid_duration() {
		let outcome = TestParser::try_parse_from([
			"test",
			"--config",
			"/tmp/config.json",
			"--credential-timeout",
			"forty-five",
		]);
		assert!(outcome.is_err(), "invalid duration must fail to parse");
	}

	/// The command-line value takes precedence over both the
	/// environment variable and the built-in default.
	#[test]
	fn command_line_credential_timeout_wins_over_environment_and_default() {
		let resolved = resolve_command_timeout(Some(Duration::from_secs(45)), Some("90s"))
			.expect("explicit command-line value resolves");
		assert_eq!(resolved, Duration::from_secs(45));
	}

	/// Without a command-line value, the environment variable
	/// provides the timeout when it is well-formed.
	#[test]
	fn environment_credential_timeout_used_when_command_line_absent() {
		let resolved = resolve_command_timeout(None, Some("90s"))
			.expect("environment value resolves when command-line is absent");
		assert_eq!(resolved, Duration::from_secs(90));
	}

	/// With neither command-line nor environment value, the
	/// built-in default applies. Locks the documented
	/// thirty-second fallback into the test surface.
	#[test]
	fn default_credential_timeout_applied_when_unspecified() {
		let resolved =
			resolve_command_timeout(None, None).expect("default applies when nothing is specified");
		assert_eq!(resolved, DEFAULT_COMMAND_TIMEOUT);
	}

	/// A malformed environment value surfaces as an error at
	/// startup rather than silently falling through to the
	/// default.
	#[test]
	fn malformed_environment_credential_timeout_returns_error() {
		let outcome = resolve_command_timeout(None, Some("forty-five"));
		assert!(
			outcome.is_err(),
			"malformed environment value must fail loudly"
		);
	}
}
