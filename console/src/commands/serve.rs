//! Handler for the `mcp serve` subcommand.
//!
//! Loads the gateway configuration, builds the application state,
//! binds the HTTP listener, and runs the axum server. All gateway
//! logic lives in the domain library crates — this handler wires
//! them together.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Args;

use mcp_gateway_credentials::CredentialProvider;
use mcp_gateway_output::Renderer;
use mcp_gateway_tls::TlsOptions;

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
	let gateway_config = mcp_gateway_config::load(&arguments.config)?;

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

	let mut credential_builder = CredentialProvider::builder().with_env_prefix("MCP_CREDENTIAL_");

	if let Some(directory) = &arguments.credentials_dir {
		credential_builder = credential_builder.with_credentials_dir(directory.clone());
	}

	let credential_provider = credential_builder.build();
	let credential_resolver: mcp_gateway_config::CredentialResolver = Box::new(move |name| {
		// Block on the async resolve within the sync resolver closure.
		let runtime = tokio::runtime::Handle::try_current().map_err(|error| error.to_string())?;
		runtime
			.block_on(credential_provider.resolve(name))
			.map(|secret| secret.expose().to_owned())
			.map_err(|error| error.to_string())
	});

	let state = mcp_gateway_daemon::AppState::new(gateway_config, Some(&credential_resolver))?;
	let state = Arc::new(state);
	let application = mcp_gateway_daemon::build_app(&state);

	// Resolve TLS configuration from the discovery chain.
	let tls_options = TlsOptions {
		cert_path: arguments.tls_cert.clone(),
		key_path: arguments.tls_key.clone(),
		self_signed: arguments.tls_self_signed,
	};
	let tls_config = mcp_gateway_tls::resolve(&tls_options).map_err(ConsoleError::Tls)?;

	let runtime = tokio::runtime::Runtime::new().map_err(ConsoleError::Serve)?;

	runtime.block_on(async {
		// Background task that periodically checks whether stdio
		// bridge processes have exited, logging crashes immediately
		// rather than waiting for the next request.
		let monitor_state = Arc::clone(&state);
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
			loop {
				interval.tick().await;
				monitor_state.check_bridge_health().await;
			}
		});

		let listener = tokio::net::TcpListener::bind(arguments.bind)
			.await
			.map_err(ConsoleError::Bind)?;

		if let Some(tls) = tls_config {
			let scheme = "https";
			renderer.human(|writer| {
				writeln!(
					writer,
					"gateway listening on {scheme}://{} (TLS: {})",
					arguments.bind,
					tls.source()
				)
			})?;

			tracing::info!(
				address = %arguments.bind,
				tls_source = %tls.source(),
				"gateway listening with TLS"
			);

			serve_tls(listener, application, tls, shutdown_signal()).await
		} else {
			renderer.human(|writer| {
				writeln!(writer, "gateway listening on http://{}", arguments.bind)
			})?;

			tracing::info!(address = %arguments.bind, "gateway listening");

			axum::serve(listener, application)
				.with_graceful_shutdown(shutdown_signal())
				.await
				.map_err(ConsoleError::Serve)?;

			Ok(())
		}?;

		renderer.human(|writer| writeln!(writer, "gateway shut down"))?;
		tracing::info!("gateway shut down");
		Ok(())
	})
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
