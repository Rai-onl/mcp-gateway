//! Top-level error type for the console dispatcher.
//!
//! [`ConsoleError`] wraps every domain-crate error so that
//! `main()` can format and exit with a single match. Exit codes
//! follow `sysexits.h` conventions, giving scripts and CI systems
//! a machine-readable signal beyond pass/fail.

use mcp_gateway_config::ConfigError;
use mcp_gateway_daemon::AppStateError;
use mcp_gateway_tls::TlsError;

/// Wraps all domain errors that can surface through the console
/// dispatcher. Each variant carries the original error for
/// transparent formatting via `thiserror`.
#[derive(Debug, thiserror::Error)]
pub enum ConsoleError {
	/// A configuration file error (missing, unreadable, or invalid).
	#[error(transparent)]
	Config(#[from] ConfigError),

	/// Application state could not be built (credential resolution
	/// failure or server runtime initialisation error).
	#[error(transparent)]
	AppState(#[from] AppStateError),

	/// TLS certificate resolution or configuration failed.
	#[error(transparent)]
	Tls(#[from] TlsError),

	/// A network binding error (address already in use, permission denied).
	#[error("failed to bind to address: {0}")]
	Bind(std::io::Error),

	/// The gateway daemon stopped unexpectedly.
	#[error("gateway stopped: {0}")]
	Serve(std::io::Error),

	/// A generic I/O error that does not belong to a specific domain.
	#[error(transparent)]
	Io(#[from] std::io::Error),

	/// An environment variable that the gateway reads at startup
	/// holds a value that cannot be interpreted. Surfaces as a
	/// configuration-class failure so operators can correct the
	/// environment without touching the configuration file.
	#[error("invalid value for environment variable {variable}: {reason}")]
	Environment {
		/// The environment variable that was being read.
		variable: String,
		/// Why the value could not be interpreted.
		reason: String,
	},
}

impl ConsoleError {
	/// Map this error to a `sysexits.h`-style exit code.
	///
	/// The mapping centralises exit code policy in the console
	/// binary — domain crates never need to know about process
	/// exit conventions.
	///
	/// | Code | Constant         | When                                      |
	/// |------|------------------|-------------------------------------------|
	/// |  1   | `EX_GENERAL`     | Generic I/O or unclassified errors         |
	/// | 70   | `EX_SOFTWARE`    | Internal software error (daemon crash)     |
	/// | 71   | `EX_OSERR`      | OS-level failure (bind, resource exhaustion)|
	/// | 78   | `EX_CONFIG`      | Configuration file errors                  |
	#[must_use]
	pub fn exit_code(&self) -> u8 {
		match self {
			Self::Config(_) | Self::AppState(_) | Self::Tls(_) | Self::Environment { .. } => 78,
			Self::Bind(_) => 71,
			Self::Serve(_) => 70,
			Self::Io(_) => 1,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Configuration errors map to `EX_CONFIG` (78) because they
	/// indicate the environment is misconfigured.
	#[test]
	fn exit_code_for_config_error() {
		let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
		let error = ConsoleError::Config(ConfigError::Io(io_error));
		assert_eq!(error.exit_code(), 78);
	}

	/// Bind failures map to `EX_OSERR` (71) because the OS cannot
	/// fulfil the requested network binding.
	#[test]
	fn exit_code_for_bind_error() {
		let error = ConsoleError::Bind(std::io::Error::new(
			std::io::ErrorKind::AddrInUse,
			"address in use",
		));
		assert_eq!(error.exit_code(), 71);
	}

	/// Daemon crashes map to `EX_SOFTWARE` (70) because the server
	/// terminated due to an internal error.
	#[test]
	fn exit_code_for_serve_error() {
		let error = ConsoleError::Serve(std::io::Error::other("unexpected shutdown"));
		assert_eq!(error.exit_code(), 70);
	}

	/// Generic I/O errors fall through to exit code 1.
	#[test]
	fn exit_code_for_io_error() {
		let error = ConsoleError::Io(std::io::Error::other("disk full"));
		assert_eq!(error.exit_code(), 1);
	}

	/// Invalid environment variables map to `EX_CONFIG` (78) so
	/// operators see the same class of failure as a bad
	/// configuration file.
	#[test]
	fn exit_code_for_environment_error() {
		let error = ConsoleError::Environment {
			variable: "MCP_CREDENTIAL_TIMEOUT".to_owned(),
			reason: "not a duration".to_owned(),
		};
		assert_eq!(error.exit_code(), 78);
	}
}
