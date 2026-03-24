//! TLS configuration and certificate discovery for the MCP gateway.
//!
//! Provides a certificate resolution chain that searches for TLS
//! certificates in multiple locations, similar to how the credentials
//! crate resolves secrets. The chain searches in priority order:
//!
//! 1. Explicit paths (CLI flags)
//! 2. Conventional paths (`~/.mcp/tls/cert.pem` + `key.pem`)
//! 3. Environment variables (`MCP_TLS_CERT` + `MCP_TLS_KEY`)
//! 4. Self-signed generation (feature-gated, opt-in)
//!
//! If no source provides certificates, the gateway runs plain HTTP.

mod discover;

#[cfg(feature = "self-signed")]
mod selfsigned;

use std::path::PathBuf;
use std::sync::Arc;

pub use discover::CertificateSource;

/// A resolved TLS configuration ready for use with a TLS acceptor.
///
/// Wraps a `rustls::ServerConfig` and records where the certificates
/// came from for diagnostic logging.
pub struct TlsConfig {
	/// The rustls server configuration.
	server_config: Arc<rustls::ServerConfig>,
	/// Where the certificates were loaded from.
	source: CertificateSource,
}

impl TlsConfig {
	/// The rustls server configuration for use with a TLS acceptor.
	#[must_use]
	pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
		Arc::clone(&self.server_config)
	}

	/// Where the certificates were loaded from.
	#[must_use]
	pub fn source(&self) -> &CertificateSource {
		&self.source
	}
}

/// Options for TLS certificate resolution.
///
/// Built by the console from CLI flags and passed to
/// [`resolve`] to discover and load certificates.
#[derive(Debug, Default)]
pub struct TlsOptions {
	/// Explicit path to a PEM certificate file.
	pub cert_path: Option<PathBuf>,
	/// Explicit path to a PEM private key file.
	pub key_path: Option<PathBuf>,
	/// Generate an ephemeral self-signed certificate for localhost.
	pub self_signed: bool,
}

/// Resolve TLS configuration from the discovery chain.
///
/// Searches for certificates in priority order and returns the
/// first valid configuration found. Returns `None` if no TLS
/// source is available (the gateway should run plain HTTP).
///
/// # Errors
///
/// Returns an error if a source is found but the certificates
/// cannot be loaded (malformed PEM, wrong key type, etc.).
pub fn resolve(options: &TlsOptions) -> Result<Option<TlsConfig>, TlsError> {
	// 1. Explicit paths from CLI flags.
	if let Some(cert_path) = &options.cert_path {
		let key_path = options
			.key_path
			.as_ref()
			.ok_or_else(|| TlsError::Configuration("--tls-cert requires --tls-key".to_owned()))?;
		let config = discover::load_from_paths(cert_path, key_path)?;
		return Ok(Some(TlsConfig {
			server_config: Arc::new(config),
			source: CertificateSource::Explicit {
				cert: cert_path.clone(),
				key: key_path.clone(),
			},
		}));
	}

	if options.key_path.is_some() {
		return Err(TlsError::Configuration(
			"--tls-key requires --tls-cert".to_owned(),
		));
	}

	// 2. Conventional paths (~/.mcp/tls/).
	if let Some((config, cert_path, key_path)) = discover::load_from_conventional_paths()? {
		tracing::info!(
			cert = %cert_path.display(),
			key = %key_path.display(),
			"discovered TLS certificates at conventional path"
		);
		return Ok(Some(TlsConfig {
			server_config: Arc::new(config),
			source: CertificateSource::Conventional {
				cert: cert_path,
				key: key_path,
			},
		}));
	}

	// 3. Environment variables.
	if let Some((config, cert_path, key_path)) = discover::load_from_env()? {
		tracing::info!(
			cert = %cert_path.display(),
			key = %key_path.display(),
			"loaded TLS certificates from environment variables"
		);
		return Ok(Some(TlsConfig {
			server_config: Arc::new(config),
			source: CertificateSource::Environment {
				cert: cert_path,
				key: key_path,
			},
		}));
	}

	// 4. Self-signed generation (feature-gated).
	if options.self_signed {
		#[cfg(feature = "self-signed")]
		{
			let (config, source) = selfsigned::generate()?;
			return Ok(Some(TlsConfig {
				server_config: Arc::new(config),
				source,
			}));
		}

		#[cfg(not(feature = "self-signed"))]
		return Err(TlsError::Configuration(
			"--tls-self-signed requires the 'self-signed' feature".to_owned(),
		));
	}

	Ok(None)
}

/// Errors from TLS certificate resolution.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
	/// A certificate or key file could not be read.
	#[error("failed to read TLS file {path}: {reason}")]
	FileRead {
		/// Path to the file that could not be read.
		path: PathBuf,
		/// Description of the failure.
		reason: String,
	},

	/// A PEM file could not be parsed.
	#[error("failed to parse PEM from {path}: {reason}")]
	PemParse {
		/// Path to the file that could not be parsed.
		path: PathBuf,
		/// Description of the failure.
		reason: String,
	},

	/// The rustls configuration could not be built.
	#[error("TLS configuration error: {0}")]
	Rustls(#[from] rustls::Error),

	/// A configuration constraint was violated.
	#[error("{0}")]
	Configuration(String),

	/// Self-signed certificate generation failed.
	#[cfg(feature = "self-signed")]
	#[error("failed to generate self-signed certificate: {0}")]
	Generation(String),
}
