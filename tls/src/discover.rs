//! Certificate discovery chain.
//!
//! Searches for TLS certificates in conventional locations:
//! explicit paths, `~/.mcp/tls/`, and environment variables.
//! Each source returns a `rustls::ServerConfig` if certificates
//! are found and valid.

use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::TlsError;

/// Where the certificates were loaded from.
///
/// Recorded for diagnostic logging so operators can verify
/// which certificates the gateway is using.
#[derive(Debug, Clone)]
pub enum CertificateSource {
	/// Certificates provided via explicit CLI flags.
	Explicit {
		/// Path to the certificate file.
		cert: PathBuf,
		/// Path to the private key file.
		key: PathBuf,
	},

	/// Certificates discovered at `~/.mcp/tls/`.
	Conventional {
		/// Path to the certificate file.
		cert: PathBuf,
		/// Path to the private key file.
		key: PathBuf,
	},

	/// Certificates loaded from `MCP_TLS_CERT` and `MCP_TLS_KEY`
	/// environment variables.
	Environment {
		/// Path to the certificate file.
		cert: PathBuf,
		/// Path to the private key file.
		key: PathBuf,
	},

	/// Ephemeral self-signed certificate generated at startup.
	SelfSigned,
}

impl std::fmt::Display for CertificateSource {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Explicit { cert, .. } => {
				write!(formatter, "explicit ({})", cert.display())
			}
			Self::Conventional { cert, .. } => {
				write!(formatter, "conventional ({})", cert.display())
			}
			Self::Environment { cert, .. } => {
				write!(formatter, "environment ({})", cert.display())
			}
			Self::SelfSigned => write!(formatter, "self-signed (ephemeral)"),
		}
	}
}

/// Load certificates from explicit file paths.
pub fn load_from_paths(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, TlsError> {
	let certs = load_certs(cert_path)?;
	let key = load_private_key(key_path)?;
	build_server_config(certs, key)
}

/// Look for certificates at `~/.mcp/tls/cert.pem` and `key.pem`.
///
/// Returns `None` if the conventional directory or files do not
/// exist. Returns an error if the files exist but cannot be parsed.
pub fn load_from_conventional_paths() -> Result<Option<(ServerConfig, PathBuf, PathBuf)>, TlsError>
{
	let Some(home) = home_dir() else {
		return Ok(None);
	};

	let cert_path = home.join(".mcp").join("tls").join("cert.pem");
	let key_path = home.join(".mcp").join("tls").join("key.pem");

	if !cert_path.exists() || !key_path.exists() {
		return Ok(None);
	}

	let config = load_from_paths(&cert_path, &key_path)?;
	Ok(Some((config, cert_path, key_path)))
}

/// Load certificates from `MCP_TLS_CERT` and `MCP_TLS_KEY`
/// environment variables.
///
/// Returns `None` if neither variable is set. Returns an error
/// if only one is set, or if the referenced files cannot be parsed.
pub fn load_from_env() -> Result<Option<(ServerConfig, PathBuf, PathBuf)>, TlsError> {
	let cert_env = std::env::var("MCP_TLS_CERT").ok();
	let key_env = std::env::var("MCP_TLS_KEY").ok();

	match (cert_env, key_env) {
		(None, None) => Ok(None),
		(Some(_), None) => Err(TlsError::Configuration(
			"MCP_TLS_CERT is set but MCP_TLS_KEY is not".to_owned(),
		)),
		(None, Some(_)) => Err(TlsError::Configuration(
			"MCP_TLS_KEY is set but MCP_TLS_CERT is not".to_owned(),
		)),
		(Some(cert), Some(key)) => {
			let cert_path = PathBuf::from(cert);
			let key_path = PathBuf::from(key);
			let config = load_from_paths(&cert_path, &key_path)?;
			Ok(Some((config, cert_path, key_path)))
		}
	}
}

/// Read PEM-encoded certificates from a file.
fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
	let file = fs::File::open(path).map_err(|error| TlsError::FileRead {
		path: path.to_path_buf(),
		reason: error.to_string(),
	})?;

	let mut reader = BufReader::new(file);
	let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
		.collect::<Result<Vec<_>, _>>()
		.map_err(|error| TlsError::PemParse {
			path: path.to_path_buf(),
			reason: error.to_string(),
		})?;

	if certs.is_empty() {
		return Err(TlsError::PemParse {
			path: path.to_path_buf(),
			reason: "no certificates found in PEM file".to_owned(),
		});
	}

	Ok(certs)
}

/// Read a PEM-encoded private key from a file.
///
/// Accepts PKCS#8, RSA, or EC private keys.
fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
	let file = fs::File::open(path).map_err(|error| TlsError::FileRead {
		path: path.to_path_buf(),
		reason: error.to_string(),
	})?;

	let mut reader = BufReader::new(file);

	loop {
		match rustls_pemfile::read_one(&mut reader) {
			Ok(Some(rustls_pemfile::Item::Pkcs1Key(key))) => return Ok(PrivateKeyDer::Pkcs1(key)),
			Ok(Some(rustls_pemfile::Item::Pkcs8Key(key))) => return Ok(PrivateKeyDer::Pkcs8(key)),
			Ok(Some(rustls_pemfile::Item::Sec1Key(key))) => return Ok(PrivateKeyDer::Sec1(key)),
			Ok(Some(_)) => {} // Skip non-key items.
			Ok(None) => {
				return Err(TlsError::PemParse {
					path: path.to_path_buf(),
					reason: "no private key found in PEM file".to_owned(),
				});
			}
			Err(error) => {
				return Err(TlsError::PemParse {
					path: path.to_path_buf(),
					reason: error.to_string(),
				});
			}
		}
	}
}

/// Build a rustls `ServerConfig` from certificates and a private key.
fn build_server_config(
	certs: Vec<CertificateDer<'static>>,
	key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TlsError> {
	ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.map_err(TlsError::Rustls)
}

/// Resolve the home directory.
///
/// Checks `HOME` on Unix and `USERPROFILE` on Windows. Does not
/// pull in a dependency for this single lookup.
fn home_dir() -> Option<PathBuf> {
	std::env::var_os("HOME")
		.or_else(|| std::env::var_os("USERPROFILE"))
		.map(PathBuf::from)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The home directory resolver finds HOME on Unix.
	#[test]
	fn home_dir_resolves() {
		// HOME is always set in test environments.
		let home = home_dir();
		assert!(home.is_some());
	}

	/// Missing conventional paths return None, not an error.
	#[test]
	fn missing_conventional_paths_return_none() {
		// Unless someone has ~/.mcp/tls/ set up, this returns None.
		// We test the "not found" path explicitly by ensuring no
		// error is returned.
		let result = load_from_conventional_paths();
		assert!(result.is_ok());
	}

	/// Loading from a nonexistent file returns a `FileRead` error.
	#[test]
	fn nonexistent_cert_file_returns_error() {
		let result = load_certs(Path::new("/nonexistent/cert.pem"));
		assert!(matches!(result, Err(TlsError::FileRead { .. })));
	}

	/// Loading from a nonexistent key file returns a `FileRead` error.
	#[test]
	fn nonexistent_key_file_returns_error() {
		let result = load_private_key(Path::new("/nonexistent/key.pem"));
		assert!(matches!(result, Err(TlsError::FileRead { .. })));
	}

	/// Explicit paths require both cert and key — checked at the
	/// `resolve` level, not here, but we test that `load_from_paths`
	/// works with valid PEM files.
	#[test]
	fn load_from_paths_with_valid_pem() {
		// Generate a test certificate using rcgen (available as
		// dev-dependency).
		let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();

		let cert_pem = cert.cert.pem();
		let key_pem = cert.key_pair.serialize_pem();

		let dir = tempfile::tempdir().unwrap();
		let cert_path = dir.path().join("cert.pem");
		let key_path = dir.path().join("key.pem");

		fs::write(&cert_path, cert_pem).unwrap();
		fs::write(&key_path, key_pem).unwrap();

		let result = load_from_paths(&cert_path, &key_path);
		assert!(result.is_ok());
	}

	/// An empty PEM file returns a parse error, not a silent success.
	#[test]
	fn empty_cert_file_returns_parse_error() {
		let dir = tempfile::tempdir().unwrap();
		let cert_path = dir.path().join("cert.pem");
		fs::write(&cert_path, "").unwrap();

		let result = load_certs(&cert_path);
		assert!(matches!(result, Err(TlsError::PemParse { .. })));
	}

	/// A PEM file with no private key returns a parse error.
	#[test]
	fn cert_file_without_key_returns_parse_error() {
		let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();

		let dir = tempfile::tempdir().unwrap();
		let key_path = dir.path().join("key.pem");
		// Write cert PEM where a key is expected.
		fs::write(&key_path, cert.cert.pem()).unwrap();

		let result = load_private_key(&key_path);
		assert!(matches!(result, Err(TlsError::PemParse { .. })));
	}
}
