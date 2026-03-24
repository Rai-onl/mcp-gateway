//! Ephemeral self-signed certificate generation.
//!
//! Generates a self-signed certificate for `localhost` and
//! `127.0.0.1` at startup. The certificate lives only in memory
//! and is not written to disk. Intended for local development
//! where the overhead of setting up real certificates is not
//! justified.

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::{CertificateSource, TlsError};

/// Generate an ephemeral self-signed certificate and build a
/// rustls `ServerConfig` from it.
///
/// The certificate covers `localhost`, `127.0.0.1`, and `::1`
/// as Subject Alternative Names. It is valid from the moment of
/// generation — expiry is left to rcgen's default (which is
/// reasonable for ephemeral development use).
///
/// # Errors
///
/// Returns an error if certificate generation or rustls
/// configuration fails.
pub fn generate() -> Result<(ServerConfig, CertificateSource), TlsError> {
	let subject_alt_names = vec![
		"localhost".to_owned(),
		"127.0.0.1".to_owned(),
		"::1".to_owned(),
	];

	let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)
		.map_err(|error| TlsError::Generation(error.to_string()))?;

	let cert_der = CertificateDer::from(certified_key.cert.der().to_vec());
	let key_der = PrivateKeyDer::Pkcs8(certified_key.key_pair.serialize_der().into());

	tracing::info!(
		"generated ephemeral self-signed certificate for localhost (valid for ~90 days)"
	);

	let config = ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(vec![cert_der], key_der)
		.map_err(TlsError::Rustls)?;

	Ok((config, CertificateSource::SelfSigned))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Self-signed generation produces a valid rustls config.
	#[test]
	fn generates_valid_config() {
		let result = generate();
		assert!(result.is_ok());

		let (_, source) = result.unwrap();
		assert!(matches!(source, CertificateSource::SelfSigned));
	}
}
