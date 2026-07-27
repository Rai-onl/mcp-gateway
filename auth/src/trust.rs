//! Trust-anchor enforcement for authorisation-server connections.
//!
//! The gateway can pin the authorisation server's TLS certificate by
//! the SHA-256 of its SubjectPublicKeyInfo (RFC 7469), defending
//! discovery, JWKS, and introspection fetches against a substituted
//! certificate even from a compromised certificate authority.
//!
//! When pins are configured the pin is the trust anchor: a leaf whose
//! SPKI matches a configured pin is accepted, and CA-chain validation
//! is intentionally not performed. Handshake signatures are still
//! verified against the leaf's key, so the peer must prove possession
//! of the pinned key rather than merely presenting a matching
//! certificate.

use std::sync::Arc;

use base64::Engine as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;

/// A rustls server-certificate verifier that accepts a connection if
/// and only if the leaf certificate's SubjectPublicKeyInfo SHA-256
/// matches one of the configured RFC 7469 pins.
#[derive(Debug)]
pub struct SpkiPinVerifier {
	/// The pinned SPKI SHA-256 values, base64-encoded (the portion
	/// after the `sha256/` prefix in configuration).
	pins: Vec<String>,
	/// Signature-verification algorithms used to validate the
	/// handshake signatures, which the SPKI check does not itself
	/// cover.
	algorithms: WebPkiSupportedAlgorithms,
}

impl SpkiPinVerifier {
	/// Build a verifier from RFC 7469 pin strings of the form
	/// `sha256/<base64>`. The `sha256/` prefix is optional and
	/// stripped when present.
	#[must_use]
	pub fn new(pins: &[String]) -> Self {
		let pins = pins
			.iter()
			.map(|pin| pin.strip_prefix("sha256/").unwrap_or(pin).to_owned())
			.collect();
		Self {
			pins,
			algorithms: mcp_gateway_crypto::provider()
				.signature_verification_algorithms,
		}
	}
}

impl ServerCertVerifier for SpkiPinVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		server_name: &ServerName<'_>,
		_ocsp_response: &[u8],
		now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		let (_, parsed) =
			x509_parser::parse_x509_certificate(end_entity.as_ref()).map_err(|error| {
				rustls::Error::General(format!("could not parse server certificate: {error}"))
			})?;

		// The leaf's key must be one the operator pinned.
		let presented = spki_sha256_base64(&parsed);
		if !self.pins.iter().any(|pin| pin == &presented) {
			return Err(rustls::Error::General(format!(
				"authorisation server certificate SPKI {presented} matches no configured pin"
			)));
		}

		// In addition to the pin (RFC 7469 §2.6 applies pinning alongside
		// normal validation, not instead of it), the certificate must be
		// currently valid and issued for the host being connected to.
		check_validity(&parsed, now)?;
		check_hostname(&parsed, server_name)?;

		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		verify_tls12_signature(message, cert, dss, &self.algorithms)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		verify_tls13_signature(message, cert, dss, &self.algorithms)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.algorithms.supported_schemes()
	}
}

/// Compute the base64-encoded SHA-256 of a certificate's
/// SubjectPublicKeyInfo, the value an RFC 7469 `sha256/...` pin names.
fn spki_sha256_base64(certificate: &X509Certificate<'_>) -> String {
	let digest = Sha256::digest(certificate.public_key().raw);
	base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Reject a certificate that is expired or not yet valid at `now`.
///
/// Pinning binds to a key, but a key the operator pinned in the past may
/// since have been rotated out and its certificate allowed to expire, so
/// the validity window is still enforced.
fn check_validity(certificate: &X509Certificate<'_>, now: UnixTime) -> Result<(), rustls::Error> {
	let now_seconds = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
	let validity = certificate.validity();
	if now_seconds < validity.not_before.timestamp() {
		return Err(rustls::Error::General(
			"pinned authorisation server certificate is not yet valid".to_owned(),
		));
	}
	if now_seconds > validity.not_after.timestamp() {
		return Err(rustls::Error::General(
			"pinned authorisation server certificate has expired".to_owned(),
		));
	}
	Ok(())
}

/// Reject a certificate that is not issued for the host being connected
/// to, matching `server_name` against the certificate's subjectAltName.
fn check_hostname(
	certificate: &X509Certificate<'_>,
	server_name: &ServerName<'_>,
) -> Result<(), rustls::Error> {
	use x509_parser::extensions::GeneralName;

	let subject_alternative_name = certificate
		.subject_alternative_name()
		.map_err(|error| {
			rustls::Error::General(format!(
				"could not read certificate subjectAltName: {error}"
			))
		})?
		.ok_or_else(|| {
			rustls::Error::General("pinned certificate has no subjectAltName".to_owned())
		})?;

	let matches = subject_alternative_name
		.value
		.general_names
		.iter()
		.any(|name| match (name, server_name) {
			(GeneralName::DNSName(dns), ServerName::DnsName(requested)) => {
				dns_name_matches(dns, requested.as_ref())
			}
			(GeneralName::IPAddress(bytes), ServerName::IpAddress(requested)) => {
				ip_address_matches(bytes, *requested)
			}
			_ => false,
		});

	if matches {
		Ok(())
	} else {
		Err(rustls::Error::General(format!(
			"pinned certificate is not valid for the requested host {server_name:?}"
		)))
	}
}

/// Whether a certificate DNS name covers the requested host. Matches
/// exactly (case-insensitively), or as a single-label `*.` wildcard.
fn dns_name_matches(certificate_name: &str, requested: &str) -> bool {
	if let Some(suffix) = certificate_name.strip_prefix("*.") {
		requested
			.split_once('.')
			.is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(suffix))
	} else {
		certificate_name.eq_ignore_ascii_case(requested)
	}
}

/// Whether a certificate subjectAltName IP-address entry (4 or 16 raw
/// bytes) equals the requested address.
fn ip_address_matches(certificate_bytes: &[u8], requested: rustls::pki_types::IpAddr) -> bool {
	let requested_bytes: &[u8] = match &requested {
		rustls::pki_types::IpAddr::V4(address) => address.as_ref(),
		rustls::pki_types::IpAddr::V6(address) => address.as_ref(),
	};
	certificate_bytes == requested_bytes
}

/// Build a reqwest client for authorisation-server calls that are not
/// certificate-pinned.
///
/// The client carries no bundled crypto provider, so this installs the
/// selected provider as the process default first (idempotently), which
/// the client falls back on when it builds its TLS layer.
///
/// Installing is process-global and first-wins. In the gateway binary
/// that is exactly one provider, so this is safe. Code embedding this
/// crate as a library should install its own provider during startup,
/// before constructing any auth client, rather than relying on this to
/// pick the provider for the whole process.
///
/// # Panics
///
/// In a `fips` build, panics through [`mcp_gateway_crypto::install`] if
/// the built provider does not report FIPS approval. Never panics in
/// the other flavours.
#[must_use]
pub fn default_http_client() -> reqwest::Client {
	mcp_gateway_crypto::install();
	reqwest::Client::new()
}

/// Build a reqwest client whose TLS layer accepts only authorisation
/// servers whose certificate SPKI matches one of `pins`.
///
/// Used by the discovery, JWKS, and introspection fetch paths when
/// `trust_anchors.authorization_server_certificate_spki_pins` is set.
///
/// # Panics
///
/// Panics if the selected crypto provider cannot configure the default
/// TLS protocol versions, or if reqwest cannot build a client from the
/// resulting configuration. Both are environment-level faults that can
/// only occur at startup and leave no safe way to continue.
#[must_use]
pub fn pinned_http_client(pins: &[String]) -> reqwest::Client {
	let config = rustls::ClientConfig::builder_with_provider(mcp_gateway_crypto::provider())
		.with_safe_default_protocol_versions()
		.expect("the crypto provider supports the default TLS protocol versions")
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(SpkiPinVerifier::new(pins)))
		.with_no_client_auth();
	reqwest::Client::builder()
		.use_preconfigured_tls(config)
		.build()
		.expect("reqwest client builds from the pinned TLS configuration")
}

#[cfg(test)]
mod tests {
	use rcgen::generate_simple_self_signed;
	use rustls::pki_types::{ServerName, UnixTime};

	use super::{check_hostname, check_validity, dns_name_matches};

	/// Generate a self-signed loopback certificate (valid for `localhost`
	/// and `127.0.0.1`) and return its DER bytes, ready to parse and feed
	/// to the validity and hostname checks. Each test parses a fresh
	/// certificate so the checks run against real, current notBefore and
	/// notAfter dates rather than a hand-built stand-in.
	fn loopback_certificate_der() -> Vec<u8> {
		generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
			.expect("certificate should generate")
			.cert
			.der()
			.to_vec()
	}

	/// A certificate that is within its validity window passes the expiry
	/// check. A freshly generated certificate has a notBefore at or before
	/// now and a notAfter well after it, so checking it against the current
	/// time must succeed: the expiry guard must not reject good
	/// certificates, only expired or not-yet-valid ones.
	#[test]
	fn validity_accepts_a_current_certificate() {
		let der = loopback_certificate_der();
		let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("certificate parses");
		assert!(check_validity(&parsed, UnixTime::now()).is_ok());
	}

	/// A pinned certificate that has passed its notAfter is rejected.
	/// Pinning binds to a key the operator trusted at some point, but that
	/// certificate may since have expired, so the validity window is still
	/// enforced. The test checks the certificate against a time far beyond
	/// any plausible notAfter (the year 9999) and asserts the expiry guard
	/// rejects it, standing in for a clock that has advanced past expiry.
	#[test]
	fn validity_rejects_an_expired_certificate() {
		let der = loopback_certificate_der();
		let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("certificate parses");
		// One day after the certificate's own notAfter: a clock that has
		// advanced past expiry, derived from the certificate so the test
		// does not depend on the generator's default validity length.
		let not_after = u64::try_from(parsed.validity().not_after.timestamp()).unwrap_or(u64::MAX);
		let past_expiry = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
			not_after.saturating_add(60 * 60 * 24),
		));
		assert!(check_validity(&parsed, past_expiry).is_err());
	}

	/// The hostname check accepts a host the certificate lists in its
	/// subjectAltName. The loopback certificate lists `localhost`, so a
	/// connection asking for `localhost` is for a host the certificate was
	/// issued for and must pass: hostname validation must not reject a
	/// legitimately matching certificate.
	#[test]
	fn hostname_accepts_a_listed_name() {
		let der = loopback_certificate_der();
		let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("certificate parses");
		let name = ServerName::try_from("localhost").expect("server name parses");
		assert!(check_hostname(&parsed, &name).is_ok());
	}

	/// The hostname check rejects a host the certificate does not list,
	/// even though the certificate is otherwise well-formed. This is the
	/// defence pinning alone does not provide: a certificate whose key is
	/// pinned but which was issued for a different host must not be
	/// accepted for `evil.example`, which the loopback certificate does
	/// not cover.
	#[test]
	fn hostname_rejects_an_unlisted_name() {
		let der = loopback_certificate_der();
		let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("certificate parses");
		let name = ServerName::try_from("evil.example").expect("server name parses");
		assert!(check_hostname(&parsed, &name).is_err());
	}

	/// A `*.` wildcard certificate name matches exactly one leading label,
	/// case-insensitively, and nothing else. This pins down the matching
	/// rule at its boundaries: `*.example.coop` covers `auth.example.coop`
	/// (one label) but not the bare `example.coop` (no label) nor
	/// `a.b.example.coop` (two labels), a non-matching wildcard must not be
	/// allowed to over-match. Exact names match case-insensitively, as DNS
	/// names are.
	#[test]
	fn wildcard_dns_name_matches_one_label() {
		assert!(dns_name_matches("*.example.coop", "auth.example.coop"));
		assert!(!dns_name_matches("*.example.coop", "example.coop"));
		assert!(!dns_name_matches("*.example.coop", "a.b.example.coop"));
		assert!(dns_name_matches("auth.example.coop", "auth.example.coop"));
		assert!(dns_name_matches("Auth.Example.Coop", "auth.example.coop"));
	}
}
