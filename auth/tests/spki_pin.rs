//! Integration tests for TLS certificate SPKI pinning (issue #29),
//! driven against the `mockoidc-kit` fixture's TLS mode with a
//! self-signed certificate generated per test.

use base64::Engine as _;
use mcp_gateway_auth::discovery::{DiscoveryClient, DiscoveryError};
use mcp_gateway_auth::jwks::JwksCache;
use mcp_gateway_auth::trust::pinned_http_client;
use mockoidc_kit::{MockIssuer, SigningAlgorithm, StartOptions, TlsConfig};
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};

/// An RFC 7469 pin for an all-zero SPKI hash: well-formed, but matches no
/// real certificate.
fn unmatchable_pin() -> String {
	format!(
		"sha256/{}",
		base64::engine::general_purpose::STANDARD.encode([0_u8; 32])
	)
}

/// A self-signed certificate plus the RFC 7469 SPKI pin that matches
/// it, ready to serve from the fixture and pin against.
struct PinnedCertificate {
	/// The certificate and private key in PEM form, handed to the
	/// fixture's TLS mode so the issuer serves this exact leaf.
	tls: TlsConfig,
	/// The `sha256/<base64>` SPKI pin computed from the certificate
	/// above, configured on the client so a successful handshake
	/// proves the server presented this certificate.
	pin: String,
}

/// Generate a loopback self-signed certificate and compute its
/// `sha256/<base64>` SPKI pin the same way the production verifier
/// does, so the matching test pins exactly what the server presents.
fn pinned_certificate() -> PinnedCertificate {
	let certified =
		generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
			.expect("self-signed certificate should generate");

	let (_, parsed) = x509_parser::parse_x509_certificate(certified.cert.der())
		.expect("generated certificate should parse");
	let digest = Sha256::digest(parsed.public_key().raw);
	let pin = format!(
		"sha256/{}",
		base64::engine::general_purpose::STANDARD.encode(digest)
	);

	PinnedCertificate {
		tls: TlsConfig {
			cert_pem: certified.cert.pem().into_bytes(),
			key_pem: certified.key_pair.serialize_pem().into_bytes(),
		},
		pin,
	}
}

/// Boot an HTTPS issuer serving the given certificate material.
async fn https_issuer(tls: TlsConfig) -> MockIssuer {
	MockIssuer::start_with(StartOptions::new(SigningAlgorithm::Es256).with_tls(tls))
		.await
		.expect("TLS fixture should boot")
}

/// A discovery fetch against an authorisation server whose certificate
/// SPKI matches the configured pin succeeds.
#[tokio::test]
async fn accepts_matching_spki_pin() {
	let certificate = pinned_certificate();
	let issuer = https_issuer(certificate.tls).await;
	let base = issuer.issuer();
	assert!(
		base.starts_with("https://"),
		"issuer should be HTTPS: {base}"
	);

	let client = DiscoveryClient::new(base.clone()).with_spki_pins(&[certificate.pin]);
	let document = client
		.fetch()
		.await
		.expect("a matching SPKI pin should let the fetch through");
	assert_eq!(document.issuer, base);
}

/// A discovery fetch against an authorisation server whose certificate
/// SPKI does not match any configured pin fails at the TLS handshake,
/// surfacing as a request error.
#[tokio::test]
async fn rejects_spki_pin_mismatch() {
	let certificate = pinned_certificate();
	let issuer = https_issuer(certificate.tls).await;

	// A pin for an all-zero SPKI hash: well-formed, but matches no
	// real certificate.
	let wrong_pin = format!(
		"sha256/{}",
		base64::engine::general_purpose::STANDARD.encode([0_u8; 32])
	);

	let client = DiscoveryClient::new(issuer.issuer()).with_spki_pins(&[wrong_pin]);
	let error = client
		.fetch()
		.await
		.expect_err("a non-matching SPKI pin must fail the handshake");
	assert!(
		matches!(error, DiscoveryError::Request(_)),
		"a pin mismatch should surface as a request (TLS handshake) error, got {error:?}",
	);
}

/// The JWKS fetch is pinned, not just the discovery fetch. The JWKS is
/// where the gateway gets the keys it verifies token signatures with, so
/// it is the most security-critical fetch: a rogue key set lets an
/// attacker mint tokens the gateway will accept. This test points a JWKS
/// cache at the HTTPS fixture but configures a pin that matches no real
/// certificate, and asserts the fetch fails at the TLS handshake. Without
/// the pin being applied to the JWKS client, a compromised certificate
/// authority could substitute the key set; the failure proves the pin is
/// enforced on this path.
#[tokio::test]
async fn jwks_fetch_rejects_spki_pin_mismatch() {
	let certificate = pinned_certificate();
	let issuer = https_issuer(certificate.tls).await;

	let cache = JwksCache::new(format!("{}/jwks", issuer.issuer()))
		.with_http_client(pinned_http_client(&[unmatchable_pin()]));
	let result = cache.key_for_kid("any-kid").await;
	assert!(
		result.is_err(),
		"a JWKS fetch against a non-matching pin must fail at the TLS handshake",
	);
}

/// The flip side of the pin check on the JWKS path: when the fixture's
/// certificate SPKI matches the configured pin, the fetch is let through.
/// Looking up a `kid` the fixture does not publish then resolves to no
/// key (rather than an error), which confirms the request actually
/// reached the JWKS endpoint and parsed its response. This guards against
/// a pin that is so strict it rejects the legitimate server.
#[tokio::test]
async fn jwks_fetch_accepts_matching_spki_pin() {
	let certificate = pinned_certificate();
	let issuer = https_issuer(certificate.tls).await;

	let cache = JwksCache::new(format!("{}/jwks", issuer.issuer()))
		.with_http_client(pinned_http_client(&[certificate.pin]));
	let result = cache
		.key_for_kid("unknown-kid")
		.await
		.expect("a matching pin must let the JWKS fetch through");
	assert!(
		result.is_none(),
		"an unknown kid resolves to no key once the fetch succeeds",
	);
}

/// Pinning is applied in addition to hostname validation, not instead of
/// it (RFC 7469 §2.6). This test builds a certificate issued only for an
/// unrelated host, serves it from the loopback issuer, and pins its SPKI
/// exactly, so the pin check passes and only the hostname check can reject
/// the connection. The fetch (to the loopback address) must still fail,
/// proving that a certificate whose key is pinned but which was issued for
/// the wrong host is not accepted: a stolen-but-pinned certificate cannot
/// be used to impersonate the authorisation server on another name.
#[tokio::test]
async fn rejects_certificate_not_issued_for_the_host() {
	// A certificate for an unrelated host only. Its SPKI is pinned
	// exactly below, so the pin check passes and the hostname check is the
	// only thing that can reject the loopback connection.
	let certified = generate_simple_self_signed(vec!["unrelated.example".to_owned()])
		.expect("self-signed certificate should generate");
	let (_, parsed) = x509_parser::parse_x509_certificate(certified.cert.der())
		.expect("generated certificate should parse");
	let pin = format!(
		"sha256/{}",
		base64::engine::general_purpose::STANDARD.encode(Sha256::digest(parsed.public_key().raw))
	);
	let tls = TlsConfig {
		cert_pem: certified.cert.pem().into_bytes(),
		key_pem: certified.key_pair.serialize_pem().into_bytes(),
	};
	let issuer = https_issuer(tls).await;

	let client = DiscoveryClient::new(issuer.issuer()).with_spki_pins(&[pin]);
	let error = client
		.fetch()
		.await
		.expect_err("a certificate not issued for the host must be rejected");
	assert!(
		matches!(error, DiscoveryError::Request(_)),
		"a hostname mismatch should surface as a request (TLS handshake) error, got {error:?}",
	);
}
