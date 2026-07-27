//! Integration tests for the authorisation-server discovery client
//! (issue #29), driven against the `mockoidc-kit` fixture.

use mcp_gateway_auth::discovery::{DiscoveryClient, DiscoveryError};
use mockoidc_kit::{Endpoint, FaultResponse, MockIssuer, SigningAlgorithm};
use serde_json::json;
use sha2::{Digest, Sha256};

/// Fetch the OIDC discovery body and return its SHA-256 as lowercase
/// hex, matching the encoding the gateway pins against.
async fn discovery_document_sha256_hex(base: &str) -> String {
	use std::fmt::Write as _;

	// The default reqwest client carries no bundled crypto provider, so
	// the process default must be installed before it connects over TLS.
	mcp_gateway_crypto::install();
	let body = reqwest::get(format!("{base}/.well-known/openid-configuration"))
		.await
		.expect("discovery body should fetch")
		.text()
		.await
		.expect("discovery body should read");
	let mut hex = String::new();
	for byte in Sha256::digest(body.as_bytes()) {
		let _ = write!(hex, "{byte:02x}");
	}
	hex
}

/// The discovery client fetches the OpenID Connect Discovery 1.0
/// document from `{issuer}/.well-known/openid-configuration` and
/// surfaces the fields the gateway relies on: the issuer, the JWKS
/// URI, the introspection endpoint, and the advertised signing
/// algorithms.
#[tokio::test]
async fn fetches_oidc_discovery_document() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let base = issuer.issuer();

	let client = DiscoveryClient::new(base.clone());
	let document = client
		.fetch()
		.await
		.expect("discovery fetch should succeed");

	assert_eq!(document.issuer, base);
	assert_eq!(document.jwks_uri, format!("{base}/jwks"));
	assert_eq!(
		document.introspection_endpoint.as_deref(),
		Some(format!("{base}/introspect").as_str()),
	);
	assert!(
		document.signing_algorithms.iter().any(|alg| alg == "ES256"),
		"discovery should surface ES256 among signing algorithms, got {:?}",
		document.signing_algorithms,
	);
}

/// When the OpenID Connect Discovery path returns 404, the client
/// falls back to the RFC 8414 OAuth 2.0 Authorization Server Metadata
/// path and produces an equivalent document. Authorisation servers
/// that publish only the OAuth metadata path (not the OIDC one) must
/// still be discoverable.
#[tokio::test]
async fn falls_back_to_rfc8414_when_oidc_path_is_404() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let base = issuer.issuer();

	// Take the OIDC well-known path down so only the RFC 8414 path
	// answers; the client must follow the fallback.
	issuer.fail(Endpoint::OidcDiscovery, FaultResponse::new(404));

	let client = DiscoveryClient::new(base.clone());
	let document = client
		.fetch()
		.await
		.expect("fetch should fall back to the RFC 8414 path");

	assert_eq!(document.issuer, base);
	assert_eq!(document.jwks_uri, format!("{base}/jwks"));
}

/// A discovery document whose `issuer` differs from the configured
/// issuer URL is rejected. A mismatch is the signature of a
/// substituted document pointing the gateway at an attacker's keys,
/// so the fetch fails rather than trusting the advertised value.
#[tokio::test]
async fn rejects_issuer_mismatch() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	issuer.tamper_discovery(|document| {
		document["issuer"] = json!("https://attacker.example.test");
	});

	let client = DiscoveryClient::new(issuer.issuer());
	let error = client
		.fetch()
		.await
		.expect_err("a mismatched issuer must fail the fetch");
	assert!(
		matches!(error, DiscoveryError::IssuerMismatch { .. }),
		"expected IssuerMismatch, got {error:?}",
	);
}

/// A discovery document advertising `none` or any `HS*` symmetric
/// algorithm is rejected. The gateway validates with asymmetric keys
/// only; an authorisation server signalling a symmetric or `none`
/// algorithm is misconfigured at the source and enables algorithm
/// confusion, so configuration load fails.
#[tokio::test]
async fn rejects_symmetric_or_none_algorithms() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	issuer.tamper_discovery(|document| {
		document["id_token_signing_alg_values_supported"] = json!(["ES256", "HS256"]);
	});

	let client = DiscoveryClient::new(issuer.issuer());
	let error = client
		.fetch()
		.await
		.expect_err("an advertised HS* algorithm must fail the fetch");
	assert!(
		matches!(error, DiscoveryError::UnsupportedAlgorithm(_)),
		"expected UnsupportedAlgorithm, got {error:?}",
	);
}

/// A non-success status on the OpenID Connect path, other than 404, is
/// rejected rather than parsed as a document. A 500, a 403, or a redirect
/// to an error or captive-portal page is not metadata, so feeding its
/// body to the JSON parser would be wrong.
#[tokio::test]
async fn rejects_non_success_oidc_status() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	issuer.fail(Endpoint::OidcDiscovery, FaultResponse::new(500));

	let client = DiscoveryClient::new(issuer.issuer());
	let error = client
		.fetch()
		.await
		.expect_err("a 500 on the discovery path must fail the fetch");
	assert!(
		matches!(error, DiscoveryError::UnexpectedStatus { status: 500 }),
		"expected UnexpectedStatus 500, got {error:?}",
	);
}

/// When the OpenID Connect path returns 404 and the RFC 8414 fallback
/// then returns a non-success status, the fetch fails rather than parsing
/// the fallback's error body.
#[tokio::test]
async fn rejects_non_success_rfc8414_fallback_status() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	issuer.fail(Endpoint::OidcDiscovery, FaultResponse::new(404));
	issuer.fail(Endpoint::Rfc8414Discovery, FaultResponse::new(500));

	let client = DiscoveryClient::new(issuer.issuer());
	let error = client
		.fetch()
		.await
		.expect_err("a 500 on the RFC 8414 fallback must fail the fetch");
	assert!(
		matches!(error, DiscoveryError::UnexpectedStatus { status: 500 }),
		"expected UnexpectedStatus 500, got {error:?}",
	);
}

/// The symmetric/`none` guard is case-insensitive: a lowercase `hs256`
/// advertised in discovery is rejected just like `HS256`. RFC 7518 names
/// algorithms in uppercase, but a misconfigured server should not slip a
/// symmetric algorithm past the guard by lowercasing it.
#[tokio::test]
async fn rejects_lowercase_symmetric_algorithm() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	issuer.tamper_discovery(|document| {
		document["id_token_signing_alg_values_supported"] = json!(["ES256", "hs256"]);
	});

	let client = DiscoveryClient::new(issuer.issuer());
	let error = client
		.fetch()
		.await
		.expect_err("a lowercase hs256 must fail the fetch");
	assert!(
		matches!(error, DiscoveryError::UnsupportedAlgorithm(_)),
		"expected UnsupportedAlgorithm, got {error:?}",
	);
}

/// When a `discovery_document_sha256` pin is configured and the
/// fetched body does not hash to it, the fetch fails. The pin defends
/// against a substituted discovery document that points the gateway
/// at attacker-controlled keys, so a mismatch is fatal.
#[tokio::test]
async fn rejects_discovery_document_hash_mismatch() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	let client =
		DiscoveryClient::new(issuer.issuer()).with_discovery_document_sha256("0".repeat(64));
	let error = client
		.fetch()
		.await
		.expect_err("a discovery body that does not match the pin must fail");
	assert!(
		matches!(error, DiscoveryError::DiscoveryHashMismatch { .. }),
		"expected DiscoveryHashMismatch, got {error:?}",
	);
}

/// A `discovery_document_sha256` pin that matches the served body
/// lets the fetch through unchanged.
#[tokio::test]
async fn accepts_matching_discovery_document_hash() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let base = issuer.issuer();
	let pin = discovery_document_sha256_hex(&base).await;

	let client = DiscoveryClient::new(base.clone()).with_discovery_document_sha256(pin);
	let document = client
		.fetch()
		.await
		.expect("a matching pin must let the fetch through");
	assert_eq!(document.issuer, base);
}
