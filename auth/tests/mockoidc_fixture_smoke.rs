//! Smoke test proving the gateway can consume `mockoidc-kit` as its
//! authorisation-server test fixture (issue #33).
//!
//! These tests do not exercise gateway code. They assert that the
//! published fixture is wired into the workspace, boots from the
//! gateway's own test harness, and exposes the capabilities the
//! later inbound-auth slices depend on: an ES256 issuer with a
//! discoverable JWKS, key rotation with an overlap window, and the
//! `control`-feature outage injection used to drive the gateway's
//! fail-closed paths. Cryptographic round-trip of a minted token
//! against the JWKS is already covered by the fixture's own suite;
//! here we only need to know the dependency is usable.

use mockoidc_kit::{Endpoint, FaultResponse, MockIssuer, SigningAlgorithm};

/// Perform an HTTP GET against `url` and return the response status
/// paired with the body decoded as JSON. A body that is absent or
/// not JSON (as on an injected fault response) decodes to
/// [`serde_json::Value::Null`]; callers that inject faults assert on
/// the status alone.
async fn get_json(url: &str) -> (u16, serde_json::Value) {
	// The default reqwest client carries no bundled crypto provider, so
	// the process default must be installed before it connects over TLS.
	mcp_gateway_crypto::install();
	let response = reqwest::get(url)
		.await
		.expect("request to the fixture should succeed");
	let status = response.status().as_u16();
	let body = response
		.json::<serde_json::Value>()
		.await
		.unwrap_or(serde_json::Value::Null);
	(status, body)
}

/// Collect the `kid` of every key advertised in a JWKS document.
fn jwks_kids(jwks: &serde_json::Value) -> Vec<String> {
	jwks["keys"]
		.as_array()
		.expect("JWKS must carry a `keys` array")
		.iter()
		.map(|key| {
			key["kid"]
				.as_str()
				.expect("every JWKS key must carry a `kid`")
				.to_owned()
		})
		.collect()
}

/// An ES256 issuer serves an OIDC discovery document rooted at its
/// own URL, advertises ES256 among its signing algorithms, and
/// publishes a P-256 elliptic-curve key in its JWKS. This is the
/// shape the gateway's discovery client (#29) and JWT validator
/// (#30) consume.
#[tokio::test]
async fn es256_issuer_serves_discovery_and_jwks() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot on an ephemeral loopback port");
	let base = issuer.issuer();

	let (discovery_status, discovery) =
		get_json(&format!("{base}/.well-known/openid-configuration")).await;
	assert_eq!(discovery_status, 200);
	assert_eq!(discovery["issuer"], serde_json::json!(base));
	assert_eq!(
		discovery["jwks_uri"],
		serde_json::json!(format!("{base}/jwks"))
	);
	let algorithms = discovery["id_token_signing_alg_values_supported"]
		.as_array()
		.expect("discovery must advertise signing algorithms");
	assert!(
		algorithms.contains(&serde_json::json!("ES256")),
		"discovery should advertise ES256, got {algorithms:?}",
	);

	let (jwks_status, jwks) = get_json(&format!("{base}/jwks")).await;
	assert_eq!(jwks_status, 200);
	let first_key = &jwks["keys"][0];
	assert_eq!(first_key["kty"], "EC");
	assert_eq!(first_key["crv"], "P-256");
	assert!(
		first_key["kid"].is_string(),
		"the published key must carry a kid",
	);
}

/// The subject builder mints a signed token. The gateway needs only
/// to know minting works through the fixture's API; the token's
/// three-part JWS compact form is the cheap structural proof.
#[tokio::test]
async fn subject_builder_mints_a_compact_jws() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	let token = issuer
		.subject("did:arai:example:alice")
		.claim("scope", "mcp:invoke:gitlab")
		.mint_id_token();

	let segments: Vec<&str> = token.split('.').collect();
	assert_eq!(
		segments.len(),
		3,
		"a JWS compact token has header.payload.signature, got {token:?}",
	);
	assert!(
		segments.iter().all(|segment| !segment.is_empty()),
		"no JWS segment may be empty",
	);
}

/// Rotation publishes the new key alongside the previous one, so a
/// JWKS fetched mid-rotation carries both. This overlap is exactly
/// what the gateway's JWKS cache (#29) must tolerate: a token signed
/// by the retiring key still verifies while the new key is adopted.
#[tokio::test]
async fn rotation_publishes_overlapping_keys() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let base = issuer.issuer();

	let (_, before) = get_json(&format!("{base}/jwks")).await;
	let kids_before = jwks_kids(&before);
	assert_eq!(kids_before.len(), 1, "a fresh issuer publishes one key");

	let new_kid = issuer.rotate().expect("rotation should succeed");

	let (_, after) = get_json(&format!("{base}/jwks")).await;
	let kids_after = jwks_kids(&after);
	assert_eq!(
		kids_after.len(),
		2,
		"after rotation both the old and new keys are published",
	);
	assert!(
		kids_after.contains(&kids_before[0]),
		"the retiring key must remain published during the overlap",
	);
	assert!(
		kids_after.contains(&new_kid),
		"the new key must be published after rotation",
	);
}

/// The `control` feature can take an endpoint down and bring it back.
/// The gateway's discovery and introspection paths are specified to
/// fail closed on upstream outage; this lever is how those paths get
/// driven under test.
#[tokio::test]
async fn control_feature_injects_and_clears_an_outage() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let base = issuer.issuer();
	let jwks_url = format!("{base}/jwks");

	let (healthy, _) = get_json(&jwks_url).await;
	assert_eq!(healthy, 200, "JWKS is served before any fault is armed");

	issuer.fail(Endpoint::Jwks, FaultResponse::new(503));
	let (faulted, _) = get_json(&jwks_url).await;
	assert_eq!(faulted, 503, "the armed fault replaces the normal response");

	issuer.recover(Endpoint::Jwks);
	let (recovered, _) = get_json(&jwks_url).await;
	assert_eq!(recovered, 200, "clearing the fault restores normal service");
}
