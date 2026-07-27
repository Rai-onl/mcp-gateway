//! Integration tests for the JWT validator (issue #30), driven
//! against the `mockoidc-kit` fixture for token minting.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mcp_gateway_auth::jwks::JwksCache;
use mcp_gateway_auth::validator::{FailureReason, JwtValidator};
use mockoidc_kit::{MockIssuer, SigningAlgorithm};
use serde_json::json;

/// The resource URL the test gateway answers for.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// A principal the test gateway admits.
const PRINCIPAL: &str = "did:arai:example:alice";

/// The default clock-skew tolerance the tests build validators with.
const SKEW: Duration = Duration::from_secs(30);

/// Build a validator wired to the fixture's JWKS, admitting the single
/// test principal and resource.
fn validator(issuer: &MockIssuer) -> JwtValidator {
	JwtValidator::new(
		issuer.issuer(),
		RESOURCE.to_owned(),
		[PRINCIPAL.to_owned()].into_iter().collect(),
		SKEW,
		JwksCache::new(format!("{}/jwks", issuer.issuer())),
	)
}

/// Mint a token that satisfies every check: correct issuer, audience,
/// principal, an unexpired lifetime, and a scope.
fn well_formed_token(issuer: &MockIssuer) -> String {
	issuer
		.subject(PRINCIPAL)
		.audience(RESOURCE)
		.claim("scope", "mcp:invoke:gitlab mcp:invoke:github")
		.mint_id_token()
}

/// Current Unix time in seconds, for crafting absolute `exp`/`nbf`.
fn now_seconds() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.expect("system clock is after the epoch")
		.as_secs()
}

/// Flip the first character of a token's signature segment, producing
/// a structurally valid JWT whose signature no longer verifies.
///
/// The first character is a full six-bit base64url position, so the
/// result stays valid base64url but decodes to different signature
/// bytes, which the verifier rejects with `InvalidSignature`. Flipping
/// the last character is unreliable: its low bits are padding, so a
/// flip can make the signature un-decodable (a malformed token) rather
/// than merely wrong.
fn with_tampered_signature(token: &str) -> String {
	let (body, signature) = token
		.rsplit_once('.')
		.expect("a JWT has a signature segment");
	let mut characters: Vec<char> = signature.chars().collect();
	characters[0] = if characters[0] == 'A' { 'B' } else { 'A' };
	let signature: String = characters.into_iter().collect();
	format!("{body}.{signature}")
}

/// A token with a valid signature, correct `iss`, `aud`, `sub`, and an
/// unexpired `exp` validates, surfacing the subject and parsed scopes.
#[tokio::test]
async fn validates_a_well_formed_token() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = well_formed_token(&issuer);

	let claims = validator(&issuer)
		.validate(&format!("Bearer {token}"))
		.await
		.expect("a well-formed token should validate");

	assert_eq!(claims.subject(), PRINCIPAL);
	assert!(claims.scopes().contains("mcp:invoke:gitlab"));
	assert!(claims.scopes().contains("mcp:invoke:github"));
}

/// An `Authorization` value with no bearer token fails with
/// `MissingToken`.
#[tokio::test]
async fn rejects_missing_token() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let reason = validator(&issuer)
		.validate("Bearer ")
		.await
		.expect_err("an empty bearer must be rejected");
	assert_eq!(reason, FailureReason::MissingToken);
}

/// A token that is not a well-formed JWT fails with `MalformedToken`.
#[tokio::test]
async fn rejects_malformed_token() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let reason = validator(&issuer)
		.validate("Bearer not-a-jwt")
		.await
		.expect_err("a non-JWT must be rejected");
	assert_eq!(reason, FailureReason::MalformedToken);
}

/// A token whose signature does not verify fails with
/// `InvalidSignature`.
#[tokio::test]
async fn rejects_invalid_signature() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = with_tampered_signature(&well_formed_token(&issuer));
	let reason = validator(&issuer)
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("a tampered signature must be rejected");
	assert_eq!(reason, FailureReason::InvalidSignature);
}

/// A token signed with `HS256` fails at parse time with
/// `InvalidAlgorithm`, before any signature check against the JWKS,
/// even though the symmetric secret would otherwise verify.
#[tokio::test]
async fn rejects_symmetric_algorithm() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");

	let mut header = Header::new(Algorithm::HS256);
	header.kid = Some("attacker-key".to_owned());
	let claims = json!({
		"iss": issuer.issuer(),
		"sub": PRINCIPAL,
		"aud": RESOURCE,
		"exp": now_seconds() + 3600,
	});
	let token = encode(
		&header,
		&claims,
		&EncodingKey::from_secret(b"shared-secret"),
	)
	.expect("HS256 token should encode");

	let reason = validator(&issuer)
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("a symmetric algorithm must be rejected");
	assert_eq!(reason, FailureReason::InvalidAlgorithm);
}

/// A token whose `iss` does not equal the configured issuer fails with
/// `InvalidIssuer`.
#[tokio::test]
async fn rejects_wrong_issuer() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = well_formed_token(&issuer);

	// Configured for a different issuer than minted the token, but
	// still pointed at the real JWKS so the signature verifies and the
	// failure is specifically the issuer check.
	let validator = JwtValidator::new(
		"https://other-issuer.example.test".to_owned(),
		RESOURCE.to_owned(),
		[PRINCIPAL.to_owned()].into_iter().collect(),
		SKEW,
		JwksCache::new(format!("{}/jwks", issuer.issuer())),
	);
	let reason = validator
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("a wrong issuer must be rejected");
	assert_eq!(reason, FailureReason::InvalidIssuer);
}

/// A token whose single `aud` is not the configured resource fails
/// with `InvalidAudience`.
#[tokio::test]
async fn rejects_wrong_audience() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = issuer
		.subject(PRINCIPAL)
		.audience("https://someone-else.example.test")
		.mint_id_token();

	let reason = validator(&issuer)
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("a wrong audience must be rejected");
	assert_eq!(reason, FailureReason::InvalidAudience);
}

/// An `aud` array containing the configured resource plus another
/// audience is rejected with `InvalidAudience`: a multi-audience token
/// is refused even when the resource is among its values.
#[tokio::test]
async fn rejects_multi_audience_token() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = issuer
		.subject(PRINCIPAL)
		.claim("aud", json!([RESOURCE, "https://another.example.test"]))
		.mint_id_token();

	let reason = validator(&issuer)
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("a multi-audience token must be rejected");
	assert_eq!(reason, FailureReason::InvalidAudience);
}

/// A token expired beyond the skew tolerance fails with `Expired`.
#[tokio::test]
async fn rejects_expired_token() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	// Issued a minute ago with a 20-second lifetime: exp is now-40s,
	// clear of the far side of the 30-second skew window.
	let token = issuer
		.subject(PRINCIPAL)
		.audience(RESOURCE)
		.issued_at(SystemTime::now() - Duration::from_mins(1))
		.expires_in(Duration::from_secs(20))
		.mint_id_token();

	let reason = validator(&issuer)
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("an expired token must be rejected");
	assert_eq!(reason, FailureReason::Expired);
}

/// Clock-skew tolerance is honoured end to end: a token expired inside
/// the 30-second skew window validates. Both the token and the
/// validator's clock are anchored to a fixed instant so wall-clock drift
/// between minting and validating cannot flip the boundary, which is
/// what made the earlier real-clock version flake under load. The
/// exhaustive boundary cases live in the validator's unit tests; the
/// complementary `rejects_expired_token` covers the far side end to end.
#[tokio::test]
async fn accepts_token_within_skew_window() {
	// A fixed reference instant shared by the token and the validator.
	// iat is anchored 60s before it and the 55s lifetime puts exp at
	// FIXED_NOW-5s: five seconds into the past, well inside the 30-second
	// window, and deterministic regardless of scheduling delay.
	const FIXED_NOW: u64 = 1_800_000_000;

	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = issuer
		.subject(PRINCIPAL)
		.audience(RESOURCE)
		.issued_at(UNIX_EPOCH + Duration::from_secs(FIXED_NOW - 60))
		.expires_in(Duration::from_secs(55))
		.mint_id_token();

	let claims = validator(&issuer)
		.with_current_time(i64::try_from(FIXED_NOW).expect("fixed instant fits in i64"))
		.validate(&format!("Bearer {token}"))
		.await
		.expect("a token expired within the skew window should validate");
	assert_eq!(claims.subject(), PRINCIPAL);
}

/// A token whose `nbf` is in the future beyond the skew tolerance
/// fails with `NotYetValid`.
#[tokio::test]
async fn rejects_not_yet_valid_token() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = issuer
		.subject(PRINCIPAL)
		.audience(RESOURCE)
		.claim("nbf", now_seconds() + 120)
		.mint_id_token();

	let reason = validator(&issuer)
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("a not-yet-valid token must be rejected");
	assert_eq!(reason, FailureReason::NotYetValid);
}

/// A token whose `sub` is not in the principal allowlist fails with
/// `UnknownPrincipal`.
#[tokio::test]
async fn rejects_unknown_principal() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = issuer
		.subject("did:arai:example:mallory")
		.audience(RESOURCE)
		.mint_id_token();

	let reason = validator(&issuer)
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("an unknown principal must be rejected");
	assert_eq!(reason, FailureReason::UnknownPrincipal);
}

/// A token signed with a key whose `kid` is not pinned fails with
/// `KidNotPinned` when pinning is configured.
#[tokio::test]
async fn rejects_unpinned_kid() {
	let issuer = MockIssuer::start(SigningAlgorithm::Es256)
		.await
		.expect("fixture should boot");
	let token = well_formed_token(&issuer);

	let validator =
		validator(&issuer).with_kid_pins(["some-other-kid".to_owned()].into_iter().collect());
	let reason = validator
		.validate(&format!("Bearer {token}"))
		.await
		.expect_err("an unpinned kid must be rejected");
	assert_eq!(reason, FailureReason::KidNotPinned);
}
