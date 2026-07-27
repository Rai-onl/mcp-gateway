//! JWT validation.
//!
//! Given an `Authorization: Bearer <jwt>` header value, the validator
//! verifies the signature against the cached JWKS and checks every
//! claim the gateway binds on, returning either a [`ValidatedClaims`]
//! or a typed [`FailureReason`]. Signature verification runs through
//! `jsonwebtoken` on its ring backend, which compares signatures in
//! constant time across the RSA and ECDSA families.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;

use crate::claims::{ValidatedClaims, sanitise_subject};
use crate::jwks::{JwksCache, JwksError};

/// The asymmetric signing algorithms the gateway accepts, fixed at
/// compile time. A token whose header algorithm is outside this set,
/// including `none` and every `HS*` symmetric algorithm, is rejected
/// before any signature check. The list is the runtime allow-list
/// RFC-0014 fixes as the algorithm-confusion mitigation; it is not
/// operator-configurable.
const ALLOWED_ALGORITHMS: [Algorithm; 9] = [
	Algorithm::RS256,
	Algorithm::RS384,
	Algorithm::RS512,
	Algorithm::PS256,
	Algorithm::PS384,
	Algorithm::PS512,
	Algorithm::ES256,
	Algorithm::ES384,
	Algorithm::EdDSA,
];

/// The accepted signing algorithms by name, in the same order as
/// [`ALLOWED_ALGORITHMS`].
///
/// The protected-resource metadata document advertises exactly this
/// set, so what the gateway publishes matches what it accepts. The two
/// lists are kept side by side; the `algorithm_names_match_enum` test
/// asserts they stay aligned.
pub const ASYMMETRIC_ALGORITHM_NAMES: [&str; 9] = [
	"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];

/// Validates inbound JWTs against a configured issuer, resource,
/// principal allowlist, and JWKS.
pub struct JwtValidator {
	/// The issuer, resource, principal allowlist, and clock-skew
	/// tolerance the token's claims are checked against.
	checks: ClaimChecks,
	/// When set, the token's `kid` must be a member; a token signed
	/// with an unpinned key is rejected even if its signature would
	/// verify.
	kid_pins: Option<HashSet<String>>,
	/// A fixed reference time, in seconds since the Unix epoch, used in
	/// place of the system clock when comparing `exp` and `nbf`. Only a
	/// test seam sets it; production always reads the system clock.
	reference_time: Option<i64>,
	/// The JWKS cache the signing key is resolved from.
	jwks: JwksCache,
}

impl JwtValidator {
	/// Construct a validator. `kid` pinning is off until
	/// [`with_kid_pins`](Self::with_kid_pins) is called.
	#[must_use]
	pub fn new(
		issuer_url: String,
		resource: String,
		principal_subjects: HashSet<String>,
		clock_skew: Duration,
		jwks: JwksCache,
	) -> Self {
		Self {
			checks: ClaimChecks::new(issuer_url, resource, principal_subjects, clock_skew),
			kid_pins: None,
			reference_time: None,
			jwks,
		}
	}

	/// Restrict accepted signing-key identifiers to the given pin
	/// set. A token whose `kid` is not pinned then fails with
	/// [`FailureReason::KidNotPinned`].
	#[must_use]
	pub fn with_kid_pins(mut self, pins: HashSet<String>) -> Self {
		self.kid_pins = Some(pins);
		self
	}

	/// Pin the reference time, in seconds since the Unix epoch, that
	/// `exp` and `nbf` are compared against, instead of reading the
	/// system clock.
	///
	/// A test seam: it lets a test assert the exact clock-skew boundary
	/// without racing the wall clock, which otherwise drifts between
	/// minting a token and validating it and makes a boundary assertion
	/// flaky under load. Production never calls this, so the validator
	/// always uses the real clock; freezing it in a running gateway
	/// would break expiry enforcement.
	#[doc(hidden)]
	#[must_use]
	pub fn with_current_time(mut self, unix_seconds: i64) -> Self {
		self.reference_time = Some(unix_seconds);
		self
	}

	/// Proactively refresh the validator's JWKS cache, replacing the
	/// cached keys with the authorisation server's current set. The
	/// daemon's background-refresh timer calls this on the configured
	/// cadence so rotated keys are picked up ahead of expiry rather than
	/// only on the first token that needs them.
	///
	/// # Errors
	///
	/// Propagates any [`JwksError`] from the underlying fetch. On failure
	/// the previously cached keys are retained, so validation keeps
	/// working against the last-good set.
	pub async fn refresh_jwks(&self) -> Result<(), JwksError> {
		self.jwks.refresh().await
	}

	/// Validate the token carried in an `Authorization` header value.
	///
	/// # Errors
	///
	/// Returns the [`FailureReason`] describing the first check that
	/// failed; no token or claim bytes beyond the sanitised `sub`
	/// reach the error.
	pub async fn validate(&self, authorization: &str) -> Result<ValidatedClaims, FailureReason> {
		let token = bearer_token(authorization)?;

		let header = decode_header(token).map_err(|_| FailureReason::MalformedToken)?;
		// Reject a disallowed algorithm before resolving any key, so a
		// symmetric or `none` token never reaches a signature check.
		if !ALLOWED_ALGORITHMS.contains(&header.alg) {
			return Err(FailureReason::InvalidAlgorithm);
		}

		let kid = header.kid.as_deref().ok_or(FailureReason::MalformedToken)?;
		if let Some(pins) = &self.kid_pins
			&& !pins.contains(kid)
		{
			return Err(FailureReason::KidNotPinned);
		}

		let jwk = self
			.jwks
			.key_for_kid(kid)
			.await
			.map_err(|_| FailureReason::InvalidSignature)?
			.ok_or(FailureReason::InvalidSignature)?;
		let key = decoding_key(&jwk)?;

		// `jsonwebtoken` verifies only the signature here; every claim
		// check is performed below so each failure maps to its own
		// typed reason rather than a single opaque error.
		let mut validation = Validation::new(header.alg);
		validation.validate_exp = false;
		validation.validate_nbf = false;
		validation.validate_aud = false;
		validation.required_spec_claims = HashSet::new();

		let raw = decode::<RawClaims>(token, &key, &validation)
			.map_err(|error| map_decode_error(&error))?
			.claims;

		let now = self.reference_time.unwrap_or_else(now_unix_seconds);
		check_claims(raw, &self.checks, now)
	}
}

/// The issuer, resource, principal allowlist, and clock-skew tolerance
/// the shared [`check_claims`] validates against, bundled so a
/// validator can carry them as one value.
#[derive(Debug, Clone)]
pub struct ClaimChecks {
	/// The issuer the token's `iss` must equal.
	pub issuer_url: String,
	/// The resource the token's `aud` must bind to.
	pub resource: String,
	/// The subjects the gateway admits.
	pub principal_subjects: HashSet<String>,
	/// Clock-skew tolerance applied to `exp` and `nbf`.
	pub clock_skew: Duration,
}

impl ClaimChecks {
	/// Bundle the claim-validation parameters.
	#[must_use]
	pub fn new(
		issuer_url: String,
		resource: String,
		principal_subjects: HashSet<String>,
		clock_skew: Duration,
	) -> Self {
		Self {
			issuer_url,
			resource,
			principal_subjects,
			clock_skew,
		}
	}
}

/// Validate the claims common to both validation strategies against
/// the configured issuer, resource, principal allowlist, and clock
/// skew, returning the [`ValidatedClaims`] on success.
///
/// Shared by the JWT validator (after it verifies the signature) and
/// the introspection validator (after the authorisation server reports
/// the token active), so a token authenticates to the same claim
/// contract whichever strategy checked it.
///
/// `now` is the reference time, in seconds since the Unix epoch, that
/// `exp` and `nbf` are compared against; the caller passes the system
/// clock in production and may pin it in tests.
///
/// # Errors
///
/// Returns the [`FailureReason`] for the first claim that fails: issuer
/// mismatch, audience mismatch, expiry, not-yet-valid, or an
/// unadmitted principal.
pub(crate) fn check_claims(
	raw: RawClaims,
	checks: &ClaimChecks,
	now: i64,
) -> Result<ValidatedClaims, FailureReason> {
	if raw.iss != checks.issuer_url {
		return Err(FailureReason::InvalidIssuer);
	}
	if !audience_binds_to(raw.aud.as_ref(), &checks.resource) {
		return Err(FailureReason::InvalidAudience);
	}

	let skew = skew_seconds(checks.clock_skew);
	if raw.exp <= now.saturating_sub(skew) {
		return Err(FailureReason::Expired);
	}
	if let Some(nbf) = raw.nbf
		&& nbf > now.saturating_add(skew)
	{
		return Err(FailureReason::NotYetValid);
	}

	if !checks.principal_subjects.contains(&raw.sub) {
		tracing::warn!(
			rejected_subject = %sanitise_subject(&raw.sub),
			"inbound token subject is not in the principal allowlist"
		);
		return Err(FailureReason::UnknownPrincipal);
	}

	let scopes = raw
		.scope
		.unwrap_or_default()
		.split_whitespace()
		.map(str::to_owned)
		.collect();
	Ok(ValidatedClaims::new(raw.sub, scopes))
}

/// Extract the bearer token from an `Authorization` header value,
/// matching the `Bearer` scheme case-insensitively (RFC 6750 §2.1).
pub(crate) fn bearer_token(authorization: &str) -> Result<&str, FailureReason> {
	match authorization.split_once(' ') {
		Some((scheme, token)) if scheme.eq_ignore_ascii_case("Bearer") => {
			let token = token.trim();
			if token.is_empty() {
				Err(FailureReason::MissingToken)
			} else {
				Ok(token)
			}
		}
		_ => Err(FailureReason::MissingToken),
	}
}

/// Build a `jsonwebtoken` decoding key from a JWK object, branching on
/// the key type. Unsupported or malformed keys map to
/// [`FailureReason::InvalidSignature`]: without a usable key the
/// signature cannot be trusted.
fn decoding_key(jwk: &Value) -> Result<DecodingKey, FailureReason> {
	let key_type = jwk_field(jwk, "kty")?;
	match key_type {
		"EC" => DecodingKey::from_ec_components(jwk_field(jwk, "x")?, jwk_field(jwk, "y")?)
			.map_err(|_| FailureReason::InvalidSignature),
		"RSA" => DecodingKey::from_rsa_components(jwk_field(jwk, "n")?, jwk_field(jwk, "e")?)
			.map_err(|_| FailureReason::InvalidSignature),
		"OKP" => DecodingKey::from_ed_components(jwk_field(jwk, "x")?)
			.map_err(|_| FailureReason::InvalidSignature),
		_ => Err(FailureReason::InvalidSignature),
	}
}

/// Read a required string field from a JWK object.
fn jwk_field<'a>(jwk: &'a Value, name: &str) -> Result<&'a str, FailureReason> {
	jwk.get(name)
		.and_then(Value::as_str)
		.ok_or(FailureReason::InvalidSignature)
}

/// Whether the token's `aud` claim binds to the configured resource:
/// a string equal to it, or an array whose every element equals it.
/// A multi-audience token carrying any other audience is rejected even
/// when the configured resource is among the values.
fn audience_binds_to(audience: Option<&Audience>, resource: &str) -> bool {
	match audience {
		Some(Audience::One(value)) => value == resource,
		Some(Audience::Many(values)) => {
			!values.is_empty() && values.iter().all(|value| value == resource)
		}
		None => false,
	}
}

/// The current time as whole seconds since the Unix epoch.
pub(crate) fn now_unix_seconds() -> i64 {
	let seconds = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_or(0, |elapsed| elapsed.as_secs());
	i64::try_from(seconds).unwrap_or(i64::MAX)
}

/// The clock-skew tolerance as whole seconds.
fn skew_seconds(skew: Duration) -> i64 {
	i64::try_from(skew.as_secs()).unwrap_or(i64::MAX)
}

/// Map a `jsonwebtoken` decode error to a typed failure reason,
/// distinguishing a bad signature and a disallowed algorithm from the
/// catch-all malformed case.
fn map_decode_error(error: &jsonwebtoken::errors::Error) -> FailureReason {
	use jsonwebtoken::errors::ErrorKind;
	match error.kind() {
		ErrorKind::InvalidSignature => FailureReason::InvalidSignature,
		ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
			FailureReason::InvalidAlgorithm
		}
		_ => FailureReason::MalformedToken,
	}
}

/// The claims [`check_claims`] validates, deserialised from a JWT
/// payload or constructed from an introspection response.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RawClaims {
	/// The issuer identifier.
	pub(crate) iss: String,
	/// The subject identifier.
	pub(crate) sub: String,
	/// The audience, a single value or an array.
	#[serde(default)]
	pub(crate) aud: Option<Audience>,
	/// The expiry, as seconds since the Unix epoch.
	pub(crate) exp: i64,
	/// The not-before, as seconds since the Unix epoch, when present.
	#[serde(default)]
	pub(crate) nbf: Option<i64>,
	/// The space-delimited scope string, when present.
	#[serde(default)]
	pub(crate) scope: Option<String>,
}

/// A token `aud` claim: either a single audience or an array.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum Audience {
	/// A single audience string.
	One(String),
	/// An array of audience strings.
	Many(Vec<String>),
}

/// The typed reason a token failed validation. Variants carry no
/// token or claim bytes; the sanitised `sub` is logged separately at
/// the point of failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FailureReason {
	/// No bearer token was present in the `Authorization` header.
	#[error("no bearer token present")]
	MissingToken,
	/// The token is not a well-formed JWT.
	#[error("malformed token")]
	MalformedToken,
	/// The signature did not verify against the resolved key.
	#[error("invalid signature")]
	InvalidSignature,
	/// The token's algorithm is outside the accepted asymmetric set.
	#[error("invalid or disallowed algorithm")]
	InvalidAlgorithm,
	/// The `iss` claim does not equal the configured issuer.
	#[error("invalid issuer")]
	InvalidIssuer,
	/// The `aud` claim does not bind to the configured resource.
	#[error("invalid audience")]
	InvalidAudience,
	/// The token has expired (after clock-skew tolerance).
	#[error("token expired")]
	Expired,
	/// The token is not yet valid (before clock-skew tolerance).
	#[error("token not yet valid")]
	NotYetValid,
	/// The `sub` claim is not in the principal allowlist.
	#[error("unknown principal")]
	UnknownPrincipal,
	/// The token lacks a scope required for the requested server.
	/// Produced by the per-server authorisation layer, not the
	/// validator itself.
	#[error("missing required scope")]
	MissingScope,
	/// The signing key's `kid` is not in the configured pin set.
	#[error("signing key is not pinned")]
	KidNotPinned,

	/// The authorisation server reported the token inactive, or its
	/// introspection endpoint could not be reached under a fail-closed
	/// policy. Either way the token is not honoured.
	#[error("token is not active")]
	Inactive,
}

#[cfg(test)]
mod tests {
	use std::str::FromStr as _;

	use super::*;

	/// A fixed reference instant, in seconds since the Unix epoch, so the
	/// clock-skew boundary tests never race the wall clock.
	const NOW: i64 = 1_800_000_000;

	/// The clock-skew tolerance the boundary tests validate against.
	const SKEW: Duration = Duration::from_secs(30);

	/// Build claims that pass every non-temporal check, with the given
	/// `exp` and `nbf`, so a test can isolate the expiry and not-before
	/// boundaries.
	fn timed_claims(exp: i64, nbf: Option<i64>) -> RawClaims {
		RawClaims {
			iss: "https://issuer.example.test".to_owned(),
			sub: "did:arai:example:alice".to_owned(),
			aud: Some(Audience::One("https://resource.example.test".to_owned())),
			exp,
			nbf,
			scope: None,
		}
	}

	/// Run [`check_claims`] against the fixed issuer, resource, principal,
	/// and [`NOW`], returning the outcome for the given claims.
	fn check_at_now(raw: RawClaims) -> Result<ValidatedClaims, FailureReason> {
		let checks = ClaimChecks::new(
			"https://issuer.example.test".to_owned(),
			"https://resource.example.test".to_owned(),
			["did:arai:example:alice".to_owned()].into_iter().collect(),
			SKEW,
		);
		check_claims(raw, &checks, NOW)
	}

	/// A token whose `exp` is within the skew window in the past still
	/// validates: expiry is enforced only beyond the tolerance.
	#[test]
	fn exp_within_skew_window_is_accepted() {
		// Expired five seconds ago, well inside the 30-second window.
		let claims = check_at_now(timed_claims(NOW - 5, None));
		assert!(claims.is_ok(), "expected acceptance, got: {claims:?}");
	}

	/// A token whose `exp` is exactly at the far edge of the skew window
	/// is rejected: the boundary is exclusive (`exp <= now - skew`).
	#[test]
	fn exp_at_skew_boundary_is_rejected() {
		let claims = check_at_now(timed_claims(NOW - 30, None));
		assert_eq!(claims.unwrap_err(), FailureReason::Expired);
	}

	/// A token expired beyond the skew window is rejected.
	#[test]
	fn exp_beyond_skew_window_is_rejected() {
		let claims = check_at_now(timed_claims(NOW - 31, None));
		assert_eq!(claims.unwrap_err(), FailureReason::Expired);
	}

	/// A token whose `nbf` is within the skew window in the future still
	/// validates: not-before is enforced only beyond the tolerance.
	#[test]
	fn nbf_within_skew_window_is_accepted() {
		let claims = check_at_now(timed_claims(NOW + 3600, Some(NOW + 5)));
		assert!(claims.is_ok(), "expected acceptance, got: {claims:?}");
	}

	/// A token whose `nbf` is beyond the skew window in the future is
	/// rejected as not yet valid.
	#[test]
	fn nbf_beyond_skew_window_is_rejected() {
		let claims = check_at_now(timed_claims(NOW + 3600, Some(NOW + 31)));
		assert_eq!(claims.unwrap_err(), FailureReason::NotYetValid);
	}

	/// The advertised algorithm names map one-to-one, in order, onto
	/// the enum the validator enforces, so the metadata document never
	/// advertises an algorithm the validator would reject.
	#[test]
	fn algorithm_names_match_enum() {
		assert_eq!(ASYMMETRIC_ALGORITHM_NAMES.len(), ALLOWED_ALGORITHMS.len());
		for (name, algorithm) in ASYMMETRIC_ALGORITHM_NAMES.iter().zip(ALLOWED_ALGORITHMS) {
			assert_eq!(
				Algorithm::from_str(name).expect("name should parse to an algorithm"),
				algorithm,
				"name {name} must match its enum entry",
			);
		}
	}
}
