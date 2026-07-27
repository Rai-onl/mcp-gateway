//! The configured token-validation strategy.
//!
//! A gateway instance validates inbound tokens one of two ways: local
//! JWT verification against the JWKS, or remote RFC 7662 introspection.
//! Both produce the same [`ValidatedClaims`], so the middleware holds a
//! [`Validator`] and never branches on which strategy is in effect.

use crate::claims::ValidatedClaims;
use crate::introspection::IntrospectionValidator;
use crate::validator::{FailureReason, JwtValidator};

/// The validation strategy in effect for an instance.
pub enum Validator {
	/// Local JWT validation against the cached JWKS.
	Jwt(JwtValidator),
	/// Remote validation by introspecting the token at the
	/// authorisation server.
	Introspection(IntrospectionValidator),
}

impl Validator {
	/// Validate the token carried in an `Authorization` header value
	/// through the configured strategy.
	///
	/// # Errors
	///
	/// Returns the strategy's [`FailureReason`]; the variants and their
	/// meanings are identical across strategies.
	pub async fn validate(&self, authorization: &str) -> Result<ValidatedClaims, FailureReason> {
		match self {
			Self::Jwt(validator) => validator.validate(authorization).await,
			Self::Introspection(validator) => validator.validate(authorization).await,
		}
	}

	/// Discard any cached validation state.
	///
	/// The introspection strategy clears its response cache so a reload
	/// does not keep serving decisions made under the previous
	/// configuration; JWT validation holds no such cache.
	pub fn flush_cache(&self) {
		if let Self::Introspection(validator) = self {
			validator.flush();
		}
	}

	/// Proactively refresh any cached signing keys.
	///
	/// For JWT validation this re-fetches the JWKS ahead of expiry. A
	/// failure is logged and the last-good keys are retained by the
	/// cache, so the daemon's timer can call this fire-and-forget.
	/// Introspection holds no JWKS, so this is a no-op.
	pub async fn refresh_keys(&self) {
		let Self::Jwt(validator) = self else {
			return;
		};
		if let Err(error) = validator.refresh_jwks().await {
			tracing::warn!(
				%error,
				"background JWKS refresh failed; keeping the previously loaded keys"
			);
		}
	}
}
