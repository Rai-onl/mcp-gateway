//! `WWW-Authenticate` challenge construction (RFC 6750 §3, RFC 9728
//! §5.1).
//!
//! A rejected request carries a `Bearer` challenge naming the realm,
//! the optional token error, and the protected-resource metadata URL
//! so a client can begin discovery from the failure response alone.

/// An RFC 6750 §3.1 token-error code carried in a challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
	/// The request carried no usable credentials, or the token failed
	/// validation. Renders as `error="invalid_token"`.
	InvalidToken,
	/// The token validated but lacks the principal or scope the route
	/// requires. Renders as `error="insufficient_scope"`.
	InsufficientScope,
}

impl TokenError {
	/// The RFC 6750 error code string.
	#[must_use]
	pub fn code(self) -> &'static str {
		match self {
			Self::InvalidToken => "invalid_token",
			Self::InsufficientScope => "insufficient_scope",
		}
	}
}

/// A builder for a `Bearer` `WWW-Authenticate` challenge value.
///
/// `Bearer` is the only scheme the gateway issues in v0; the builder
/// is the single place a future scheme (DPoP) would add a sibling
/// challenge.
#[derive(Debug, Clone)]
pub struct BearerChallenge {
	/// The protection-space realm, the instance's resource identifier.
	realm: String,
	/// The protected-resource-metadata URL clients discover from.
	resource_metadata: String,
	/// The token error and its human-readable description, when the
	/// challenge accompanies a specific failure.
	error: Option<(TokenError, String)>,
}

impl BearerChallenge {
	/// Begin a challenge for the given realm, pointing clients at the
	/// protected-resource metadata URL.
	#[must_use]
	pub fn new(realm: impl Into<String>, resource_metadata: impl Into<String>) -> Self {
		Self {
			realm: realm.into(),
			resource_metadata: resource_metadata.into(),
			error: None,
		}
	}

	/// Attach a token error and description to the challenge.
	#[must_use]
	pub fn with_error(mut self, error: TokenError, description: impl Into<String>) -> Self {
		self.error = Some((error, description.into()));
		self
	}

	/// Render the challenge as a `WWW-Authenticate` header value.
	///
	/// The parameters follow RFC 6750 §3: `realm`, then the optional
	/// `error` and `error_description`, then the RFC 9728 §5.1
	/// `resource_metadata` pointer, comma-separated.
	#[must_use]
	pub fn into_header_value(self) -> String {
		use std::fmt::Write as _;

		let mut value = format!(r#"Bearer realm="{}""#, escape_quoted(&self.realm));
		if let Some((error, description)) = &self.error {
			let _ = write!(
				value,
				r#", error="{}", error_description="{}""#,
				error.code(),
				escape_quoted(description)
			);
		}
		let _ = write!(
			value,
			r#", resource_metadata="{}""#,
			escape_quoted(&self.resource_metadata)
		);
		value
	}
}

/// Escape a value for an RFC 7235 quoted-string: backslash and
/// double-quote are backslash-escaped so the value cannot terminate the
/// quoted string early, and control characters (which a header value
/// cannot carry) are dropped. The realm and description derive from
/// configuration rather than a token, so this is a low-risk gap, but a
/// quoted-string value still has to be well-formed.
fn escape_quoted(value: &str) -> String {
	let mut escaped = String::with_capacity(value.len());
	for character in value.chars() {
		match character {
			'\\' => escaped.push_str(r"\\"),
			'"' => escaped.push_str("\\\""),
			control if control.is_control() => {}
			other => escaped.push(other),
		}
	}
	escaped
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A bare challenge names the scheme, realm, and resource-metadata
	/// URL.
	#[test]
	fn renders_realm_and_resource_metadata() {
		let value = BearerChallenge::new(
			"alice.gateway.example.test",
			"https://alice.gateway.example.test/.well-known/oauth-protected-resource",
		)
		.into_header_value();

		assert!(
			value.starts_with("Bearer "),
			"must name the Bearer scheme: {value}"
		);
		assert!(
			value.contains(r#"realm="alice.gateway.example.test""#),
			"{value}"
		);
		assert!(
			value.contains(
				r#"resource_metadata="https://alice.gateway.example.test/.well-known/oauth-protected-resource""#
			),
			"{value}",
		);
		assert!(
			!value.contains("error="),
			"a bare challenge has no error: {value}"
		);
	}

	/// An invalid-token challenge carries the error code and
	/// description.
	#[test]
	fn renders_invalid_token_error() {
		let value = BearerChallenge::new("realm", "https://example.test/metadata")
			.with_error(TokenError::InvalidToken, "the access token expired")
			.into_header_value();

		assert!(value.contains(r#"error="invalid_token""#), "{value}");
		assert!(
			value.contains(r#"error_description="the access token expired""#),
			"{value}",
		);
	}

	/// An insufficient-scope challenge carries that error code, the
	/// 403 case.
	#[test]
	fn renders_insufficient_scope_error() {
		let value = BearerChallenge::new("realm", "https://example.test/metadata")
			.with_error(
				TokenError::InsufficientScope,
				"scope mcp:invoke:gitlab required",
			)
			.into_header_value();

		assert!(value.contains(r#"error="insufficient_scope""#), "{value}");
	}

	/// A double-quote or backslash in a parameter value is escaped, so a
	/// realm or description carrying one (both derive from configuration,
	/// not from a token) cannot break out of the quoted string and forge
	/// a malformed header. RFC 7235 quoted-string syntax backslash-escapes
	/// both characters.
	#[test]
	fn escapes_quotes_and_backslashes_in_parameter_values() {
		let value = BearerChallenge::new(r#"re"al\m"#, "https://example.test/metadata")
			.with_error(TokenError::InsufficientScope, r#"needs "scope" \ here"#)
			.into_header_value();

		assert!(
			value.contains(r#"realm="re\"al\\m""#),
			"the realm's quote and backslash must be escaped: {value}",
		);
		assert!(
			value.contains(r#"error_description="needs \"scope\" \\ here""#),
			"the description's quote and backslash must be escaped: {value}",
		);
	}
}
