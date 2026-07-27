//! Validated token claims and the subject-sanitisation used before
//! any claim value is written to a log field.
//!
//! Both the JWT and introspection validation strategies produce a
//! [`ValidatedClaims`], so the middleware that consumes the result
//! does not branch on which strategy validated the token.

use std::collections::HashSet;

/// The claims the gateway extracts from a validated token.
///
/// The `subject` is the raw `sub` claim, retained for audit and for
/// the principal-allowlist match the validator has already performed.
/// It is never written to a log field directly: callers log
/// [`sanitised_subject`](Self::sanitised_subject) so a hostile `sub`
/// cannot inject control characters or forge log structure.
#[derive(Debug, Clone)]
pub struct ValidatedClaims {
	/// The raw `sub` claim value.
	subject: String,
	/// The token's scopes, parsed from the space-delimited `scope`
	/// claim (RFC 6749 §3.3). Per-server scope authorisation is
	/// applied by a later layer; the validator only surfaces them.
	scopes: HashSet<String>,
}

impl ValidatedClaims {
	/// Construct a claims set from a raw subject and parsed scopes.
	#[must_use]
	pub fn new(subject: String, scopes: HashSet<String>) -> Self {
		Self { subject, scopes }
	}

	/// The raw `sub` claim. Use [`sanitised_subject`](Self::sanitised_subject)
	/// for anything written to a log field.
	#[must_use]
	pub fn subject(&self) -> &str {
		&self.subject
	}

	/// The token's scopes.
	#[must_use]
	pub fn scopes(&self) -> &HashSet<String> {
		&self.scopes
	}

	/// The `sub` claim in a form safe to write to a log field:
	/// control characters percent-encoded and the result capped at
	/// 256 bytes. See [`sanitise_subject`].
	#[must_use]
	pub fn sanitised_subject(&self) -> String {
		sanitise_subject(&self.subject)
	}
}

/// The byte cap applied to a sanitised subject, bounding how much a
/// caller-controlled `sub` can write into a log line.
const SUBJECT_BYTE_CAP: usize = 256;

/// Render a `sub` claim safe to write to a log field.
///
/// Percent-encodes every C0 control (U+0000–U+001F), `DEL` (U+007F),
/// and C1 control (U+0080–U+009F) as `%XX` over its UTF-8 bytes, so a
/// `sub` carrying newlines or terminal escapes cannot forge log
/// structure. Printable characters, including non-ASCII, are left
/// untouched. The result is capped at [`SUBJECT_BYTE_CAP`] bytes,
/// truncated at a character boundary.
#[must_use]
pub fn sanitise_subject(raw: &str) -> String {
	use std::fmt::Write as _;

	let mut sanitised = String::with_capacity(raw.len());
	for character in raw.chars() {
		if is_log_unsafe_control(character) {
			let mut encode_buffer = [0_u8; 4];
			for byte in character.encode_utf8(&mut encode_buffer).bytes() {
				let _ = write!(sanitised, "%{byte:02X}");
			}
		} else {
			sanitised.push(character);
		}
	}

	truncate_to_byte_cap(sanitised, SUBJECT_BYTE_CAP)
}

/// Whether a character is a control the gateway percent-encodes
/// before logging: a C0 control, `DEL`, or a C1 control.
fn is_log_unsafe_control(character: char) -> bool {
	matches!(character, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}')
}

/// Truncate a string to at most `cap` bytes, stepping back to the
/// nearest character boundary so a multi-byte character is never
/// split.
fn truncate_to_byte_cap(mut value: String, cap: usize) -> String {
	if value.len() <= cap {
		return value;
	}
	let mut boundary = cap;
	while !value.is_char_boundary(boundary) {
		boundary -= 1;
	}
	value.truncate(boundary);
	value
}

#[cfg(test)]
mod tests {
	use super::*;

	/// C0 control characters (newline, carriage return, tab) are
	/// percent-encoded over their single UTF-8 byte.
	#[test]
	fn percent_encodes_c0_control_characters() {
		assert_eq!(sanitise_subject("a\nb\rc\td"), "a%0Ab%0Dc%09d");
	}

	/// `DEL` (U+007F, one byte) and a C1 control (U+0085 NEL, two
	/// UTF-8 bytes) are both percent-encoded byte by byte.
	#[test]
	fn percent_encodes_delete_and_c1_controls() {
		assert_eq!(sanitise_subject("x\u{007F}y\u{0085}z"), "x%7Fy%C2%85z");
	}

	/// Printable characters, including a multi-byte non-ASCII one,
	/// pass through unchanged.
	#[test]
	fn leaves_printable_characters_untouched() {
		assert_eq!(
			sanitise_subject("did:arai:example:älice"),
			"did:arai:example:älice"
		);
	}

	/// A subject longer than the cap is truncated to exactly the cap
	/// in bytes.
	#[test]
	fn caps_long_subjects_at_the_byte_limit() {
		let sanitised = sanitise_subject(&"a".repeat(300));
		assert_eq!(sanitised.len(), SUBJECT_BYTE_CAP);
	}

	/// A subject carrying a log-forging payload is rendered inert:
	/// the control characters are encoded and the raw newline is
	/// gone.
	#[test]
	fn renders_a_log_forging_subject_inert() {
		let sanitised = sanitise_subject("alice\n{\"forged\":true}");
		assert!(!sanitised.contains('\n'), "raw newline must not survive");
		assert!(
			sanitised.contains("%0A"),
			"the newline must be percent-encoded, got {sanitised:?}",
		);
	}
}
