//! Authorisation-server discovery.
//!
//! Retrieves and parses the metadata document the gateway validates
//! tokens against. The primary source is OpenID Connect Discovery
//! 1.0 at `{issuer}/.well-known/openid-configuration`; an RFC 8414
//! document at `{issuer}/.well-known/oauth-authorization-server`
//! serves as a fallback. Both deserialise into the same
//! [`DiscoveryDocument`].

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// The subset of an authorisation server's discovery metadata the
/// gateway relies on.
///
/// An OpenID Connect Discovery 1.0 document and an RFC 8414 OAuth 2.0
/// Authorization Server Metadata document both deserialise into this
/// shape; the gateway treats them identically once parsed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DiscoveryDocument {
	/// The issuer identifier. Cross-checked against the configured
	/// issuer URL, which it must match exactly.
	pub issuer: String,

	/// The JSON Web Key Set endpoint, source of the keys used to
	/// verify JWT signatures.
	pub jwks_uri: String,

	/// The RFC 7662 token introspection endpoint, when the
	/// authorisation server advertises one.
	#[serde(default)]
	pub introspection_endpoint: Option<String>,

	/// The signing algorithms the authorisation server advertises.
	/// Cross-checked against the gateway's fixed asymmetric-only
	/// allow-list; `none` or any `HS*` value fails load.
	#[serde(rename = "id_token_signing_alg_values_supported", default)]
	pub signing_algorithms: Vec<String>,

	/// The scopes the authorisation server advertises. Informational;
	/// used to sanity-check the operator's scope configuration.
	#[serde(default)]
	pub scopes_supported: Vec<String>,

	/// Whether the authorisation server advertises support for the
	/// RFC 8707 `resource` parameter.
	///
	/// RFC 8707 defines no standardised discovery field for this, so
	/// the gateway looks for a conventional `resource_indicators_supported`
	/// boolean and warns at load when it is absent or false: RFC 8707
	/// is what makes the gateway's per-instance audience binding
	/// reliable, and an authorisation server that ignores it can mint
	/// a token with no `aud`.
	#[serde(default)]
	pub resource_indicators_supported: bool,
}

/// A client that retrieves and parses an authorisation server's
/// discovery document.
pub struct DiscoveryClient {
	http: reqwest::Client,
	issuer_url: String,
	/// Optional pinned SHA-256 of the discovery body, hex-encoded,
	/// from `trust_anchors.discovery_document_sha256`. When set, the
	/// fetched body must hash to this value or the fetch fails.
	discovery_document_sha256: Option<String>,
}

impl DiscoveryClient {
	/// Construct a discovery client for the given issuer URL.
	///
	/// The URL must not carry a trailing slash; the well-known paths
	/// are appended to it directly.
	#[must_use]
	pub fn new(issuer_url: String) -> Self {
		Self {
			http: crate::trust::default_http_client(),
			issuer_url,
			discovery_document_sha256: None,
		}
	}

	/// Pin the expected SHA-256 of the discovery document body
	/// (hex-encoded). When set, [`fetch`](Self::fetch) verifies the
	/// served body hashes to this value and fails otherwise.
	#[must_use]
	pub fn with_discovery_document_sha256(mut self, expected_hex: String) -> Self {
		self.discovery_document_sha256 = Some(expected_hex);
		self
	}

	/// Pin the authorisation server's TLS certificate by its
	/// SubjectPublicKeyInfo (RFC 7469 `sha256/...` values). When set,
	/// the client rebuilds its HTTP layer so every fetch accepts only
	/// a leaf certificate whose SPKI matches one of the pins; a
	/// mismatch fails the TLS handshake and therefore the fetch.
	#[must_use]
	pub fn with_spki_pins(mut self, pins: &[String]) -> Self {
		self.http = crate::trust::pinned_http_client(pins);
		self
	}

	/// Fetch and parse the discovery document.
	///
	/// The primary path is OpenID Connect Discovery 1.0 at
	/// `{issuer}/.well-known/openid-configuration`. When that path
	/// returns 404, the client falls back to RFC 8414 OAuth 2.0
	/// Authorization Server Metadata at
	/// `{issuer}/.well-known/oauth-authorization-server`; both paths
	/// produce the same [`DiscoveryDocument`]. The advertised
	/// `issuer` is cross-checked against the configured issuer URL.
	///
	/// # Errors
	///
	/// Returns [`DiscoveryError::Request`] if an HTTP request fails,
	/// [`DiscoveryError::Parse`] if the body is not valid discovery
	/// JSON, and [`DiscoveryError::IssuerMismatch`] if the document's
	/// `issuer` does not equal the configured issuer URL.
	pub async fn fetch(&self) -> Result<DiscoveryDocument, DiscoveryError> {
		let oidc_url = format!("{}/.well-known/openid-configuration", self.issuer_url);
		let response = self
			.http
			.get(&oidc_url)
			.send()
			.await
			.map_err(DiscoveryError::Request)?;

		// OpenID Connect Discovery 1.0 is the primary path. A 404
		// there means the authorisation server publishes only the
		// RFC 8414 OAuth metadata path, so fall back to it. Any other
		// non-success status is not a metadata document (a 500, a 403,
		// a redirect to an error or captive-portal page) and must not
		// be parsed as one.
		let status = response.status();
		let body = if status == reqwest::StatusCode::NOT_FOUND {
			// RFC 8414 §3.1 inserts the well-known segment before any path
			// component of the issuer, unlike the appended OpenID Connect
			// path above.
			let rfc8414_url = well_known_url(&self.issuer_url, "oauth-authorization-server");
			let fallback = self
				.http
				.get(&rfc8414_url)
				.send()
				.await
				.map_err(DiscoveryError::Request)?;
			let fallback_status = fallback.status();
			if !fallback_status.is_success() {
				return Err(DiscoveryError::UnexpectedStatus {
					status: fallback_status.as_u16(),
				});
			}
			fallback.text().await.map_err(DiscoveryError::Request)?
		} else if status.is_success() {
			response.text().await.map_err(DiscoveryError::Request)?
		} else {
			return Err(DiscoveryError::UnexpectedStatus {
				status: status.as_u16(),
			});
		};

		// Trust-anchor content pin: the body the gateway is about to
		// trust must hash to the configured value. Checked before
		// parsing, on the exact bytes received, because the pin
		// defends against a substituted document regardless of whether
		// it parses.
		if let Some(expected) = &self.discovery_document_sha256 {
			let actual = sha256_hex(&body);
			if !actual.eq_ignore_ascii_case(expected) {
				return Err(DiscoveryError::DiscoveryHashMismatch {
					expected: expected.clone(),
					actual,
				});
			}
		}

		let document: DiscoveryDocument =
			serde_json::from_str(&body).map_err(DiscoveryError::Parse)?;

		if document.issuer != self.issuer_url {
			return Err(DiscoveryError::IssuerMismatch {
				configured: self.issuer_url.clone(),
				advertised: document.issuer,
			});
		}

		// The gateway validates with asymmetric keys only. An
		// authorisation server advertising `none` or any `HS*`
		// symmetric algorithm is misconfigured at the source and
		// opens an algorithm-confusion path, so its presence fails
		// the load regardless of any acceptable algorithms alongside.
		if let Some(rejected) = document
			.signing_algorithms
			.iter()
			.find(|algorithm| is_symmetric_or_none(algorithm))
		{
			return Err(DiscoveryError::UnsupportedAlgorithm(rejected.clone()));
		}

		Ok(document)
	}
}

/// Build a `.well-known` URL for `base_url` per RFC 8414 §3.1 and RFC
/// 9728 §3.1: the well-known segment is inserted between the authority
/// and any path component, not appended. For a base with no path the two
/// are equivalent, which is the common case.
///
/// `well_known_suffix` is the part after `.well-known/`, for example
/// `oauth-authorization-server` or `oauth-protected-resource`. (OpenID
/// Connect Discovery 1.0 instead appends `openid-configuration` to the
/// issuer, so that path is built directly rather than through here.)
pub(crate) fn well_known_url(base_url: &str, well_known_suffix: &str) -> String {
	match split_origin_and_path(base_url) {
		Some((origin, path)) if !path.is_empty() => {
			format!("{origin}/.well-known/{well_known_suffix}/{path}")
		}
		Some((origin, _)) => format!("{origin}/.well-known/{well_known_suffix}"),
		// A base without a `scheme://` is malformed; fall back to append
		// so the caller still produces a usable, if unconventional, URL.
		None => format!("{base_url}/.well-known/{well_known_suffix}"),
	}
}

/// Split a URL into its origin (`scheme://authority`) and the path that
/// follows it (without the leading or trailing slash), or `None` when the
/// URL carries no `scheme://`.
fn split_origin_and_path(url: &str) -> Option<(&str, &str)> {
	let authority_start = url.find("://")? + 3;
	match url[authority_start..].find('/') {
		Some(offset) => {
			let slash = authority_start + offset;
			Some((&url[..slash], url[slash + 1..].trim_end_matches('/')))
		}
		None => Some((url, "")),
	}
}

/// Whether a JWS algorithm name is one the gateway refuses to trust:
/// `none` (unsigned) or any `HS*` keyed-hash (symmetric) algorithm.
///
/// The comparison is case-insensitive. RFC 7518 names algorithms in
/// uppercase, but a misconfigured server should not slip a symmetric
/// algorithm past the guard by lowercasing it.
fn is_symmetric_or_none(algorithm: &str) -> bool {
	let upper = algorithm.to_ascii_uppercase();
	upper == "NONE" || upper.starts_with("HS")
}

/// Compute the lowercase hex-encoded SHA-256 of a discovery body, the
/// encoding `trust_anchors.discovery_document_sha256` is compared in.
fn sha256_hex(body: &str) -> String {
	use std::fmt::Write as _;

	let digest = Sha256::digest(body.as_bytes());
	let mut hex = String::with_capacity(digest.len() * 2);
	for byte in digest {
		// Writing into a pre-sized String avoids the per-byte
		// allocation a `map(format!).collect()` would incur.
		let _ = write!(hex, "{byte:02x}");
	}
	hex
}

/// Emit `warn`-level advisories about a freshly fetched discovery
/// document. These do not fail the load; they flag a deployment that
/// is missing a defence the gateway recommends.
///
/// The current advisory is the absence of RFC 8707 resource-indicator
/// support. Per-instance audience binding depends on the authorisation
/// server honouring the `resource` parameter; one that ignores it can
/// issue a token with no `aud`, which the gateway rejects, producing a
/// misleading symptom. The startup path calls this after a successful
/// fetch so the operator sees the advisory once at load.
pub fn emit_discovery_warnings(document: &DiscoveryDocument) {
	if !document.resource_indicators_supported {
		tracing::warn!(
			"the authorisation server's discovery document does not advertise RFC 8707 \
			 resource-indicator support (resource_indicators_supported); the gateway's \
			 per-instance audience binding relies on it, and a server that ignores the \
			 resource parameter can issue tokens with no aud, which the gateway rejects"
		);
	}
}

/// Errors that can occur while retrieving or validating a discovery
/// document.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
	/// The HTTP request to the discovery endpoint failed (network
	/// error, DNS failure, TLS error).
	#[error("discovery request failed: {0}")]
	Request(reqwest::Error),

	/// The discovery response body could not be parsed as a metadata
	/// document.
	#[error("discovery document is not valid JSON: {0}")]
	Parse(serde_json::Error),

	/// The discovery endpoint returned a non-success HTTP status, other
	/// than the 404 that triggers the RFC 8414 fallback. The body is not
	/// a metadata document and is not parsed.
	#[error("discovery endpoint returned unexpected status {status}")]
	UnexpectedStatus {
		/// The HTTP status code the endpoint returned.
		status: u16,
	},

	/// The discovery document advertised a signing algorithm the
	/// gateway refuses to trust: `none` or an `HS*` symmetric
	/// algorithm. Carries the offending algorithm name.
	#[error("discovery advertises an unsupported signing algorithm: {0}")]
	UnsupportedAlgorithm(String),

	/// The fetched discovery body did not hash to the pinned
	/// `discovery_document_sha256`. A mismatch signals a substituted
	/// document and fails the fetch.
	#[error("discovery document SHA-256 {actual} does not match pinned {expected}")]
	DiscoveryHashMismatch {
		/// The pinned hash the operator configured (hex).
		expected: String,
		/// The hash of the body actually served (hex).
		actual: String,
	},

	/// The `issuer` advertised by the discovery document does not
	/// match the configured issuer URL. A mismatch is a substitution
	/// signal and fails the fetch.
	#[error("discovery issuer {advertised:?} does not match configured issuer {configured:?}")]
	IssuerMismatch {
		/// The issuer URL the gateway was configured with.
		configured: String,
		/// The issuer the discovery document advertised.
		advertised: String,
	},
}

#[cfg(test)]
mod tests {
	use std::io;
	use std::sync::{Arc, Mutex};

	use super::*;

	/// A test writer that captures everything written to it into a
	/// shared buffer, so a test can assert on emitted tracing output.
	#[derive(Clone, Default)]
	struct CapturingWriter {
		buffer: Arc<Mutex<Vec<u8>>>,
	}

	impl io::Write for CapturingWriter {
		fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
			self.buffer
				.lock()
				.expect("capture buffer poisoned")
				.extend_from_slice(buf);
			Ok(buf.len())
		}

		fn flush(&mut self) -> io::Result<()> {
			Ok(())
		}
	}

	impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
		type Writer = Self;
		fn make_writer(&'a self) -> Self::Writer {
			self.clone()
		}
	}

	/// Run `body` inside a `warn`-level capturing subscriber and
	/// return whatever tracing output it emitted.
	fn capture_tracing<F: FnOnce()>(body: F) -> String {
		let writer = CapturingWriter::default();
		let captured = Arc::clone(&writer.buffer);
		let subscriber = tracing_subscriber::fmt()
			.with_writer(writer)
			.with_max_level(tracing::Level::WARN)
			.with_ansi(false)
			.with_target(false)
			.finish();
		tracing::subscriber::with_default(subscriber, body);
		String::from_utf8(captured.lock().expect("capture buffer poisoned").clone())
			.expect("captured tracing output should be valid UTF-8")
	}

	/// Build a discovery document with the RFC 8707 advertisement
	/// flag set as given and otherwise-acceptable contents.
	fn document_with_resource_indicators(supported: bool) -> DiscoveryDocument {
		DiscoveryDocument {
			issuer: "https://issuer.example.test".to_owned(),
			jwks_uri: "https://issuer.example.test/jwks".to_owned(),
			introspection_endpoint: None,
			signing_algorithms: vec!["ES256".to_owned()],
			scopes_supported: Vec::new(),
			resource_indicators_supported: supported,
		}
	}

	/// A document that does not advertise RFC 8707 resource-indicator
	/// support emits a `warn` naming the gap. Configuration still
	/// loads; the advisory is informational.
	#[test]
	fn warns_when_resource_indicators_unadvertised() {
		let document = document_with_resource_indicators(false);
		let captured = capture_tracing(|| emit_discovery_warnings(&document));
		assert!(
			captured.contains("RFC 8707"),
			"expected an RFC 8707 advisory, got: {captured:?}",
		);
	}

	/// A document that advertises RFC 8707 support emits no advisory.
	#[test]
	fn no_warning_when_resource_indicators_advertised() {
		let document = document_with_resource_indicators(true);
		let captured = capture_tracing(|| emit_discovery_warnings(&document));
		assert!(
			!captured.contains("RFC 8707"),
			"unexpected RFC 8707 advisory when support is advertised: {captured:?}",
		);
	}

	/// For a base URL with no path, the well-known segment is simply
	/// appended: insertion and appending coincide, which is the common
	/// case for both issuers and resources.
	#[test]
	fn well_known_url_appends_for_a_path_less_base() {
		assert_eq!(
			well_known_url("https://issuer.example.test", "oauth-authorization-server"),
			"https://issuer.example.test/.well-known/oauth-authorization-server",
		);
	}

	/// For a base URL with a path component, the well-known segment is
	/// inserted before the path, per RFC 8414 §3.1 and RFC 9728 §3.1, not
	/// appended after it.
	#[test]
	fn well_known_url_inserts_before_a_path() {
		assert_eq!(
			well_known_url(
				"https://issuer.example.test/tenant1",
				"oauth-authorization-server",
			),
			"https://issuer.example.test/.well-known/oauth-authorization-server/tenant1",
		);
	}

	/// A trailing slash on the base is not treated as a path component, so
	/// it does not produce a stray empty segment.
	#[test]
	fn well_known_url_ignores_a_trailing_slash() {
		assert_eq!(
			well_known_url("https://issuer.example.test/", "oauth-protected-resource"),
			"https://issuer.example.test/.well-known/oauth-protected-resource",
		);
	}

	/// A port and a multi-segment path are preserved: the authority
	/// (host and port) stays before the well-known segment and the whole
	/// path follows it.
	#[test]
	fn well_known_url_preserves_port_and_multi_segment_path() {
		assert_eq!(
			well_known_url("https://host.example:8443/a/b", "oauth-protected-resource"),
			"https://host.example:8443/.well-known/oauth-protected-resource/a/b",
		);
	}
}
