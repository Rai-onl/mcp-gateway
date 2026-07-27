//! Integration test (issue #34) verifying the scope decision is
//! recorded for audit: the matched scope on accept, the reason on
//! reject.
//!
//! Kept in its own test binary so the thread-local capturing
//! subscriber is reliable without within-binary parallelism.
//! `pre_dispatch` is synchronous, so no runtime is needed.

use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcp_gateway_auth::authorise::ScopePolicy;
use mcp_gateway_auth::claims::ValidatedClaims;
use mcp_gateway_auth::jwks::JwksCache;
use mcp_gateway_auth::middleware::AuthState;
use mcp_gateway_auth::strategy::Validator;
use mcp_gateway_auth::validator::JwtValidator;

/// A test writer capturing tracing output into a shared buffer.
#[derive(Clone, Default)]
struct CapturingWriter {
	/// The shared sink the subscriber writes formatted events into.
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

/// Build an `AuthState` whose validator is never exercised (the scope
/// seam does not touch it), carrying a policy that authorises `gitlab`
/// with `mcp:invoke:gitlab`.
fn auth_state() -> AuthState {
	let validator = JwtValidator::new(
		"https://issuer.example.test".to_owned(),
		"https://gateway.example.test".to_owned(),
		HashSet::new(),
		Duration::from_secs(30),
		JwksCache::new("https://issuer.example.test/jwks".to_owned()),
	);
	let mut server_scopes = std::collections::HashMap::new();
	server_scopes.insert("gitlab".to_owned(), vec!["mcp:invoke:gitlab".to_owned()]);
	AuthState::new(
		Validator::Jwt(validator),
		"https://gateway.example.test",
		"https://gateway.example.test/.well-known/oauth-protected-resource",
		ScopePolicy::new(&server_scopes),
	)
}

/// Claims for the given subject carrying the given scopes.
fn claims(scopes: &[&str]) -> ValidatedClaims {
	ValidatedClaims::new(
		"did:arai:example:alice".to_owned(),
		scopes.iter().map(|scope| (*scope).to_owned()).collect(),
	)
}

/// An accepted request records `auth.matched_scope` naming the scope
/// that granted access; a rejected one records `auth.reject_reason`.
#[test]
fn scope_decision_is_recorded_for_audit() {
	let writer = CapturingWriter::default();
	let captured = Arc::clone(&writer.buffer);
	let subscriber = tracing_subscriber::fmt()
		.with_writer(writer)
		.with_max_level(tracing::Level::DEBUG)
		.with_ansi(false)
		.with_target(false)
		.finish();

	tracing::subscriber::with_default(subscriber, || {
		let state = auth_state();
		assert!(
			state
				.pre_dispatch(&claims(&["mcp:invoke:gitlab"]), "/servers/gitlab/mcp")
				.is_ok(),
		);
		assert!(
			state
				.pre_dispatch(&claims(&[]), "/servers/gitlab/mcp")
				.is_err(),
		);
	});

	let logged = String::from_utf8(captured.lock().expect("capture buffer poisoned").clone())
		.expect("captured tracing output should be valid UTF-8");
	assert!(
		logged.contains("auth.matched_scope") && logged.contains("mcp:invoke:gitlab"),
		"the matched scope must be recorded on accept, got: {logged:?}",
	);
	assert!(
		logged.contains("auth.reject_reason") && logged.contains("insufficient_scope"),
		"the reject reason must be recorded on reject, got: {logged:?}",
	);
}
