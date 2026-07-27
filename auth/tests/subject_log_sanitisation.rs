//! Integration test (issue #30) verifying the validator sanitises a
//! hostile `sub` before it reaches a tracing field.
//!
//! Kept in its own test binary so it is the only test running: a
//! thread-local capturing subscriber is reliable without the
//! within-binary parallelism that races the dispatcher when this runs
//! alongside the rest of the validator suite.

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mcp_gateway_auth::jwks::JwksCache;
use mcp_gateway_auth::validator::{FailureReason, JwtValidator};
use mockoidc_kit::{MockIssuer, SigningAlgorithm};

/// The resource URL the test gateway answers for.
const RESOURCE: &str = "https://alice.gateway.example.test";

/// The single principal the test gateway admits; the hostile subject
/// is deliberately not this value, so it is rejected and logged.
const PRINCIPAL: &str = "did:arai:example:alice";

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

/// A hostile `sub` carrying control characters is sanitised before it
/// reaches a tracing field: the encoded form appears and the raw
/// newline does not.
///
/// Driven through a single-threaded runtime inside
/// [`tracing::subscriber::with_default`], so the capturing subscriber
/// is the thread-local default for the whole run, including the
/// warning the rejection emits.
#[test]
fn sanitises_subject_before_logging() {
	let writer = CapturingWriter::default();
	let captured = Arc::clone(&writer.buffer);
	let subscriber = tracing_subscriber::fmt()
		.with_writer(writer)
		.with_max_level(tracing::Level::WARN)
		.with_ansi(false)
		.with_target(false)
		.finish();

	tracing::subscriber::with_default(subscriber, || {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.expect("current-thread runtime should build");
		runtime.block_on(async {
			let issuer = MockIssuer::start(SigningAlgorithm::Es256)
				.await
				.expect("fixture should boot");
			let validator = JwtValidator::new(
				issuer.issuer(),
				RESOURCE.to_owned(),
				[PRINCIPAL.to_owned()].into_iter().collect(),
				Duration::from_secs(30),
				JwksCache::new(format!("{}/jwks", issuer.issuer())),
			);

			// A subject not in the allowlist (so it is rejected and
			// logged) carrying a newline and a JSON-breaking payload.
			let token = issuer
				.subject("mallory\n{\"forged\":true}")
				.audience(RESOURCE)
				.mint_id_token();

			let reason = validator
				.validate(&format!("Bearer {token}"))
				.await
				.expect_err("the hostile subject is not a known principal");
			assert_eq!(reason, FailureReason::UnknownPrincipal);
		});
	});

	let logged = String::from_utf8(captured.lock().expect("capture buffer poisoned").clone())
		.expect("captured tracing output should be valid UTF-8");
	assert!(
		logged.contains("%0A"),
		"the newline must be percent-encoded in the log, got: {logged:?}",
	);
	assert!(
		!logged.contains("mallory\n"),
		"the raw newline must not reach the log",
	);
}
