//! Build-time selection of the rustls cryptographic provider.
//!
//! rustls needs a cryptographic provider, and two exist: `ring` and
//! `aws-lc-rs`. When more than one is compiled in, rustls cannot decide
//! which to use and panics the first time any code builds a TLS
//! configuration. This crate makes the choice a build-time feature so
//! exactly one provider is ever linked, and offers a single place to
//! obtain and install it.
//!
//! - [`provider`] returns the selected provider for use with
//!   `ServerConfig::builder_with_provider` or `ClientConfig`.
//! - [`install`] registers it as the process-wide default, which is what
//!   provider-less consumers (notably `reqwest` built with a
//!   no-provider feature) fall back on.
//!
//! Select the provider with the crate's mutually exclusive features:
//! `ring` (default, wasm-capable, no C toolchain), `aws-lc-rs`, or
//! `fips` (aws-lc-rs plus rustls's FIPS module). Enabling neither or
//! both fails the build.

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
compile_error!(
	"mcp-gateway-crypto: enable exactly one provider feature, `ring` or `aws-lc-rs`, not both"
);

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("mcp-gateway-crypto: enable one provider feature, `ring` or `aws-lc-rs`");

/// Build the selected provider as an owned value.
#[cfg(feature = "ring")]
fn build_provider() -> CryptoProvider {
	rustls::crypto::ring::default_provider()
}

/// Build the selected provider as an owned value.
#[cfg(all(feature = "aws-lc-rs", not(feature = "ring"), not(feature = "fips")))]
fn build_provider() -> CryptoProvider {
	rustls::crypto::aws_lc_rs::default_provider()
}

/// Build the FIPS-approved provider as an owned value.
///
/// The `fips` feature enables `aws-lc-rs`, so this could call
/// `aws_lc_rs::default_provider` and get the same result today. It calls
/// rustls's dedicated FIPS constructor instead so a FIPS build is
/// self-evidently FIPS and stays correct if the two ever diverge. The
/// [`provider`] and [`install`] entry points additionally assert the
/// result reports FIPS, turning a silent downgrade into a loud failure.
#[cfg(feature = "fips")]
fn build_provider() -> CryptoProvider {
	rustls::crypto::default_fips_provider()
}

/// The selected cryptographic provider.
///
/// Pass it to `rustls::ServerConfig::builder_with_provider` or
/// `ClientConfig::builder_with_provider` to build a configuration that
/// does not depend on rustls's ambiguous automatic detection.
///
/// # Panics
///
/// In a `fips` build, panics if the built provider does not report
/// FIPS approval, so a misbuilt compliance binary fails loudly rather
/// than serving unapproved crypto. Never panics in the other flavours.
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
	let provider = build_provider();
	// A `fips` build must produce a FIPS-approved provider; if it ever
	// does not, fail loudly here rather than silently downgrading a
	// compliance build to unapproved crypto. The other flavours make no
	// FIPS claim, so the assertion is compiled out for them.
	#[cfg(feature = "fips")]
	assert!(
		provider.fips(),
		"the fips flavour must build a FIPS-approved provider"
	);
	Arc::new(provider)
}

/// Install the selected provider as the process-wide default.
///
/// Consumers that build rustls configurations without naming a provider
/// (such as `reqwest` compiled with a no-provider feature) use the
/// process default, so this must run before the first such use, for
/// example at the start of the binary's `main`. Calling it more than
/// once is harmless: a provider is already installed and the extra call
/// is ignored.
///
/// # Panics
///
/// In a `fips` build, panics if the built provider does not report
/// FIPS approval, the same guard as [`provider`]. Never panics in the
/// other flavours.
pub fn install() {
	let provider = build_provider();
	// See `provider`: a `fips` build must never install an unapproved
	// provider. Compiled out for the non-FIPS flavours.
	#[cfg(feature = "fips")]
	assert!(
		provider.fips(),
		"the fips flavour must install a FIPS-approved provider"
	);
	let _ = provider.install_default();
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The selected provider exposes at least one cipher suite, proving
	/// a real provider was linked rather than an empty stub.
	#[test]
	fn provider_is_populated() {
		assert!(!provider().cipher_suites.is_empty());
	}

	/// Installing the default provider succeeds and is idempotent: a
	/// second call does not panic.
	#[test]
	fn install_is_idempotent() {
		install();
		install();
	}

	/// After install, rustls's provider-less client builder (the path
	/// reqwest takes when built without a bundled provider) finds the
	/// selected provider and builds without panicking.
	#[test]
	fn provider_less_client_config_builds_after_install() {
		install();
		let _config = rustls::ClientConfig::builder()
			.with_root_certificates(rustls::RootCertStore::empty())
			.with_no_client_auth();
	}
}
