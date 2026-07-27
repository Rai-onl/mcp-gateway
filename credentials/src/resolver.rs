//! Credential resolver trait and the in-memory `StaticResolver`.
//!
//! `Secret` describes a credential value; `CredentialResolver`
//! describes how a value is fetched at use time. Keeping the two
//! together lets every consumer (proxy, bridge, daemon, future
//! resolvers) share one dependency for the credential surface.

use std::collections::HashMap;

use async_trait::async_trait;

use crate::Secret;

/// Resolves a credential name to its current value.
///
/// Async because some implementations (OAuth, dynamic Vault tokens)
/// need to reach out to a remote authorisation server. The trait is
/// satisfied by both *materialised* credentials (file, command, env:
/// pre-resolved at startup into a [`StaticResolver`]) and *issued*
/// credentials (OAuth, refreshed against an authorisation server with
/// a TTL cache). Per-credential-kind branching does not appear in
/// callers; they hold an `Arc<dyn CredentialResolver>` and call
/// `resolve` uniformly.
///
/// The trait is dyn-compatible courtesy of the `async-trait` macro,
/// which boxes the returned future. The boxing cost is negligible
/// compared to the credential resolution itself.
#[async_trait]
pub trait CredentialResolver: Send + Sync {
	/// Return the current value for the named credential, or a
	/// human-readable error describing why resolution failed.
	///
	/// Implementations that always succeed instantly (e.g.
	/// [`StaticResolver`]) still surface as `async`; the cost is one
	/// poll on a ready future.
	async fn resolve(&self, name: &str) -> Result<Secret, String>;
}

/// In-memory resolver backed by a precomputed map of credential
/// values.
///
/// Used for materialised credentials: values fetched once at startup
/// from files, command helpers, or environment variables. Every
/// consumer sees the same `Arc<dyn CredentialResolver>` whether the
/// credential is static or dynamic. Lookups are zero-allocation in
/// the hit path: the cached [`Secret`] is cloned (a cheap reference
/// bump on the underlying `Zeroizing<String>`).
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
	secrets: HashMap<String, Secret>,
}

impl StaticResolver {
	/// Build a static resolver from a map of credential-name →
	/// pre-resolved [`Secret`].
	#[must_use]
	pub fn new(secrets: HashMap<String, Secret>) -> Self {
		Self { secrets }
	}
}

#[async_trait]
impl CredentialResolver for StaticResolver {
	async fn resolve(&self, name: &str) -> Result<Secret, String> {
		self.secrets
			.get(name)
			.cloned()
			.ok_or_else(|| format!("credential '{name}' was not pre-resolved"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// `StaticResolver` returns a known credential's pre-resolved
	/// value through the async trait surface.
	#[tokio::test]
	async fn static_resolver_returns_known_credential() {
		let mut secrets = HashMap::new();
		secrets.insert(
			"github-token".to_owned(),
			Secret::new("ghp_test".to_owned()),
		);
		let resolver = StaticResolver::new(secrets);

		let value = resolver
			.resolve("github-token")
			.await
			.expect("known credential resolves");
		assert_eq!(value.expose(), "ghp_test");
	}

	/// `StaticResolver` returns a human-readable error when asked
	/// for a credential that was never registered.
	#[tokio::test]
	async fn static_resolver_errors_on_unknown_credential() {
		let resolver = StaticResolver::default();

		let outcome = resolver.resolve("absent").await;
		match outcome {
			Err(message) => assert!(
				message.contains("absent"),
				"error must name the missing credential, got {message:?}",
			),
			Ok(_) => panic!("unknown credential must fail"),
		}
	}

	/// A test-only async resolver demonstrates the trait satisfies
	/// dynamic-credential lifecycles. Production implementations
	/// (OAuth, Vault) compose under the same trait without callers
	/// branching on kind.
	struct MockDynamicResolver {
		token: String,
	}

	#[async_trait]
	impl CredentialResolver for MockDynamicResolver {
		async fn resolve(&self, _name: &str) -> Result<Secret, String> {
			tokio::task::yield_now().await;
			Ok(Secret::new(self.token.clone()))
		}
	}

	/// The trait is dyn-compatible: callers can hold an
	/// `Arc<dyn CredentialResolver>` and dispatch to either strategy
	/// without per-kind branching.
	#[tokio::test]
	async fn trait_object_dispatches_across_strategies() {
		let mut secrets = HashMap::new();
		secrets.insert(
			"static-name".to_owned(),
			Secret::new("static-value".to_owned()),
		);
		let static_resolver: std::sync::Arc<dyn CredentialResolver> =
			std::sync::Arc::new(StaticResolver::new(secrets));
		let dynamic_resolver: std::sync::Arc<dyn CredentialResolver> =
			std::sync::Arc::new(MockDynamicResolver {
				token: "issued-value".to_owned(),
			});

		let static_value = static_resolver.resolve("static-name").await.unwrap();
		let dynamic_value = dynamic_resolver.resolve("anything").await.unwrap();

		assert_eq!(static_value.expose(), "static-value");
		assert_eq!(dynamic_value.expose(), "issued-value");
	}
}
