//! [`CompositeResolver`]: routes a credential name to a per-name
//! resolver and falls back to a shared resolver for everything else.
//!
//! The console builds one of these once at startup so the proxy and
//! bridge see a single `Arc<dyn CredentialResolver>` regardless of
//! whether a credential is materialised (file/command/env, behind a
//! [`StaticResolver`](crate::StaticResolver)) or issued (OAuth,
//! behind an [`OAuthResolver`](crate::OAuthResolver), and any future
//! Vault-style strategies).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::{CredentialResolver, Secret};

/// Routing resolver that dispatches each credential name to the
/// resolver that owns it, with a fallback for everything else.
///
/// `handlers` is keyed by credential name. A name absent from the
/// map is delegated to `fallback`. Lookups are read-only after
/// construction; reload rebuilds a fresh composite rather than
/// mutating an existing one.
pub struct CompositeResolver {
	handlers: HashMap<String, Arc<dyn CredentialResolver>>,
	fallback: Arc<dyn CredentialResolver>,
}

impl CompositeResolver {
	/// Build a composite from a per-name handler map and a fallback.
	///
	/// Pass an empty map and the fallback alone if the configuration
	/// has no specialised credentials; the composite still wraps the
	/// fallback so callers always hold the same trait shape.
	#[must_use]
	pub fn new(
		handlers: HashMap<String, Arc<dyn CredentialResolver>>,
		fallback: Arc<dyn CredentialResolver>,
	) -> Self {
		Self { handlers, fallback }
	}
}

#[async_trait]
impl CredentialResolver for CompositeResolver {
	async fn resolve(&self, name: &str) -> Result<Secret, String> {
		match self.handlers.get(name) {
			Some(handler) => handler.resolve(name).await,
			None => self.fallback.resolve(name).await,
		}
	}
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicUsize, Ordering};

	use crate::StaticResolver;

	use super::*;

	/// Resolver fixture that always returns the same value and
	/// records how many times it was consulted.
	struct CountingResolver {
		value: String,
		calls: AtomicUsize,
	}

	#[async_trait]
	impl CredentialResolver for CountingResolver {
		async fn resolve(&self, _name: &str) -> Result<Secret, String> {
			self.calls.fetch_add(1, Ordering::SeqCst);
			Ok(Secret::new(self.value.clone()))
		}
	}

	/// Names listed in `handlers` are dispatched to their handler
	/// and never reach the fallback.
	#[tokio::test]
	async fn handler_takes_precedence_over_fallback() {
		let handler = Arc::new(CountingResolver {
			value: "from-handler".to_owned(),
			calls: AtomicUsize::new(0),
		});
		let fallback = Arc::new(CountingResolver {
			value: "from-fallback".to_owned(),
			calls: AtomicUsize::new(0),
		});

		let mut handlers: HashMap<String, Arc<dyn CredentialResolver>> = HashMap::new();
		handlers.insert("oauth-name".to_owned(), Arc::clone(&handler) as _);

		let composite = CompositeResolver::new(handlers, Arc::clone(&fallback) as _);

		let value = composite
			.resolve("oauth-name")
			.await
			.expect("handler resolves");
		assert_eq!(value.expose(), "from-handler");
		assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
		assert_eq!(
			fallback.calls.load(Ordering::SeqCst),
			0,
			"fallback must not be consulted when the handler claims the name",
		);
	}

	/// Names absent from `handlers` are forwarded to the fallback.
	#[tokio::test]
	async fn unknown_name_falls_through_to_fallback() {
		let handler = Arc::new(CountingResolver {
			value: "from-handler".to_owned(),
			calls: AtomicUsize::new(0),
		});
		let fallback = Arc::new(CountingResolver {
			value: "from-fallback".to_owned(),
			calls: AtomicUsize::new(0),
		});

		let mut handlers: HashMap<String, Arc<dyn CredentialResolver>> = HashMap::new();
		handlers.insert("oauth-name".to_owned(), Arc::clone(&handler) as _);

		let composite = CompositeResolver::new(handlers, Arc::clone(&fallback) as _);

		let value = composite
			.resolve("static-name")
			.await
			.expect("fallback resolves");
		assert_eq!(value.expose(), "from-fallback");
		assert_eq!(handler.calls.load(Ordering::SeqCst), 0);
		assert_eq!(fallback.calls.load(Ordering::SeqCst), 1);
	}

	/// An empty handler map degrades cleanly to "everything goes to
	/// the fallback", so callers don't need a separate code path
	/// when the configuration has no specialised credentials.
	#[tokio::test]
	async fn empty_handlers_delegates_everything_to_fallback() {
		let mut secrets = HashMap::new();
		secrets.insert("name".to_owned(), Secret::new("value".to_owned()));
		let fallback: Arc<dyn CredentialResolver> = Arc::new(StaticResolver::new(secrets));

		let composite = CompositeResolver::new(HashMap::new(), fallback);

		let value = composite
			.resolve("name")
			.await
			.expect("fallback handles every name when handlers is empty");
		assert_eq!(value.expose(), "value");
	}
}
