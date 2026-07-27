//! Per-server scope authorisation.
//!
//! Authentication decides whether a token is genuine; authorisation
//! decides whether that token may invoke a given backend server. The
//! rule is a scope intersection: a request to `POST /servers/{name}/mcp`
//! is authorised when the token's `scope` claim holds at least one of
//! the scopes the operator configured for `{name}`.
//!
//! The wildcard `mcp:invoke:*` carries no special meaning here: it is a
//! literal scope a server may list to opt in, matched by ordinary
//! intersection. A token holding the wildcard gains nothing against a
//! server that does not list it.

use std::collections::{HashMap, HashSet};

/// The per-server scope policy: which scopes authorise which server.
pub struct ScopePolicy {
	/// Each configured server's set of authorising scopes.
	server_scopes: HashMap<String, HashSet<String>>,
}

impl ScopePolicy {
	/// Build a policy from the configured `server_scopes` mapping.
	#[must_use]
	pub fn new(server_scopes: &HashMap<String, Vec<String>>) -> Self {
		Self {
			server_scopes: server_scopes
				.iter()
				.map(|(server, scopes)| (server.clone(), scopes.iter().cloned().collect()))
				.collect(),
		}
	}

	/// Decide whether a token's scopes authorise invoking `server`.
	///
	/// On success returns the scope that granted access, for audit. A
	/// server with no configured scopes (including one not in the
	/// policy at all) authorises nothing.
	///
	/// # Errors
	///
	/// Returns [`ScopeRejection::InsufficientScope`] when the token
	/// holds no scope the server requires.
	pub fn authorise(
		&self,
		server: &str,
		token_scopes: &HashSet<String>,
	) -> Result<String, ScopeRejection> {
		self.server_scopes
			.get(server)
			.and_then(|configured| token_scopes.intersection(configured).next())
			.cloned()
			.ok_or(ScopeRejection::InsufficientScope)
	}
}

/// Why a scope check rejected a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRejection {
	/// The token holds none of the scopes the server requires.
	InsufficientScope,
}

impl ScopeRejection {
	/// A short, stable reason string for audit logging.
	#[must_use]
	pub fn reason(self) -> &'static str {
		match self {
			Self::InsufficientScope => "insufficient_scope",
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Build a policy from server-to-scopes pairs.
	fn policy(entries: &[(&str, &[&str])]) -> ScopePolicy {
		let map = entries
			.iter()
			.map(|(server, scopes)| {
				(
					(*server).to_owned(),
					scopes.iter().map(|scope| (*scope).to_owned()).collect(),
				)
			})
			.collect();
		ScopePolicy::new(&map)
	}

	/// Build a token scope set.
	fn scopes(values: &[&str]) -> HashSet<String> {
		values.iter().map(|value| (*value).to_owned()).collect()
	}

	/// A token whose scope set intersects the server's configured
	/// scopes is authorised, and the matched scope is returned.
	#[test]
	fn matching_scope_authorises() {
		let policy = policy(&[("gitlab", &["mcp:invoke:gitlab"])]);
		assert_eq!(
			policy.authorise("gitlab", &scopes(&["mcp:invoke:gitlab"])),
			Ok("mcp:invoke:gitlab".to_owned()),
		);
	}

	/// A scope configured for one server does not authorise another.
	#[test]
	fn non_matching_scope_is_rejected() {
		let policy = policy(&[("github", &["mcp:invoke:github"])]);
		assert_eq!(
			policy.authorise("github", &scopes(&["mcp:invoke:gitlab"])),
			Err(ScopeRejection::InsufficientScope),
		);
	}

	/// The wildcard is a literal: it authorises a server that lists it,
	/// and grants nothing against a server that does not.
	#[test]
	fn wildcard_is_a_literal_scope() {
		let wildcard_server = policy(&[("gitlab", &["mcp:invoke:*"])]);
		assert!(
			wildcard_server
				.authorise("gitlab", &scopes(&["mcp:invoke:*"]))
				.is_ok(),
		);

		let specific_server = policy(&[("gitlab", &["mcp:invoke:gitlab"])]);
		assert_eq!(
			specific_server.authorise("gitlab", &scopes(&["mcp:invoke:*"])),
			Err(ScopeRejection::InsufficientScope),
			"a wildcard token must not authorise a server that lists only a specific scope",
		);
	}

	/// A token is authorised when any one of its several scopes matches.
	#[test]
	fn any_matching_scope_authorises() {
		let policy = policy(&[("gitlab", &["mcp:invoke:gitlab"])]);
		assert!(
			policy
				.authorise("gitlab", &scopes(&["urn:other", "mcp:invoke:gitlab"]))
				.is_ok(),
		);
	}

	/// A token with no scopes authorises nothing.
	#[test]
	fn empty_token_scopes_are_rejected() {
		let policy = policy(&[("gitlab", &["mcp:invoke:gitlab"])]);
		assert_eq!(
			policy.authorise("gitlab", &scopes(&[])),
			Err(ScopeRejection::InsufficientScope),
		);
	}

	/// A server absent from the policy authorises nothing, whatever the
	/// token carries.
	#[test]
	fn unknown_server_is_rejected() {
		let policy = policy(&[("gitlab", &["mcp:invoke:gitlab"])]);
		assert_eq!(
			policy.authorise("unconfigured", &scopes(&["mcp:invoke:gitlab"])),
			Err(ScopeRejection::InsufficientScope),
		);
	}
}
