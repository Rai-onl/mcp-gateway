//! Credential resolution for the MCP gateway.
//!
//! Each MCP server in the gateway configuration may reference a
//! named credential. The credential provider chain resolves that
//! name to a secret value by searching through a sequence of
//! sources:
//!
//! 1. **Command**: run a configured credential helper command
//! 2. **File**: read from a credentials directory
//! 3. **Environment**: read from an environment variable
//!
//! The chain stops at the first source that provides a value.
//! This design allows any secrets management tool (Leyni, Vault,
//! AWS KMS, manual files, environment variables) to supply
//! credentials without the gateway knowing about the tool.
//!
//! Multiple servers reference different credential names, and
//! each is resolved independently through the same chain.

mod chain;
mod composite;
pub mod oauth;
mod oauth_cache;
mod oauth_resolver;
mod resolver;

pub use chain::{CredentialError, CredentialProvider, DEFAULT_COMMAND_TIMEOUT, Secret};
pub use composite::CompositeResolver;
pub use oauth_cache::{Clock, DEFAULT_REFRESH_SKEW, OAuthCache, SystemClock};
pub use oauth_resolver::OAuthResolver;
pub use resolver::{CredentialResolver, StaticResolver};

/// Build a reqwest client for tests, installing the selected crypto
/// provider first so its TLS layer has a process default to fall back
/// on (the workspace's reqwest carries no bundled provider).
#[cfg(test)]
pub(crate) fn test_http_client() -> reqwest::Client {
	mcp_gateway_crypto::install();
	reqwest::Client::new()
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use super::*;
	use chain::credential_env_var_name;

	/// Environment variable names are derived from the credential
	/// name: prefix + uppercase + hyphens replaced with underscores.
	#[test]
	fn env_var_name_derived_from_credential_name() {
		let name = credential_env_var_name("MCP_CREDENTIAL_", "github-token");
		assert_eq!(name, "MCP_CREDENTIAL_GITHUB_TOKEN");
	}

	/// Underscores in credential names are preserved.
	#[test]
	fn env_var_name_preserves_underscores() {
		let name = credential_env_var_name("MCP_CREDENTIAL_", "my_api_key");
		assert_eq!(name, "MCP_CREDENTIAL_MY_API_KEY");
	}

	/// A credential available as a file in the credentials
	/// directory is resolved by the provider chain.
	#[tokio::test]
	async fn resolves_from_file() {
		let temp_dir = tempfile::tempdir().unwrap();
		let cred_path = temp_dir.path().join("github-token");
		std::fs::write(&cred_path, "file-secret-value\n").unwrap();

		let provider = CredentialProvider::builder()
			.with_credentials_dir(temp_dir.path().to_path_buf())
			.build();

		let result = provider.resolve("github-token").await;
		assert_eq!(result.unwrap().expose(), "file-secret-value");
	}

	/// File-based credentials have trailing whitespace trimmed,
	/// since most secret injection tools append a trailing newline.
	#[tokio::test]
	async fn file_credentials_trim_trailing_whitespace() {
		let temp_dir = tempfile::tempdir().unwrap();
		let cred_path = temp_dir.path().join("padded-token");
		std::fs::write(&cred_path, "  value-with-spaces  \n\n").unwrap();

		let provider = CredentialProvider::builder()
			.with_credentials_dir(temp_dir.path().to_path_buf())
			.build();

		let result = provider.resolve("padded-token").await;
		assert_eq!(result.unwrap().expose(), "  value-with-spaces");
	}

	/// A credential available via a command helper is resolved
	/// by running the command and capturing stdout.
	#[tokio::test]
	async fn resolves_from_command() {
		let mut commands = HashMap::new();
		commands.insert(
			"echo-token".to_owned(),
			vec!["echo".to_owned(), "command-secret-value".to_owned()],
		);

		let provider = CredentialProvider::builder()
			.with_commands(commands)
			.build();

		let result = provider.resolve("echo-token").await;
		assert_eq!(result.unwrap().expose(), "command-secret-value");
	}

	/// The chain resolves in order: command → file → env.
	/// A command takes precedence over a file with the same name.
	#[tokio::test]
	async fn command_takes_precedence_over_file() {
		let temp_dir = tempfile::tempdir().unwrap();
		let cred_path = temp_dir.path().join("priority-token");
		std::fs::write(&cred_path, "file-value").unwrap();

		let mut commands = HashMap::new();
		commands.insert(
			"priority-token".to_owned(),
			vec!["echo".to_owned(), "command-value".to_owned()],
		);

		let provider = CredentialProvider::builder()
			.with_credentials_dir(temp_dir.path().to_path_buf())
			.with_commands(commands)
			.build();

		let result = provider.resolve("priority-token").await;
		assert_eq!(result.unwrap().expose(), "command-value");
	}

	/// Multiple credentials can be resolved independently; each
	/// server references its own credential name.
	#[tokio::test]
	async fn resolves_multiple_credentials_independently() {
		let temp_dir = tempfile::tempdir().unwrap();
		std::fs::write(temp_dir.path().join("github-token"), "gh-secret").unwrap();
		std::fs::write(temp_dir.path().join("gitlab-token"), "gl-secret").unwrap();
		std::fs::write(temp_dir.path().join("slack-token"), "sl-secret").unwrap();

		let provider = CredentialProvider::builder()
			.with_credentials_dir(temp_dir.path().to_path_buf())
			.build();

		assert_eq!(
			provider.resolve("github-token").await.unwrap().expose(),
			"gh-secret"
		);
		assert_eq!(
			provider.resolve("gitlab-token").await.unwrap().expose(),
			"gl-secret"
		);
		assert_eq!(
			provider.resolve("slack-token").await.unwrap().expose(),
			"sl-secret"
		);
	}

	/// A credential name that exists nowhere in the chain
	/// produces a clear not-found error.
	#[tokio::test]
	async fn unknown_credential_returns_error() {
		let provider = CredentialProvider::builder().build();

		let error = provider
			.resolve("nonexistent")
			.await
			.expect_err("unknown credential should fail");
		assert!(matches!(error, CredentialError::NotFound(_)));
	}

	/// A failing command produces a command-specific error,
	/// not a generic not-found.
	#[tokio::test]
	async fn failing_command_returns_error() {
		let mut commands = HashMap::new();
		commands.insert("bad-command".to_owned(), vec!["false".to_owned()]);

		let provider = CredentialProvider::builder()
			.with_commands(commands)
			.build();

		let error = provider
			.resolve("bad-command")
			.await
			.expect_err("failing command should produce error");
		assert!(matches!(error, CredentialError::CommandFailed { .. }));
	}

	/// The Secret type redacts its value in Debug output to
	/// prevent accidental logging of credentials.
	#[test]
	fn secret_debug_is_redacted() {
		let secret = chain::Secret::new("sensitive-value".to_owned());
		let debug_output = format!("{secret:?}");
		assert_eq!(debug_output, "[REDACTED]");
		assert!(!debug_output.contains("sensitive"));
	}

	/// Secret implements `AsRef<OsStr>` so it can be passed as the
	/// value half of a `(key, value)` pair into
	/// `tokio::process::Command::envs`. Without this impl, callers
	/// would have to allocate an intermediate `String` for every
	/// child-process environment variable derived from a credential.
	#[test]
	fn secret_can_be_used_as_os_str() {
		use std::ffi::OsStr;

		let secret = chain::Secret::new("env-value".to_owned());
		let view: &OsStr = secret.as_ref();
		assert_eq!(view, OsStr::new("env-value"));
	}

	/// Secret deserialises from a JSON string, so configuration
	/// fields that hold credential-derived values (env maps, header
	/// maps) can read directly into `Secret` without going through
	/// an intermediate `String`.
	#[test]
	fn secret_deserialises_from_json_string() {
		let secret: chain::Secret =
			serde_json::from_str("\"a-secret-value\"").expect("deserialises from string");
		assert_eq!(secret.expose(), "a-secret-value");
	}

	/// Secret round-trips through serde so configurations
	/// containing secrets can be reloaded after a write; the
	/// gateway never serialises secrets to a network channel, but
	/// in-process round-tripping (validation, defaults, tests)
	/// must work.
	#[test]
	fn secret_round_trips_through_json() {
		let original = chain::Secret::new("round-trip-value".to_owned());
		let serialised = serde_json::to_string(&original).expect("serialises to JSON string");
		let restored: chain::Secret =
			serde_json::from_str(&serialised).expect("deserialises back into Secret");
		assert_eq!(restored.expose(), "round-trip-value");
	}

	/// Constructing and dropping a non-empty `Secret` runs the
	/// page-locking and unlocking paths without panicking. The OS
	/// may reject `mlock` (low `RLIMIT_MEMLOCK`, unsupported
	/// platform) and that must surface as a successful, unlocked
	/// `Secret` rather than a panic; the policy is best-effort.
	#[test]
	fn secret_construction_runs_mlock_path_without_panicking() {
		// Drop is what exercises the zero → munlock → free order;
		// the test is a smoke-check that the code path doesn't
		// abort the test thread.
		let secret = chain::Secret::new("mlock-target".to_owned());
		assert_eq!(secret.expose(), "mlock-target");
		drop(secret);
	}

	/// An empty `Secret` is valid (some configurations rely on
	/// optional credentials). The `region` crate rejects zero-length
	/// `mlock` calls, so the constructor's empty-input fast path
	/// must skip locking and succeed.
	#[test]
	fn empty_secret_skips_mlock_and_constructs_successfully() {
		let secret = chain::Secret::new(String::new());
		assert_eq!(secret.expose(), "");
	}

	/// Cloning a `Secret` produces an independent value with its
	/// own locked allocation. The clone's lifetime is independent
	/// of the original, so dropping one must not unlock the other.
	#[test]
	fn cloned_secret_has_independent_lock() {
		let original = chain::Secret::new("rotatable-token".to_owned());
		let copy = original.clone();
		assert_eq!(copy.expose(), "rotatable-token");
		drop(original);
		// The copy must still be readable: dropping the original
		// must not have unlocked or zeroed our independent
		// allocation.
		assert_eq!(copy.expose(), "rotatable-token");
	}

	/// A fast credential helper command resolves comfortably
	/// within the default timeout. Confirms the default value is
	/// loose enough for healthy helpers and that the timeout
	/// machinery does not regress them.
	#[tokio::test]
	async fn fast_command_resolves_within_default_timeout() {
		let mut commands = HashMap::new();
		commands.insert(
			"quick-token".to_owned(),
			vec!["echo".to_owned(), "fast-value".to_owned()],
		);

		let provider = CredentialProvider::builder()
			.with_commands(commands)
			.build();

		let secret = provider
			.resolve("quick-token")
			.await
			.expect("a fast helper resolves within the default timeout");
		assert_eq!(secret.expose(), "fast-value");
	}

	/// The default command timeout is exposed publicly so callers
	/// (and operators reading documentation) can rely on a known
	/// value. The constant matches the documented default and is
	/// what `CredentialProviderBuilder::default()` applies.
	#[test]
	fn default_command_timeout_is_thirty_seconds() {
		assert_eq!(
			chain::DEFAULT_COMMAND_TIMEOUT,
			std::time::Duration::from_secs(30)
		);
	}

	/// A credential helper command that runs longer than the
	/// configured timeout fails with a dedicated error variant
	/// carrying the credential name and the elapsed bound. The
	/// dedicated variant lets operators tell a hung helper apart
	/// from one that exited non-zero, and gives callers a typed
	/// hook for any future retry policy.
	#[tokio::test]
	async fn command_helper_timeout_returns_dedicated_error() {
		let mut commands = HashMap::new();
		commands.insert(
			"slow-token".to_owned(),
			vec!["sleep".to_owned(), "10".to_owned()],
		);

		let provider = CredentialProvider::builder()
			.with_commands(commands)
			.with_command_timeout(std::time::Duration::from_millis(100))
			.build();

		let error = provider
			.resolve("slow-token")
			.await
			.expect_err("a command that exceeds the timeout must fail");

		match error {
			CredentialError::CommandTimeout { name, after } => {
				assert_eq!(name, "slow-token");
				assert_eq!(after, std::time::Duration::from_millis(100));
			}
			other => panic!("expected CommandTimeout, got {other:?}"),
		}
	}
}
