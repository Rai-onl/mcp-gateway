//! Credential resolution for the MCP gateway.
//!
//! Each MCP server in the gateway configuration may reference a
//! named credential. The credential provider chain resolves that
//! name to a secret value by searching through a sequence of
//! sources:
//!
//! 1. **Command** — run a configured credential helper command
//! 2. **File** — read from a credentials directory
//! 3. **Environment** — read from an environment variable
//!
//! The chain stops at the first source that provides a value.
//! This design allows any secrets management tool (Leyni, Vault,
//! AWS KMS, manual files, environment variables) to supply
//! credentials without the gateway knowing about the tool.
//!
//! Multiple servers reference different credential names, and
//! each is resolved independently through the same chain.

mod chain;

pub use chain::{CredentialError, CredentialProvider};

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

	/// Multiple credentials can be resolved independently — each
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
}
