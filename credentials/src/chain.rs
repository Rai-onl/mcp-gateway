//! Credential provider chain.
//!
//! Resolves named credentials by searching through a sequence of
//! sources. Each server in the gateway config references a
//! credential by name; the chain finds the value regardless of
//! which secrets management tool provided it.
//!
//! Resolution order: command → file → environment variable.

use std::collections::HashMap;
use std::path::PathBuf;

/// A resolved credential value.
///
/// Wraps the secret string and provides controlled access to
/// prevent accidental logging or display. The value is exposed
/// only through the explicit [`expose`](Secret::expose) method.
/// The backing storage is zeroised when the `Secret` is dropped,
/// reducing the window during which the credential persists in
/// freed memory.
#[derive(Clone)]
pub struct Secret {
	value: zeroize::Zeroizing<String>,
}

impl Secret {
	/// Wrap a string value as a secret.
	#[must_use]
	pub fn new(value: String) -> Self {
		Self {
			value: zeroize::Zeroizing::new(value),
		}
	}

	/// Access the secret value.
	///
	/// Call this only at the point of use (HTTP header injection,
	/// process environment setup). Never pass the exposed value
	/// to logging, serialisation, or error messages.
	#[must_use]
	pub fn expose(&self) -> &str {
		&self.value
	}
}

impl std::fmt::Debug for Secret {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("[REDACTED]")
	}
}

/// Resolves named credentials through a chain of sources.
///
/// Built via [`CredentialProvider::builder`]. Each source is
/// optional — the chain skips sources that are not configured
/// and stops at the first that provides a value.
#[derive(Debug)]
pub struct CredentialProvider {
	/// Credential helper commands keyed by credential name.
	/// Each value is the command and arguments to execute.
	commands: HashMap<String, Vec<String>>,

	/// Directory containing credential files, one per credential.
	/// File names match credential names.
	credentials_dir: Option<PathBuf>,

	/// Prefix for environment variable lookup. The credential
	/// name is uppercased and hyphens replaced with underscores,
	/// then appended to this prefix.
	env_prefix: Option<String>,
}

impl CredentialProvider {
	/// Create a builder for configuring the credential chain.
	#[must_use]
	pub fn builder() -> CredentialProviderBuilder {
		CredentialProviderBuilder::default()
	}

	/// Resolve a named credential through the provider chain.
	///
	/// Searches in order: configured command → file in credentials
	/// directory → environment variable. Returns the first value
	/// found, or an error if no source provides the credential.
	///
	/// # Errors
	///
	/// Returns [`CredentialError::NotFound`] if no source provides
	/// the named credential, or a source-specific error if a
	/// configured source fails (e.g., command exits with non-zero).
	pub async fn resolve(&self, name: &str) -> Result<Secret, CredentialError> {
		// Reject credential names that could cause path traversal.
		if !is_safe_credential_name(name) {
			return Err(CredentialError::InvalidName(name.to_owned()));
		}

		// 1. Command helper
		if let Some(command_args) = self.commands.get(name) {
			return self.resolve_from_command(name, command_args).await;
		}

		// 2. File in credentials directory
		if let Some(directory) = &self.credentials_dir {
			let file_path = directory.join(name);
			if file_path.exists() {
				return Self::resolve_from_file(name, &file_path);
			}
		}

		// 3. Environment variable
		if let Some(prefix) = &self.env_prefix {
			let var_name = format!("{}{}", prefix, name.to_uppercase().replace('-', "_"));
			if let Ok(value) = std::env::var(&var_name) {
				return Ok(Secret::new(value));
			}
		}

		Err(CredentialError::NotFound(name.to_owned()))
	}

	/// Run a credential helper command and capture its stdout.
	async fn resolve_from_command(
		&self,
		name: &str,
		command_args: &[String],
	) -> Result<Secret, CredentialError> {
		let (command, arguments) =
			command_args
				.split_first()
				.ok_or_else(|| CredentialError::CommandFailed {
					name: name.to_owned(),
					reason: "empty command".to_owned(),
				})?;

		let output = tokio::process::Command::new(command)
			.args(arguments)
			.stdout(std::process::Stdio::piped())
			.stderr(std::process::Stdio::inherit())
			.output()
			.await
			.map_err(|error| CredentialError::CommandFailed {
				name: name.to_owned(),
				reason: error.to_string(),
			})?;

		if !output.status.success() {
			return Err(CredentialError::CommandFailed {
				name: name.to_owned(),
				reason: format!("exited with status {}", output.status),
			});
		}

		let value =
			String::from_utf8(output.stdout).map_err(|_| CredentialError::CommandFailed {
				name: name.to_owned(),
				reason: "output is not valid UTF-8".to_owned(),
			})?;

		Ok(Secret::new(value.trim_end().to_owned()))
	}

	/// Read a credential from a file, trimming trailing whitespace.
	fn resolve_from_file(name: &str, path: &std::path::Path) -> Result<Secret, CredentialError> {
		let contents =
			std::fs::read_to_string(path).map_err(|error| CredentialError::FileReadFailed {
				name: name.to_owned(),
				path: path.to_path_buf(),
				reason: error.to_string(),
			})?;

		Ok(Secret::new(contents.trim_end().to_owned()))
	}
}

/// Builder for [`CredentialProvider`].
#[derive(Debug, Default)]
pub struct CredentialProviderBuilder {
	commands: HashMap<String, Vec<String>>,
	credentials_dir: Option<PathBuf>,
	env_prefix: Option<String>,
}

impl CredentialProviderBuilder {
	/// Register credential helper commands keyed by credential name.
	///
	/// Each entry maps a credential name to a command and its
	/// arguments. When resolving that credential, the command is
	/// executed and its stdout captured as the secret value.
	#[must_use]
	pub fn with_commands(mut self, commands: HashMap<String, Vec<String>>) -> Self {
		self.commands = commands;
		self
	}

	/// Set the directory containing credential files.
	///
	/// Each file in the directory is named after a credential.
	/// The file contents (with trailing whitespace trimmed) are
	/// used as the secret value.
	#[must_use]
	pub fn with_credentials_dir(mut self, directory: PathBuf) -> Self {
		self.credentials_dir = Some(directory);
		self
	}

	/// Set the environment variable prefix for credential lookup.
	///
	/// The credential name is uppercased and hyphens replaced
	/// with underscores, then appended to this prefix. For
	/// example, with prefix `MCP_CREDENTIAL_`, credential
	/// `github-token` resolves from `MCP_CREDENTIAL_GITHUB_TOKEN`.
	#[must_use]
	pub fn with_env_prefix(mut self, prefix: &str) -> Self {
		self.env_prefix = Some(prefix.to_owned());
		self
	}

	/// Build the credential provider.
	#[must_use]
	pub fn build(self) -> CredentialProvider {
		CredentialProvider {
			commands: self.commands,
			credentials_dir: self.credentials_dir,
			env_prefix: self.env_prefix,
		}
	}
}

/// Derive the environment variable name for a credential.
///
/// The credential name is uppercased and hyphens replaced with
/// underscores, then appended to the prefix. For example,
/// `credential_env_var_name("MCP_CREDENTIAL_", "github-token")`
/// returns `"MCP_CREDENTIAL_GITHUB_TOKEN"`.
#[cfg(test)]
#[must_use]
pub fn credential_env_var_name(prefix: &str, credential_name: &str) -> String {
	format!(
		"{}{}",
		prefix,
		credential_name.to_uppercase().replace('-', "_")
	)
}

/// Check whether a credential name is safe for use as a file name
/// and environment variable suffix. Allows alphanumeric characters,
/// hyphens, underscores, and dots. Rejects path separators, empty
/// names, and names starting with a dot (hidden files).
fn is_safe_credential_name(name: &str) -> bool {
	!name.is_empty()
		&& !name.starts_with('.')
		&& name.bytes().all(|byte| {
			byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
		})
}

/// Errors from credential resolution.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
	/// The credential name contains invalid characters.
	#[error("invalid credential name: {0}")]
	InvalidName(String),

	/// The named credential was not found in any source.
	#[error("credential not found: {0}")]
	NotFound(String),

	/// A credential helper command failed.
	#[error("credential command failed for '{name}': {reason}")]
	CommandFailed {
		/// The credential name that was being resolved.
		name: String,
		/// Description of the failure.
		reason: String,
	},

	/// A credential file could not be read.
	#[error("failed to read credential file for '{name}' at {path}: {reason}")]
	FileReadFailed {
		/// The credential name that was being resolved.
		name: String,
		/// Path to the file that could not be read.
		path: PathBuf,
		/// Description of the failure.
		reason: String,
	},
}
