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
use std::time::Duration;

/// Default upper bound on the wall-clock time spent waiting for a
/// credential helper command to produce output. Chosen to be
/// comfortable for cold-start helpers (Vault CLI on first invocation,
/// remote secret stores) while still surfacing a hung helper within a
/// container readiness window.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// A resolved credential value.
///
/// Wraps the secret string and provides controlled access to
/// prevent accidental logging or display. The value is exposed
/// only through the explicit [`expose`](Secret::expose) method.
/// The backing storage is zeroised when the `Secret` is dropped,
/// reducing the window during which the credential persists in
/// freed memory.
///
/// On platforms where `mlock` is available, the page range covering
/// the credential's bytes is pinned in physical RAM at construction
/// so the kernel cannot page the secret out to swap (where it could
/// outlive the process). Locking is best-effort: a low
/// `RLIMIT_MEMLOCK` or an unsupported platform leaves the secret
/// unlocked rather than failing construction. Operators who care
/// about this guarantee should raise `RLIMIT_MEMLOCK` (or grant
/// `CAP_IPC_LOCK` on Linux) for the gateway process.
///
/// `PartialEq` and `Eq` are provided so containers holding
/// `Secret` values (e.g. `HashMap<String, Secret>` inside a
/// `GatewayConfig`) can be compared for equality in tests and
/// round-trip checks. The implementation compares exposed values
/// directly and is *not* constant-time; do not use it as part of
/// any authentication path.
pub struct Secret {
	/// Underlying credential bytes. Held as plain `String` rather
	/// than `Zeroizing<String>` so the manual [`Drop`] impl below
	/// can interleave zeroisation and `munlock` in the right order:
	/// `Zeroizing` would otherwise zero *after* the field-order drop
	/// leaves us no chance to `munlock` while the allocation is still
	/// ours.
	value: String,
	/// Lock guard for the page range covering `value`'s heap bytes.
	/// `Some` when [`region::lock`] succeeded; `None` when locking
	/// was skipped (empty value, OS rejected the request, platform
	/// does not support it). The manual [`Drop`] takes this so the
	/// `munlock` call happens between the zeroise and the
	/// deallocation that follows.
	lock: Option<region::LockGuard>,
}

impl PartialEq for Secret {
	fn eq(&self, other: &Self) -> bool {
		self.value.as_str() == other.value.as_str()
	}
}

impl Eq for Secret {}

impl Clone for Secret {
	fn clone(&self) -> Self {
		Self::new(self.value.clone())
	}
}

impl Drop for Secret {
	fn drop(&mut self) {
		// Zeroise first, while the pages are still pinned. An
		// unlocked page could be swapped to disk by the kernel
		// between unlock and zeroise on a memory-pressured host;
		// doing the wipe first means the swap-out (if any) only
		// ever sees zeros.
		use zeroize::Zeroize;
		self.value.zeroize();

		// Drop the lock guard so `munlock` runs while the buffer is
		// still ours. The allocator may hand these pages to a fresh
		// allocation moments later, and we don't want it to inherit a
		// `mlock`ed status it didn't ask for.
		drop(self.lock.take());

		// `value` (now empty thanks to the zeroise above) drops at
		// end of body, freeing the underlying allocation.
	}
}

impl Secret {
	/// Wrap a string value as a secret.
	///
	/// On construction the value's heap bytes are page-locked via
	/// [`region::lock`] when the platform supports it; failure is
	/// silent because operators may legitimately run with a tight
	/// `RLIMIT_MEMLOCK` and we never want secret construction to
	/// fail solely because the memory protection upgrade was
	/// unavailable.
	#[must_use]
	pub fn new(value: String) -> Self {
		let lock = lock_value_pages(&value);
		Self { value, lock }
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

/// Pin the heap bytes of a non-empty string in physical RAM.
///
/// Returns `None` for empty inputs (no pages to lock) and on any
/// `mlock` rejection (low `RLIMIT_MEMLOCK`, unsupported platform,
/// OS error). Page-locking the underlying String allocation is sound
/// because [`Secret`] never mutates `value` after construction; the
/// allocation never moves while the lock guard is alive.
fn lock_value_pages(value: &str) -> Option<region::LockGuard> {
	if value.is_empty() {
		return None;
	}
	region::lock(value.as_ptr(), value.len()).ok()
}

impl std::fmt::Debug for Secret {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("[REDACTED]")
	}
}

impl AsRef<std::ffi::OsStr> for Secret {
	fn as_ref(&self) -> &std::ffi::OsStr {
		std::ffi::OsStr::new(self.value.as_str())
	}
}

impl serde::Serialize for Secret {
	fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
		serializer.serialize_str(self.value.as_str())
	}
}

impl<'de> serde::Deserialize<'de> for Secret {
	fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
		String::deserialize(deserializer).map(Self::new)
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

	/// Upper bound on the wall-clock time spent waiting for a
	/// credential helper command to produce output. A helper that
	/// exceeds this bound fails with [`CredentialError::CommandTimeout`].
	command_timeout: Duration,
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

		let invocation = tokio::process::Command::new(command)
			.args(arguments)
			.stdout(std::process::Stdio::piped())
			.stderr(std::process::Stdio::inherit())
			.output();

		let output = match tokio::time::timeout(self.command_timeout, invocation).await {
			Ok(result) => result.map_err(|error| CredentialError::CommandFailed {
				name: name.to_owned(),
				reason: error.to_string(),
			})?,
			Err(_elapsed) => {
				return Err(CredentialError::CommandTimeout {
					name: name.to_owned(),
					after: self.command_timeout,
				});
			}
		};

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
#[derive(Debug)]
pub struct CredentialProviderBuilder {
	commands: HashMap<String, Vec<String>>,
	credentials_dir: Option<PathBuf>,
	env_prefix: Option<String>,
	command_timeout: Duration,
}

impl Default for CredentialProviderBuilder {
	fn default() -> Self {
		Self {
			commands: HashMap::new(),
			credentials_dir: None,
			env_prefix: None,
			command_timeout: DEFAULT_COMMAND_TIMEOUT,
		}
	}
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

	/// Override the credential helper command timeout.
	///
	/// The default is [`DEFAULT_COMMAND_TIMEOUT`] (30 seconds). A
	/// helper that does not produce output before the timeout fails
	/// with [`CredentialError::CommandTimeout`]. Setting a value
	/// shorter than the slowest expected helper will cause spurious
	/// failures; setting it longer defeats the purpose of bounding
	/// startup latency. Operators should size the value to the
	/// slowest legitimate helper plus a safety margin.
	#[must_use]
	pub fn with_command_timeout(mut self, timeout: Duration) -> Self {
		self.command_timeout = timeout;
		self
	}

	/// Build the credential provider.
	#[must_use]
	pub fn build(self) -> CredentialProvider {
		CredentialProvider {
			commands: self.commands,
			credentials_dir: self.credentials_dir,
			env_prefix: self.env_prefix,
			command_timeout: self.command_timeout,
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

	/// A credential helper command did not produce output before
	/// the configured timeout elapsed.
	#[error("credential command for '{name}' timed out after {after:?}")]
	CommandTimeout {
		/// The credential name that was being resolved.
		name: String,
		/// The timeout that elapsed.
		after: Duration,
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
