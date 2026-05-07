//! Child process management for stdio MCP servers.
//!
//! Spawns a server process, pipes stdin/stdout for JSON-RPC
//! communication, and manages the process lifecycle including
//! the MCP initialize handshake.

use std::collections::HashMap;
use std::fmt;
use std::process::Stdio;
use std::sync::Arc;

use mcp_gateway_config::CredentialInjection;
use mcp_gateway_credentials::{CredentialResolver, Secret};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{Duration, timeout};

use crate::handshake::{self, Handshake, HandshakeError};

/// Environment-variable name used for stdio credential injection.
/// Set on every child spawn whose `injection` is
/// [`CredentialInjection::Env`].
const ENV_CREDENTIAL_VARIABLE: &str = "MCP_CREDENTIAL";

/// Configuration for spawning a bridge process.
#[derive(Clone)]
pub struct SpawnConfig {
	/// Path to the MCP server binary or script.
	pub command: String,

	/// Command-line arguments.
	pub args: Vec<String>,

	/// Operator-supplied environment variables injected into the
	/// child process verbatim.
	///
	/// Values are stored as [`Secret`] so credential-derived entries
	/// are zeroized when the spawn config is dropped. The kernel has
	/// already copied the env into the child by the time the parent
	/// drops the config, so the protection bounds the parent's
	/// in-memory exposure window.
	pub env: HashMap<String, Secret>,

	/// Resolver consulted at spawn time when `injection` is set.
	/// Stored as a trait object so the bridge does not need to know
	/// whether the credential is materialised (file/command/env
	/// pre-resolved into a `StaticResolver`) or issued (OAuth or
	/// dynamic Vault tokens behind a TTL cache).
	pub resolver: Arc<dyn CredentialResolver>,

	/// Optional credential injection metadata. Only the
	/// [`CredentialInjection::Env`] variant applies to stdio
	/// bridges; receiving the `Header` variant is treated as a
	/// router-side programming error.
	pub injection: Option<CredentialInjection>,
}

impl fmt::Debug for SpawnConfig {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		// The resolver behind the trait object has no useful Debug
		// representation; render only the fields developers actually
		// inspect when diagnosing a bridge spawn issue.
		formatter
			.debug_struct("SpawnConfig")
			.field("command", &self.command)
			.field("args", &self.args)
			.field("env_keys", &self.env.keys().collect::<Vec<_>>())
			.field("injection", &self.injection)
			.finish_non_exhaustive()
	}
}

/// A running stdio bridge to an MCP server process.
///
/// Debug output omits the child process handles since they do
/// not implement `Debug` in a useful way.
pub struct Bridge {
	child: Child,
	stdin: tokio::process::ChildStdin,
	reader: BufReader<tokio::process::ChildStdout>,
	handshake: Handshake,
}

impl fmt::Debug for Bridge {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("Bridge")
			.field("handshake", &self.handshake)
			.finish_non_exhaustive()
	}
}

impl Bridge {
	/// Spawn a new MCP server process and perform the initialize
	/// handshake. Returns a ready-to-use bridge on success.
	///
	/// The handshake must complete within the given timeout.
	///
	/// # Errors
	///
	/// Returns an error if the process cannot be spawned, the
	/// handshake times out, or the server returns an invalid
	/// initialize response.
	pub async fn spawn(
		config: &SpawnConfig,
		handshake_timeout: Duration,
	) -> Result<Self, BridgeError> {
		let resolved_env = resolve_environment(config).await?;

		let mut cmd = Command::new(&config.command);
		cmd.args(&config.args)
			.envs(&resolved_env)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.stderr(Stdio::inherit())
			.kill_on_drop(true);

		let mut child = cmd.spawn().map_err(BridgeError::Spawn)?;

		let stdin = child.stdin.take().ok_or(BridgeError::StdioPipe)?;
		let stdout = child.stdout.take().ok_or(BridgeError::StdioPipe)?;
		let reader = BufReader::new(stdout);

		let mut bridge = Self {
			child,
			stdin,
			reader,
			handshake: Handshake {
				protocol_version: String::new(),
				capabilities: Value::Null,
				server_info: None,
			},
		};

		let hs = timeout(handshake_timeout, bridge.perform_handshake())
			.await
			.map_err(|_| BridgeError::HandshakeTimeout)??;

		bridge.handshake = hs;
		Ok(bridge)
	}

	/// The handshake result from the server's initialize response.
	#[must_use]
	pub fn handshake(&self) -> &Handshake {
		&self.handshake
	}

	/// Send a JSON-RPC message to the server and read the response.
	///
	/// The message is written as a single line to stdin, and one
	/// line is read from stdout as the response. The entire
	/// send-receive cycle must complete within the given timeout.
	///
	/// # Errors
	///
	/// Returns an error if writing to stdin or reading from stdout
	/// fails, the response is not valid JSON, or the timeout expires.
	pub async fn send(
		&mut self,
		message: &Value,
		request_timeout: Duration,
	) -> Result<Value, BridgeError> {
		timeout(request_timeout, async {
			self.write_message(message).await?;
			self.read_message().await
		})
		.await
		.map_err(|_| BridgeError::RequestTimeout)?
	}

	/// Send a notification to the server (no response expected).
	///
	/// # Errors
	///
	/// Returns an error if writing to stdin fails.
	pub async fn notify(&mut self, message: &Value) -> Result<(), BridgeError> {
		self.write_message(message).await
	}

	/// Check whether the child process is still running.
	pub fn is_alive(&mut self) -> bool {
		matches!(self.child.try_wait(), Ok(None))
	}

	/// Perform the MCP initialize handshake.
	async fn perform_handshake(&mut self) -> Result<Handshake, BridgeError> {
		let init_request = handshake::initialize_request();
		self.write_message(&init_request).await?;

		let response = self.read_message().await?;
		let hs = handshake::parse_initialize_response(&response)?;

		let initialized = handshake::initialized_notification();
		self.write_message(&initialized).await?;

		Ok(hs)
	}

	/// Write a JSON value as a single newline-terminated line to stdin.
	async fn write_message(&mut self, message: &Value) -> Result<(), BridgeError> {
		let mut line = serde_json::to_string(message).map_err(BridgeError::Serialise)?;
		line.push('\n');
		self.stdin
			.write_all(line.as_bytes())
			.await
			.map_err(BridgeError::Write)?;
		self.stdin.flush().await.map_err(BridgeError::Write)?;
		Ok(())
	}

	/// Read a single newline-terminated JSON line from stdout.
	async fn read_message(&mut self) -> Result<Value, BridgeError> {
		let mut line = String::new();
		let bytes_read = self
			.reader
			.read_line(&mut line)
			.await
			.map_err(BridgeError::Read)?;

		if bytes_read == 0 {
			return Err(BridgeError::ProcessExited);
		}

		serde_json::from_str(line.trim()).map_err(BridgeError::InvalidResponse)
	}
}

/// Errors from the stdio bridge.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
	/// Failed to spawn the child process.
	#[error("failed to spawn process: {0}")]
	Spawn(std::io::Error),

	/// Could not capture stdin or stdout pipes.
	#[error("failed to capture stdio pipes")]
	StdioPipe,

	/// The MCP handshake did not complete within the timeout.
	#[error("MCP handshake timed out")]
	HandshakeTimeout,

	/// A request did not complete within the timeout.
	#[error("request timed out")]
	RequestTimeout,

	/// Error during the MCP handshake.
	#[error("MCP handshake failed: {0}")]
	Handshake(#[from] HandshakeError),

	/// Failed to write to the child process stdin.
	#[error("failed to write to process stdin: {0}")]
	Write(std::io::Error),

	/// Failed to read from the child process stdout.
	#[error("failed to read from process stdout: {0}")]
	Read(std::io::Error),

	/// The child process exited unexpectedly.
	#[error("process exited unexpectedly")]
	ProcessExited,

	/// Failed to serialise a JSON-RPC message.
	#[error("failed to serialise message: {0}")]
	Serialise(serde_json::Error),

	/// The response from the child process was not valid JSON.
	#[error("invalid JSON response from process: {0}")]
	InvalidResponse(serde_json::Error),

	/// The named credential could not be resolved at spawn time.
	#[error("credential '{credential}' could not be resolved: {reason}")]
	CredentialResolution {
		/// The name of the credential whose resolution failed.
		credential: String,
		/// Human-readable reason produced by the resolver.
		reason: String,
	},

	/// The router supplied injection metadata that does not apply
	/// to a stdio bridge — surfaces a programming error up-front
	/// rather than silently no-ing.
	#[error("invalid injection for stdio bridge: {0}")]
	InvalidInjection(String),
}

/// Build the environment map applied to the child process.
///
/// Operator-supplied entries are cloned in first; the credential
/// from a [`CredentialInjection::Env`] is then resolved through the
/// supplied resolver and inserted under
/// [`ENV_CREDENTIAL_VARIABLE`]. A `Header` injection is rejected as
/// a router-side programming error before any I/O happens.
async fn resolve_environment(config: &SpawnConfig) -> Result<HashMap<String, Secret>, BridgeError> {
	let mut env = config.env.clone();

	let injection = match &config.injection {
		None => return Ok(env),
		Some(CredentialInjection::Env { credential_name }) => credential_name,
		Some(CredentialInjection::Header { .. }) => {
			return Err(BridgeError::InvalidInjection(
				"HTTP header injection is not valid for a stdio bridge".to_owned(),
			));
		}
	};

	let secret = config.resolver.resolve(injection).await.map_err(|reason| {
		BridgeError::CredentialResolution {
			credential: injection.clone(),
			reason,
		}
	})?;
	env.insert(ENV_CREDENTIAL_VARIABLE.to_owned(), secret);
	Ok(env)
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};

	use async_trait::async_trait;
	use mcp_gateway_config::CredentialInjection;
	use mcp_gateway_credentials::CredentialResolver;

	use super::*;

	/// Test resolver that records every `resolve` call by name.
	/// Used to assert the bridge resolved the right credential at
	/// spawn time (handshake is allowed to fail later — the call
	/// log proves resolution happened first).
	struct CountingResolver {
		calls: std::sync::Mutex<Vec<String>>,
		value: String,
	}

	#[async_trait]
	impl CredentialResolver for CountingResolver {
		async fn resolve(&self, name: &str) -> Result<Secret, String> {
			self.calls.lock().unwrap().push(name.to_owned());
			Ok(Secret::new(self.value.clone()))
		}
	}

	/// Test resolver that always fails — used to verify spawn-time
	/// resolution failure surfaces as
	/// [`BridgeError::CredentialResolution`] before the child
	/// process is spawned.
	struct FailingResolver {
		called: AtomicUsize,
	}

	#[async_trait]
	impl CredentialResolver for FailingResolver {
		async fn resolve(&self, _name: &str) -> Result<Secret, String> {
			self.called.fetch_add(1, Ordering::SeqCst);
			Err("resolver always fails".to_owned())
		}
	}

	fn unused_resolver() -> Arc<dyn CredentialResolver> {
		Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "unused".to_owned(),
		})
	}

	/// A bridge can spawn a simple echo process (`cat`), which
	/// reflects stdin to stdout. The handshake will fail because
	/// `cat` echoes the request verbatim (as a "response"), and
	/// the echoed initialize request lacks a `result` field.
	/// This verifies the spawn and handshake error path.
	#[tokio::test]
	async fn spawn_with_non_mcp_process_fails_handshake() {
		let config = SpawnConfig {
			command: "cat".into(),
			args: vec![],
			env: HashMap::new(),
			resolver: unused_resolver(),
			injection: None,
		};

		let err = Bridge::spawn(&config, Duration::from_secs(2))
			.await
			.expect_err("cat should fail the MCP handshake");
		assert!(
			matches!(err, BridgeError::Handshake(_)),
			"expected handshake error, got: {err}"
		);
	}

	/// Spawning a nonexistent binary produces a spawn error.
	#[tokio::test]
	async fn spawn_nonexistent_binary_fails() {
		let config = SpawnConfig {
			command: "/nonexistent/binary/path".into(),
			args: vec![],
			env: HashMap::new(),
			resolver: unused_resolver(),
			injection: None,
		};

		let err = Bridge::spawn(&config, Duration::from_secs(1))
			.await
			.expect_err("nonexistent binary should fail to spawn");
		assert!(matches!(err, BridgeError::Spawn(_)));
	}

	/// A process that exits immediately (before responding)
	/// produces a process-exited error during handshake.
	#[tokio::test]
	async fn spawn_immediately_exiting_process_fails() {
		let config = SpawnConfig {
			command: "true".into(),
			args: vec![],
			env: HashMap::new(),
			resolver: unused_resolver(),
			injection: None,
		};

		let _err = Bridge::spawn(&config, Duration::from_secs(1))
			.await
			.expect_err("immediately exiting process should fail handshake");
	}

	/// `Bridge::spawn` resolves the credential through the resolver
	/// before launching the child. Confirmed via the call log on
	/// the test resolver — the handshake is allowed to fail later
	/// because `cat` is not an MCP server, but resolution happens
	/// first regardless.
	#[tokio::test]
	async fn spawn_resolves_env_credential_before_launching_child() {
		let resolver = Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "secret-value".to_owned(),
		});
		let config = SpawnConfig {
			command: "cat".into(),
			args: vec![],
			env: HashMap::new(),
			resolver: Arc::clone(&resolver) as _,
			injection: Some(CredentialInjection::Env {
				credential_name: "stdio-token".to_owned(),
			}),
		};

		let _outcome = Bridge::spawn(&config, Duration::from_secs(2)).await;

		let calls = resolver.calls.lock().unwrap().clone();
		assert_eq!(
			calls,
			vec!["stdio-token".to_owned()],
			"the resolver must be consulted exactly once before spawn",
		);
	}

	/// Without injection metadata, the resolver is never consulted
	/// — operator-supplied env entries pass through verbatim.
	#[tokio::test]
	async fn spawn_without_injection_skips_resolver() {
		let resolver = Arc::new(CountingResolver {
			calls: std::sync::Mutex::new(Vec::new()),
			value: "unused".to_owned(),
		});
		let config = SpawnConfig {
			command: "true".into(),
			args: vec![],
			env: HashMap::new(),
			resolver: Arc::clone(&resolver) as _,
			injection: None,
		};

		let _outcome = Bridge::spawn(&config, Duration::from_secs(1)).await;

		assert!(
			resolver.calls.lock().unwrap().is_empty(),
			"resolver must not be invoked when there is no injection metadata",
		);
	}

	/// A spawn-time resolver failure short-circuits before the
	/// child is launched and surfaces as a typed bridge error
	/// carrying the credential name.
	#[tokio::test]
	async fn spawn_resolution_failure_returns_bridge_error_without_launching() {
		let resolver = Arc::new(FailingResolver {
			called: AtomicUsize::new(0),
		});
		let config = SpawnConfig {
			command: "/nonexistent/binary/path".into(),
			args: vec![],
			env: HashMap::new(),
			resolver: Arc::clone(&resolver) as _,
			injection: Some(CredentialInjection::Env {
				credential_name: "missing".to_owned(),
			}),
		};

		let error = Bridge::spawn(&config, Duration::from_secs(1))
			.await
			.expect_err("resolver failure must surface");

		match error {
			BridgeError::CredentialResolution {
				credential,
				ref reason,
			} => {
				assert_eq!(credential, "missing");
				assert!(
					reason.contains("always fails"),
					"the resolver's error message must propagate, got {reason:?}",
				);
			}
			other => panic!("expected CredentialResolution error, got {other:?}"),
		}
		assert_eq!(
			resolver.called.load(Ordering::SeqCst),
			1,
			"the resolver is consulted once and the child is never spawned",
		);
	}

	/// Constructing a `SpawnConfig` with HTTP-only injection
	/// metadata is a router-side programming error and is rejected
	/// at spawn time. Bridges only consume `Env` injections.
	#[tokio::test]
	async fn spawn_rejects_header_injection_metadata() {
		let config = SpawnConfig {
			command: "true".into(),
			args: vec![],
			env: HashMap::new(),
			resolver: unused_resolver(),
			injection: Some(CredentialInjection::Header {
				credential_name: "http-token".to_owned(),
				header_name: "Authorization".to_owned(),
				header_prefix: "Bearer ".to_owned(),
			}),
		};

		let error = Bridge::spawn(&config, Duration::from_secs(1))
			.await
			.expect_err("header injection on a stdio bridge must be rejected");
		assert!(
			matches!(error, BridgeError::InvalidInjection(_)),
			"expected InvalidInjection, got {error:?}",
		);
	}
}
