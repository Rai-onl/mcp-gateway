//! Child process management for stdio MCP servers.
//!
//! Spawns a server process, pipes stdin/stdout for JSON-RPC
//! communication, and manages the process lifecycle including
//! the MCP initialize handshake.

use std::collections::HashMap;
use std::fmt;
use std::process::Stdio;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{Duration, timeout};

use crate::handshake::{self, Handshake, HandshakeError};

/// Configuration for spawning a bridge process.
#[derive(Debug, Clone)]
pub struct SpawnConfig {
	/// Path to the MCP server binary or script.
	pub command: String,

	/// Command-line arguments.
	pub args: Vec<String>,

	/// Environment variables injected into the child process.
	pub env: HashMap<String, String>,
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
		let mut cmd = Command::new(&config.command);
		cmd.args(&config.args)
			.envs(&config.env)
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
}

#[cfg(test)]
mod tests {
	use super::*;

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
		};

		let _err = Bridge::spawn(&config, Duration::from_secs(1))
			.await
			.expect_err("immediately exiting process should fail handshake");
	}
}
