//! Server dispatch — routes MCP messages to the correct runtime.
//!
//! The router holds the gateway configuration and maps server
//! names to their transport type. When a request arrives, it
//! looks up the server, determines whether to use the stdio
//! bridge or HTTP proxy runtime, and dispatches the message.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use mcp_gateway_bridge::{Bridge, SpawnConfig};
use mcp_gateway_config::{GatewayConfig, ServerDefinition, Transport};
use mcp_gateway_proxy::Proxy;
use mcp_gateway_transport::MessageKind;
use serde_json::Value;
use tokio::sync::Mutex;

/// Default timeout for the MCP handshake when spawning bridge processes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for a single MCP request to a bridge process.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Response from dispatching an MCP message through the router.
#[derive(Debug)]
pub enum RouterResponse {
	/// A JSON-RPC response from the backend server.
	Reply(Value),

	/// The message was a notification — no response expected.
	Accepted,
}

/// The router dispatches MCP messages to backend server runtimes.
pub struct Router {
	/// Enabled server definitions keyed by server name.
	servers: HashMap<String, ServerDefinition>,

	/// Per-server stdio bridge mutexes. Each server gets its own
	/// lock so that independent servers can handle requests
	/// concurrently without blocking each other.
	bridges: HashMap<String, Arc<Mutex<Option<Bridge>>>>,

	/// HTTP proxy instances keyed by server name.
	proxies: HashMap<String, Proxy>,
}

impl Router {
	/// Build a router from the gateway configuration.
	///
	/// Only enabled servers are registered. Disabled servers are
	/// excluded from routing and will return `ServerNotFound` if
	/// requested.
	///
	/// # Errors
	///
	/// Returns an error if an HTTP proxy client cannot be
	/// constructed (TLS backend misconfiguration).
	pub fn from_config(config: &GatewayConfig) -> Result<Self, RouterError> {
		let servers: HashMap<String, ServerDefinition> = config
			.servers
			.iter()
			.filter(|(_, definition)| definition.enabled)
			.map(|(name, definition)| (name.clone(), definition.clone()))
			.collect();

		let bridges = servers
			.iter()
			.filter(|(_, definition)| matches!(definition.transport, Transport::Stdio { .. }))
			.map(|(name, _)| (name.clone(), Arc::new(Mutex::new(None))))
			.collect();

		let mut proxies = HashMap::new();
		for (name, definition) in &servers {
			if let Transport::Http { url, headers } = &definition.transport {
				let proxy = Proxy::new(url.clone(), headers.clone())
					.map_err(|error| RouterError::Configuration(error.to_string()))?;
				proxies.insert(name.clone(), proxy);
			}
		}

		Ok(Self {
			servers,
			bridges,
			proxies,
		})
	}

	/// Check all active bridges and log any that have exited.
	///
	/// Called periodically by a background monitor task so that
	/// bridge crashes are logged immediately rather than waiting
	/// for the next request to discover them.
	pub async fn check_bridge_health(&self) {
		for (name, bridge_slot) in &self.bridges {
			let mut guard = bridge_slot.lock().await;
			if let Some(bridge) = guard.as_mut()
				&& !bridge.is_alive()
			{
				tracing::warn!(server = name.as_str(), "bridge process exited");
				*guard = None;
			}
		}
	}

	/// The names of all enabled servers.
	pub fn server_names(&self) -> Vec<&str> {
		self.servers.keys().map(String::as_str).collect()
	}

	/// Dispatch an MCP message to the named server.
	///
	/// The message is classified as a request or notification,
	/// then forwarded to the correct runtime. Requests return
	/// the server's response; notifications return `Accepted`.
	///
	/// # Errors
	///
	/// Returns an error if the server is not found, the bridge
	/// process cannot be spawned, or the upstream proxy request
	/// fails.
	pub async fn dispatch(
		&self,
		server_name: &str,
		message: &Value,
	) -> Result<RouterResponse, RouterError> {
		let definition = self
			.servers
			.get(server_name)
			.ok_or_else(|| RouterError::ServerNotFound(server_name.to_owned()))?;

		let kind = mcp_gateway_transport::classify(message);

		match &definition.transport {
			Transport::Stdio { command, args } => {
				self.dispatch_stdio(server_name, command, args, &definition.env, message, kind)
					.await
			}
			Transport::Http { .. } => self.dispatch_http(server_name, message, kind).await,
			#[cfg(feature = "sse")]
			Transport::Sse { .. } => Err(RouterError::UnsupportedTransport(
				server_name.to_owned(),
				"sse".to_owned(),
			)),
		}
	}

	/// Dispatch to a stdio bridge runtime.
	///
	/// Each server has its own mutex so independent servers handle
	/// requests concurrently. The bridge process is spawned lazily
	/// on first request and respawned automatically if it exits.
	async fn dispatch_stdio(
		&self,
		server_name: &str,
		command: &str,
		args: &[String],
		env: &HashMap<String, String>,
		message: &Value,
		kind: MessageKind,
	) -> Result<RouterResponse, RouterError> {
		let bridge_slot = self
			.bridges
			.get(server_name)
			.ok_or_else(|| RouterError::ServerNotFound(server_name.to_owned()))?;

		let mut bridge_guard = bridge_slot.lock().await;

		// Remove dead bridges so they get respawned below.
		if let Some(bridge) = bridge_guard.as_mut()
			&& !bridge.is_alive()
		{
			tracing::warn!(server = server_name, "bridge process exited, respawning");
			*bridge_guard = None;
		}

		// Lazy-spawn: start the bridge process on first request
		// or after a crash.
		if bridge_guard.is_none() {
			let spawn_config = SpawnConfig {
				command: command.to_owned(),
				args: args.to_vec(),
				env: env.clone(),
			};

			let bridge = Bridge::spawn(&spawn_config, HANDSHAKE_TIMEOUT)
				.await
				.map_err(RouterError::Bridge)?;

			tracing::info!(server = server_name, "bridge process started");
			*bridge_guard = Some(bridge);
		}

		let bridge = bridge_guard
			.as_mut()
			.expect("bridge was just spawned above");

		match kind {
			MessageKind::Request => match bridge.send(message, REQUEST_TIMEOUT).await {
				Ok(response) => Ok(RouterResponse::Reply(response)),
				Err(mcp_gateway_bridge::BridgeError::ProcessExited) => {
					tracing::warn!(server = server_name, "bridge process exited during request");
					*bridge_guard = None;
					Err(RouterError::Bridge(
						mcp_gateway_bridge::BridgeError::ProcessExited,
					))
				}
				Err(error) => Err(RouterError::Bridge(error)),
			},
			MessageKind::Notification => {
				bridge.notify(message).await.map_err(RouterError::Bridge)?;
				Ok(RouterResponse::Accepted)
			}
			MessageKind::Malformed | MessageKind::Batch => Err(RouterError::MalformedMessage),
		}
	}

	/// Dispatch to an HTTP proxy runtime.
	async fn dispatch_http(
		&self,
		server_name: &str,
		message: &Value,
		kind: MessageKind,
	) -> Result<RouterResponse, RouterError> {
		if matches!(kind, MessageKind::Malformed | MessageKind::Batch) {
			return Err(RouterError::MalformedMessage);
		}

		let proxy = self
			.proxies
			.get(server_name)
			.ok_or_else(|| RouterError::ServerNotFound(server_name.to_owned()))?;

		if kind == MessageKind::Notification {
			// Fire-and-forget: send but don't wait for a meaningful response.
			let _ = proxy.forward(message).await.map_err(RouterError::Proxy)?;
			return Ok(RouterResponse::Accepted);
		}

		let response = proxy.forward(message).await.map_err(RouterError::Proxy)?;
		Ok(RouterResponse::Reply(response.body))
	}
}

/// Errors from the router.
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
	/// The requested server name is not registered or is disabled.
	#[error("server not found: {0}")]
	ServerNotFound(String),

	/// The incoming message is not valid JSON-RPC.
	#[error("malformed JSON-RPC message")]
	MalformedMessage,

	/// The stdio bridge runtime encountered an error.
	#[error("bridge error: {0}")]
	Bridge(#[from] mcp_gateway_bridge::BridgeError),

	/// The HTTP proxy runtime encountered an error.
	#[error("proxy error: {0}")]
	Proxy(#[from] mcp_gateway_proxy::ProxyError),

	/// The server's transport type is not supported by the router.
	#[error("server '{0}' uses unsupported transport '{1}'")]
	UnsupportedTransport(String, String),

	/// A server runtime could not be initialised from configuration.
	#[error("configuration error: {0}")]
	Configuration(String),
}
