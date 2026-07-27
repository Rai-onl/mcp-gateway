//! Server dispatch: routes MCP messages to the correct runtime.
//!
//! The router holds the gateway configuration and maps server
//! names to their transport type. When a request arrives, it
//! looks up the server, determines whether to use the stdio
//! bridge or HTTP proxy runtime, and dispatches the message.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mcp_gateway_bridge::{Bridge, BridgeError, SpawnConfig};
use mcp_gateway_config::{CredentialInjection, GatewayConfig, ServerDefinition, Transport};
use mcp_gateway_credentials::{CredentialResolver, Secret};
use mcp_gateway_proxy::Proxy;
use mcp_gateway_transport::MessageKind;
use serde_json::Value;
use tokio::sync::Mutex;

/// Default timeout for the MCP handshake when spawning bridge processes.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum interval between successive spawns of one server's bridge.
/// A child that dies immediately after spawning would otherwise be
/// respawned on every request; this bounds the churn.
const SPAWN_BACKOFF: Duration = Duration::from_millis(500);

/// Default timeout for a liveness-probe `ping` to a stdio bridge. Kept
/// short so a wedged child is detected promptly rather than blocking
/// the health monitor for a full request timeout.
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// The number of consecutive liveness-probe failures that condemns a
/// bridge. One transient failure is tolerated; two in a row, with no
/// successful request in between, means the child is wedged.
const HEALTH_FAILURE_THRESHOLD: u32 = 2;

/// Borrowed view of the stdio invocation parameters held by a
/// `ServerDefinition`. Bundling them into one parameter keeps
/// `dispatch_stdio`'s signature inside the workspace's
/// `too-many-arguments-threshold`.
struct StdioInvocation<'definition> {
	command: &'definition str,
	args: &'definition [String],
	env: &'definition HashMap<String, Secret>,
	injection: Option<&'definition CredentialInjection>,
	request_timeout: Duration,
}

/// Response from dispatching an MCP message through the router.
#[derive(Debug)]
pub enum RouterResponse {
	/// A JSON-RPC response from the backend server.
	Reply(Value),

	/// The message was a notification: no response expected.
	Accepted,
}

/// The per-server state for a stdio bridge: the current bridge, if
/// any, and when one was last spawned. The spawn time drives
/// respawn rate-limiting so an immediately-dying child cannot
/// crash-loop.
#[derive(Default)]
struct BridgeSlot {
	/// The live bridge, shared with in-flight requests through an
	/// [`Arc`]. `None` before the first request or after the bridge is
	/// dropped for being dead or wedged.
	bridge: Option<Arc<Bridge>>,

	/// When a bridge was last spawned into this slot, used to enforce
	/// [`SPAWN_BACKOFF`].
	last_spawn: Option<Instant>,
}

/// The router dispatches MCP messages to backend server runtimes.
pub struct Router {
	/// Enabled server definitions keyed by server name.
	servers: HashMap<String, ServerDefinition>,

	/// Per-server stdio bridge slots. Each server gets its own lock so
	/// independent servers work concurrently. The bridge is held behind
	/// an inner [`Arc`] so a request can clone it, release the slot
	/// lock, and issue its call while other requests to the same server
	/// multiplex onto the shared child.
	bridges: HashMap<String, Arc<Mutex<BridgeSlot>>>,

	/// HTTP proxy instances keyed by server name.
	proxies: HashMap<String, Proxy>,

	/// Credential resolver shared with the proxy and bridge
	/// runtimes. Each `Proxy` already holds its own `Arc` clone for
	/// per-request use; bridges are spawned lazily, so the router
	/// hands the resolver to `Bridge::spawn` at the spawn point.
	credential_resolver: Arc<dyn CredentialResolver>,

	/// An optional override for the per-request stdio timeout. `None` in
	/// production, where each server's own `request_timeout_seconds`
	/// (default 30s) applies; set through [`Router::with_request_timeout`]
	/// as a test seam for exercising the timeout path quickly.
	request_timeout_override: Option<Duration>,

	/// The timeout applied to a liveness-probe `ping`. Defaults to
	/// [`HEALTH_PROBE_TIMEOUT`]; overridable through
	/// [`Router::with_health_probe_timeout`].
	health_probe_timeout: Duration,
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
	pub fn from_config(
		config: &GatewayConfig,
		credential_resolver: Arc<dyn CredentialResolver>,
	) -> Result<Self, RouterError> {
		let servers: HashMap<String, ServerDefinition> = config
			.servers
			.iter()
			.filter(|(_, definition)| definition.enabled)
			.map(|(name, definition)| (name.clone(), definition.clone()))
			.collect();

		let bridges = servers
			.iter()
			.filter(|(_, definition)| matches!(definition.transport, Transport::Stdio { .. }))
			.map(|(name, _)| (name.clone(), Arc::new(Mutex::new(BridgeSlot::default()))))
			.collect();

		let mut proxies = HashMap::new();
		for (name, definition) in &servers {
			if let Transport::Http { url, headers } = &definition.transport {
				let proxy = Proxy::with_request_timeout(
					url.clone(),
					headers.clone(),
					Arc::clone(&credential_resolver),
					definition.credential_injection.clone(),
					definition.request_timeout(),
				)
				.map_err(|error| RouterError::Configuration(error.to_string()))?;
				proxies.insert(name.clone(), proxy);
			}
		}

		Ok(Self {
			servers,
			bridges,
			proxies,
			credential_resolver,
			request_timeout_override: None,
			health_probe_timeout: HEALTH_PROBE_TIMEOUT,
		})
	}

	/// Override the per-request timeout applied to every stdio bridge
	/// call, ignoring each server's configured `request_timeout_seconds`.
	///
	/// A seam for tests that exercise the timeout-driven recovery path
	/// without waiting a full production timeout. Hidden from the public
	/// API surface: when set it overrides every server's configured
	/// `request_timeout_seconds`, which is a test-only behaviour and not
	/// something a library consumer should reach for.
	#[doc(hidden)]
	#[must_use]
	pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
		self.request_timeout_override = Some(request_timeout);
		self
	}

	/// Override the liveness-probe timeout used by
	/// [`Router::check_bridge_health`]. A seam for tests that exercise
	/// the heartbeat without waiting the full probe timeout.
	#[doc(hidden)]
	#[must_use]
	pub fn with_health_probe_timeout(mut self, health_probe_timeout: Duration) -> Self {
		self.health_probe_timeout = health_probe_timeout;
		self
	}

	/// Whether the named server currently holds a live bridge. Used by
	/// the health monitor's tests and available for readiness
	/// reporting.
	#[must_use]
	pub async fn is_bridge_active(&self, server_name: &str) -> bool {
		match self.bridges.get(server_name) {
			Some(slot) => slot.lock().await.bridge.is_some(),
			None => false,
		}
	}

	/// Check all active bridges and log any that have exited.
	///
	/// Called periodically by a background monitor task so that
	/// bridge crashes are logged immediately rather than waiting
	/// for the next request to discover them.
	pub async fn check_bridge_health(&self) {
		for (name, bridge_slot) in &self.bridges {
			self.probe_bridge(name, bridge_slot).await;
		}
	}

	/// Probe one server's bridge, replacing it if it has exited or
	/// failed the liveness probe repeatedly.
	///
	/// Snapshots the current bridge under a `try_lock` and releases the
	/// slot immediately, so the probe never blocks dispatch and never
	/// stalls behind a slot that a request is currently spawning or
	/// replacing (that lock is held across the handshake). Requests
	/// multiplex onto the shared child concurrently, so the probe is
	/// just another correlated request.
	async fn probe_bridge(&self, name: &str, bridge_slot: &Mutex<BridgeSlot>) {
		let Ok(slot_guard) = bridge_slot.try_lock() else {
			return;
		};
		let bridge = slot_guard.bridge.clone();
		drop(slot_guard);

		let Some(bridge) = bridge else {
			return;
		};

		// A child whose stdout has closed is already gone.
		if !bridge.is_alive() {
			tracing::warn!(server = name, "bridge is no longer alive; reaping");
			clear_bridge_if_current(bridge_slot, &bridge).await;
			return;
		}

		// Actively probe: a wedged-but-alive child fails this. Reap only
		// after repeated failures with no successful request in between,
		// so a momentary stall does not condemn a healthy child.
		if !bridge.health_check(self.health_probe_timeout).await
			&& bridge.consecutive_ping_failures() >= HEALTH_FAILURE_THRESHOLD
		{
			tracing::warn!(
				server = name,
				failures = bridge.consecutive_ping_failures(),
				"bridge failed liveness probe; replacing"
			);
			clear_bridge_if_current(bridge_slot, &bridge).await;
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
				let request_timeout = self
					.request_timeout_override
					.unwrap_or_else(|| definition.request_timeout());
				let invocation = StdioInvocation {
					command,
					args,
					env: &definition.env,
					injection: definition.credential_injection.as_ref(),
					request_timeout,
				};
				self.dispatch_stdio(server_name, &invocation, message, kind)
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
	/// The bridge process is spawned lazily on first request and shared
	/// between all requests to the server. The slot lock is released
	/// before the request is issued, so requests multiplex concurrently
	/// onto the one child and responses are correlated by id inside the
	/// bridge. A bridge that has exited or wedged is replaced on the
	/// next request.
	async fn dispatch_stdio(
		&self,
		server_name: &str,
		invocation: &StdioInvocation<'_>,
		message: &Value,
		kind: MessageKind,
	) -> Result<RouterResponse, RouterError> {
		let bridge_slot = self
			.bridges
			.get(server_name)
			.ok_or_else(|| RouterError::ServerNotFound(server_name.to_owned()))?;

		let bridge = self
			.acquire_bridge(server_name, bridge_slot, invocation)
			.await?;

		match kind {
			MessageKind::Request => match bridge.send(message, invocation.request_timeout).await {
				Ok(response) => Ok(RouterResponse::Reply(response)),
				Err(error) => {
					if replacement_warranted(&error, &bridge) {
						tracing::warn!(
							server = server_name,
							%error,
							"replacing bridge after failed request"
						);
						clear_bridge_if_current(bridge_slot, &bridge).await;
					}
					Err(RouterError::Bridge(error))
				}
			},
			MessageKind::Notification => {
				bridge.notify(message).await.map_err(RouterError::Bridge)?;
				Ok(RouterResponse::Accepted)
			}
			MessageKind::Malformed | MessageKind::Batch => Err(RouterError::MalformedMessage),
		}
	}

	/// Return a live bridge for the server, spawning one if the slot is
	/// empty or holds a dead bridge. The returned [`Arc`] lets the
	/// caller issue its request after releasing the slot lock so that
	/// concurrent requests share the one child.
	async fn acquire_bridge(
		&self,
		server_name: &str,
		bridge_slot: &Mutex<BridgeSlot>,
		invocation: &StdioInvocation<'_>,
	) -> Result<Arc<Bridge>, RouterError> {
		let mut slot = bridge_slot.lock().await;

		if let Some(bridge) = slot.bridge.as_ref() {
			if bridge.is_alive() {
				return Ok(Arc::clone(bridge));
			}
			tracing::warn!(server = server_name, "replacing dead bridge before request");
			slot.bridge = None;
		}

		// Rate-limit respawns so a child that dies immediately after
		// spawning cannot be relaunched on every request.
		if let Some(last_spawn) = slot.last_spawn
			&& last_spawn.elapsed() < SPAWN_BACKOFF
		{
			return Err(RouterError::BridgeCooldown(server_name.to_owned()));
		}

		let spawn_config = SpawnConfig {
			command: invocation.command.to_owned(),
			args: invocation.args.to_vec(),
			env: invocation.env.clone(),
			resolver: Arc::clone(&self.credential_resolver),
			injection: invocation.injection.cloned(),
		};

		// Record the attempt before spawning so a failed spawn also
		// counts against the backoff window.
		slot.last_spawn = Some(Instant::now());
		let bridge = Arc::new(
			Bridge::spawn(&spawn_config, HANDSHAKE_TIMEOUT)
				.await
				.map_err(RouterError::Bridge)?,
		);
		tracing::info!(server = server_name, "bridge process started");
		slot.bridge = Some(Arc::clone(&bridge));
		Ok(bridge)
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
		if response.body.is_null() {
			// A success status with an empty body is the proxy's no-content
			// sentinel. It is the correct reply to a notification (handled
			// above and discarded), but as the answer to a request it means
			// the upstream returned nothing to relay. Surface it as an
			// upstream failure rather than handing the client a bare `null`,
			// which is not a valid JSON-RPC response.
			return Err(RouterError::EmptyUpstreamReply(server_name.to_owned()));
		}
		Ok(RouterResponse::Reply(response.body))
	}
}

/// Whether a failed request means the shared bridge should be dropped
/// and respawned: the child has gone (exited, or its stdout closed) or
/// it wedged and the request timed out. A generous request timeout is
/// what separates a genuinely wedged child from a merely slow one.
fn replacement_warranted(error: &BridgeError, bridge: &Bridge) -> bool {
	matches!(error, BridgeError::RequestTimeout) || !bridge.is_alive()
}

/// Clear a bridge slot only if it still holds the specific bridge that
/// failed. Pointer identity ensures a bridge that another concurrent
/// request already replaced is never evicted a second time.
async fn clear_bridge_if_current(bridge_slot: &Mutex<BridgeSlot>, used: &Arc<Bridge>) {
	let mut slot = bridge_slot.lock().await;
	if slot
		.bridge
		.as_ref()
		.is_some_and(|current| Arc::ptr_eq(current, used))
	{
		slot.bridge = None;
	}
}

/// The details of an upstream HTTP failure, borrowed from a
/// [`RouterError`] so the daemon can shape a client response and a log
/// line without depending on the proxy error type.
#[derive(Debug)]
pub struct UpstreamFailure<'a> {
	/// The non-2xx HTTP status the upstream returned.
	pub status: u16,
	/// The response `Content-Type`, for diagnostics.
	pub content_type: &'a str,
	/// A bounded preview of the response body, for logging only.
	pub body_preview: &'a str,
	/// The upstream's `Retry-After` header value, when present.
	pub retry_after: Option<&'a str>,
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

	/// A bridge cannot be respawned yet: one was spawned very recently
	/// and is unavailable, so the caller should retry shortly rather
	/// than the gateway relaunching the child on every request.
	#[error("bridge for '{0}' is cooling down after a recent respawn")]
	BridgeCooldown(String),

	/// The HTTP proxy runtime encountered an error.
	#[error("proxy error: {0}")]
	Proxy(#[from] mcp_gateway_proxy::ProxyError),

	/// An HTTP upstream answered a request with a success status but an
	/// empty body, so there is no result to return. Valid for a
	/// notification, a protocol violation for a request.
	#[error("upstream '{0}' returned an empty response to a request")]
	EmptyUpstreamReply(String),

	/// The server's transport type is not supported by the router.
	#[error("server '{0}' uses unsupported transport '{1}'")]
	UnsupportedTransport(String, String),

	/// A server runtime could not be initialised from configuration.
	#[error("configuration error: {0}")]
	Configuration(String),
}

impl RouterError {
	/// If this error is an upstream HTTP failure (a non-2xx response
	/// from an HTTP-transport server), return its details. Lets the
	/// daemon map the failure to a meaningful client response and log
	/// without needing to name the proxy error type.
	#[must_use]
	pub fn upstream_failure(&self) -> Option<UpstreamFailure<'_>> {
		match self {
			RouterError::Proxy(mcp_gateway_proxy::ProxyError::UpstreamStatus {
				status,
				content_type,
				body_preview,
				retry_after,
			}) => Some(UpstreamFailure {
				status: *status,
				content_type,
				body_preview,
				retry_after: retry_after.as_deref(),
			}),
			_ => None,
		}
	}

	/// Whether this error is a stdio bridge request- or handshake-timeout
	/// (a wedged backend), as opposed to another bridge failure (a dead
	/// or unwritable one). Lets the daemon map a wedged backend to 504
	/// Gateway Timeout and other bridge failures to 502 Bad Gateway,
	/// without naming the bridge error type.
	#[must_use]
	pub fn is_bridge_timeout(&self) -> bool {
		matches!(
			self,
			RouterError::Bridge(
				mcp_gateway_bridge::BridgeError::RequestTimeout
					| mcp_gateway_bridge::BridgeError::HandshakeTimeout
			)
		)
	}
}
