//! JSON-RPC session over a stdio server's stdin/stdout streams.
//!
//! A [`Connection`] owns the write half of a child process's stdin
//! and spawns a background task that owns the read half of its
//! stdout. The reader task continuously parses newline-delimited
//! JSON-RPC frames and demultiplexes them:
//!
//! - responses are matched to their originating request by `id` and
//!   delivered through a per-request [`oneshot`] channel;
//! - notifications and unsupported server-to-client requests are
//!   logged and dropped, because the gateway advertises no
//!   capabilities and exposes no downstream push channel to clients;
//! - lines that are not valid JSON are logged and skipped.
//!
//! This id-correlated design is what keeps a full-duplex stdio
//! stream from desynchronising. An earlier implementation wrote a
//! request and then read exactly one line as its reply, so a single
//! unsolicited notification interleaved on stdout shifted every
//! subsequent reply by one frame and wedged the bridge permanently.
//!
//! The session is transport-agnostic: it is generic over any
//! [`AsyncRead`]/[`AsyncWrite`] pair, so its behaviour can be
//! exercised over an in-memory [`tokio::io::duplex`] pipe without
//! spawning a real child process.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, timeout};

use crate::process::BridgeError;

/// The maximum number of bytes of a non-JSON stdout line echoed into
/// a diagnostic log, so a chatty or binary line cannot flood the log.
const LOG_PREVIEW_BYTES: usize = 120;

/// A map from a bridge-local request id to the channel awaiting that
/// request's response. Shared between the sender side ([`Connection`])
/// and the background reader task.
type PendingRequests = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

/// A JSON-RPC session over a child process's stdio streams.
///
/// Cloning is intentionally not supported: a `Connection` owns the
/// single writer and the reader task for one child. The router shares
/// it between concurrent requests through an [`Arc`].
pub struct Connection {
	/// The child's stdin, guarded so concurrent senders serialise
	/// their single-line writes without holding the lock across the
	/// wait for a reply.
	writer: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,

	/// Requests awaiting a correlated response, keyed by the
	/// bridge-local id assigned in [`Connection::send`].
	pending_requests: PendingRequests,

	/// The next bridge-local request id. Every outbound request is
	/// rewritten to a fresh value so correlation never depends on the
	/// ids chosen by multiplexed clients.
	next_request_id: AtomicU64,

	/// Set by the reader task when stdout reaches end of file or
	/// errors. Once set, the child can no longer answer requests.
	is_dead: Arc<AtomicBool>,

	/// Handle to the background reader task, aborted on drop.
	reader_task: JoinHandle<()>,
}

impl Connection {
	/// Open a session over the given read and write halves and spawn
	/// the background reader task that owns the read half.
	///
	/// The read half is consumed by the reader task; the write half
	/// is retained for [`Connection::send`] and
	/// [`Connection::notify`].
	pub fn open<R, W>(read: R, write: W) -> Self
	where
		R: AsyncRead + Unpin + Send + 'static,
		W: AsyncWrite + Unpin + Send + 'static,
	{
		let pending_requests: PendingRequests = Arc::new(Mutex::new(HashMap::new()));
		let is_dead = Arc::new(AtomicBool::new(false));

		let reader_task = tokio::spawn(reader_loop(
			BufReader::new(read),
			Arc::clone(&pending_requests),
			Arc::clone(&is_dead),
		));

		Self {
			writer: Mutex::new(Box::new(write)),
			pending_requests,
			next_request_id: AtomicU64::new(0),
			is_dead,
			reader_task,
		}
	}

	/// Send a JSON-RPC request and await its correlated response.
	///
	/// The outbound `id` is rewritten to a fresh bridge-local value so
	/// that responses can be matched unambiguously even when several
	/// clients multiplex onto one child; the caller's original `id` is
	/// restored in the returned response. The whole exchange must
	/// complete within `request_timeout`.
	///
	/// # Errors
	///
	/// Returns [`BridgeError::Write`] or [`BridgeError::Serialise`] if
	/// the request cannot be written, [`BridgeError::RequestTimeout`]
	/// if no response arrives in time, and
	/// [`BridgeError::ProcessExited`] if the child's stdout closes
	/// while the request is in flight.
	pub async fn send(
		&self,
		message: &Value,
		request_timeout: Duration,
	) -> Result<Value, BridgeError> {
		let bridge_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
		let original_id = message.get("id").cloned().unwrap_or(Value::Null);

		let mut outbound = message.clone();
		if let Some(object) = outbound.as_object_mut() {
			object.insert("id".to_owned(), Value::from(bridge_id));
		}

		// Register the pending slot before writing so a fast reply
		// cannot arrive before the reader knows to route it.
		let (sender, receiver) = oneshot::channel();
		self.pending_requests.lock().await.insert(bridge_id, sender);

		// Fail fast if the reader task has already shut down. It sets
		// `is_dead` before clearing the pending map, and both that clear
		// and the insert above go through the same mutex, so an insert
		// ordered after the clear is guaranteed to observe the flag here
		// (and an insert ordered before it has its sender dropped by the
		// clear). Either way the caller gets `ProcessExited`, never a
		// stall waiting on a reply that can no longer arrive.
		if self.is_dead() {
			self.pending_requests.lock().await.remove(&bridge_id);
			return Err(BridgeError::ProcessExited);
		}

		// The write and the reply-wait share one `request_timeout` budget,
		// so the whole exchange is bounded by it rather than by twice it.
		// Track when the budget starts and charge the write against it.
		let started = Instant::now();

		// Write the whole request under the remaining budget, kept out of
		// the reply-wait. A slow reply must never cancel a half-written
		// line: `write_all` is not cancellation-safe, and a partial line
		// left on the shared stdin would desynchronise every later request.
		// If the write cannot complete in time, a partial line may already
		// have reached the child, so the connection is poisoned and the
		// router replaces it rather than trusting the stream again.
		match timeout(request_timeout, self.write_message(&outbound)).await {
			Ok(Ok(())) => {}
			Ok(Err(error)) => {
				self.pending_requests.lock().await.remove(&bridge_id);
				return Err(error);
			}
			Err(_elapsed) => {
				self.is_dead.store(true, Ordering::Relaxed);
				self.pending_requests.lock().await.remove(&bridge_id);
				return Err(BridgeError::RequestTimeout);
			}
		}

		// Await the correlated reply within whatever of the budget the
		// write left. A dropped sender (reader task on end of file)
		// surfaces as a receive error: the child is gone.
		let remaining = request_timeout.saturating_sub(started.elapsed());
		let result = match timeout(remaining, receiver).await {
			Ok(Ok(mut response)) => {
				if let Some(object) = response.as_object_mut() {
					object.insert("id".to_owned(), original_id);
				}
				Ok(response)
			}
			Ok(Err(_receive)) => Err(BridgeError::ProcessExited),
			Err(_elapsed) => Err(BridgeError::RequestTimeout),
		};

		// Remove our slot on the reply path. On success the reader already
		// removed it; on timeout this prevents a leak, and a late reply is
		// then dropped as unmatched.
		self.pending_requests.lock().await.remove(&bridge_id);

		result
	}

	/// Send a JSON-RPC notification, which expects no response.
	///
	/// # Errors
	///
	/// Returns [`BridgeError::Write`] or [`BridgeError::Serialise`] if
	/// the notification cannot be written.
	pub async fn notify(&self, message: &Value) -> Result<(), BridgeError> {
		self.write_message(message).await
	}

	/// Whether the reader task has observed the child's stdout close.
	///
	/// A dead connection can no longer answer requests and should be
	/// replaced by the router.
	#[must_use]
	pub fn is_dead(&self) -> bool {
		self.is_dead.load(Ordering::Relaxed)
	}

	/// Write a JSON value as a single newline-terminated line to the
	/// child's stdin, holding the writer lock only for the write.
	async fn write_message(&self, message: &Value) -> Result<(), BridgeError> {
		let mut line = serde_json::to_string(message).map_err(BridgeError::Serialise)?;
		line.push('\n');

		let mut writer = self.writer.lock().await;
		// A prior write that was cancelled (a timed-out send) or failed may
		// have left a partial line on the shared stdin and poisoned the
		// connection under this same lock. Appending onto that partial line
		// would desynchronise the stream, so bail instead.
		if self.is_dead() {
			return Err(BridgeError::ProcessExited);
		}
		// `write_all` is not cancellation-safe, so a write dropped mid-flight
		// (the enclosing `send` timing out) can leave a partial line. Poison
		// the connection if that happens. The guard drops before the writer
		// lock, so `is_dead` is set while the lock is still held and the next
		// writer observes it above rather than writing onto the partial line.
		let poison = PoisonOnDrop::new(&self.is_dead);
		writer
			.write_all(line.as_bytes())
			.await
			.map_err(BridgeError::Write)?;
		writer.flush().await.map_err(BridgeError::Write)?;
		poison.disarm();
		Ok(())
	}
}

/// Marks a connection dead when dropped before being disarmed.
///
/// A write holds one across `write_all`/`flush`: if that write is
/// cancelled or errors, the guard sets the liveness flag while the writer
/// lock is still held, so the partial line it may have left cannot be
/// followed by another writer's line. A completed write disarms it.
struct PoisonOnDrop<'a> {
	/// The connection liveness flag to set on an undisarmed drop.
	is_dead: &'a AtomicBool,
	/// Whether an undisarmed drop should still poison the connection.
	armed: bool,
}

impl<'a> PoisonOnDrop<'a> {
	/// Arm a poison guard on the given liveness flag.
	fn new(is_dead: &'a AtomicBool) -> Self {
		Self {
			is_dead,
			armed: true,
		}
	}

	/// Disarm the guard so a completed write leaves the connection alive.
	fn disarm(mut self) {
		self.armed = false;
	}
}

impl Drop for PoisonOnDrop<'_> {
	/// Poison the connection unless the guarded write disarmed first.
	fn drop(&mut self) {
		if self.armed {
			self.is_dead.store(true, Ordering::Relaxed);
		}
	}
}

impl Drop for Connection {
	/// Abort the reader task so it does not outlive the connection.
	///
	/// The child's stdout closing would end the task on its own, but
	/// the explicit abort removes the dependence on the child actually
	/// dying and closes the small window between drop and end of file.
	fn drop(&mut self) {
		self.reader_task.abort();
	}
}

/// The classification of a frame read from the child's stdout.
enum InboundFrame {
	/// A response carrying the given bridge-local request id.
	Response(u64),
	/// A notification (a `method`, no `id`).
	Notification,
	/// A server-to-client request (a `method` and an `id`).
	ServerRequest,
	/// A frame that is neither a well-formed response nor a message
	/// with a `method`.
	Unrecognised,
}

/// Classify a parsed stdout frame from the child's point of view.
///
/// This is deliberately distinct from
/// [`mcp_gateway_transport::classify`], which classifies messages the
/// gateway receives from clients (and therefore requires a `method`).
/// A response from a server carries no `method`, so it needs its own
/// rule: an `id` alongside a `result` or `error`.
fn classify_inbound(frame: &Value) -> InboundFrame {
	let Some(object) = frame.as_object() else {
		return InboundFrame::Unrecognised;
	};

	if object.contains_key("method") {
		return if object.contains_key("id") {
			InboundFrame::ServerRequest
		} else {
			InboundFrame::Notification
		};
	}

	let carries_outcome = object.contains_key("result") || object.contains_key("error");
	match (object.get("id").and_then(Value::as_u64), carries_outcome) {
		(Some(id), true) => InboundFrame::Response(id),
		_ => InboundFrame::Unrecognised,
	}
}

/// Deliver a response frame to its waiting request, if one is still
/// pending. An unmatched id (a late reply to a timed-out request, or a
/// duplicate) is logged and dropped rather than corrupting the stream.
async fn deliver_response(frame: Value, bridge_id: u64, pending_requests: &PendingRequests) {
	let waiting = pending_requests.lock().await.remove(&bridge_id);
	match waiting {
		Some(sender) => {
			// A receive-side drop (request already timed out) is
			// expected and harmless.
			let _ = sender.send(frame);
		}
		None => {
			tracing::warn!(
				bridge_id,
				"dropping stdio response with no matching pending request"
			);
		}
	}
}

/// The background task that owns the child's stdout and routes every
/// frame it reads. Runs until end of file or a read error, then marks
/// the connection dead and fails all in-flight requests by dropping
/// their response channels.
async fn reader_loop<R>(
	mut reader: BufReader<R>,
	pending_requests: PendingRequests,
	is_dead: Arc<AtomicBool>,
) where
	R: AsyncRead + Unpin,
{
	let mut buffer = Vec::new();
	loop {
		buffer.clear();
		match reader.read_until(b'\n', &mut buffer).await {
			Ok(0) => break,
			Ok(_) => {
				// A stdio MCP server should emit UTF-8 JSON, but a wrapped
				// child can leak a stray non-UTF-8 diagnostic byte on
				// stdout. Decode lossily so such a line is rejected by the
				// JSON parser as a skippable line, rather than surfacing as
				// a fatal read error that would kill an otherwise-healthy
				// bridge. Genuine I/O errors still take the fatal path.
				let line = String::from_utf8_lossy(&buffer);
				let trimmed = line.trim();
				if trimmed.is_empty() {
					continue;
				}
				match serde_json::from_str::<Value>(trimmed) {
					Ok(frame) => match classify_inbound(&frame) {
						InboundFrame::Response(bridge_id) => {
							deliver_response(frame, bridge_id, &pending_requests).await;
						}
						InboundFrame::Notification => {
							tracing::debug!("dropping stdio server notification");
						}
						InboundFrame::ServerRequest => {
							tracing::warn!(
								"dropping unsupported stdio server-to-client request"
							);
						}
						InboundFrame::Unrecognised => {
							tracing::warn!("dropping unrecognised stdio frame");
						}
					},
					Err(error) => {
						tracing::warn!(
							%error,
							preview = %log_preview(trimmed),
							"skipping non-JSON line from stdio server"
						);
					}
				}
			}
			Err(error) => {
				tracing::warn!(%error, "stdio read error; marking connection dead");
				break;
			}
		}
	}

	// End of file or read error: no further responses will arrive.
	// Mark dead first, then drop every pending sender so each waiting
	// request observes a receive error and maps it to `ProcessExited`.
	is_dead.store(true, Ordering::Relaxed);
	pending_requests.lock().await.clear();
}

/// Truncate a line to a bounded, character-boundary-safe preview for
/// logging, appending an ellipsis marker when truncated.
fn log_preview(text: &str) -> String {
	if text.len() <= LOG_PREVIEW_BYTES {
		return text.to_owned();
	}
	let mut end = LOG_PREVIEW_BYTES;
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
	use serde_json::json;
	use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};

	use super::*;

	/// A generous per-request timeout for tests that expect success;
	/// the exchanges are in-memory and complete in well under this.
	const TEST_TIMEOUT: Duration = Duration::from_secs(5);

	/// Build a JSON-RPC request with a fixed numeric client id, so
	/// tests can assert the original id is restored after the internal
	/// rewrite.
	fn request(method: &str) -> Value {
		request_with_id(&json!(1), method)
	}

	/// Build a JSON-RPC request carrying an arbitrary client-chosen
	/// `id`, used to prove ids of any JSON type survive rewriting.
	fn request_with_id(id: &Value, method: &str) -> Value {
		json!({"jsonrpc": "2.0", "id": id, "method": method, "params": {}})
	}

	/// Write a JSON value as one newline-terminated line, mimicking a
	/// well-behaved stdio MCP server.
	async fn write_line<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) {
		let mut line = serde_json::to_string(value).unwrap();
		line.push('\n');
		writer.write_all(line.as_bytes()).await.unwrap();
		writer.flush().await.unwrap();
	}

	/// Read one newline-terminated frame, returning `None` at end of
	/// file. Panics if the line is not valid JSON, which would itself
	/// be a test failure.
	async fn read_frame<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Option<Value> {
		let mut line = String::new();
		let count = reader.read_line(&mut line).await.unwrap();
		if count == 0 {
			return None;
		}
		Some(serde_json::from_str(line.trim()).unwrap())
	}

	/// Build a success response echoing the request's method back
	/// under `result.echo`, preserving the request's (rewritten) id.
	fn echo_response(request: &Value) -> Value {
		json!({
			"jsonrpc": "2.0",
			"id": request["id"],
			"result": {"echo": request["method"]},
		})
	}

	/// Open a `Connection` over one end of an in-memory duplex pipe,
	/// returning it alongside the split halves of the other end that a
	/// scripted fake child reads from and writes to.
	fn connect() -> (
		Connection,
		BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
		tokio::io::WriteHalf<tokio::io::DuplexStream>,
	) {
		let (client_side, child_side) = tokio::io::duplex(8192);
		let (client_read, client_write) = tokio::io::split(client_side);
		let (child_read, child_write) = tokio::io::split(child_side);
		let connection = Connection::open(client_read, client_write);
		(connection, BufReader::new(child_read), child_write)
	}

	/// A request receives its matching response and the caller's
	/// original id is restored.
	#[tokio::test]
	async fn request_returns_matching_response_with_original_id() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let request = read_frame(&mut child_read).await.unwrap();
			write_line(&mut child_write, &echo_response(&request)).await;
		});

		let response = connection
			.send(&request_with_id(&json!(7), "ping"), TEST_TIMEOUT)
			.await
			.unwrap();

		assert_eq!(response["id"], json!(7));
		assert_eq!(response["result"]["echo"], "ping");
	}

	/// A notification arriving before the response is skipped and the
	/// response is still delivered.
	#[tokio::test]
	async fn notification_before_response_is_skipped() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let request = read_frame(&mut child_read).await.unwrap();
			write_line(
				&mut child_write,
				&json!({"jsonrpc": "2.0", "method": "notifications/message"}),
			)
			.await;
			write_line(&mut child_write, &echo_response(&request)).await;
		});

		let response = connection
			.send(&request("tools/list"), TEST_TIMEOUT)
			.await
			.unwrap();
		assert_eq!(response["result"]["echo"], "tools/list");
	}

	/// Regression for the live incident: an unsolicited notification
	/// emitted after the first reply must not shift the second reply.
	/// Before id correlation, the second request received the first
	/// notification's frame instead of its own response.
	#[tokio::test]
	async fn unsolicited_notification_does_not_desync_next_request() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let first = read_frame(&mut child_read).await.unwrap();
			write_line(&mut child_write, &echo_response(&first)).await;
			write_line(
				&mut child_write,
				&json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
			)
			.await;
			let second = read_frame(&mut child_read).await.unwrap();
			write_line(&mut child_write, &echo_response(&second)).await;
		});

		let first = connection
			.send(&request("tools/list"), TEST_TIMEOUT)
			.await
			.unwrap();
		let second = connection
			.send(&request("tools/call"), TEST_TIMEOUT)
			.await
			.unwrap();

		assert_eq!(first["result"]["echo"], "tools/list");
		assert_eq!(second["result"]["echo"], "tools/call");
	}

	/// A line that is not valid JSON is skipped and the following
	/// valid response is still delivered.
	#[tokio::test]
	async fn non_json_line_is_skipped() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let request = read_frame(&mut child_read).await.unwrap();
			child_write
				.write_all(b"this is not json\n")
				.await
				.unwrap();
			write_line(&mut child_write, &echo_response(&request)).await;
		});

		let response = connection
			.send(&request("tools/list"), TEST_TIMEOUT)
			.await
			.unwrap();
		assert_eq!(response["result"]["echo"], "tools/list");
	}

	/// A server-to-client request is logged and dropped, not consumed
	/// as the pending request's reply.
	#[tokio::test]
	async fn server_to_client_request_is_dropped() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let request = read_frame(&mut child_read).await.unwrap();
			write_line(
				&mut child_write,
				&json!({"jsonrpc": "2.0", "id": 9001, "method": "sampling/createMessage"}),
			)
			.await;
			write_line(&mut child_write, &echo_response(&request)).await;
		});

		let response = connection
			.send(&request("tools/list"), TEST_TIMEOUT)
			.await
			.unwrap();
		assert_eq!(response["result"]["echo"], "tools/list");
	}

	/// A response whose id matches no pending request is dropped, and
	/// a genuine request still succeeds afterwards.
	#[tokio::test]
	async fn unmatched_response_id_is_dropped() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let request = read_frame(&mut child_read).await.unwrap();
			write_line(
				&mut child_write,
				&json!({"jsonrpc": "2.0", "id": 424_242, "result": {"stray": true}}),
			)
			.await;
			write_line(&mut child_write, &echo_response(&request)).await;
		});

		let response = connection
			.send(&request("tools/list"), TEST_TIMEOUT)
			.await
			.unwrap();
		assert_eq!(response["result"]["echo"], "tools/list");
	}

	/// End of file while a request is in flight fails it with
	/// `ProcessExited` rather than hanging until the timeout.
	#[tokio::test]
	async fn end_of_file_fails_pending_request() {
		let (connection, mut child_read, child_write) = connect();
		tokio::spawn(async move {
			let _request = read_frame(&mut child_read).await.unwrap();
			// Drop the write half without replying, closing stdout.
			drop(child_write);
		});

		let outcome = connection.send(&request("tools/list"), TEST_TIMEOUT).await;
		assert!(matches!(outcome, Err(BridgeError::ProcessExited)));
	}

	/// End of file marks the connection dead.
	#[tokio::test]
	async fn end_of_file_marks_connection_dead() {
		let (connection, mut child_read, child_write) = connect();
		tokio::spawn(async move {
			let _request = read_frame(&mut child_read).await.unwrap();
			drop(child_write);
		});

		let _outcome = connection.send(&request("tools/list"), TEST_TIMEOUT).await;
		assert!(connection.is_dead());
	}

	/// A client-chosen string id survives the internal numeric rewrite.
	#[tokio::test]
	async fn string_id_is_restored() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let request = read_frame(&mut child_read).await.unwrap();
			write_line(&mut child_write, &echo_response(&request)).await;
		});

		let response = connection
			.send(&request_with_id(&json!("abc-123"), "ping"), TEST_TIMEOUT)
			.await
			.unwrap();
		assert_eq!(response["id"], json!("abc-123"));
	}

	/// A client-chosen null id survives the internal numeric rewrite.
	#[tokio::test]
	async fn null_id_is_restored() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let request = read_frame(&mut child_read).await.unwrap();
			write_line(&mut child_write, &echo_response(&request)).await;
		});

		let response = connection
			.send(&request_with_id(&Value::Null, "ping"), TEST_TIMEOUT)
			.await
			.unwrap();
		assert_eq!(response["id"], Value::Null);
	}

	/// A timed-out request removes its pending entry so a later request
	/// still correlates, and the late reply to the timed-out request is
	/// dropped rather than delivered to the wrong caller.
	#[tokio::test]
	async fn timed_out_request_does_not_poison_later_request() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let first = read_frame(&mut child_read).await.unwrap();
			// Reply to the first request only after its short timeout
			// has elapsed, so its reply arrives late and unmatched.
			tokio::time::sleep(Duration::from_millis(300)).await;
			write_line(&mut child_write, &echo_response(&first)).await;
			let second = read_frame(&mut child_read).await.unwrap();
			write_line(&mut child_write, &echo_response(&second)).await;
		});

		let first = connection
			.send(&request("slow"), Duration::from_millis(100))
			.await;
		assert!(matches!(first, Err(BridgeError::RequestTimeout)));

		let second = connection
			.send(&request("tools/call"), TEST_TIMEOUT)
			.await
			.unwrap();
		assert_eq!(second["result"]["echo"], "tools/call");
	}

	/// A concurrent pair of requests whose replies arrive out of order
	/// each resolve to their own response.
	#[tokio::test]
	async fn concurrent_requests_correlate_out_of_order() {
		let (connection, mut child_read, mut child_write) = connect();
		tokio::spawn(async move {
			let first = read_frame(&mut child_read).await.unwrap();
			let second = read_frame(&mut child_read).await.unwrap();
			// Reply in reverse order.
			write_line(&mut child_write, &echo_response(&second)).await;
			write_line(&mut child_write, &echo_response(&first)).await;
		});

		let first_request = request("first");
		let second_request = request("second");
		let (first, second) = tokio::join!(
			connection.send(&first_request, TEST_TIMEOUT),
			connection.send(&second_request, TEST_TIMEOUT),
		);

		assert_eq!(first.unwrap()["result"]["echo"], "first");
		assert_eq!(second.unwrap()["result"]["echo"], "second");
	}

	/// A notification is written and expects no response.
	#[tokio::test]
	async fn notify_writes_without_expecting_a_response() {
		let (connection, mut child_read, _child_write) = connect();
		let received = tokio::spawn(async move { read_frame(&mut child_read).await });

		connection
			.notify(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
			.await
			.unwrap();

		let frame = received.await.unwrap().unwrap();
		assert_eq!(frame["method"], "notifications/initialized");
		assert!(frame.get("id").is_none());
	}

	/// A write that cannot complete within the timeout (a child that
	/// stops draining its stdin) fails with a timeout and poisons the
	/// connection, so the router replaces it rather than trusting a
	/// possibly half-written stream. The write is bounded separately
	/// from the reply-wait precisely so a slow reply can never cancel a
	/// partial write.
	#[tokio::test]
	async fn write_timeout_poisons_the_connection() {
		// A tiny pipe whose child side is never read, so a large write
		// fills the buffer and blocks. `child_side` is kept alive so the
		// pipe stays open (blocking) rather than broken.
		let (client_side, child_side) = tokio::io::duplex(64);
		let (client_read, client_write) = tokio::io::split(client_side);
		let connection = Connection::open(client_read, client_write);

		let big_request = json!({
			"jsonrpc": "2.0",
			"id": 1,
			"method": "tools/call",
			"params": {"blob": "x".repeat(10_000)},
		});
		let outcome = connection
			.send(&big_request, Duration::from_millis(200))
			.await;

		assert!(matches!(outcome, Err(BridgeError::RequestTimeout)));
		assert!(
			connection.is_dead(),
			"a timed-out write must poison the connection"
		);
		drop(child_side);
	}

	/// Dropping the connection closes stdin, which the child observes
	/// as end of file on its read half.
	#[tokio::test]
	async fn dropping_connection_closes_child_stdin() {
		let (connection, mut child_read, _child_write) = connect();
		drop(connection);
		let frame = read_frame(&mut child_read).await;
		assert!(frame.is_none());
	}
}
