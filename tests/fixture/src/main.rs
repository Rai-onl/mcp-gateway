//! Minimal MCP test server for integration testing.
//!
//! Speaks MCP over stdio (newline-delimited JSON-RPC on
//! stdin/stdout). Handles the initialize handshake, tools/list,
//! tools/call, and ping. Designed to be spawned by the gateway's
//! stdio bridge for end-to-end testing.
//!
//! Two environment variables let a test drive failure modes that
//! exercise the bridge's self-healing:
//!
//! - `MCP_FIXTURE_WEDGE_TOOLS_CALL_ONCE=<marker path>`: the first
//!   instance to start creates the marker file and then never replies
//!   to `tools/call` (it stays alive but wedged); any later instance,
//!   seeing the marker already present, behaves normally. This lets a
//!   test observe a request time out, the bridge respawn, and the
//!   replacement succeed.
//! - `MCP_FIXTURE_IGNORE_PING=1`: never reply to `ping`, so an
//!   otherwise-healthy child looks wedged to the liveness heartbeat.
//! - `MCP_FIXTURE_PING_ERROR=1`: reply to `ping` with a JSON-RPC error
//!   (method not found), modelling a server that does not implement
//!   `ping` but is otherwise alive and correlating replies.

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

/// Decide whether this instance should wedge on `tools/call`.
///
/// When `MCP_FIXTURE_WEDGE_TOOLS_CALL_ONCE` names a marker path, the
/// first instance to run creates the marker and wedges; subsequent
/// instances find the marker and run normally. Absent the variable,
/// the instance never wedges.
fn wedging_on_tools_call() -> bool {
	let Ok(marker) = std::env::var("MCP_FIXTURE_WEDGE_TOOLS_CALL_ONCE") else {
		return false;
	};
	if std::path::Path::new(&marker).exists() {
		return false;
	}
	// First instance: claim the marker and wedge.
	let _ = std::fs::write(&marker, b"1");
	true
}

fn main() {
	let stdin = io::stdin().lock();
	let mut stdout = io::stdout().lock();

	let wedge_tools_call = wedging_on_tools_call();
	let ignore_ping = std::env::var("MCP_FIXTURE_IGNORE_PING").is_ok();
	let ping_error = std::env::var("MCP_FIXTURE_PING_ERROR").is_ok();

	for line in stdin.lines() {
		let line = match line {
			Ok(line) => line,
			Err(_) => break,
		};

		let message: Value = match serde_json::from_str(&line) {
			Ok(value) => value,
			Err(_) => continue,
		};

		let method = message
			.get("method")
			.and_then(Value::as_str)
			.unwrap_or("");

		// Notifications have no id: no response needed.
		let Some(id) = message.get("id").cloned() else {
			continue;
		};

		// Failure-mode injection: stay alive but never answer.
		if (method == "tools/call" && wedge_tools_call) || (method == "ping" && ignore_ping) {
			continue;
		}

		let response = match method {
			"initialize" => json!({
				"jsonrpc": "2.0",
				"id": id,
				"result": {
					"protocolVersion": "2025-03-26",
					"capabilities": {
						"tools": {"listChanged": false}
					},
					"serverInfo": {
						"name": "mcp-test-server",
						"version": "0.0.0"
					}
				}
			}),

			"tools/list" => json!({
				"jsonrpc": "2.0",
				"id": id,
				"result": {
					"tools": [
						{
							"name": "echo",
							"description": "Echoes the input back",
							"inputSchema": {
								"type": "object",
								"properties": {
									"message": {"type": "string"}
								},
								"required": ["message"]
							}
						}
					]
				}
			}),

			"tools/call" => {
				let tool_name = message
					.pointer("/params/name")
					.and_then(Value::as_str)
					.unwrap_or("unknown");

				if tool_name == "echo" {
					let input_message = message
						.pointer("/params/arguments/message")
						.and_then(Value::as_str)
						.unwrap_or("");

					json!({
						"jsonrpc": "2.0",
						"id": id,
						"result": {
							"content": [
								{
									"type": "text",
									"text": input_message
								}
							]
						}
					})
				} else {
					json!({
						"jsonrpc": "2.0",
						"id": id,
						"error": {
							"code": -32601,
							"message": format!("Unknown tool: {tool_name}")
						}
					})
				}
			}

			"ping" if ping_error => json!({
				"jsonrpc": "2.0",
				"id": id,
				"error": {
					"code": -32601,
					"message": "ping not supported"
				}
			}),

			"ping" => json!({
				"jsonrpc": "2.0",
				"id": id,
				"result": {}
			}),

			_ => json!({
				"jsonrpc": "2.0",
				"id": id,
				"error": {
					"code": -32601,
					"message": format!("Method not found: {method}")
				}
			}),
		};

		let mut response_line = serde_json::to_string(&response)
			.expect("failed to serialise response");
		response_line.push('\n');
		stdout
			.write_all(response_line.as_bytes())
			.expect("failed to write response");
		stdout.flush().expect("failed to flush stdout");
	}
}
