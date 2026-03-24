//! Minimal MCP test server for integration testing.
//!
//! Speaks MCP over stdio (newline-delimited JSON-RPC on
//! stdin/stdout). Handles the initialize handshake, tools/list,
//! tools/call, and ping. Designed to be spawned by the gateway's
//! stdio bridge for end-to-end testing.

use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

fn main() {
	let stdin = io::stdin().lock();
	let mut stdout = io::stdout().lock();

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

		// Notifications have no id — no response needed.
		let Some(id) = message.get("id").cloned() else {
			continue;
		};

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
