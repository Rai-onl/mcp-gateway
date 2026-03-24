//! MCP gateway console entry point.
//!
//! Initialises tracing, detects output mode, and dispatches to the
//! appropriate subcommand handler. The console binary is a thin
//! dispatcher — all logic lives in the domain library crates.

mod commands;
mod error;

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use mcp_gateway_output::{OutputMode, Renderer, detect_colour};

fn main() -> ExitCode {
	let console = commands::Console::parse();

	init_tracing();

	let output_mode = if console.uses_json_output() {
		OutputMode::Json
	} else {
		OutputMode::Human
	};
	let colour_enabled = detect_colour(output_mode);
	let renderer = Renderer::new(output_mode, colour_enabled, console.is_quiet());

	match console.run(&renderer) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			renderer.error(&error, i32::from(error.exit_code()));
			ExitCode::from(error.exit_code())
		}
	}
}

/// Initialise the `tracing` subscriber with env-filter support.
///
/// Checks `MCP_LOG` first for gateway-specific verbosity control,
/// then falls back to `RUST_LOG` for compatibility with the broader
/// Rust ecosystem, and defaults to `info` if neither is set.
///
/// All trace output goes to stderr so it never contaminates stdout,
/// which is reserved for command output (human text or JSON).
fn init_tracing() {
	let filter = EnvFilter::try_from_env("MCP_LOG")
		.or_else(|_| EnvFilter::try_from_default_env())
		.unwrap_or_else(|_| EnvFilter::new("info"));

	tracing_subscriber::fmt()
		.with_env_filter(filter)
		.with_writer(std::io::stderr)
		.init();
}
