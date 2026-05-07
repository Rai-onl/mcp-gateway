//! Top-level command dispatch for the MCP gateway console.
//!
//! Each subcommand module handles argument parsing via clap and
//! delegates to the corresponding domain library crate. This module
//! contains no logic itself — it is purely a dispatcher.

pub mod credential_resolution;
pub mod memory;
pub mod reload;
pub mod serve;

use clap::{Parser, Subcommand};

use mcp_gateway_output::Renderer;

use crate::error::ConsoleError;

/// MCP gateway — route MCP requests to server runtimes.
///
/// The gateway exposes MCP servers over Streamable HTTP, bridging
/// stdio-based servers and proxying remote HTTP servers through a
/// single entry point.
#[derive(Parser, Debug)]
#[command(name = "mcp", version, about)]
pub struct Console {
	/// Output results as JSON instead of human-readable text.
	#[arg(long, global = true)]
	json: bool,

	/// Suppress all output except errors.
	#[arg(long, short = 'q', global = true)]
	quiet: bool,

	/// The subcommand to execute.
	#[command(subcommand)]
	command: Command,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
enum Command {
	/// Start the gateway daemon.
	Serve(serve::ServeArguments),
}

impl Console {
	/// Whether the `--json` flag was passed on the command line.
	///
	/// Used by `main()` to determine output mode, giving the
	/// explicit flag precedence over any default.
	#[must_use]
	pub fn uses_json_output(&self) -> bool {
		self.json
	}

	/// Whether the `--quiet` flag was passed on the command line.
	///
	/// When quiet, human output is suppressed. Errors still reach
	/// stderr. JSON output is unaffected.
	#[must_use]
	pub fn is_quiet(&self) -> bool {
		self.quiet
	}

	/// Dispatch the parsed command to its handler.
	///
	/// This is the single entry point for all command execution.
	/// Each match arm calls into a thin handler function that
	/// delegates to the corresponding domain library.
	///
	/// # Errors
	///
	/// Returns a [`ConsoleError`] if the command handler fails.
	pub fn run(&self, renderer: &Renderer) -> Result<(), ConsoleError> {
		match &self.command {
			Command::Serve(arguments) => serve::run(arguments, renderer),
		}
	}
}
