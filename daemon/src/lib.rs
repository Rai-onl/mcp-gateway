//! HTTP daemon for the MCP gateway.
//!
//! Exposes MCP server endpoints over Streamable HTTP using axum.
//! Each configured server is accessible at `POST /servers/{name}/mcp`.
//! A health endpoint at `GET /health` reports the status of all
//! configured servers.
//!
//! When the gateway runs behind a trusted reverse proxy, the
//! identity middleware extracts client certificate information
//! from forwarded headers (RFC 9440).

pub mod identity;
mod refresh;
mod server;

pub use refresh::{run_discovery_refresh, run_key_refresh};
pub use server::{AppState, AppStateError, build_app};
