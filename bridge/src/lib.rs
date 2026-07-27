//! Stdio bridge runtime for the MCP gateway.
//!
//! Spawns MCP server processes as children, performs the MCP
//! `initialize` handshake over stdin/stdout, and forwards
//! JSON-RPC messages between HTTP requests and the child
//! process's stdio streams.

mod connection;
mod handshake;
mod process;

pub use connection::Connection;
pub use handshake::Handshake;
pub use process::{Bridge, BridgeError, SpawnConfig};
