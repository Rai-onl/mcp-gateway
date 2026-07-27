//! HTTP proxy runtime for the MCP gateway.
//!
//! Forwards MCP requests to upstream remote MCP servers over HTTP,
//! injecting configured headers and passing through the response. The
//! proxy does not interpret MCP message contents; it forwards the
//! JSON-RPC body as-is.

mod client;

pub use client::{Proxy, ProxyError, ProxyResponse};
