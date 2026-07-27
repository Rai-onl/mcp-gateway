//! Inbound authentication for the MCP gateway.
//!
//! This crate hosts the OAuth 2.1 resource-server behaviour the
//! gateway uses to authenticate inbound MCP requests: discovery
//! and JWKS retrieval, JWT and introspection validation, scope
//! evaluation, the protected resource metadata document, and the
//! axum middleware that ties them together.
//!
//! The configuration types this crate consumes live in
//! `mcp-gateway-config` under the `authentication` module.

pub mod authorise;
pub mod challenge;
pub mod claims;
pub mod cors;
pub mod discovery;
pub mod introspection;
pub mod jwks;
pub mod metadata;
pub mod middleware;
pub mod setup;
pub mod strategy;
pub mod trust;
pub mod validator;
