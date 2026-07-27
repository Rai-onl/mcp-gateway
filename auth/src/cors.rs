//! CORS layer for browser-native MCP clients.
//!
//! Browser clients are cross-origin from any hosted gateway. The layer
//! is built from the operator's allow-list (no wildcard), the fixed
//! method set MCP needs, the configured request headers, the response
//! headers browser clients must be able to read, and the configured
//! preflight max-age. When the `cors` section lists no origins, no
//! browser origin is permitted.

use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, Method};
use mcp_gateway_config::CorsConfig;
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Response headers browser MCP clients must be able to read: the
/// session identifier and the W3C trace-context pair.
const EXPOSED_HEADERS: [HeaderName; 3] = [
	HeaderName::from_static("mcp-session-id"),
	HeaderName::from_static("traceparent"),
	HeaderName::from_static("tracestate"),
];

/// Build the CORS layer from the operator's configuration.
///
/// Origins and request headers that do not parse are dropped rather
/// than failing the build; configuration validation rejects malformed
/// entries earlier, so this is belt-and-braces. Methods are fixed to
/// the set MCP uses (`GET`, `POST`, `OPTIONS`).
pub fn cors_layer(config: &CorsConfig) -> CorsLayer {
	let origins: Vec<HeaderValue> = config
		.allowed_origins
		.iter()
		.filter_map(|origin| origin.parse().ok())
		.collect();
	let request_headers: Vec<HeaderName> = config
		.allowed_headers
		.iter()
		.filter_map(|header| header.parse().ok())
		.collect();

	CorsLayer::new()
		.allow_origin(AllowOrigin::list(origins))
		.allow_methods([Method::GET, Method::POST, Method::OPTIONS])
		.allow_headers(request_headers)
		.expose_headers(EXPOSED_HEADERS)
		.max_age(Duration::from_secs(config.max_age_seconds))
}
