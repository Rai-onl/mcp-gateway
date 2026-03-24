//! Client identity extraction from trusted proxy headers.
//!
//! When the gateway runs behind a reverse proxy that terminates
//! mTLS, the proxy verifies client certificates and forwards
//! identity information via HTTP headers. This module provides
//! middleware that extracts that identity — but only when the
//! request arrives from a trusted proxy address.
//!
//! Requests from untrusted sources have identity headers stripped
//! to prevent forgery.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

use mcp_gateway_config::ClientIdentityHeaders;

/// Client identity extracted from proxy-forwarded headers.
///
/// Attached to request extensions when the request arrives from
/// a trusted proxy. Downstream handlers can retrieve it via
/// `request.extensions().get::<ClientIdentity>()`.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
	/// The client certificate in base64-encoded DER format
	/// (RFC 9440 `Client-Cert` header value).
	pub certificate: Option<String>,

	/// The certificate chain in base64-encoded DER format
	/// (RFC 9440 `Client-Cert-Chain` header value).
	pub certificate_chain: Option<String>,
}

/// Configuration for the trusted proxy middleware.
///
/// Shared across all requests via `Arc` in axum state.
#[derive(Debug, Clone)]
pub struct TrustedProxyConfig {
	/// CIDR ranges of trusted proxy addresses.
	pub trusted_networks: Vec<IpNet>,

	/// Header names to read client identity from.
	pub identity_headers: ClientIdentityHeaders,
}

impl TrustedProxyConfig {
	/// Whether the given address is within a trusted proxy network.
	#[must_use]
	pub fn is_trusted(&self, address: IpAddr) -> bool {
		self.trusted_networks
			.iter()
			.any(|network| network.contains(&address))
	}
}

/// Axum middleware that extracts client identity from trusted proxy
/// headers.
///
/// This middleware is only added to the router when `trusted_proxies`
/// is configured. For requests from trusted proxy addresses, it
/// reads identity headers and attaches a [`ClientIdentity`] to
/// request extensions. For all other requests, identity headers
/// are stripped to prevent forgery.
pub async fn extract_client_identity(
	axum::extract::Extension(proxy_config): axum::extract::Extension<Arc<TrustedProxyConfig>>,
	mut request: Request,
	next: Next,
) -> Response {
	// Read the remote address from ConnectInfo if available.
	// ConnectInfo is present when the server was started with
	// `into_make_service_with_connect_info`, but may be absent
	// in tests or behind certain proxies.
	let remote_address = request
		.extensions()
		.get::<ConnectInfo<SocketAddr>>()
		.map(|info| info.0.ip());

	let is_trusted = remote_address.is_some_and(|address| proxy_config.is_trusted(address));

	let certificate_header = &proxy_config.identity_headers.certificate;
	let chain_header = &proxy_config.identity_headers.certificate_chain;

	if is_trusted {
		// Extract identity from the forwarded headers.
		// RFC 9440 specifies base64-encoded values; reject
		// values that contain non-base64 characters.
		let certificate = request
			.headers()
			.get(certificate_header.as_str())
			.and_then(|value| value.to_str().ok())
			.filter(|value| is_base64_encoded(value))
			.map(String::from);

		let certificate_chain = request
			.headers()
			.get(chain_header.as_str())
			.and_then(|value| value.to_str().ok())
			.filter(|value| is_base64_encoded(value))
			.map(String::from);

		if certificate.is_some() || certificate_chain.is_some() {
			let identity = ClientIdentity {
				certificate,
				certificate_chain,
			};

			tracing::debug!(
				source = ?remote_address,
				has_certificate = identity.certificate.is_some(),
				has_chain = identity.certificate_chain.is_some(),
				"extracted client identity from trusted proxy"
			);

			request.extensions_mut().insert(identity);
		}
	} else if remote_address.is_some() {
		tracing::trace!(
			source = ?remote_address,
			"stripping identity headers from untrusted source"
		);
	}

	// Always remove identity headers from the forwarded request,
	// whether trusted or not. Trusted requests have the values
	// captured in ClientIdentity; untrusted requests must not
	// propagate forged headers.
	request.headers_mut().remove(certificate_header.as_str());
	request.headers_mut().remove(chain_header.as_str());

	next.run(request).await
}

/// Check whether a string contains only valid base64 characters
/// (standard or URL-safe alphabet, with optional padding).
fn is_base64_encoded(value: &str) -> bool {
	!value.is_empty()
		&& value.bytes().all(|byte| {
			byte.is_ascii_alphanumeric()
				|| byte == b'+'
				|| byte == b'/'
				|| byte == b'-'
				|| byte == b'_'
				|| byte == b'='
				|| byte == b' '
		})
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;
	use std::sync::Arc;

	use axum::Router;
	use axum::body::Body;
	use axum::extract::Request;
	use axum::http::StatusCode;
	use axum::middleware;
	use axum::routing::get;
	use http_body_util::BodyExt;
	use tower::ServiceExt;

	use mcp_gateway_config::ClientIdentityHeaders;

	use super::*;

	fn trusted_proxy_config(networks: Vec<&str>) -> Arc<TrustedProxyConfig> {
		Arc::new(TrustedProxyConfig {
			trusted_networks: networks
				.into_iter()
				.map(|network| network.parse().unwrap())
				.collect(),
			identity_headers: ClientIdentityHeaders::default(),
		})
	}

	fn test_router(proxy_config: Arc<TrustedProxyConfig>) -> Router {
		Router::new()
			.route("/test", get(handler))
			.layer(middleware::from_fn(extract_client_identity))
			.layer(axum::extract::Extension(proxy_config))
	}

	async fn handler(request: Request) -> String {
		match request.extensions().get::<ClientIdentity>() {
			Some(identity) => {
				format!(
					"cert={},chain={}",
					identity.certificate.as_deref().unwrap_or("none"),
					identity.certificate_chain.as_deref().unwrap_or("none"),
				)
			}
			None => "no-identity".to_owned(),
		}
	}

	/// Requests from a trusted proxy with identity headers produce
	/// a `ClientIdentity` in request extensions.
	#[tokio::test]
	async fn trusted_proxy_extracts_identity() {
		let config = trusted_proxy_config(vec!["127.0.0.0/8"]);
		let application = test_router(config);

		let request = Request::builder()
			.uri("/test")
			.header("Client-Cert", "base64-cert-data")
			.header("Client-Cert-Chain", "base64-chain-data")
			.extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))))
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		assert_eq!(response.status(), StatusCode::OK);

		let body = response.into_body().collect().await.unwrap().to_bytes();
		let text = String::from_utf8(body.to_vec()).unwrap();
		assert_eq!(text, "cert=base64-cert-data,chain=base64-chain-data");
	}

	/// Requests from an untrusted source have identity headers
	/// stripped and no `ClientIdentity` is attached.
	#[tokio::test]
	async fn untrusted_source_strips_headers() {
		let config = trusted_proxy_config(vec!["10.0.0.0/8"]);
		let application = test_router(config);

		let request = Request::builder()
			.uri("/test")
			.header("Client-Cert", "forged-cert")
			.extension(ConnectInfo(SocketAddr::from(([192, 168, 1, 1], 5000))))
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		let body = response.into_body().collect().await.unwrap().to_bytes();
		let text = String::from_utf8(body.to_vec()).unwrap();
		assert_eq!(text, "no-identity");
	}

	/// When no trusted proxies are configured, the middleware is
	/// not added and identity headers pass through unmodified.
	/// This test verifies the middleware correctly strips headers
	/// when the trusted networks list is empty.
	#[tokio::test]
	async fn empty_trusted_proxies_strips_headers() {
		let config = trusted_proxy_config(vec![]);
		let application = test_router(config);

		let request = Request::builder()
			.uri("/test")
			.header("Client-Cert", "should-be-stripped")
			.extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))))
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		let body = response.into_body().collect().await.unwrap().to_bytes();
		let text = String::from_utf8(body.to_vec()).unwrap();
		assert_eq!(text, "no-identity");
	}

	/// A trusted proxy request with only the certificate header
	/// (no chain) still produces a `ClientIdentity`.
	#[tokio::test]
	async fn partial_identity_with_cert_only() {
		let config = trusted_proxy_config(vec!["127.0.0.0/8"]);
		let application = test_router(config);

		let request = Request::builder()
			.uri("/test")
			.header("Client-Cert", "cert-only")
			.extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))))
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		let body = response.into_body().collect().await.unwrap().to_bytes();
		let text = String::from_utf8(body.to_vec()).unwrap();
		assert_eq!(text, "cert=cert-only,chain=none");
	}

	/// A trusted proxy request with no identity headers at all
	/// does not attach a `ClientIdentity`.
	#[tokio::test]
	async fn trusted_proxy_without_identity_headers() {
		let config = trusted_proxy_config(vec!["127.0.0.0/8"]);
		let application = test_router(config);

		let request = Request::builder()
			.uri("/test")
			.extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))))
			.body(Body::empty())
			.unwrap();

		let response = application.oneshot(request).await.unwrap();
		let body = response.into_body().collect().await.unwrap().to_bytes();
		let text = String::from_utf8(body.to_vec()).unwrap();
		assert_eq!(text, "no-identity");
	}

	/// The `is_trusted` method correctly matches IPv4 CIDR ranges.
	#[test]
	fn is_trusted_matches_cidr() {
		let config = TrustedProxyConfig {
			trusted_networks: vec!["10.0.0.0/8".parse().unwrap()],
			identity_headers: ClientIdentityHeaders::default(),
		};

		assert!(config.is_trusted("10.0.0.1".parse().unwrap()));
		assert!(config.is_trusted("10.255.255.255".parse().unwrap()));
		assert!(!config.is_trusted("192.168.1.1".parse().unwrap()));
	}

	/// The `is_trusted` method supports IPv6 CIDR ranges.
	#[test]
	fn is_trusted_matches_ipv6() {
		let config = TrustedProxyConfig {
			trusted_networks: vec!["fd00::/8".parse().unwrap()],
			identity_headers: ClientIdentityHeaders::default(),
		};

		assert!(config.is_trusted("fd00::1".parse().unwrap()));
		assert!(!config.is_trusted("2001:db8::1".parse().unwrap()));
	}
}
