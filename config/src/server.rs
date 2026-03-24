//! MCP server definition types.
//!
//! Each server in the gateway configuration has a transport type
//! that determines how the gateway connects to it. The transport
//! field acts as a tagged-union discriminator — transport-specific
//! fields are only valid for their respective transport type.

use std::collections::HashMap;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Top-level gateway configuration loaded from a JSON file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewayConfig {
	/// Named server definitions keyed by server name.
	#[serde(default)]
	pub servers: HashMap<String, ServerDefinition>,

	/// CIDR ranges of trusted reverse proxies.
	///
	/// When a request arrives from an address within one of these
	/// ranges, the gateway reads client identity from forwarded
	/// headers (see `client_identity_headers`). Requests from
	/// untrusted sources have identity headers stripped to prevent
	/// forgery.
	///
	/// If absent or empty, forwarded identity headers are ignored
	/// on all requests (safe default).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub trusted_proxies: Vec<IpNet>,

	/// Header names carrying client identity forwarded by a
	/// trusted reverse proxy.
	///
	/// Defaults align with RFC 9440 (`Client-Cert`). Only read
	/// when the request originates from a `trusted_proxies` address.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub client_identity_headers: Option<ClientIdentityHeaders>,

	/// Maximum request body size in bytes for the MCP endpoint.
	///
	/// Requests exceeding this limit are rejected before parsing.
	/// Defaults to 4 MiB (4,194,304 bytes) if not specified.
	#[serde(default = "default_max_body_bytes")]
	pub max_body_bytes: usize,
}

/// Default maximum body size: 4 MiB.
const fn default_max_body_bytes() -> usize {
	4 * 1024 * 1024
}

impl Default for GatewayConfig {
	fn default() -> Self {
		Self {
			servers: HashMap::new(),
			trusted_proxies: Vec::new(),
			client_identity_headers: None,
			max_body_bytes: default_max_body_bytes(),
		}
	}
}

/// Header names for client identity forwarded by a reverse proxy.
///
/// These headers are only trusted when the request arrives from an
/// address listed in `trusted_proxies`. The defaults follow RFC 9440.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientIdentityHeaders {
	/// Header carrying the client certificate (RFC 9440).
	/// Defaults to `Client-Cert`.
	#[serde(default = "default_client_cert_header")]
	pub certificate: String,

	/// Header carrying the certificate chain (RFC 9440).
	/// Defaults to `Client-Cert-Chain`.
	#[serde(default = "default_client_cert_chain_header")]
	pub certificate_chain: String,
}

impl Default for ClientIdentityHeaders {
	fn default() -> Self {
		Self {
			certificate: default_client_cert_header(),
			certificate_chain: default_client_cert_chain_header(),
		}
	}
}

fn default_client_cert_header() -> String {
	"Client-Cert".to_owned()
}

fn default_client_cert_chain_header() -> String {
	"Client-Cert-Chain".to_owned()
}

/// A single MCP server definition.
///
/// Shared fields (`enabled`, `env`, `credential`) apply to all
/// transport types. Transport-specific fields are carried by the
/// `Transport` enum variants, making invalid combinations
/// unrepresentable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerDefinition {
	/// Whether this server is active. Disabled servers are
	/// preserved in configuration but not started by the gateway.
	#[serde(default = "default_true")]
	pub enabled: bool,

	/// Environment variables injected into stdio server processes.
	#[serde(default, skip_serializing_if = "HashMap::is_empty")]
	pub env: HashMap<String, String>,

	/// Named credential resolved via the credential provider chain.
	///
	/// The name is looked up through command helpers, credential
	/// files, and environment variables. The resolved value is
	/// injected into the server's runtime by the gateway:
	///
	/// - **HTTP servers**: injected as a request header (see
	///   `credential_header` and `credential_prefix`)
	/// - **Stdio servers**: injected as the `MCP_CREDENTIAL`
	///   environment variable on the child process
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub credential: Option<String>,

	/// HTTP header name for credential injection on HTTP servers.
	/// Defaults to `Authorization` when a credential is set.
	/// Ignored for stdio servers.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub credential_header: Option<String>,

	/// Value prefix prepended to the credential value when
	/// injecting into HTTP headers. Defaults to `Bearer `.
	/// Ignored for stdio servers.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub credential_prefix: Option<String>,

	/// Transport-specific connection configuration.
	#[serde(flatten)]
	pub transport: Transport,
}

impl ServerDefinition {
	/// The HTTP header name to use for credential injection.
	/// Returns `Authorization` if not explicitly configured.
	#[must_use]
	pub fn resolved_credential_header(&self) -> &str {
		self.credential_header.as_deref().unwrap_or("Authorization")
	}

	/// The prefix prepended to the credential value in HTTP headers.
	/// Returns `Bearer ` if not explicitly configured.
	#[must_use]
	pub fn resolved_credential_prefix(&self) -> &str {
		self.credential_prefix.as_deref().unwrap_or("Bearer ")
	}
}

/// Transport-specific connection configuration.
///
/// The `transport` field in JSON acts as the discriminator.
/// Each variant carries only the fields relevant to that
/// transport type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "transport", rename_all = "lowercase")]
pub enum Transport {
	/// Spawn a local child process communicating via stdin/stdout.
	Stdio {
		/// Path to the MCP server binary or script.
		command: String,

		/// Command-line arguments appended after the command.
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		args: Vec<String>,
	},

	/// Forward requests to a remote MCP server over HTTP.
	Http {
		/// The full endpoint URL including protocol and path.
		url: String,

		/// HTTP headers sent with each request. Values may contain
		/// `${VAR}` placeholders resolved at runtime.
		#[serde(default, skip_serializing_if = "HashMap::is_empty")]
		headers: HashMap<String, String>,
	},

	/// Connect to a remote MCP server via the legacy HTTP+SSE
	/// transport. Requires the `sse` feature flag.
	#[cfg(feature = "sse")]
	#[serde(rename = "sse")]
	Sse {
		/// The SSE endpoint URL for the initial event stream.
		url: String,

		/// HTTP headers sent with both the SSE connection and
		/// POST requests to the message endpoint.
		#[serde(default, skip_serializing_if = "HashMap::is_empty")]
		headers: HashMap<String, String>,
	},
}

const fn default_true() -> bool {
	true
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A stdio server definition deserialises with the command
	/// and transport fields correctly populated.
	#[test]
	fn stdio_definition_deserialises() {
		let json = r#"{
			"transport": "stdio",
			"command": "/usr/local/bin/mcp-server",
			"args": ["--root", "/data"]
		}"#;
		let def: ServerDefinition = serde_json::from_str(json).unwrap();
		assert!(def.enabled);
		assert!(matches!(
			def.transport,
			Transport::Stdio { ref command, ref args }
			if command == "/usr/local/bin/mcp-server" && args.len() == 2
		));
	}

	/// An HTTP server definition deserialises with the URL and
	/// headers correctly populated.
	#[test]
	fn http_definition_deserialises() {
		let json = r#"{
			"transport": "http",
			"url": "https://api.example.com/mcp/",
			"headers": {
				"Authorization": "Bearer ${API_TOKEN}"
			}
		}"#;
		let def: ServerDefinition = serde_json::from_str(json).unwrap();
		assert!(def.enabled);
		assert!(matches!(
			def.transport,
			Transport::Http { ref url, ref headers }
			if url == "https://api.example.com/mcp/"
				&& headers.get("Authorization").map(String::as_str)
					== Some("Bearer ${API_TOKEN}")
		));
	}

	/// The `enabled` field defaults to true when omitted, since
	/// most servers should be active after registration.
	#[test]
	fn enabled_defaults_to_true() {
		let json = r#"{"transport": "stdio", "command": "cat"}"#;
		let def: ServerDefinition = serde_json::from_str(json).unwrap();
		assert!(def.enabled);
	}

	/// An explicitly disabled server preserves its state through
	/// serialisation round-trips.
	#[test]
	fn disabled_server_round_trips() {
		let json = r#"{"transport": "stdio", "command": "cat", "enabled": false}"#;
		let def: ServerDefinition = serde_json::from_str(json).unwrap();
		assert!(!def.enabled);

		let serialised = serde_json::to_string(&def).unwrap();
		let reloaded: ServerDefinition = serde_json::from_str(&serialised).unwrap();
		assert!(!reloaded.enabled);
	}

	/// Environment variables on a stdio definition survive
	/// serialisation round-trips.
	#[test]
	fn env_vars_round_trip() {
		let json = r#"{
			"transport": "stdio",
			"command": "server",
			"env": {"LOG_LEVEL": "debug", "API_KEY": "${SECRET}"}
		}"#;
		let def: ServerDefinition = serde_json::from_str(json).unwrap();
		assert_eq!(def.env.get("LOG_LEVEL").map(String::as_str), Some("debug"));
		assert_eq!(
			def.env.get("API_KEY").map(String::as_str),
			Some("${SECRET}")
		);

		let serialised = serde_json::to_string(&def).unwrap();
		let reloaded: ServerDefinition = serde_json::from_str(&serialised).unwrap();
		assert_eq!(reloaded.env, def.env);
	}

	/// A full gateway configuration with multiple servers
	/// deserialises correctly from JSON.
	#[test]
	fn gateway_config_deserialises() {
		let json = r#"{
			"servers": {
				"filesystem": {
					"transport": "stdio",
					"command": "/usr/local/bin/mcp-filesystem",
					"args": ["--root", "/data"]
				},
				"remote-tools": {
					"transport": "http",
					"url": "https://api.example.com/mcp/",
					"headers": {
						"Authorization": "Bearer ${API_TOKEN}"
					}
				}
			}
		}"#;
		let config: GatewayConfig = serde_json::from_str(json).unwrap();
		assert_eq!(config.servers.len(), 2);
		assert!(config.servers.contains_key("filesystem"));
		assert!(config.servers.contains_key("remote-tools"));
	}

	/// An empty servers map is valid — the gateway starts with
	/// no configured servers.
	#[test]
	fn empty_config_is_valid() {
		let json = r#"{"servers": {}}"#;
		let config: GatewayConfig = serde_json::from_str(json).unwrap();
		assert!(config.servers.is_empty());
	}

	/// A missing servers key defaults to an empty map.
	#[test]
	fn missing_servers_defaults_to_empty() {
		let json = r"{}";
		let config: GatewayConfig = serde_json::from_str(json).unwrap();
		assert!(config.servers.is_empty());
	}

	/// A stdio definition without a command is a deserialisation
	/// error — command is required for stdio transport.
	#[test]
	fn stdio_without_command_fails() {
		let json = r#"{"transport": "stdio"}"#;
		let result = serde_json::from_str::<ServerDefinition>(json);
		assert!(result.is_err());
	}

	/// An HTTP definition without a URL is a deserialisation
	/// error — url is required for HTTP transport.
	#[test]
	fn http_without_url_fails() {
		let json = r#"{"transport": "http"}"#;
		let result = serde_json::from_str::<ServerDefinition>(json);
		assert!(result.is_err());
	}

	/// An unknown transport type is a deserialisation error.
	#[test]
	fn unknown_transport_fails() {
		let json = r#"{"transport": "grpc", "url": "localhost:50051"}"#;
		let result = serde_json::from_str::<ServerDefinition>(json);
		assert!(result.is_err());
	}

	/// A credential name is optional — servers without credentials
	/// deserialise without one.
	#[test]
	fn credential_is_optional() {
		let json = r#"{"transport": "stdio", "command": "cat"}"#;
		let definition: ServerDefinition = serde_json::from_str(json).unwrap();
		assert!(definition.credential.is_none());
	}

	/// A credential name is preserved through deserialisation.
	#[test]
	fn credential_name_deserialises() {
		let json = r#"{
			"transport": "http",
			"url": "https://api.example.com/mcp/",
			"credential": "github-token"
		}"#;
		let definition: ServerDefinition = serde_json::from_str(json).unwrap();
		assert_eq!(definition.credential.as_deref(), Some("github-token"));
	}

	/// Credential header and prefix default to Authorization
	/// and Bearer when not specified.
	#[test]
	fn credential_header_defaults() {
		let json = r#"{
			"transport": "http",
			"url": "https://api.example.com/mcp/",
			"credential": "my-token"
		}"#;
		let definition: ServerDefinition = serde_json::from_str(json).unwrap();
		assert_eq!(definition.resolved_credential_header(), "Authorization");
		assert_eq!(definition.resolved_credential_prefix(), "Bearer ");
	}

	/// Custom credential header and prefix override the defaults.
	#[test]
	fn custom_credential_header_and_prefix() {
		let json = r#"{
			"transport": "http",
			"url": "https://api.example.com/mcp/",
			"credential": "api-key",
			"credential_header": "X-Api-Key",
			"credential_prefix": ""
		}"#;
		let definition: ServerDefinition = serde_json::from_str(json).unwrap();
		assert_eq!(definition.resolved_credential_header(), "X-Api-Key");
		assert_eq!(definition.resolved_credential_prefix(), "");
	}

	/// Trusted proxies deserialise from CIDR notation strings.
	#[test]
	fn trusted_proxies_deserialise() {
		let json = r#"{
			"trusted_proxies": ["10.0.0.0/8", "172.16.0.0/12"],
			"servers": {}
		}"#;
		let config: GatewayConfig = serde_json::from_str(json).unwrap();
		assert_eq!(config.trusted_proxies.len(), 2);
	}

	/// Missing trusted proxies defaults to an empty list.
	#[test]
	fn missing_trusted_proxies_defaults_to_empty() {
		let json = r#"{"servers": {}}"#;
		let config: GatewayConfig = serde_json::from_str(json).unwrap();
		assert!(config.trusted_proxies.is_empty());
	}

	/// Client identity headers deserialise with custom values.
	#[test]
	fn custom_client_identity_headers() {
		let json = r#"{
			"trusted_proxies": ["10.0.0.0/8"],
			"client_identity_headers": {
				"certificate": "Forwarded-Client-Cert",
				"certificate_chain": "Forwarded-Client-Chain"
			},
			"servers": {}
		}"#;
		let config: GatewayConfig = serde_json::from_str(json).unwrap();
		let headers = config.client_identity_headers.unwrap();
		assert_eq!(headers.certificate, "Forwarded-Client-Cert");
		assert_eq!(headers.certificate_chain, "Forwarded-Client-Chain");
	}

	/// Client identity headers default to RFC 9440 values.
	#[test]
	fn client_identity_headers_default_to_rfc_9440() {
		let headers = ClientIdentityHeaders::default();
		assert_eq!(headers.certificate, "Client-Cert");
		assert_eq!(headers.certificate_chain, "Client-Cert-Chain");
	}
}
