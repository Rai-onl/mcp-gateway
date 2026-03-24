//! Server definition types and configuration loading.
//!
//! The gateway loads its configuration from a JSON file that
//! describes the MCP servers it manages. Each server has a
//! transport type (stdio or HTTP) with transport-specific fields
//! enforced by a tagged-union model — invalid combinations are
//! unrepresentable.

mod resolve;
mod server;
mod validate;

pub use resolve::{CredentialResolutionError, CredentialResolver, resolve_credentials};
pub use server::{ClientIdentityHeaders, GatewayConfig, ServerDefinition, Transport};
pub use validate::validate;

/// Load a gateway configuration from a JSON file at the given path.
///
/// # Errors
///
/// Returns an error if the file cannot be read or the JSON is
/// invalid or does not conform to the configuration schema.
pub fn load(path: &std::path::Path) -> Result<GatewayConfig, ConfigError> {
	let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
	serde_json::from_str(&contents).map_err(ConfigError::Parse)
}

/// Errors that can occur when loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	/// The configuration file could not be read.
	#[error("failed to read configuration file: {0}")]
	Io(#[from] std::io::Error),

	/// The configuration file contains invalid JSON or does not
	/// conform to the expected schema.
	#[error("failed to parse configuration: {0}")]
	Parse(#[from] serde_json::Error),
}
