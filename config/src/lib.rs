//! Server definition types and configuration loading.
//!
//! The gateway loads its configuration from a JSON file that
//! describes the MCP servers it manages. Each server has a
//! transport type (stdio or HTTP) with transport-specific fields
//! enforced by a tagged-union model: invalid combinations are
//! unrepresentable.

pub mod authentication;
mod interpolate;
mod resolve;
mod server;
mod validate;

pub use authentication::{
	AuthenticationConfig, CorsConfig, IntrospectionOutagePolicy, IssuerConfig, TrustAnchorsConfig,
	ValidationStrategy,
};
pub use interpolate::{ConfigInterpolationError, InterpolationError};
pub use resolve::{CredentialResolutionError, resolve_credentials};
pub use server::{
	ClientIdentityHeaders, CredentialInjection, GatewayConfig, OAuthCredential, ServerDefinition,
	Transport,
};
pub use validate::validate;

/// Load a gateway configuration from a JSON file at the given path.
///
/// After parsing, every interpolatable field (environment values,
/// HTTP and SSE header values) has its `${VAR}` references expanded
/// from the gateway process's environment. URLs, commands, and
/// command-line arguments are not interpolated. A reference to a
/// variable that is not set (and not given a `${VAR:-default}`)
/// fails the load.
///
/// # Errors
///
/// Returns [`ConfigError`] if the file cannot be read, the JSON is
/// invalid, the configuration does not conform to the schema, or an
/// interpolation reference cannot be resolved.
pub fn load(path: &std::path::Path) -> Result<GatewayConfig, ConfigError> {
	let contents = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
	let mut config: GatewayConfig = serde_json::from_str(&contents).map_err(ConfigError::Parse)?;
	interpolate::interpolate_configuration(&mut config, &interpolate::ProcessEnvironment)
		.map_err(ConfigError::Interpolation)?;
	Ok(config)
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

	/// A `${VAR}` reference inside an interpolatable field could
	/// not be expanded, typically because the variable is not set
	/// in the process environment and the reference does not
	/// supply a `${VAR:-default}` fallback.
	#[error(transparent)]
	Interpolation(#[from] ConfigInterpolationError),
}
