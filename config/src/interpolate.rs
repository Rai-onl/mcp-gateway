//! POSIX-shell-style variable interpolation for configuration
//! values.
//!
//! The gateway lets operators reference values from outside the
//! configuration file inside an allow-list of fields (environment
//! values, HTTP and SSE header values). The substitution syntax
//! mirrors POSIX shell parameter expansion:
//!
//! - `${VAR}` expands to the named variable's value.
//! - `${VAR:-fallback}` expands to the value, or to `fallback` when
//!   the variable is absent or empty.
//! - `$$` is the escape for a literal `$`. So `$${VAR}` produces the
//!   five-character string `${VAR}` because `$$` reduces to a single
//!   `$` and the trailing `{VAR}` is then ordinary text.
//!
//! Interpolation is single-pass: the result of one expansion is not
//! re-scanned for further `${...}` patterns. Without that rule,
//! quoting becomes recursive and operator intent gets ambiguous.

use std::borrow::Cow;
use std::collections::HashMap;

use mcp_gateway_credentials::Secret;

use crate::server::{GatewayConfig, ServerDefinition, Transport};

/// A source of values for interpolation.
///
/// Defined as a trait so the same parser can be exercised against
/// the process environment in production and against an in-memory
/// `HashMap` in tests, without paying for environment lookups in
/// the test path.
pub(crate) trait InterpolationSource {
	fn lookup(&self, name: &str) -> Option<String>;
}

/// Source backed by the gateway process's environment variables.
pub(crate) struct ProcessEnvironment;

impl InterpolationSource for ProcessEnvironment {
	fn lookup(&self, name: &str) -> Option<String> {
		std::env::var(name).ok()
	}
}

/// Source backed by an in-memory map. Used in tests to keep the
/// process environment untouched.
impl InterpolationSource for HashMap<String, String> {
	fn lookup(&self, name: &str) -> Option<String> {
		self.get(name).cloned()
	}
}

/// Interpolate `${VAR}` references in `template` using `source`.
///
/// Returns the original `template` borrow when no `$` is present so
/// the common case allocates nothing.
///
/// # Errors
///
/// Returns [`InterpolationError`] if the template references a
/// variable that the source does not provide and no default is
/// supplied, or if a `${...}` opening is not closed.
pub(crate) fn interpolate<'input>(
	template: &'input str,
	source: &dyn InterpolationSource,
) -> Result<Cow<'input, str>, InterpolationError> {
	if !template.contains('$') {
		return Ok(Cow::Borrowed(template));
	}

	let mut output = String::with_capacity(template.len());
	let mut chars = template.chars().peekable();
	while let Some(character) = chars.next() {
		if character != '$' {
			output.push(character);
			continue;
		}
		match chars.peek() {
			Some('$') => {
				chars.next();
				output.push('$');
			}
			Some('{') => {
				chars.next();
				expand_brace(&mut chars, &mut output, source)?;
			}
			_ => {
				return Err(InterpolationError::Malformed(
					"`$` must be followed by `$` or `{`; a bare `$` is reserved".to_owned(),
				));
			}
		}
	}
	Ok(Cow::Owned(output))
}

/// Consume a `${NAME}` or `${NAME:-default}` expression from the
/// iterator and append the expansion to `output`.
fn expand_brace(
	chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
	output: &mut String,
	source: &dyn InterpolationSource,
) -> Result<(), InterpolationError> {
	let mut variable = String::new();
	let mut default: Option<String> = None;
	let mut closed = false;

	while let Some(character) = chars.next() {
		match character {
			'}' => {
				closed = true;
				break;
			}
			':' if chars.peek() == Some(&'-') => {
				chars.next();
				default = Some(read_default(chars)?);
				closed = true;
				break;
			}
			_ => variable.push(character),
		}
	}

	if !closed {
		return Err(InterpolationError::Malformed(
			"unterminated `${...}` expression".to_owned(),
		));
	}
	if variable.is_empty() {
		return Err(InterpolationError::Malformed(
			"empty variable name in `${...}` expression".to_owned(),
		));
	}

	let resolved = source.lookup(&variable).filter(|value| !value.is_empty());
	let value = match (resolved, default) {
		(Some(actual), _) => actual,
		(None, Some(fallback)) => fallback,
		(None, None) => return Err(InterpolationError::Missing(variable)),
	};
	output.push_str(&value);
	Ok(())
}

/// Read characters up to the closing `}` and return them as the
/// default value for a `${VAR:-default}` expression.
fn read_default(
	chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Result<String, InterpolationError> {
	let mut default = String::new();
	for character in chars.by_ref() {
		if character == '}' {
			return Ok(default);
		}
		default.push(character);
	}
	Err(InterpolationError::Malformed(
		"unterminated default value in `${VAR:-default}` expression".to_owned(),
	))
}

/// Errors from interpolation.
#[derive(Debug, thiserror::Error)]
pub enum InterpolationError {
	/// A referenced variable is not available from the source.
	#[error("variable `{0}` is not set and no default was provided")]
	Missing(String),

	/// The template syntax is invalid.
	#[error("malformed interpolation: {0}")]
	Malformed(String),
}

/// Walk every interpolatable field in a [`GatewayConfig`] and
/// expand `${VAR}` references through `source`.
///
/// The allow-listed fields are environment-variable values for stdio
/// servers and HTTP/SSE header values for remote servers. URLs,
/// commands, command-line arguments, and environment-variable keys
/// are *not* interpolated: those are positional and would invite
/// surprising behaviour if a substitution slipped in.
///
/// On the first failure, returns the failure paired with a JSON
/// pointer-style field path so operators can locate the offending
/// value in the configuration file.
///
/// # Errors
///
/// Returns [`ConfigInterpolationError`] containing the field path
/// and underlying [`InterpolationError`] if any interpolation fails.
pub(crate) fn interpolate_configuration(
	config: &mut GatewayConfig,
	source: &dyn InterpolationSource,
) -> Result<(), ConfigInterpolationError> {
	for (server_name, definition) in &mut config.servers {
		interpolate_server(server_name, definition, source)?;
	}
	Ok(())
}

/// Apply interpolation to one server's allow-listed fields,
/// attaching the server's name to any failure's field path.
fn interpolate_server(
	server_name: &str,
	definition: &mut ServerDefinition,
	source: &dyn InterpolationSource,
) -> Result<(), ConfigInterpolationError> {
	for (key, value) in &mut definition.env {
		expand_secret(value, source).map_err(|error| ConfigInterpolationError {
			field: format!("servers.{server_name}.env.{key}"),
			source: error,
		})?;
	}

	let headers = match &mut definition.transport {
		Transport::Http { headers, .. } => Some(headers),
		#[cfg(feature = "sse")]
		Transport::Sse { headers, .. } => Some(headers),
		Transport::Stdio { .. } => None,
	};

	if let Some(headers) = headers {
		for (key, value) in headers.iter_mut() {
			expand_secret(value, source).map_err(|error| ConfigInterpolationError {
				field: format!("servers.{server_name}.headers.{key}"),
				source: error,
			})?;
		}
	}
	Ok(())
}

/// Expand any `${...}` references inside `secret`, replacing the
/// stored value when the expansion produced new bytes. The original
/// `Secret` is dropped (and zeroized) only when a replacement is
/// installed.
fn expand_secret(
	secret: &mut Secret,
	source: &dyn InterpolationSource,
) -> Result<(), InterpolationError> {
	if !secret.expose().contains('$') {
		return Ok(());
	}
	let expanded = interpolate(secret.expose(), source)?;
	if let Cow::Owned(value) = expanded {
		*secret = Secret::new(value);
	}
	Ok(())
}

/// An interpolation failure attached to a JSON-pointer-style field
/// path inside the configuration. The path lets operators jump
/// straight to the offending value in their configuration file.
#[derive(Debug, thiserror::Error)]
#[error("failed to interpolate {field}: {source}")]
pub struct ConfigInterpolationError {
	/// JSON-pointer-style path inside the configuration document
	/// (for example `servers.alpha.env.API_KEY`).
	pub field: String,
	/// The underlying interpolation error.
	#[source]
	pub source: InterpolationError,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::server::ServerDefinition;

	/// Build an in-memory interpolation source from a slice of
	/// `(name, value)` pairs. Used in place of the process
	/// environment so each test controls exactly which variables are
	/// available without mutating real environment state.
	fn source(entries: &[(&str, &str)]) -> HashMap<String, String> {
		entries
			.iter()
			.map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
			.collect()
	}

	/// A template without `$` characters is returned as a borrowed
	/// reference into the original input, with no allocation.
	#[test]
	fn templates_without_dollar_are_borrowed_unchanged() {
		let env = HashMap::new();
		let result = interpolate("plain string with no markers", &env).unwrap();
		assert_eq!(result, "plain string with no markers");
		assert!(matches!(result, Cow::Borrowed(_)));
	}

	/// A `${VAR}` reference expands to the source's value.
	#[test]
	fn expands_simple_variable() {
		let env = source(&[("HOST", "example.com")]);
		let result = interpolate("https://${HOST}/path", &env).unwrap();
		assert_eq!(result, "https://example.com/path");
	}

	/// Multiple references in one template all expand.
	#[test]
	fn expands_multiple_variables() {
		let env = source(&[("USER", "alice"), ("HOST", "example.com")]);
		let result = interpolate("user=${USER}, host=${HOST}", &env).unwrap();
		assert_eq!(result, "user=alice, host=example.com");
	}

	/// `${VAR:-default}` falls back when the variable is absent.
	#[test]
	fn default_fallback_used_when_variable_absent() {
		let env = HashMap::new();
		let result = interpolate("${MISSING:-fallback}", &env).unwrap();
		assert_eq!(result, "fallback");
	}

	/// `${VAR:-default}` falls back when the variable is set to an
	/// empty string. Empty environment values are treated as absent.
	#[test]
	fn default_fallback_used_when_variable_is_empty() {
		let env = source(&[("EMPTY", "")]);
		let result = interpolate("${EMPTY:-fallback}", &env).unwrap();
		assert_eq!(result, "fallback");
	}

	/// A set non-empty variable wins over its default.
	#[test]
	fn set_variable_takes_precedence_over_default() {
		let env = source(&[("SET", "actual")]);
		let result = interpolate("${SET:-fallback}", &env).unwrap();
		assert_eq!(result, "actual");
	}

	/// `$$` produces a single literal `$`. Combined with subsequent
	/// `{VAR}` text, `$${VAR}` therefore produces `${VAR}` literally.
	#[test]
	fn double_dollar_escapes_to_literal_dollar() {
		let env = source(&[("VAR", "should-not-appear")]);
		let result = interpolate("price: $$50; literal: $${VAR}", &env).unwrap();
		assert_eq!(result, "price: $50; literal: ${VAR}");
	}

	/// A reference to an unset variable without a default fails with
	/// the variable name in the error.
	#[test]
	fn missing_variable_returns_named_error() {
		let env = HashMap::new();
		let outcome = interpolate("hello ${ABSENT}", &env);
		match outcome {
			Err(InterpolationError::Missing(name)) => assert_eq!(name, "ABSENT"),
			other => panic!("expected Missing error, got {other:?}"),
		}
	}

	/// An unterminated `${...}` expression fails at parse time.
	#[test]
	fn unterminated_expression_fails() {
		let env = HashMap::new();
		let outcome = interpolate("hello ${UNCLOSED", &env);
		assert!(matches!(outcome, Err(InterpolationError::Malformed(_))));
	}

	/// An empty variable name (`${}`) fails at parse time.
	#[test]
	fn empty_variable_name_fails() {
		let env = HashMap::new();
		let outcome = interpolate("oops ${}", &env);
		assert!(matches!(outcome, Err(InterpolationError::Malformed(_))));
	}

	/// A bare `$` not followed by `$` or `{` is a syntax error.
	/// Operators wanting a literal `$` must double it.
	#[test]
	fn bare_dollar_is_rejected() {
		let env = HashMap::new();
		let outcome = interpolate("price: $50", &env);
		assert!(matches!(outcome, Err(InterpolationError::Malformed(_))));
	}

	/// Build an HTTP-transport `ServerDefinition` whose `headers`
	/// map is pre-populated with the given key/value pairs wrapped
	/// in `Secret`. Used by interpolation tests that exercise the
	/// header-expansion path.
	fn http_server(headers: &[(&str, &str)]) -> ServerDefinition {
		let mut header_map = HashMap::new();
		for (key, value) in headers {
			header_map.insert((*key).to_owned(), Secret::new((*value).to_owned()));
		}
		ServerDefinition {
			enabled: true,
			env: HashMap::new(),
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Http {
				url: "https://upstream.invalid/mcp/".to_owned(),
				headers: header_map,
			},
		}
	}

	/// Build a stdio-transport `ServerDefinition` whose `env` map is
	/// pre-populated with the given key/value pairs wrapped in
	/// `Secret`. Used by interpolation tests that exercise the
	/// env-expansion path.
	fn stdio_server(env: &[(&str, &str)]) -> ServerDefinition {
		let mut env_map = HashMap::new();
		for (key, value) in env {
			env_map.insert((*key).to_owned(), Secret::new((*value).to_owned()));
		}
		ServerDefinition {
			enabled: true,
			env: env_map,
			credential: None,
			credential_header: None,
			credential_prefix: None,
			request_timeout_seconds: None,
			credential_injection: None,
			transport: Transport::Stdio {
				command: "/usr/bin/example".to_owned(),
				args: vec![],
			},
		}
	}

	/// `interpolate_configuration` expands references in stdio env
	/// values.
	#[test]
	fn configuration_interpolation_expands_env_values() {
		let mut config = GatewayConfig::default();
		config
			.servers
			.insert("alpha".to_owned(), stdio_server(&[("API_KEY", "${TOKEN}")]));
		let env = source(&[("TOKEN", "secret-value")]);

		interpolate_configuration(&mut config, &env).expect("interpolation succeeds");

		let alpha = &config.servers["alpha"];
		assert_eq!(
			alpha.env.get("API_KEY").map(Secret::expose),
			Some("secret-value")
		);
	}

	/// `interpolate_configuration` expands references in HTTP header
	/// values.
	#[test]
	fn configuration_interpolation_expands_header_values() {
		let mut config = GatewayConfig::default();
		config
			.servers
			.insert("beta".to_owned(), http_server(&[("X-Region", "${REGION}")]));
		let env = source(&[("REGION", "eu-west-1")]);

		interpolate_configuration(&mut config, &env).expect("interpolation succeeds");

		let Transport::Http { headers, .. } = &config.servers["beta"].transport else {
			panic!("expected HTTP transport");
		};
		assert_eq!(
			headers.get("X-Region").map(Secret::expose),
			Some("eu-west-1")
		);
	}

	/// Field paths in interpolation errors are JSON-pointer-style
	/// so operators can locate the offending value in the config
	/// file.
	#[test]
	fn missing_variable_error_carries_field_path() {
		let mut config = GatewayConfig::default();
		config.servers.insert(
			"gamma".to_owned(),
			stdio_server(&[("API_KEY", "${MISSING}")]),
		);
		let env: HashMap<String, String> = HashMap::new();

		let error =
			interpolate_configuration(&mut config, &env).expect_err("missing variable must error");
		assert_eq!(error.field, "servers.gamma.env.API_KEY");
		assert!(matches!(error.source, InterpolationError::Missing(name) if name == "MISSING"));
	}

	/// URLs and commands are *not* interpolated: they're positional
	/// and accidental substitution would be a surprise.
	#[test]
	fn urls_and_commands_are_not_interpolated() {
		let mut config = GatewayConfig::default();
		config.servers.insert(
			"delta".to_owned(),
			ServerDefinition {
				enabled: true,
				env: HashMap::new(),
				credential: None,
				credential_header: None,
				credential_prefix: None,
				request_timeout_seconds: None,
				credential_injection: None,
				transport: Transport::Http {
					url: "https://${HOST}/path".to_owned(),
					headers: HashMap::new(),
				},
			},
		);
		let env = source(&[("HOST", "should-not-substitute")]);

		interpolate_configuration(&mut config, &env)
			.expect("URLs left alone, no interpolation invoked");

		let Transport::Http { url, .. } = &config.servers["delta"].transport else {
			panic!("expected HTTP transport");
		};
		assert_eq!(url, "https://${HOST}/path");
	}
}
