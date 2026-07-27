//! Authentication middleware.
//!
//! Mounted on the routes that require a bearer token, the middleware
//! dispatches on the `Authorization` scheme, validates a `Bearer`
//! token through the [`JwtValidator`], attaches the resulting
//! [`ValidatedClaims`] to the request, and rejects anything else with
//! an RFC 6750 challenge. A `pre_dispatch` seam runs after validation
//! and before the handler, enforcing per-server scope authorisation;
//! it is the extension point future per-tool scope work composes onto.

use axum::Json;
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::authorise::ScopePolicy;
use crate::challenge::{BearerChallenge, TokenError};
use crate::claims::ValidatedClaims;
use crate::strategy::Validator;
use crate::validator::FailureReason;

/// Shared state the authentication middleware needs: the validator, the
/// values it builds challenges from, and the per-server scope policy.
pub struct AuthState {
	/// The validator every bearer token is checked against, under the
	/// configured strategy.
	validator: Validator,
	/// The protection-space realm, the instance's resource identifier.
	realm: String,
	/// The protected-resource-metadata URL challenges point clients at.
	resource_metadata_url: String,
	/// The per-server scope policy the `pre_dispatch` seam enforces.
	scope_policy: ScopePolicy,
}

impl AuthState {
	/// Construct the middleware state.
	#[must_use]
	pub fn new(
		validator: Validator,
		realm: impl Into<String>,
		resource_metadata_url: impl Into<String>,
		scope_policy: ScopePolicy,
	) -> Self {
		Self {
			validator,
			realm: realm.into(),
			resource_metadata_url: resource_metadata_url.into(),
			scope_policy,
		}
	}

	/// Proactively refresh the validator's cached signing keys.
	///
	/// Called by the daemon's background-refresh timer on the configured
	/// cadence. Delegates to the validation strategy: JWT validation
	/// re-fetches the JWKS, introspection is a no-op. Failures are logged
	/// and the last-good keys retained, so this is safe to call
	/// fire-and-forget.
	pub async fn refresh_keys(&self) {
		self.validator.refresh_keys().await;
	}

	/// The per-request authorisation seam, run after the token
	/// validates and before the handler.
	///
	/// For a `POST /servers/{name}/mcp` route it enforces the scope
	/// policy: the token must hold a scope the named server requires.
	/// Routes that do not address a server (the server-card endpoint)
	/// carry no per-server scope and pass. The matched scope is
	/// recorded for audit on success, the reason on rejection.
	///
	/// It is the extension point future per-tool scope work composes
	/// onto by chaining further checks.
	///
	/// # Errors
	///
	/// Returns [`AuthError`] when the token holds no scope the route's
	/// server requires.
	pub fn pre_dispatch(&self, claims: &ValidatedClaims, route: &str) -> Result<(), AuthError> {
		let Some(server) = server_from_route(route) else {
			return Ok(());
		};
		match self.scope_policy.authorise(server, claims.scopes()) {
			Ok(matched) => {
				tracing::debug!(auth.matched_scope = %matched, server, "request authorised by scope");
				Ok(())
			}
			Err(rejection) => {
				tracing::warn!(
					auth.reject_reason = rejection.reason(),
					server,
					"request rejected: the token lacks a scope this server requires"
				);
				Err(AuthError {
					description: format!("a scope authorising server '{server}' is required"),
				})
			}
		}
	}
}

/// Extract the server name from a `/servers/{name}/mcp` route path.
/// Returns `None` for any other route, which then carries no
/// per-server scope requirement.
fn server_from_route(route: &str) -> Option<&str> {
	route
		.strip_prefix("/servers/")
		.and_then(|rest| rest.split('/').next())
		.filter(|server| !server.is_empty())
}

/// A denial raised by the `pre_dispatch` seam after a token validated:
/// the token is authentic but not authorised for this route. Renders
/// as a 403 `insufficient_scope` challenge.
#[derive(Debug, Clone)]
pub struct AuthError {
	/// Human-readable reason, surfaced in the challenge description.
	description: String,
}

/// Authentication middleware: validate the bearer token, attach the
/// claims, and run the next layer, or reject with a challenge.
///
/// Takes the [`AuthState`] by reference rather than through an axum
/// `State` extractor so the daemon can load the current state from its
/// reload-swappable holder per request and delegate here.
pub async fn authenticate(state: &AuthState, mut request: Request, next: Next) -> Response {
	let route = request.uri().path().to_owned();

	let header_value = request
		.headers()
		.get(header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok());

	// No credentials, or a scheme other than Bearer: a bare challenge
	// advertising Bearer, with no `error` (RFC 6750 §3 reserves
	// `error` for a token that was supplied and rejected).
	let Some(header_value) = header_value else {
		return unauthorized(state, None);
	};
	let scheme = header_value.split(' ').next().unwrap_or_default();
	if !scheme.eq_ignore_ascii_case("Bearer") {
		return unauthorized(state, None);
	}

	match state.validator.validate(header_value).await {
		Ok(claims) => {
			if let Err(error) = state.pre_dispatch(&claims, &route) {
				return forbidden(state, &error.description);
			}
			request.extensions_mut().insert(claims);
			next.run(request).await
		}
		Err(reason) => reject(state, reason),
	}
}

/// Map a validation failure to a challenge response: an authentic but
/// unauthorised principal is a 403 `insufficient_scope`; everything
/// else is a 401 `invalid_token`.
fn reject(state: &AuthState, reason: FailureReason) -> Response {
	match reason {
		FailureReason::UnknownPrincipal | FailureReason::MissingScope => {
			forbidden(state, reason_description(reason))
		}
		_ => unauthorized(state, Some(reason_description(reason))),
	}
}

/// A short, claim-free description for a failure reason, safe to place
/// in a challenge `error_description`.
fn reason_description(reason: FailureReason) -> &'static str {
	match reason {
		FailureReason::MissingToken => "no bearer token was supplied",
		FailureReason::MalformedToken => "the token is not a well-formed JWT",
		FailureReason::InvalidSignature => "the token signature did not verify",
		FailureReason::InvalidAlgorithm => "the token algorithm is not accepted",
		FailureReason::InvalidIssuer => "the token issuer is not recognised",
		FailureReason::InvalidAudience => "the token audience does not bind to this resource",
		FailureReason::Expired => "the access token expired",
		FailureReason::NotYetValid => "the token is not yet valid",
		FailureReason::UnknownPrincipal => "the token principal is not permitted",
		FailureReason::MissingScope => "the token lacks the required scope",
		FailureReason::KidNotPinned => "the signing key is not pinned",
		FailureReason::Inactive => "the token is not active",
	}
}

/// Build a 401 `invalid_token` challenge response, optionally carrying
/// an error description (absent for the missing-credentials case).
fn unauthorized(state: &AuthState, error_description: Option<&str>) -> Response {
	let mut challenge = BearerChallenge::new(&state.realm, &state.resource_metadata_url);
	if let Some(description) = error_description {
		challenge = challenge.with_error(TokenError::InvalidToken, description);
	}
	challenge_response(StatusCode::UNAUTHORIZED, challenge, "Unauthorized")
}

/// Build a 403 `insufficient_scope` challenge response.
fn forbidden(state: &AuthState, description: &str) -> Response {
	let challenge = BearerChallenge::new(&state.realm, &state.resource_metadata_url)
		.with_error(TokenError::InsufficientScope, description);
	challenge_response(StatusCode::FORBIDDEN, challenge, "Forbidden")
}

/// Assemble a challenge response: the status, a JSON-RPC error body for
/// parity with the gateway's other error responses, and the
/// `WWW-Authenticate` header.
fn challenge_response(status: StatusCode, challenge: BearerChallenge, message: &str) -> Response {
	let body = serde_json::json!({
		"jsonrpc": "2.0",
		"error": { "code": -32001, "message": message },
		"id": null,
	});
	let mut response = (status, Json(body)).into_response();
	if let Ok(header_value) = challenge.into_header_value().parse() {
		response
			.headers_mut()
			.insert(header::WWW_AUTHENTICATE, header_value);
	}
	response
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The server name is extracted from a `/servers/{name}/mcp` route,
	/// and any other route yields `None` (no per-server scope gate).
	#[test]
	fn server_is_extracted_from_servers_route() {
		assert_eq!(server_from_route("/servers/gitlab/mcp"), Some("gitlab"));
		assert_eq!(server_from_route("/.well-known/mcp-server-card"), None);
		assert_eq!(server_from_route("/health"), None);
		assert_eq!(server_from_route("/servers//mcp"), None);
	}

	/// An unknown principal renders as a 403 `insufficient_scope`
	/// challenge, distinguishing an authentic-but-unauthorised token
	/// from an unauthenticated one.
	#[test]
	fn unknown_principal_maps_to_insufficient_scope() {
		let description = reason_description(FailureReason::UnknownPrincipal);
		assert_eq!(description, "the token principal is not permitted");
	}
}
