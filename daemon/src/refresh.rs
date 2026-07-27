//! Background refresh of inbound-authentication state.
//!
//! Two loops keep the validator current ahead of expiry, complementing
//! the lazy and operator-triggered refresh paths:
//!
//! - [`run_key_refresh`] re-fetches the JWKS on the `jwks_cache_seconds`
//!   cadence, so a routine key rotation is picked up before any token
//!   needs the new key, rather than only on the lazy refresh-on-unknown-
//!   `kid` path.
//! - [`run_discovery_refresh`] re-fetches the discovery document on the
//!   `discovery_cache_seconds` cadence and rebuilds the validator when it
//!   changes, rather than only at startup or on a `SIGHUP` reload.
//!
//! Both read the live configuration and reload-swappable auth state fresh
//! each tick, so a validator (and the principals and scopes it enforces)
//! replaced by a reload is followed from the next tick onward, and a
//! discovery change never reverts a reload.

use std::sync::Arc;
use std::time::Duration;

use mcp_gateway_auth::discovery::DiscoveryDocument;
use mcp_gateway_auth::setup::{assemble_auth_state, fetch_discovery};

use crate::server::AppState;

/// Run the background key-refresh loop until the task is cancelled.
///
/// Every `interval`, the current auth state's signing keys are refreshed.
/// A refresh failure is swallowed by the validator (the last-good keys are
/// retained and the failure logged), so a transient authorisation-server
/// outage does not break the loop. When no auth state is installed (the
/// gateway runs without inbound authentication) the tick is a no-op.
///
/// The first immediate tick of the interval is consumed before the loop
/// body, so the first refresh happens one full `interval` after startup:
/// the startup fetch has just populated the cache, so there is nothing to
/// refresh yet.
pub async fn run_key_refresh(state: Arc<AppState>, interval: Duration) {
	let mut ticker = tokio::time::interval(interval);
	// Skip, not burst: if a refresh runs longer than the interval (a slow
	// authorisation server), do not fire the missed ticks back-to-back on
	// recovery and flood it.
	ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	ticker.tick().await;
	loop {
		ticker.tick().await;
		if let Some(auth) = state.auth() {
			auth.refresh_keys().await;
		}
	}
}

/// Run the background discovery-refresh loop until the task is cancelled.
///
/// Every `interval`, the discovery document is re-fetched, using the live
/// authentication configuration so a reload that changed the issuer or
/// trust anchors is honoured. When the fetched document differs from the
/// one the loop last applied, the validator is rebuilt and swapped into
/// `state`, so a change at the authorisation server (a new JWKS endpoint,
/// an introspection endpoint appearing) is adopted without an
/// operator-triggered reload. An unchanged document is a no-op, and a
/// failed fetch keeps the current validator.
///
/// The rebuild reads the live configuration and runs under
/// [`AppState::lock_auth_rebuild`], so it rebuilds from the post-reload
/// principals and scopes and cannot revert a reload that ran alongside
/// it. The first successful fetch establishes the baseline rather than
/// rebuilding, since it should match what startup built from; a change
/// observed on a later tick triggers the rebuild. As with
/// [`run_key_refresh`], the first immediate tick is consumed so the first
/// fetch happens one full `interval` after startup.
pub async fn run_discovery_refresh(state: Arc<AppState>, interval: Duration) {
	let mut ticker = tokio::time::interval(interval);
	// Skip, not burst: a slow or briefly unavailable discovery fetch must
	// not cause a burst of catch-up fetches on recovery.
	ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	ticker.tick().await;
	let mut last_applied: Option<DiscoveryDocument> = None;
	loop {
		ticker.tick().await;
		let Some(authentication) = state.current().config.authentication.clone() else {
			// Authentication was removed by a reload; nothing to refresh.
			continue;
		};
		let document = match fetch_discovery(&authentication).await {
			Ok(document) => document,
			Err(error) => {
				tracing::warn!(%error, "discovery refresh fetch failed; keeping the current validator");
				continue;
			}
		};
		match &last_applied {
			None => last_applied = Some(document),
			Some(previous) if *previous == document => {}
			Some(_) => {
				if rebuild_validator(&state, &document).await {
					last_applied = Some(document);
				}
			}
		}
	}
}

/// Rebuild the validator from a changed discovery document and swap it in,
/// serialised against reload and reading the live configuration.
///
/// Returns `true` when the validator was rebuilt and installed, so the
/// caller records the document as applied. Returns `false` when the
/// configuration no longer has an authentication section or the rebuild
/// failed, in which case the previous validator keeps serving.
async fn rebuild_validator(state: &Arc<AppState>, document: &DiscoveryDocument) -> bool {
	// Hold the rebuild lock across the read, build, and swap so a reload
	// cannot interleave, and re-read the configuration under it so the
	// rebuilt validator reflects the post-reload principals and scopes.
	let _guard = state.lock_auth_rebuild().await;
	let inner = state.current();
	let Some(authentication) = inner.config.authentication.clone() else {
		return false;
	};
	match assemble_auth_state(&authentication, document, inner.resolver.as_ref()).await {
		Ok(auth) => {
			state.set_auth(Arc::new(auth));
			tracing::info!("discovery document changed; rebuilt and swapped the validator");
			true
		}
		Err(error) => {
			tracing::warn!(
				%error,
				"discovery refresh: validator rebuild failed; keeping the previous validator"
			);
			false
		}
	}
}
