//! Process-level memory hardening helpers.
//!
//! Pairs with [`mcp_gateway_credentials::Secret`]'s page-locking by
//! preventing the process from leaking secrets through core dumps.
//! Where `Secret`'s `mlock` keeps the bytes out of swap files,
//! `disable_core_dumps` keeps them out of post-mortem files: a crash
//! handler that writes a full memory image to disk would otherwise
//! capture every live secret.
//!
//! This is a defence-in-depth control. Operators running under
//! `systemd` or container runtimes that already block core dumps
//! still benefit, since the gateway's own behaviour does not depend
//! on the surrounding runtime.

#[cfg(unix)]
use rlimit::Resource;

/// Errors from process-level hardening calls.
#[derive(Debug, thiserror::Error)]
pub enum HardeningError {
	/// `setrlimit(RLIMIT_CORE, 0, 0)` failed. Surfaces the
	/// underlying I/O error so an operator can tell apart a
	/// permissions issue (`EPERM`) from a missing kernel feature.
	#[error("failed to disable core dumps: {0}")]
	CoreDumpDisable(std::io::Error),
}

/// Disable core dumps for the running process by setting both the
/// soft and hard `RLIMIT_CORE` limits to zero.
///
/// Once a hard limit is lowered the process cannot raise it again,
/// so calling this early during startup makes the constraint
/// permanent for the lifetime of the gateway. On non-Unix platforms
/// this is a no-op: there is no portable equivalent to
/// `RLIMIT_CORE`, and the platforms in question do not produce
/// core files in the same form.
///
/// # Errors
///
/// Returns [`HardeningError::CoreDumpDisable`] when `setrlimit`
/// rejects the request. The most common cause is a parent process
/// that already lowered the hard limit and refuses to set it again
/// (which is the desired end state); callers can treat that case as
/// success after inspecting the limit, or surface the error for
/// diagnostic logging.
#[cfg(unix)]
pub fn disable_core_dumps() -> Result<(), HardeningError> {
	rlimit::setrlimit(Resource::CORE, 0, 0).map_err(HardeningError::CoreDumpDisable)
}

/// No-op stub for non-Unix platforms. Documented as a stub so
/// callers can call it unconditionally without a `cfg` switch.
#[cfg(not(unix))]
pub fn disable_core_dumps() -> Result<(), HardeningError> {
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// After `disable_core_dumps`, `getrlimit(RLIMIT_CORE)` reports
	/// `(0, 0)`. The hard limit becomes zero too, so a future caller
	/// (or a malicious in-process plugin) cannot reverse the
	/// reduction by raising the soft limit alone.
	#[cfg(unix)]
	#[test]
	fn disable_core_dumps_lowers_both_limits_to_zero() {
		disable_core_dumps().expect("disabling core dumps must succeed in unprivileged tests");
		let (soft, hard) =
			rlimit::getrlimit(Resource::CORE).expect("getrlimit reads the current limits");
		assert_eq!(
			(soft, hard),
			(0, 0),
			"both limits must be zero after disabling core dumps",
		);
	}
}
