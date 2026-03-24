//! Structured output rendering for the MCP gateway console.
//!
//! Console commands produce results that must be consumable by both
//! humans at a terminal and machines parsing JSON. The [`Renderer`]
//! centralises this concern so that command handlers remain
//! format-agnostic — they write human text via a closure and return
//! a serialisable payload, and the renderer decides which channel
//! to use based on the active [`OutputMode`].
//!
//! # Output modes
//!
//! | Mode    | Human text | JSON envelope | Errors  |
//! |---------|-----------|---------------|---------|
//! | Human   | stdout    | suppressed    | stderr  |
//! | JSON    | suppressed| stdout        | stdout  |
//! | Quiet   | suppressed| suppressed    | stderr  |
//!
//! # JSON envelope
//!
//! All JSON output uses a standard envelope so that consumers can
//! distinguish success from failure without inspecting the process
//! exit code:
//!
//! ```json
//! {"ok": true,  "data": { ... }}
//! {"ok": false, "error": {"code": 78, "message": "..."}}
//! ```
//!
//! # Colour
//!
//! Bold and dim ANSI styling is available via [`Renderer::bold`]
//! and [`Renderer::dim`]. Colour is automatically disabled when
//! the `NO_COLOR` environment variable is set, stdout is not a
//! terminal, or the output mode is JSON. See <https://no-color.org/>.

use std::borrow::Cow;
use std::fmt::Display;
use std::io::{self, IsTerminal, Write};

use serde::Serialize;

/// ANSI escape sequence for bold text.
const BOLD_START: &str = "\x1b[1m";

/// ANSI escape sequence for dim (faint) text.
const DIM_START: &str = "\x1b[2m";

/// ANSI escape sequence to reset all styling.
const RESET: &str = "\x1b[0m";

/// Output format for the current invocation.
///
/// Selected once at startup from the global `--json` flag and
/// immutable for the lifetime of the process. Defaults to
/// human-readable output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputMode {
	/// Human-readable text to stdout, errors to stderr.
	#[default]
	Human,
	/// Machine-readable JSON envelope to stdout for both
	/// successful results and errors.
	Json,
}

/// Detect whether ANSI colour output should be enabled.
///
/// Colour is enabled when all of the following are true:
/// - The output mode is human (JSON output must never contain ANSI)
/// - The `NO_COLOR` environment variable is not set (per <https://no-color.org/>)
/// - stdout is connected to a terminal (not piped to a file or process)
#[must_use]
pub fn detect_colour(mode: OutputMode) -> bool {
	mode == OutputMode::Human
		&& std::env::var_os("NO_COLOR").is_none()
		&& io::stdout().is_terminal()
}

/// Writes command output in the active [`OutputMode`].
///
/// Constructed once at startup and threaded through to command
/// handlers. Each handler calls [`human`] for freeform text and
/// [`success`] for the structured payload; the renderer ensures
/// only the appropriate channel produces output.
///
/// [`human`]: Renderer::human
/// [`success`]: Renderer::success
#[derive(Debug, Clone)]
pub struct Renderer {
	mode: OutputMode,
	colour_enabled: bool,
	quiet: bool,
}

impl Renderer {
	/// Create a renderer with the given output mode, colour
	/// preference, and quiet flag.
	///
	/// Use [`detect_colour`] to determine the `colour_enabled`
	/// value based on terminal capability and environment.
	#[must_use]
	pub fn new(mode: OutputMode, colour_enabled: bool, quiet: bool) -> Self {
		Self {
			mode,
			colour_enabled,
			quiet,
		}
	}

	/// The output mode this renderer was constructed with.
	#[must_use]
	pub fn mode(&self) -> OutputMode {
		self.mode
	}

	/// Whether ANSI colour output is enabled.
	#[must_use]
	pub fn colour_enabled(&self) -> bool {
		self.colour_enabled
	}

	/// Whether quiet mode is active.
	#[must_use]
	pub fn is_quiet(&self) -> bool {
		self.quiet
	}

	/// Wrap text in bold ANSI styling if colour is enabled,
	/// returning the text unchanged otherwise.
	#[must_use]
	pub fn bold<'text>(&self, text: &'text str) -> Cow<'text, str> {
		if self.colour_enabled {
			Cow::Owned(format!("{BOLD_START}{text}{RESET}"))
		} else {
			Cow::Borrowed(text)
		}
	}

	/// Wrap text in dim (faint) ANSI styling if colour is enabled,
	/// returning the text unchanged otherwise.
	#[must_use]
	pub fn dim<'text>(&self, text: &'text str) -> Cow<'text, str> {
		if self.colour_enabled {
			Cow::Owned(format!("{DIM_START}{text}{RESET}"))
		} else {
			Cow::Borrowed(text)
		}
	}

	/// Write human-readable output to stdout.
	///
	/// The closure receives a locked stdout handle and can make
	/// multiple `write!` / `writeln!` calls within a single lock
	/// acquisition. Suppressed in JSON mode and quiet mode.
	///
	/// # Errors
	///
	/// Returns an I/O error if writing to stdout fails.
	pub fn human(
		&self,
		writer_function: impl FnOnce(&mut dyn Write) -> io::Result<()>,
	) -> io::Result<()> {
		if self.mode == OutputMode::Human && !self.quiet {
			let mut output = io::stdout().lock();
			writer_function(&mut output)?;
		}
		Ok(())
	}

	/// Emit a successful result as a JSON envelope to stdout.
	///
	/// Wraps the payload in `{"ok": true, "data": ...}` and writes
	/// a trailing newline. In human mode this does nothing because
	/// human output is produced directly by the closure passed to
	/// [`Renderer::human`].
	pub fn success(&self, payload: &impl Serialize) {
		if self.mode == OutputMode::Json {
			let envelope = SuccessEnvelope {
				ok: true,
				data: payload,
			};
			let _ = serde_json::to_writer(io::stdout().lock(), &envelope);
			let _ = writeln!(io::stdout().lock());
		}
	}

	/// Emit an error in the active output mode.
	///
	/// In human mode the message is written to stderr with an
	/// `error:` prefix. In JSON mode the error is wrapped in
	/// `{"ok": false, "error": {...}}` on stdout.
	///
	/// Errors are never suppressed by quiet mode — they always
	/// reach the operator.
	pub fn error(&self, error: &impl Display, code: i32) {
		match self.mode {
			OutputMode::Human => {
				let _ = writeln!(io::stderr().lock(), "error: {error}");
			}
			OutputMode::Json => {
				let envelope = ErrorEnvelope {
					ok: false,
					error: ErrorDetail {
						code,
						message: error.to_string(),
					},
				};
				let _ = serde_json::to_writer(io::stdout().lock(), &envelope);
				let _ = writeln!(io::stdout().lock());
			}
		}
	}

	/// Variant of [`human`](Renderer::human) that writes to an
	/// arbitrary writer, allowing tests to capture output without
	/// touching real file descriptors.
	#[cfg(test)]
	fn human_to(
		&self,
		writer: &mut impl Write,
		writer_function: impl FnOnce(&mut dyn Write) -> io::Result<()>,
	) -> io::Result<()> {
		if self.mode == OutputMode::Human && !self.quiet {
			writer_function(writer)?;
		}
		Ok(())
	}

	/// Variant of [`success`](Renderer::success) that writes to an
	/// arbitrary writer for test capture.
	#[cfg(test)]
	fn success_to(&self, writer: &mut impl Write, payload: &impl Serialize) {
		if self.mode == OutputMode::Json {
			let envelope = SuccessEnvelope {
				ok: true,
				data: payload,
			};
			let _ = serde_json::to_writer(&mut *writer, &envelope);
			let _ = writeln!(writer);
		}
	}

	/// Variant of [`error`](Renderer::error) that writes to an
	/// arbitrary writer for test capture.
	#[cfg(test)]
	fn error_to(&self, writer: &mut impl Write, error: &impl Display, code: i32) {
		match self.mode {
			OutputMode::Human => {
				let _ = writeln!(writer, "error: {error}");
			}
			OutputMode::Json => {
				let envelope = ErrorEnvelope {
					ok: false,
					error: ErrorDetail {
						code,
						message: error.to_string(),
					},
				};
				let _ = serde_json::to_writer(&mut *writer, &envelope);
				let _ = writeln!(writer);
			}
		}
	}
}

/// JSON envelope for successful command results.
#[derive(Serialize)]
struct SuccessEnvelope<'payload, T: Serialize> {
	ok: bool,
	data: &'payload T,
}

/// JSON envelope for command errors.
#[derive(Serialize)]
struct ErrorEnvelope {
	ok: bool,
	error: ErrorDetail,
}

/// Error payload within the JSON error envelope.
#[derive(Serialize)]
struct ErrorDetail {
	/// Process exit code, following `sysexits.h` conventions.
	code: i32,
	/// Human-readable error description.
	message: String,
}

#[cfg(test)]
mod tests {
	use super::*;

	fn human_renderer() -> Renderer {
		Renderer::new(OutputMode::Human, false, false)
	}

	fn json_renderer() -> Renderer {
		Renderer::new(OutputMode::Json, false, false)
	}

	/// A JSON success envelope must contain `ok: true` and nest
	/// the serialised payload under `data`.
	#[test]
	fn json_success_envelope_shape() {
		#[derive(Serialize)]
		struct TestPayload {
			version: String,
		}

		let renderer = json_renderer();
		let mut buffer = Vec::new();

		let payload = TestPayload {
			version: "1.0.0".to_owned(),
		};
		renderer.success_to(&mut buffer, &payload);

		let output = String::from_utf8(buffer).unwrap();
		let value: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
		assert_eq!(value["ok"], true);
		assert_eq!(value["data"]["version"], "1.0.0");
	}

	/// A JSON error envelope must contain `ok: false` with the
	/// exit code and message nested under `error`.
	#[test]
	fn json_error_envelope_shape() {
		let renderer = json_renderer();
		let mut buffer = Vec::new();

		renderer.error_to(&mut buffer, &"something broke", 78);

		let output = String::from_utf8(buffer).unwrap();
		let value: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
		assert_eq!(value["ok"], false);
		assert_eq!(value["error"]["code"], 78);
		assert_eq!(value["error"]["message"], "something broke");
	}

	/// In human mode, the closure passed to `human_to` must be
	/// called and its output written to the provided writer.
	#[test]
	fn human_mode_writes_output() {
		let renderer = human_renderer();
		let mut buffer = Vec::new();

		renderer
			.human_to(&mut buffer, |writer| writeln!(writer, "hello"))
			.unwrap();

		assert_eq!(String::from_utf8(buffer).unwrap(), "hello\n");
	}

	/// In JSON mode, human output must be suppressed entirely.
	#[test]
	fn json_mode_suppresses_human_output() {
		let renderer = json_renderer();
		let mut buffer = Vec::new();

		renderer
			.human_to(&mut buffer, |writer| writeln!(writer, "should not appear"))
			.unwrap();

		assert!(buffer.is_empty());
	}

	/// In human mode, the JSON success envelope must not be emitted.
	#[test]
	fn human_mode_suppresses_json_success() {
		let renderer = human_renderer();
		let mut buffer = Vec::new();

		renderer.success_to(&mut buffer, &"payload");

		assert!(buffer.is_empty());
	}

	/// Human-mode errors must be prefixed with `error:`.
	#[test]
	fn human_mode_error_has_prefix() {
		let renderer = human_renderer();
		let mut buffer = Vec::new();

		renderer.error_to(&mut buffer, &"bad config", 78);

		assert_eq!(String::from_utf8(buffer).unwrap(), "error: bad config\n");
	}

	/// When colour is enabled, bold must wrap text in ANSI bold.
	#[test]
	fn bold_wraps_text_when_colour_enabled() {
		let renderer = Renderer::new(OutputMode::Human, true, false);
		let result = renderer.bold("hello");
		assert_eq!(result.as_ref(), "\x1b[1mhello\x1b[0m");
	}

	/// When colour is disabled, bold must return text unchanged.
	#[test]
	fn bold_returns_plain_text_when_colour_disabled() {
		let renderer = human_renderer();
		let result = renderer.bold("hello");
		assert_eq!(result.as_ref(), "hello");
	}

	/// When colour is enabled, dim must wrap text in ANSI dim.
	#[test]
	fn dim_wraps_text_when_colour_enabled() {
		let renderer = Renderer::new(OutputMode::Human, true, false);
		let result = renderer.dim("secondary");
		assert_eq!(result.as_ref(), "\x1b[2msecondary\x1b[0m");
	}

	/// Quiet mode must suppress human output entirely.
	#[test]
	fn quiet_mode_suppresses_human_output() {
		let renderer = Renderer::new(OutputMode::Human, false, true);
		let mut buffer = Vec::new();

		renderer
			.human_to(&mut buffer, |writer| writeln!(writer, "should not appear"))
			.unwrap();

		assert!(buffer.is_empty());
	}

	/// Quiet mode must not suppress error output.
	#[test]
	fn quiet_mode_preserves_error_output() {
		let renderer = Renderer::new(OutputMode::Human, false, true);
		let mut buffer = Vec::new();

		renderer.error_to(&mut buffer, &"something failed", 1);

		assert_eq!(
			String::from_utf8(buffer).unwrap(),
			"error: something failed\n"
		);
	}
}
