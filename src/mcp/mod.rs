//! `ferrowarden-mcp`: a stdio MCP server that is a thin client of a running
//! Ferrowarden. It holds one agent key, never vault access, and never starts
//! or reads the proxy. See `docs/mcp.md`.
//!
//! Stdout belongs to the MCP protocol. Nothing in this tree prints to it
//! (clippy's `print_stdout` is denied in the binary), and every log line goes
//! to stderr.

pub mod cli;
pub mod client;
pub mod config;
pub mod render;
pub mod server;
pub mod tools;

#[cfg(test)]
mod tests;

/// The log filter for a `FERROWARDEN_MCP_LOG` value: a level, nothing else.
/// The level applies to this program only. HTTP and TLS libraries stay off
/// (their debug output can include request URLs, whose path may be the secret
/// api_prefix), and the MCP SDK is limited to errors.
pub fn log_filter(value: &str) -> Option<String> {
    let level = value.trim().to_ascii_lowercase();
    matches!(
        level.as_str(),
        "error" | "warn" | "info" | "debug" | "trace" | "off"
    )
    .then(|| format!("off,rmcp=error,ferrowarden_mcp={level}"))
}

/// Set up logging to stderr: plain text, default level `warn`, changed with
/// `FERROWARDEN_MCP_LOG`. Stdout is never used for logs.
pub fn init_logging() {
    use tracing_subscriber::EnvFilter;

    let raw = std::env::var("FERROWARDEN_MCP_LOG").unwrap_or_default();
    let directive = if raw.trim().is_empty() {
        log_filter("warn")
    } else {
        let parsed = log_filter(&raw);
        if parsed.is_none() {
            eprintln!(
                "ferrowarden-mcp: ignoring FERROWARDEN_MCP_LOG (use error, warn, info, debug, \
                 trace or off); using warn"
            );
        }
        parsed.or_else(|| log_filter("warn"))
    }
    .expect("a valid level");
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(directive))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_target(false)
        .init();
}
#[cfg(test)]
mod log_tests;
