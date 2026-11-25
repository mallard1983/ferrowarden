//! Command line of `ferrowarden-mcp`: `--help`, `--version`, nothing else.
//! Everything is configured through the environment (see `config`).

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Cli {
    /// No arguments: serve MCP on stdin and stdout.
    Run,
    Help,
    Version,
    /// An argument that is not recognised.
    Unknown(String),
}

/// Parse the arguments after the program name. The first argument decides.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Cli {
    match args.into_iter().next().as_deref() {
        None => Cli::Run,
        Some("--help" | "-h") => Cli::Help,
        Some("--version" | "-V") => Cli::Version,
        Some(other) => Cli::Unknown(other.chars().take(64).collect()),
    }
}

pub const USAGE: &str = "\
ferrowarden-mcp \u{2014} MCP tools for calling APIs through Ferrowarden with named vault credentials.

Usage: ferrowarden-mcp [--help | --version]

Speaks the Model Context Protocol on stdin and stdout; start it from an MCP
client. Configuration comes from environment variables; see docs/mcp.md.

Environment:
  FERROWARDEN_URL                Base URL of Ferrowarden, including any api_prefix (required)
  FERROWARDEN_AGENT_KEY          Agent key (required, or use FERROWARDEN_AGENT_KEY_FILE)
  FERROWARDEN_AGENT_KEY_FILE     File holding the agent key (not together with the above)
  FERROWARDEN_CA_FILE            Extra root certificates, PEM bundle (optional)
  FERROWARDEN_MCP_TIMEOUT_SECS   Per-request timeout, 1 to 600 (default 60)
  FERROWARDEN_MCP_ALLOW_HTTP     1 to allow http:// to a non-loopback host (trusted networks only)
  FERROWARDEN_MCP_LOG            Log level: error, warn, info, debug, trace or off; to stderr (default warn)

Options:
  -h, --help     Print this help and exit
  -V, --version  Print the version and exit
";

#[cfg(test)]
mod tests;
