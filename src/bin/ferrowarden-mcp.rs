//! `ferrowarden-mcp`: MCP tools for calling APIs through Ferrowarden with
//! named vault credentials. A stdio MCP server and a thin HTTP client of a
//! running Ferrowarden. See docs/mcp.md.
//!
//! Stdout carries only MCP protocol messages (and `--help` / `--version`
//! output before the server starts). Logs and startup problems go to stderr.
// Anything printed to stdout in this binary would corrupt the protocol.
#![deny(clippy::print_stdout, clippy::dbg_macro)]

#[path = "../mcp/mod.rs"]
mod mcp;

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::Arc;

use rmcp::ServiceExt;

use mcp::cli::{parse_args, Cli, USAGE};
use mcp::client::FerroClient;
use mcp::config::Config;
use mcp::server::FerrowardenMcp;

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)) {
        Cli::Run => {}
        Cli::Help => {
            let _ = std::io::stdout().write_all(USAGE.as_bytes());
            return ExitCode::SUCCESS;
        }
        Cli::Version => {
            let _ = writeln!(
                std::io::stdout(),
                "ferrowarden-mcp {}",
                env!("CARGO_PKG_VERSION")
            );
            return ExitCode::SUCCESS;
        }
        Cli::Unknown(arg) => {
            eprintln!("ferrowarden-mcp: unrecognized argument {arg:?}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    }

    mcp::init_logging();

    // Configuration problems end here, with exit code 2, before any MCP
    // message is written. The messages never contain the key or the URL path.
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("ferrowarden-mcp: configuration error: {error}");
            return ExitCode::from(2);
        }
    };
    if config.uses_insecure_http() {
        tracing::warn!(
            host = %config.host_for_log(),
            "FERROWARDEN_URL uses plain http:// (FERROWARDEN_MCP_ALLOW_HTTP=1): the agent key and \
             all traffic are sent unencrypted; use this only on a trusted internal network"
        );
    }
    let client = match FerroClient::new(&config) {
        Ok(client) => Arc::new(client),
        Err(error) => {
            eprintln!("ferrowarden-mcp: configuration error: {error}");
            return ExitCode::from(2);
        }
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        host = %config.host_for_log(),
        timeout_secs = config.timeout.as_secs(),
        "ferrowarden-mcp starting on stdio"
    );
    // The client holds what it needs; drop the configuration copy of the key.
    drop(config);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => {
            eprintln!("ferrowarden-mcp: could not start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(serve(client));
    // A blocked read of stdin must not hold the process open.
    runtime.shutdown_background();
    code
}

async fn serve(client: Arc<FerroClient>) -> ExitCode {
    let service = match FerrowardenMcp::new(client)
        .serve(rmcp::transport::stdio())
        .await
    {
        Ok(service) => service,
        Err(error) => {
            // The SDK's error describes the protocol failure, not our config.
            tracing::error!(%error, "MCP session could not start");
            return ExitCode::FAILURE;
        }
    };
    match service.waiting().await {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "MCP session ended abnormally");
            ExitCode::FAILURE
        }
    }
}
