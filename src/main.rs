mod api;
mod config;
mod error;
mod events;
mod healthcheck;
mod keys;
mod metrics;
mod middleware;
mod net;
mod notify;
mod policy;
mod proxy;
mod state;
mod ui;
mod vault;

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use config::{split_list, Config, UnlockMode};
use events::{Action, EventLog, SecurityEvent};
use state::AppState;
use vault::refresh::{spawn_refresher, unlock_from_file};

/// The one `startup` event: security-relevant settings, never secrets.
/// `keys_without_policy` counts 0.1.0 key entries that run deny-all.
fn startup_event(
    config: &Config,
    agent_key_count: usize,
    keys_without_policy: usize,
) -> SecurityEvent {
    SecurityEvent::new(Action::Startup)
        .detail("version", env!("CARGO_PKG_VERSION"))
        .detail("tls_enabled", config.tls_enabled)
        .detail("vault_backend", config.vault.backend.as_str())
        .detail(
            "unlock_mode",
            match config.unlock_mode {
                UnlockMode::File => "file",
                UnlockMode::Manual => "manual",
            },
        )
        .detail("keys_without_policy", keys_without_policy)
        .detail("enforce_credential_hosts", config.enforce_credential_hosts)
        .detail("allow_private_targets", config.allow_private_targets)
        .detail("allowed_targets", split_list(&config.allowed_targets).len())
        .detail("trusted_proxies", split_list(&config.trusted_proxies).len())
        .detail("api_prefix_set", !config.api_prefix.is_empty())
        .detail("agent_key_count", agent_key_count)
        .detail("sinks", config.events.enabled_sinks())
        .detail(
            "notify_senders",
            config
                .notify
                .urls()
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
        )
        .detail(
            "notify_allow_http",
            config.notify.enabled() && config.notify.allow_http,
        )
        .detail("ui_enabled", config.ui.enabled())
        .detail("ui_tls", config.ui.enabled() && config.tls_enabled)
        .detail(
            "ui_insecure_http",
            config.ui.enabled() && config.ui.insecure_http,
        )
        .detail("metrics_enabled", config.metrics.enabled())
        .detail("metrics_auth", config.metrics.auth().as_str())
        .detail(
            "metrics_tls",
            config.metrics.enabled() && config.tls_enabled,
        )
        .detail(
            "metrics_credential_labels",
            config.metrics.enabled() && config.metrics.credential_labels,
        )
}

/// What the command line asks for. Ferrowarden takes no options: configuration
/// comes from `ferrowarden.toml` and `FERROWARDEN_*` environment variables.
/// The one subcommand is `healthcheck`.
#[derive(Debug, PartialEq, Eq)]
enum Cli {
    /// No arguments: run the proxy.
    Run,
    Help,
    Version,
    /// `healthcheck`: probe the running server's `/health` and exit 0 or 1.
    /// This is the container health check (the image has no `curl`).
    Healthcheck,
    /// An argument that is not recognised.
    Unknown(String),
}

/// Parse the arguments after the program name. The first argument decides;
/// `healthcheck` takes no arguments of its own.
fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Cli {
    let mut args = args.into_iter();
    match args.next().as_deref() {
        None => Cli::Run,
        Some("--help" | "-h") => Cli::Help,
        Some("--version" | "-V") => Cli::Version,
        Some("healthcheck") => match args.next() {
            None => Cli::Healthcheck,
            Some(extra) => Cli::Unknown(extra),
        },
        Some(other) => Cli::Unknown(other.to_string()),
    }
}

const USAGE: &str = "\
Ferrowarden \u{2014} proxy authenticated API calls for agents using named vault credentials.

Usage: ferrowarden [healthcheck | --help | --version]

Ferrowarden takes no other options. Configuration comes from ferrowarden.toml
and FERROWARDEN_* environment variables; see docs/setup.md for the full list.

Commands:
  healthcheck    Check that the running server answers GET /health (HTTP 200
                 within 3 seconds). Exits 0 if healthy, 1 if not, with one
                 line on stderr. Uses the same configuration as the server,
                 needs no secrets, and verifies the server's TLS certificate.
                 This is the container health check.

Options:
  -h, --help     Print this help and exit
  -V, --version  Print the version and exit
";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match parse_args(std::env::args().skip(1)) {
        Cli::Run => {}
        Cli::Help => {
            print!("{USAGE}");
            return Ok(());
        }
        Cli::Version => {
            println!("ferrowarden {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Cli::Healthcheck => std::process::exit(healthcheck::run().await),
        Cli::Unknown(arg) => {
            eprintln!("ferrowarden: unrecognized argument {arg:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    }

    // Structured JSON logging — compatible with Loki/Grafana.
    // Level is controlled by FERROWARDEN_LOG_LEVEL (default: info).
    // Valid levels: trace, debug, info, warn, error.
    // Module-scoped filtering is supported: "ferrowarden=debug,tower_http=warn".
    //
    // Requires a container restart to change — this is intentional. A log level
    // change produces a container restart event in Docker logs, creating an audit
    // trail. An attacker who gains access cannot silently suppress logging.
    let log_filter = std::env::var("FERROWARDEN_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let filter = EnvFilter::try_new(&log_filter).unwrap_or_else(|_| {
        eprintln!(
            "Invalid FERROWARDEN_LOG_LEVEL {:?}, falling back to info",
            log_filter
        );
        EnvFilter::new("info")
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "Ferrowarden {} starting \u{2014} the credential boundary for AI agents",
        env!("CARGO_PKG_VERSION")
    );

    let config = Config::load()?;

    // Security events: ring buffer for /v1/admin/audit plus the configured
    // sinks (stdout by default). Application logs stay on tracing.
    let events = EventLog::start(&config.events)?;

    // Push notifications: another consumer of the event stream, with its own
    // queue and workers. Nothing starts unless a sender URL is configured.
    let notify = notify::start(&config.notify, &events)?;
    if config.notify.enabled() && config.notify.allow_http {
        tracing::warn!(
            "notify.allow_http = true: notifications to http:// URLs cross the network in clear text"
        );
    }

    // Prometheus metrics: one more consumer of the event stream, started
    // before the first event so `startup` is counted. Nothing starts unless
    // `metrics.bind` is set.
    let metrics = metrics::start(&config.metrics, config.vault.backend.as_str(), &events);

    if config.vault.backend == config::VaultBackend::Native {
        // The native backend keeps the vault's keys in this process: no core
        // dumps, no ptrace by other unprivileged processes (Linux; best effort).
        let failed = vault::native::hardening::apply();
        if failed.is_empty() {
            tracing::info!("Process hardened: core dumps disabled");
        } else {
            tracing::warn!(failed = ?failed, "Process hardening was only partly applied");
        }
    }

    let state = Arc::new(AppState::try_new(config.clone(), events.clone())?.with_notify(notify));

    // Load persisted agent keys if a key file is configured. Keys written by
    // 0.1.0 carry no policy and load as deny-all; they are counted so the
    // operator can see them (startup event, warning, `policy_set: false`).
    let mut keys_without_policy: usize = 0;
    if let Some(ref path) = config.keys_file {
        keys_without_policy = state.load_keys(path).await?;
    }
    if keys_without_policy > 0 {
        tracing::warn!(
            keys_without_policy,
            "agent keys without a policy are deny-all: they can neither list nor use credentials. \
             Set a policy with PATCH /v1/admin/keys/{{id}} and a body of \
             {{\"credentials\": [...], \"methods\": [...]}} (use [\"*\"] to allow everything)."
        );
    }

    // One startup event with the security-relevant settings (never secrets;
    // the API prefix is reported only as set / not set).
    events.emit(startup_event(
        &config,
        state.agent_keys.read().await.len(),
        keys_without_policy,
    ));

    // File mode: read and use the password before accepting any requests.
    // unlock_from_file also syncs bw serve and loads the credential cache.
    if config.unlock_mode == UnlockMode::File {
        tracing::info!(
            "File unlock mode: reading password from {:?}",
            config.unlock_file
        );
        if let Err(e) = unlock_from_file(&state, "file").await {
            // The failure event is already queued; get it out before exiting.
            events.flush().await;
            return Err(e.into());
        }
        tracing::info!("Vault unlocked via file mode");
    } else {
        tracing::info!("Manual unlock mode: POST /v1/unlock with admin key to unlock the vault");
    }

    // Periodic sync/refresh; also re-unlocks in file mode if bw serve restarts.
    spawn_refresher(state.clone());

    if config.enforce_credential_hosts {
        tracing::info!("Credential host binding enforced: credentials are only sent to hosts in their vault item URIs");
    } else {
        tracing::warn!("enforce_credential_hosts = false: any agent can send any credential to any reachable host");
    }
    if config.api_prefix.is_empty() {
        tracing::info!("API served at /v1/... (no api_prefix set)");
    } else {
        // The prefix value is deliberately not logged (or put in any event):
        // it is a secret-by-obscurity setting, and operators already have it
        // in their own configuration.
        tracing::info!("API served under the configured api_prefix");
    }
    if config.allow_private_targets {
        tracing::warn!("allow_private_targets = true: agents may reach private/internal addresses (bw serve is still blocked)");
    }

    let router = api::router(state.clone());

    // The admin UI is a separate server on its own port: never merged into
    // the API router above. Disabled unless `ui.bind` is set.
    let mut ui_for_metrics = None;
    let ui_server = if config.ui.enabled() {
        let addr: SocketAddr = config.ui.bind.trim().parse()?;
        let ui_state = ui::UiState::new(state.clone()).map_err(|e| anyhow::anyhow!(e))?;
        ui_for_metrics = Some(ui_state.clone());
        if config.ui.insecure_http {
            tracing::warn!(
                "ui.insecure_http = true: the admin UI serves its sign-in form over plain HTTP. \
                 The vault master password crosses the network unencrypted unless a TLS proxy \
                 sits in front. Use only for local testing."
            );
        }
        Some((addr, ui::router(ui_state)))
    } else {
        None
    };

    // The metrics endpoint is a third server on its own port, serving
    // `GET /metrics` only. Never merged into the API or UI router.
    let metrics_server = match (&metrics, config.metrics.addr()) {
        (Some(metrics), Some(addr)) => {
            match config.metrics.auth() {
                config::MetricsAuth::Token => {
                    if !config.tls_enabled {
                        tracing::warn!(
                            "tls_enabled = false: the metrics bearer token crosses the network in clear text. Keep the metrics port on an internal-only network."
                        );
                    }
                }
                config::MetricsAuth::None if config.metrics.allow_unauthenticated => {
                    tracing::warn!(
                        "metrics.allow_unauthenticated = true: anyone who can reach {addr} can read the metrics"
                    );
                }
                config::MetricsAuth::None => {
                    tracing::info!(
                        "No metrics token set: the metrics listener is on a loopback address"
                    );
                }
            }
            if config.metrics.credential_labels {
                tracing::warn!(
                    "metrics.credential_labels = true: credential names appear as metric labels and reveal what the vault holds"
                );
            }
            let server = metrics::server::MetricsServer::new(
                state.clone(),
                metrics.clone(),
                &config.metrics,
                ui_for_metrics,
            );
            Some((addr, metrics::server::router(server)))
        }
        _ => None,
    };

    // Set by the signal handler, read after the servers stop.
    let signal: Arc<OnceLock<&'static str>> = Arc::new(OnceLock::new());
    // One stop signal for every listener.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn({
        let signal = signal.clone();
        async move {
            let _ = signal.set(shutdown_signal().await);
            let _ = stop_tx.send(true);
        }
    });

    let addr: std::net::SocketAddr = config.bind_addr.parse()?;

    // The same certificate serves the API and, if enabled, the UI.
    let tls_config = if config.tls_enabled {
        let cert = config
            .tls_cert_file
            .as_ref()
            .expect("tls_cert_file required when tls_enabled");
        let key = config
            .tls_key_file
            .as_ref()
            .expect("tls_key_file required when tls_enabled");
        Some(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?)
    } else {
        // TLS is disabled. This is only safe when the agent and ferrowarden
        // run on the same host (e.g. same Docker network, same machine).
        tracing::warn!("╔══════════════════════════════════════════════════════════╗");
        tracing::warn!("║  WARNING: TLS IS DISABLED                                ║");
        tracing::warn!("║  Ferrowarden is serving plaintext HTTP.                  ║");
        tracing::warn!("║  Credential values will be transmitted unencrypted.      ║");
        tracing::warn!("║  This is ONLY acceptable when the agent and ferrowarden  ║");
        tracing::warn!("║  run on the SAME HOST with no network hop between them.  ║");
        tracing::warn!("╚══════════════════════════════════════════════════════════╝");
        None
    };

    let api = serve(
        "Listening",
        router,
        addr,
        tls_config.clone(),
        stop_rx.clone(),
    );
    let (ui_tls, ui_stop) = (tls_config.clone(), stop_rx.clone());
    let ui = async move {
        match ui_server {
            Some((ui_addr, ui_router)) => {
                serve("Admin UI listening", ui_router, ui_addr, ui_tls, ui_stop).await
            }
            None => Ok(()),
        }
    };
    let metrics_listener = async {
        match metrics_server {
            Some((metrics_addr, metrics_router)) => {
                serve(
                    "Metrics listening",
                    metrics_router,
                    metrics_addr,
                    tls_config,
                    stop_rx,
                )
                .await
            }
            None => Ok(()),
        }
    };
    tokio::try_join!(api, ui, metrics_listener)?;

    // Graceful stop: tell the stream, then flush the sinks before exiting.
    events.emit(
        SecurityEvent::new(Action::Shutdown)
            .detail("signal", signal.get().copied().unwrap_or("none")),
    );
    events.flush().await;
    tracing::info!("Ferrowarden stopped");

    Ok(())
}

/// Serve `router` on `addr` (with TLS when a config is given) until the stop
/// signal fires, then let in-flight requests finish.
async fn serve(
    name: &'static str,
    router: axum::Router,
    addr: SocketAddr,
    tls: Option<axum_server::tls_rustls::RustlsConfig>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    match tls {
        Some(tls) => {
            tracing::info!("{name} on https://{} (TLS)", addr);
            let handle = axum_server::Handle::new();
            tokio::spawn({
                let handle = handle.clone();
                async move {
                    let _ = stop.wait_for(|stopped| *stopped).await;
                    handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
                }
            });
            axum_server::bind_rustls(addr, tls)
                .handle(handle)
                .serve(make_service)
                .await?;
        }
        None => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!("{name} on http://{} (plaintext)", addr);
            axum::serve(listener, make_service)
                .with_graceful_shutdown(async move {
                    let _ = stop.wait_for(|stopped| *stopped).await;
                })
                .await?;
        }
    }
    Ok(())
}

/// How long in-flight requests get to finish after a shutdown signal.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Resolves when the process is asked to stop: Ctrl-C (SIGINT), or SIGTERM on
/// Unix (what `docker stop` sends). Returns the signal's name.
async fn shutdown_signal() -> &'static str {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => "SIGINT",
            // Could not install the handler: never resolve rather than
            // shutting down immediately.
            Err(_) => std::future::pending().await,
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
                "SIGTERM"
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<&'static str>();

    tokio::select! {
        name = ctrl_c => name,
        name = terminate => name,
    }
}

#[cfg(test)]
mod tests;
