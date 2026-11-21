mod api;
mod config;
mod error;
mod events;
mod keys;
mod middleware;
mod net;
mod policy;
mod proxy;
mod state;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    tracing::info!("Ferrowarden starting");

    let config = Config::load()?;

    // Security events: ring buffer for /v1/admin/audit plus the configured
    // sinks (stdout by default). Application logs stay on tracing.
    let events = EventLog::start(&config.events)?;

    let state = Arc::new(AppState::new(config.clone(), events.clone()));

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

    let router = api::router(state);

    // Set by the signal handler, read after the server stops.
    let signal: Arc<OnceLock<&'static str>> = Arc::new(OnceLock::new());

    let addr: std::net::SocketAddr = config.bind_addr.parse()?;

    if config.tls_enabled {
        let cert = config
            .tls_cert_file
            .as_ref()
            .expect("tls_cert_file required when tls_enabled");
        let key = config
            .tls_key_file
            .as_ref()
            .expect("tls_key_file required when tls_enabled");

        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key).await?;

        tracing::info!("Listening on https://{} (TLS)", addr);
        let handle = axum_server::Handle::new();
        tokio::spawn({
            let handle = handle.clone();
            let signal = signal.clone();
            async move {
                let _ = signal.set(shutdown_signal().await);
                handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
            }
        });
        axum_server::bind_rustls(addr, tls_config)
            .handle(handle)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
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

        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!("Listening on http://{} (plaintext)", addr);
        let signal = signal.clone();
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = signal.set(shutdown_signal().await);
        })
        .await?;
    }

    // Graceful stop: tell the stream, then flush the sinks before exiting.
    events.emit(
        SecurityEvent::new(Action::Shutdown)
            .detail("signal", signal.get().copied().unwrap_or("none")),
    );
    events.flush().await;
    tracing::info!("Ferrowarden stopped");

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
