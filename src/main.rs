mod api;
mod audit;
mod config;
mod error;
mod keys;
mod middleware;
mod net;
mod proxy;
mod state;
mod vault;

use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use audit::AuditLog;
use config::{Config, UnlockMode};
use state::AppState;
use vault::refresh::{spawn_refresher, unlock_from_file};

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
    let log_filter = std::env::var("FERROWARDEN_LOG_LEVEL")
        .unwrap_or_else(|_| "info".to_string());
    let filter = EnvFilter::try_new(&log_filter)
        .unwrap_or_else(|_| {
            eprintln!("Invalid FERROWARDEN_LOG_LEVEL {:?}, falling back to info", log_filter);
            EnvFilter::new("info")
        });

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!("Ferrowarden starting");

    let config = Config::load()?;

    let audit = Arc::new(AuditLog::new(1000));

    let state = Arc::new(AppState::new_with_audit(config.clone(), audit));

    // Load persisted agent keys if a key file is configured
    if let Some(ref path) = config.keys_file {
        let stored = keys::load(path)?;
        if !stored.is_empty() {
            let mut map = state.agent_keys.write().await;
            for k in stored {
                map.insert(k.token_hash, crate::state::AgentKey {
                    id: k.id,
                    name: k.name,
                    created_at: k.created_at,
                });
            }
            tracing::info!("Loaded {} agent key(s) from {:?}", map.len(), path);
        }
    }

    // File mode: read and use the password before accepting any requests.
    // unlock_from_file also syncs bw serve and loads the credential cache.
    if config.unlock_mode == UnlockMode::File {
        tracing::info!("File unlock mode: reading password from {:?}", config.unlock_file);
        unlock_from_file(&state).await?;
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
    if config.allow_private_targets {
        tracing::warn!("allow_private_targets = true: agents may reach private/internal addresses (bw serve is still blocked)");
    }

    let router = api::router(state);

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
        axum_server::bind_rustls(addr, tls_config)
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
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    }

    Ok(())
}
