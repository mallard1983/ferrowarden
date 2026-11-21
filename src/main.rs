mod api;
mod audit;
mod config;
mod error;
mod keys;
mod proxy;
mod state;
mod vault;

use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use audit::AuditLog;
use config::{Config, UnlockMode};
use state::AppState;
use vault::{read_password_file, unlock_vault, VaultClient};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Structured JSON logging — compatible with Loki/Grafana
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
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

    // File mode: read and use the password before accepting any requests
    if config.unlock_mode == UnlockMode::File {
        let path = config
            .unlock_file
            .as_ref()
            .expect("unlock_file required in file mode");

        tracing::info!("File unlock mode: reading password from {:?}", path);

        let password = read_password_file(path)?;
        unlock_vault(&config.bw_serve_url, password).await?;

        // Populate credential name cache
        let vault_client = VaultClient::new(config.bw_serve_url.clone());
        let names = vault_client.list_item_names().await?;
        *state.credential_names.write().await = names;

        state.set_unlocked().await;

        tracing::info!("Vault unlocked via file mode");
    } else {
        tracing::info!("Manual unlock mode: POST /v1/unlock with admin key to unlock the vault");
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
            .serve(router.into_make_service())
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
        axum::serve(listener, router).await?;
    }

    Ok(())
}
