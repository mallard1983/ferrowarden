mod api;
mod audit;
mod config;
mod error;
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
        tracing::info!(
            "Manual unlock mode: POST /v1/unlock with admin key to unlock the vault"
        );
    }

    let router = api::router(state);

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!("Listening on {}", config.bind_addr);

    axum::serve(listener, router).await?;

    Ok(())
}
