mod allocator;
mod config;
mod ha;
mod lease;
mod wal;

use config::Config;
use lease::store::LeaseStore;
use tracing::{error, info};
use wal::Wal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/rdhcpd/config.toml".to_string());

    let config = match Config::load(&config_path) {
        Ok(c) => {
            info!(path = %config_path, "configuration loaded");
            c
        }
        Err(e) => {
            error!(path = %config_path, error = %e, "failed to load configuration");
            std::process::exit(1);
        }
    };

    // Initialize WAL
    let wal = Wal::open(&config.global.lease_db).await?;
    info!(path = %config.global.lease_db, "WAL opened");

    // Initialize lease store and replay WAL
    let lease_store = LeaseStore::new();
    let replayed = wal.replay(&lease_store).await?;
    info!(replayed, "WAL replay complete");

    // Initialize allocators from config and lease state
    let allocators = allocator::build_allocators(&config, &lease_store)?;
    info!(subnets = allocators.len(), "subnet allocators initialized");

    // Start lease expiry background task
    let expiry_store = lease_store.clone();
    let expiry_handle = tokio::spawn(async move {
        lease::expiry::run_expiry_task(expiry_store).await;
    });

    info!("rdhcpd starting");

    // TODO: Phase 2+ — start DHCPv4/v6 listeners, HA backend, management API

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("shutting down");

    expiry_handle.abort();
    wal.flush().await?;
    info!("WAL flushed, goodbye");

    Ok(())
}
