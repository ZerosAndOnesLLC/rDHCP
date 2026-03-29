mod allocator;
mod config;
mod dhcpv4;
mod dhcpv6;
mod ha;
mod lease;
mod wal;

use std::net::Ipv4Addr;
use std::sync::Arc;

use config::Config;
use dhcpv4::server::DhcpV4Server;
use dhcpv6::server::{generate_server_duid, DhcpV6Server};
use ha::StandaloneBackend;
use lease::store::LeaseStore;
use tokio::net::UdpSocket;
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
    let wal = Arc::new(Wal::open(&config.global.lease_db).await?);
    info!(path = %config.global.lease_db, "WAL opened");

    // Initialize lease store and replay WAL
    let lease_store = LeaseStore::new();
    let replayed = wal.replay(&lease_store).await?;
    info!(replayed, "WAL replay complete");

    // Initialize allocators from config and lease state
    let allocators = Arc::new(allocator::build_allocators(&config, &lease_store)?);
    info!(subnets = allocators.len(), "subnet allocators initialized");

    // Initialize HA backend
    // TODO: Phase 4/5 — select based on config.ha
    let ha: Arc<StandaloneBackend> = Arc::new(StandaloneBackend);

    let config = Arc::new(config);

    // Start lease expiry background task
    let expiry_store = lease_store.clone();
    let expiry_handle = tokio::spawn(async move {
        lease::expiry::run_expiry_task(expiry_store).await;
    });

    // Determine server IP for DHCPv4
    let server_ip = config
        .subnet
        .iter()
        .find_map(|s| {
            s.router
                .as_ref()
                .and_then(|r| r.parse::<Ipv4Addr>().ok())
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    // Check if we have v4 subnets
    let has_v4 = config.subnet.iter().any(|s| {
        s.network.contains('.') && s.subnet_type != "prefix-delegation"
    });

    // Check if we have v6 subnets
    let has_v6 = config.subnet.iter().any(|s| s.network.contains(':'));

    // Start DHCPv4 server if v4 subnets configured
    let dhcpv4_handle = if has_v4 {
        let dhcpv4_socket = Arc::new(
            UdpSocket::bind("0.0.0.0:67")
                .await
                .map_err(|e| {
                    format!(
                        "failed to bind DHCPv4 socket on port 67: {} (try running as root)",
                        e
                    )
                })?,
        );
        dhcpv4_socket.set_broadcast(true)?;

        let dhcpv4_server = DhcpV4Server::new(
            config.clone(),
            lease_store.clone(),
            allocators.clone(),
            wal.clone(),
            ha.clone(),
            server_ip,
        );

        Some(tokio::spawn(async move {
            if let Err(e) = dhcpv4_server.run(dhcpv4_socket).await {
                error!(error = %e, "DHCPv4 server error");
            }
        }))
    } else {
        info!("no IPv4 subnets configured, DHCPv4 disabled");
        None
    };

    // Start DHCPv6 server if v6 subnets configured
    let dhcpv6_handle = if has_v6 {
        let dhcpv6_socket = Arc::new(
            UdpSocket::bind("[::]:547")
                .await
                .map_err(|e| {
                    format!(
                        "failed to bind DHCPv6 socket on port 547: {} (try running as root)",
                        e
                    )
                })?,
        );

        // Generate or load server DUID
        // TODO: persist DUID to disk so it survives restarts
        let server_duid = generate_server_duid();
        info!(duid_len = server_duid.len(), "server DUID generated");

        let dhcpv6_server = DhcpV6Server::new(
            config.clone(),
            lease_store.clone(),
            allocators.clone(),
            wal.clone(),
            ha.clone(),
            server_duid,
        );

        Some(tokio::spawn(async move {
            if let Err(e) = dhcpv6_server.run(dhcpv6_socket).await {
                error!(error = %e, "DHCPv6 server error");
            }
        }))
    } else {
        info!("no IPv6 subnets configured, DHCPv6 disabled");
        None
    };

    info!(
        server_ip = %server_ip,
        v4 = has_v4,
        v6 = has_v6,
        "rdhcpd started"
    );

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("shutting down");

    if let Some(h) = dhcpv4_handle {
        h.abort();
    }
    if let Some(h) = dhcpv6_handle {
        h.abort();
    }
    expiry_handle.abort();
    wal.flush().await?;
    info!("WAL flushed, goodbye");

    Ok(())
}
