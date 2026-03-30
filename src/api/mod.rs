//! Management REST API for querying leases, subnets, HA status, and metrics.

mod handlers;
mod metrics;

use std::collections::HashMap;
use std::sync::Arc;

use axum::routing::{delete, get};
use axum::Router;
use tokio::net::TcpListener;
use tracing::info;

use crate::allocator::SubnetAllocator;
use crate::ha::HaBackend;
use crate::lease::store::LeaseStore;

/// Shared state available to all API handlers
pub struct ApiState<H: HaBackend> {
    /// In-memory lease store for querying active and historical leases
    pub lease_store: LeaseStore,
    /// Subnet allocators keyed by network CIDR string
    pub allocators: Arc<HashMap<String, SubnetAllocator>>,
    /// High-availability backend for peer state replication
    pub ha: Arc<H>,
    /// Optional API key for authenticating management requests
    pub api_key: Option<String>,
}

/// Start the management API server
pub async fn start<H: HaBackend + 'static>(
    listen_addr: &str,
    state: Arc<ApiState<H>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        // Lease endpoints
        .route("/api/v1/leases", get(handlers::list_leases::<H>))
        .route("/api/v1/leases/{ip}", get(handlers::get_lease::<H>))
        .route(
            "/api/v1/leases/{ip}",
            delete(handlers::delete_lease::<H>),
        )
        .route("/api/v1/leases/stats", get(handlers::lease_stats::<H>))
        // Subnet endpoints
        .route("/api/v1/subnets", get(handlers::list_subnets::<H>))
        // HA endpoints
        .route("/api/v1/ha/status", get(handlers::ha_status::<H>))
        // Health check
        .route("/health", get(handlers::health_check::<H>))
        .route("/healthz", get(handlers::health_check::<H>))
        // Metrics
        .route("/metrics", get(metrics::metrics_handler::<H>))
        .with_state(state);

    let listener = TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, "management API started");

    axum::serve(listener, app).await?;

    Ok(())
}
