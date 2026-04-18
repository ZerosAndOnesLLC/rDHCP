//! Management REST API for querying leases, subnets, HA status, and metrics.

mod handlers;
mod metrics;

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get};
use axum::Router;
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tracing::info;

use crate::allocator::SubnetAllocator;
use crate::ha::HaBackend;
use crate::lease::store::LeaseStore;
use crate::wal::Wal;

/// Shared state available to all API handlers
pub struct ApiState<H: HaBackend> {
    /// In-memory lease store for querying active and historical leases
    pub lease_store: LeaseStore,
    /// Subnet allocators keyed by network CIDR string
    pub allocators: Arc<HashMap<String, SubnetAllocator>>,
    /// High-availability backend for peer state replication
    pub ha: Arc<H>,
    /// Write-ahead log for durable lease persistence
    pub wal: Arc<Wal>,
    /// Optional API key for authenticating management requests
    pub api_key: Option<String>,
    /// DHCPv4 relay observability counters
    pub dhcpv4_stats: Arc<crate::dhcpv4::stats::DhcpV4Stats>,
}

/// Authentication middleware — checks X-API-Key header against configured key.
/// Health and metrics endpoints are exempt.
async fn auth_middleware<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip auth for health checks only (metrics require auth as they expose pool data)
    let path = req.uri().path();
    if path == "/health" || path == "/healthz" {
        return Ok(next.run(req).await);
    }

    // If no API key configured, allow everything
    let Some(ref expected_key) = state.api_key else {
        return Ok(next.run(req).await);
    };

    // Check X-API-Key header (constant-time comparison to prevent timing attacks)
    match req.headers().get("x-api-key") {
        Some(provided)
            if provided.as_bytes().ct_eq(expected_key.as_bytes()).into() =>
        {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
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
        // Authentication middleware
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::<H>,
        ))
        .with_state(state);

    let listener = TcpListener::bind(listen_addr).await?;
    info!(addr = %listen_addr, "management API started");

    axum::serve(listener, app).await?;

    Ok(())
}
