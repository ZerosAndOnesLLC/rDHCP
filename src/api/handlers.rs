use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use super::ApiState;
use crate::ha::HaBackend;

/// Query parameters for lease listing
#[derive(Debug, Deserialize)]
pub struct LeaseQuery {
    pub subnet: Option<String>,
    pub mac: Option<String>,
    pub state: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Lease response
#[derive(Debug, Serialize)]
pub struct LeaseResponse {
    pub ip: String,
    pub mac: Option<String>,
    pub client_id: Option<String>,
    pub hostname: Option<String>,
    pub lease_time: u32,
    pub state: String,
    pub start_time: u64,
    pub expire_time: u64,
    pub subnet: String,
}

/// Lease statistics per subnet
#[derive(Debug, Serialize)]
pub struct SubnetStats {
    pub subnet: String,
    pub total: u64,
    pub allocated: u64,
    pub available: u64,
    pub utilization: f64,
}

/// HA status response
#[derive(Debug, Serialize)]
pub struct HaStatusResponse {
    pub mode: String,
    pub role: String,
    pub peer_state: Option<String>,
    pub healthy: bool,
}

/// Subnet info response
#[derive(Debug, Serialize)]
pub struct SubnetResponse {
    pub network: String,
    pub pool_capacity: u64,
    pub allocated: u64,
    pub available: u64,
    pub utilization: f64,
}

// --- Handlers ---

pub async fn list_leases<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
    Query(query): Query<LeaseQuery>,
) -> Json<Vec<LeaseResponse>> {
    let limit = query.limit.unwrap_or(1000).min(10_000);
    let offset = query.offset.unwrap_or(0);

    let leases: Vec<LeaseResponse> = if let Some(ref subnet) = query.subnet {
        state
            .lease_store
            .leases_for_subnet(subnet)
            .into_iter()
            .map(lease_to_response)
            .collect()
    } else {
        // Get all leases (iterate all subnets via allocators)
        let mut all = Vec::new();
        for subnet_key in state.allocators.keys() {
            let subnet_leases = state.lease_store.leases_for_subnet(subnet_key);
            all.extend(subnet_leases.into_iter().map(lease_to_response));
        }
        all
    };

    // Apply MAC filter
    let leases: Vec<LeaseResponse> = if let Some(ref mac_filter) = query.mac {
        let mac_lower = mac_filter.to_lowercase();
        leases
            .into_iter()
            .filter(|l| {
                l.mac
                    .as_ref()
                    .is_some_and(|m| m.to_lowercase() == mac_lower)
            })
            .collect()
    } else {
        leases
    };

    // Apply state filter
    let leases: Vec<LeaseResponse> = if let Some(ref state_filter) = query.state {
        leases
            .into_iter()
            .filter(|l| l.state == *state_filter)
            .collect()
    } else {
        leases
    };

    // Apply pagination
    let leases: Vec<LeaseResponse> = leases.into_iter().skip(offset).take(limit).collect();

    Json(leases)
}

pub async fn get_lease<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
    Path(ip): Path<String>,
) -> Result<Json<LeaseResponse>, StatusCode> {
    let ip_addr: IpAddr = ip.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    match state.lease_store.get(&ip_addr) {
        Some(lease) => Ok(Json(lease_to_response(lease))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn delete_lease<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
    Path(ip): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let ip_addr: IpAddr = ip.parse().map_err(|_| StatusCode::BAD_REQUEST)?;

    match state.lease_store.remove(&ip_addr) {
        Some(_) => {
            // Release back to allocator
            for (_, allocator) in state.allocators.iter() {
                if allocator.contains(&ip_addr) {
                    allocator.release(&ip_addr);
                    break;
                }
            }
            Ok(StatusCode::NO_CONTENT)
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

pub async fn lease_stats<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
) -> Json<Vec<SubnetStats>> {
    let stats: Vec<SubnetStats> = state
        .allocators
        .iter()
        .map(|(subnet, allocator)| SubnetStats {
            subnet: subnet.clone(),
            total: allocator.capacity(),
            allocated: allocator.allocated(),
            available: allocator.available(),
            utilization: allocator.utilization(),
        })
        .collect();

    Json(stats)
}

pub async fn list_subnets<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
) -> Json<Vec<SubnetResponse>> {
    let subnets: Vec<SubnetResponse> = state
        .allocators
        .iter()
        .map(|(network, allocator)| SubnetResponse {
            network: network.clone(),
            pool_capacity: allocator.capacity(),
            allocated: allocator.allocated(),
            available: allocator.available(),
            utilization: allocator.utilization(),
        })
        .collect();

    Json(subnets)
}

pub async fn ha_status<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
) -> Json<HaStatusResponse> {
    let status = state.ha.status();
    Json(HaStatusResponse {
        mode: status.mode,
        role: status.role,
        peer_state: status.peer_state,
        healthy: status.healthy,
    })
}

/// Health check endpoint
pub async fn health_check<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ha_status = state.ha.status();
    Ok(Json(serde_json::json!({
        "status": "ok",
        "ha_mode": ha_status.mode,
        "ha_healthy": ha_status.healthy,
    })))
}

fn lease_to_response(lease: crate::lease::types::Lease) -> LeaseResponse {
    LeaseResponse {
        ip: lease.ip.to_string(),
        mac: lease.mac.map(|m| {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        }),
        client_id: lease
            .client_id
            .as_ref()
            .map(|c| c.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
        hostname: lease.hostname.map(|h| h.to_string()),
        lease_time: lease.lease_time,
        state: match lease.state {
            crate::lease::types::LeaseState::Offered => "offered".to_string(),
            crate::lease::types::LeaseState::Bound => "bound".to_string(),
            crate::lease::types::LeaseState::Expired => "expired".to_string(),
            crate::lease::types::LeaseState::Released => "released".to_string(),
            crate::lease::types::LeaseState::Declined => "declined".to_string(),
        },
        start_time: lease.start_time,
        expire_time: lease.expire_time,
        subnet: lease.subnet.to_string(),
    }
}
