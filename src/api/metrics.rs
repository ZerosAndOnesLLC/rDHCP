use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use super::ApiState;
use crate::ha::HaBackend;

/// Prometheus metrics handler — exposition format
pub async fn metrics_handler<H: HaBackend>(
    State(state): State<Arc<ApiState<H>>>,
) -> impl IntoResponse {
    let mut output = String::with_capacity(4096);

    // Lease metrics per subnet
    output.push_str("# HELP rdhcpd_pool_total Total IPs in pool\n");
    output.push_str("# TYPE rdhcpd_pool_total gauge\n");
    for (subnet, allocator) in state.allocators.iter() {
        output.push_str(&format!(
            "rdhcpd_pool_total{{subnet=\"{}\"}} {}\n",
            subnet,
            allocator.capacity()
        ));
    }

    output.push_str("# HELP rdhcpd_pool_allocated Currently allocated IPs\n");
    output.push_str("# TYPE rdhcpd_pool_allocated gauge\n");
    for (subnet, allocator) in state.allocators.iter() {
        output.push_str(&format!(
            "rdhcpd_pool_allocated{{subnet=\"{}\"}} {}\n",
            subnet,
            allocator.allocated()
        ));
    }

    output.push_str("# HELP rdhcpd_pool_available Available IPs in pool\n");
    output.push_str("# TYPE rdhcpd_pool_available gauge\n");
    for (subnet, allocator) in state.allocators.iter() {
        output.push_str(&format!(
            "rdhcpd_pool_available{{subnet=\"{}\"}} {}\n",
            subnet,
            allocator.available()
        ));
    }

    output.push_str("# HELP rdhcpd_pool_utilization Pool utilization percentage\n");
    output.push_str("# TYPE rdhcpd_pool_utilization gauge\n");
    for (subnet, allocator) in state.allocators.iter() {
        output.push_str(&format!(
            "rdhcpd_pool_utilization{{subnet=\"{}\"}} {:.2}\n",
            subnet,
            allocator.utilization()
        ));
    }

    // Lease state counts
    output.push_str("# HELP rdhcpd_leases_by_state Number of leases by state\n");
    output.push_str("# TYPE rdhcpd_leases_by_state gauge\n");
    for subnet_key in state.allocators.keys() {
        let leases = state.lease_store.leases_for_subnet(subnet_key);
        let mut offered = 0u64;
        let mut bound = 0u64;
        let mut expired = 0u64;
        let mut declined = 0u64;

        for lease in &leases {
            match lease.state {
                crate::lease::types::LeaseState::Offered => offered += 1,
                crate::lease::types::LeaseState::Bound => bound += 1,
                crate::lease::types::LeaseState::Expired => expired += 1,
                crate::lease::types::LeaseState::Declined => declined += 1,
                crate::lease::types::LeaseState::Released => {}
            }
        }

        output.push_str(&format!(
            "rdhcpd_leases_by_state{{subnet=\"{}\",state=\"offered\"}} {}\n",
            subnet_key, offered
        ));
        output.push_str(&format!(
            "rdhcpd_leases_by_state{{subnet=\"{}\",state=\"bound\"}} {}\n",
            subnet_key, bound
        ));
        output.push_str(&format!(
            "rdhcpd_leases_by_state{{subnet=\"{}\",state=\"expired\"}} {}\n",
            subnet_key, expired
        ));
        output.push_str(&format!(
            "rdhcpd_leases_by_state{{subnet=\"{}\",state=\"declined\"}} {}\n",
            subnet_key, declined
        ));
    }

    // HA status
    let ha_status = state.ha.status();
    output.push_str("# HELP rdhcpd_ha_healthy Whether HA is healthy\n");
    output.push_str("# TYPE rdhcpd_ha_healthy gauge\n");
    output.push_str(&format!(
        "rdhcpd_ha_healthy{{mode=\"{}\"}} {}\n",
        ha_status.mode,
        if ha_status.healthy { 1 } else { 0 }
    ));

    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], output)
}
