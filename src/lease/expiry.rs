use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn};

use super::store::LeaseStore;
use super::types::LeaseState;
use crate::allocator::SubnetAllocator;

/// Process a single expiry tick: drain leases that expired by `now_epoch`,
/// mark them Expired, and release each IP back to its subnet allocator.
///
/// Returns the number of leases expired in this tick.
///
/// The lease record itself is preserved in the store (state -> Expired,
/// MAC/cid index intact) so the previous client can be re-offered the same
/// IP per RFC 2131 §4.3.1 when it reappears.
pub fn process_expired_once(
    store: &LeaseStore,
    allocators: &HashMap<String, SubnetAllocator>,
    now_epoch: u64,
) -> usize {
    let expired = store.drain_expired(now_epoch);
    for ip in &expired {
        let subnet = store.get(ip).map(|l| l.subnet.to_string());
        store.update_state(ip, LeaseState::Expired);

        match subnet {
            Some(net) => match allocators.get(&net) {
                Some(alloc) => {
                    alloc.release(ip);
                    debug!(%ip, subnet = %net, "lease expired, IP released to pool");
                }
                None => warn!(%ip, subnet = %net, "no allocator for expired lease subnet"),
            },
            None => debug!(%ip, "lease expired (no subnet record)"),
        }
    }
    expired.len()
}

/// Background task that drains the expiry queue once per second and releases
/// expired IPs back to their subnet allocators (issue #68).
pub async fn run_expiry_task(store: LeaseStore, allocators: Arc<HashMap<String, SubnetAllocator>>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let count = process_expired_once(&store, &allocators, now_epoch);
        if count > 0 {
            info!(count, "leases expired");
        }
    }
}
