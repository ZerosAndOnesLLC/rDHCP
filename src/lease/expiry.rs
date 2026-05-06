use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, info, warn};

use super::store::LeaseStore;
use super::types::LeaseState;
use crate::allocator::SubnetAllocator;

/// Background task that drains the expiry queue and marks leases as expired.
/// Uses the time-indexed BTreeMap instead of full table scans.
///
/// Releases the IP back to its subnet allocator so the bitmap reflects truth
/// (issue #68). The lease record itself is preserved in the store so that the
/// previous client can be re-offered the same IP per RFC 2131 §4.3.1 when it
/// reappears.
pub async fn run_expiry_task(
    store: LeaseStore,
    allocators: Arc<HashMap<String, SubnetAllocator>>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

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
        if !expired.is_empty() {
            info!(count = expired.len(), "leases expired");
        }
    }
}
