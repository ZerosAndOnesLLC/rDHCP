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
    retention_secs: u64,
) -> usize {
    let expired = store.drain_expired(now_epoch);
    for ip in &expired {
        let subnet = store.get(ip).map(|l| l.subnet.to_string());
        store.update_state(ip, LeaseState::Expired);

        // Retain the expired lease for stickiness, but schedule it to be reaped
        // after the retention window so memory stays bounded (0 = keep forever).
        if retention_secs > 0 {
            store.schedule_reap(*ip, now_epoch.saturating_add(retention_secs));
        }

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

/// Reap expired leases that have outlived the retention window, fully removing
/// them from the store (primary map + MAC/client-id indexes). A lease that was
/// re-offered within the window is skipped. Returns the number reaped.
pub fn reap_expired_once(store: &LeaseStore, now_epoch: u64, retention_secs: u64) -> usize {
    if retention_secs == 0 {
        return 0;
    }
    let reapable = store.drain_reapable(now_epoch, retention_secs);
    for ip in &reapable {
        store.remove(ip);
        debug!(%ip, "expired lease reaped from store after retention window");
    }
    reapable.len()
}

/// Background task that drains the expiry queue once per second, releases expired
/// IPs back to their subnet allocators (issue #68), and reaps expired leases that
/// have outlived `retention_secs` so the store stays bounded (issue #73).
pub async fn run_expiry_task(
    store: LeaseStore,
    allocators: Arc<HashMap<String, SubnetAllocator>>,
    retention_secs: u64,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let count = process_expired_once(&store, &allocators, now_epoch, retention_secs);
        if count > 0 {
            info!(count, "leases expired");
        }

        let reaped = reap_expired_once(&store, now_epoch, retention_secs);
        if reaped > 0 {
            info!(reaped, "expired leases reaped from store");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::types::Lease;
    use std::net::IpAddr;
    use std::time::Instant;

    fn make_lease(ip: &str, mac: u8, expire_time: u64, state: LeaseState) -> Lease {
        Lease {
            ip: ip.parse::<IpAddr>().unwrap(),
            mac: Some([mac; 6]),
            client_id: None,
            hostname: None,
            lease_time: 60,
            state,
            start_time: 0,
            expire_time,
            expires_at: Instant::now(),
            subnet: Arc::from("10.0.0.0/8"),
        }
    }

    /// Mimic what `process_expired_once` does when a lease expires.
    fn expire_and_schedule(store: &LeaseStore, ip: IpAddr, now: u64, retention: u64) {
        store.update_state(&ip, LeaseState::Expired);
        store.schedule_reap(ip, now + retention);
    }

    #[test]
    fn expired_lease_reaped_after_retention() {
        let store = LeaseStore::new();
        let ip: IpAddr = "10.0.1.5".parse().unwrap();
        store.upsert(make_lease("10.0.1.5", 1, 100, LeaseState::Bound));
        expire_and_schedule(&store, ip, 100, 60); // reap at 160

        assert!(store.get(&ip).is_some(), "retained during window");
        assert_eq!(
            reap_expired_once(&store, 159, 60),
            0,
            "not reaped before window ends"
        );
        assert_eq!(
            reap_expired_once(&store, 160, 60),
            1,
            "reaped at window end"
        );
        assert!(store.get(&ip).is_none(), "fully removed from primary map");
        assert!(
            store.get_by_mac(&[1u8; 6]).is_none(),
            "MAC index cleaned up"
        );
    }

    #[test]
    fn reoffered_lease_within_window_not_reaped() {
        let store = LeaseStore::new();
        let ip: IpAddr = "10.0.1.6".parse().unwrap();
        store.upsert(make_lease("10.0.1.6", 2, 100, LeaseState::Bound));
        expire_and_schedule(&store, ip, 100, 60);
        // Client returns before the window closes — re-offered, active again.
        store.upsert(make_lease("10.0.1.6", 2, 300, LeaseState::Bound));

        assert_eq!(
            reap_expired_once(&store, 160, 60),
            0,
            "active lease must not be reaped"
        );
        assert_eq!(store.get(&ip).unwrap().state, LeaseState::Bound);
    }

    #[test]
    fn retention_zero_keeps_forever() {
        let store = LeaseStore::new();
        let ip: IpAddr = "10.0.1.7".parse().unwrap();
        store.upsert(make_lease("10.0.1.7", 3, 100, LeaseState::Bound));
        store.update_state(&ip, LeaseState::Expired);

        assert_eq!(
            reap_expired_once(&store, 10_000_000, 0),
            0,
            "no-op when retention=0"
        );
        assert!(
            store.get(&ip).is_some(),
            "expired lease kept forever when retention=0"
        );
    }

    #[test]
    fn reallocated_slot_not_reaped_early() {
        // IP expires (reap scheduled at 160). Before then it is reallocated to a new
        // client whose short lease also expires. The stale reap entry must not remove
        // the new client's still-within-retention expired lease.
        let store = LeaseStore::new();
        let ip: IpAddr = "10.0.1.8".parse().unwrap();
        store.upsert(make_lease("10.0.1.8", 4, 100, LeaseState::Bound));
        expire_and_schedule(&store, ip, 100, 60); // stale reap_at = 160

        store.upsert(make_lease("10.0.1.8", 5, 150, LeaseState::Bound));
        expire_and_schedule(&store, ip, 150, 60); // new reap_at = 210

        assert_eq!(
            reap_expired_once(&store, 160, 60),
            0,
            "new client's lease preserved"
        );
        assert!(store.get(&ip).is_some());
        assert_eq!(
            reap_expired_once(&store, 210, 60),
            1,
            "reaped once its own window closes"
        );
        assert!(store.get(&ip).is_none());
    }
}
