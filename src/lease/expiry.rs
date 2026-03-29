use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, info};

use super::store::LeaseStore;
use super::types::LeaseState;

/// Background task that drains the expiry queue and marks leases as expired.
/// Uses the time-indexed BTreeMap instead of full table scans.
pub async fn run_expiry_task(store: LeaseStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired = store.drain_expired(now_epoch);
        for ip in &expired {
            store.update_state(ip, LeaseState::Expired);
            debug!(%ip, "lease expired");
        }
        if !expired.is_empty() {
            info!(count = expired.len(), "leases expired");
        }
    }
}
