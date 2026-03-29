use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{debug, info};

use super::store::LeaseStore;
use super::types::LeaseState;

/// Background task that periodically checks for and cleans up expired leases.
/// Runs every second to catch expirations promptly.
pub async fn run_expiry_task(store: LeaseStore) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        interval.tick().await;

        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Expire bound leases
        let expired = store.collect_expired(now_epoch);
        for ip in &expired {
            store.update_state(ip, LeaseState::Expired);
            debug!(%ip, "lease expired");
        }
        if !expired.is_empty() {
            info!(count = expired.len(), "leases expired");
        }

        // Clean up stale offers (offers that were never followed by a Request)
        let stale_offers = store.collect_stale_offers(now_epoch);
        for ip in &stale_offers {
            store.remove(ip);
            debug!(%ip, "stale offer removed");
        }
    }
}
