use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;

use super::types::{Lease, LeaseState};

/// Thread-safe, lock-free lease store backed by DashMap.
/// Uses atomic counters for O(1) stats and a time-indexed expiry queue
/// to avoid full-table scans.
#[derive(Debug, Clone)]
pub struct LeaseStore {
    inner: Arc<LeaseStoreInner>,
}

#[derive(Debug)]
struct LeaseStoreInner {
    /// Primary index: IP → Lease
    leases: DashMap<IpAddr, Lease>,
    /// Secondary index: MAC → IP (for fast client lookups in DHCPv4)
    mac_index: DashMap<[u8; 6], IpAddr>,
    /// Secondary index: client_id → IP (for DHCPv6 DUID lookups)
    client_id_index: DashMap<Vec<u8>, IpAddr>,
    /// Expiry queue: expire_time → list of IPs expiring at that second.
    /// Protected by Mutex since it's only accessed by the expiry task + upsert.
    expiry_queue: Mutex<BTreeMap<u64, Vec<IpAddr>>>,
    /// Atomic active lease counter (Offered + Bound)
    active_count: AtomicUsize,
}

impl LeaseStore {
    /// Create an empty lease store with no leases.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(LeaseStoreInner {
                leases: DashMap::new(),
                mac_index: DashMap::new(),
                client_id_index: DashMap::new(),
                expiry_queue: Mutex::new(BTreeMap::new()),
                active_count: AtomicUsize::new(0),
            }),
        }
    }

    /// Insert or update a lease. Cleans up stale secondary indexes.
    pub fn upsert(&self, lease: Lease) {
        let ip = lease.ip;
        let was_active;

        // Clean up old secondary indexes if IP already existed with different identifiers
        if let Some(old) = self.inner.leases.get(&ip) {
            was_active = old.is_active();
            if let Some(old_mac) = old.mac {
                if lease.mac != Some(old_mac) {
                    self.inner.mac_index.remove(&old_mac);
                }
            }
            if let Some(ref old_cid) = old.client_id {
                if lease.client_id.as_ref() != Some(old_cid) {
                    self.inner.client_id_index.remove(old_cid);
                }
            }
        } else {
            was_active = false;
        }

        let is_active = lease.is_active();

        // Update active counter
        if is_active && !was_active {
            self.inner.active_count.fetch_add(1, Ordering::Relaxed);
        } else if !is_active && was_active {
            self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
        }

        // Update secondary indexes
        if let Some(mac) = lease.mac {
            self.inner.mac_index.insert(mac, ip);
        }
        if let Some(ref cid) = lease.client_id {
            self.inner.client_id_index.insert(cid.clone(), ip);
        }

        // Add to expiry queue
        if is_active {
            let mut eq = self.inner.expiry_queue.lock().unwrap();
            eq.entry(lease.expire_time).or_insert_with(Vec::new).push(ip);
        }

        self.inner.leases.insert(ip, lease);
    }

    /// Get a lease by IP address.
    pub fn get(&self, ip: &IpAddr) -> Option<Lease> {
        self.inner.leases.get(ip).map(|r| r.clone())
    }

    /// Find a lease by MAC address.
    pub fn get_by_mac(&self, mac: &[u8; 6]) -> Option<Lease> {
        let ip = *self.inner.mac_index.get(mac)?.value();
        self.inner.leases.get(&ip).map(|r| r.clone())
    }

    /// Find a lease by client ID / DUID.
    pub fn get_by_client_id(&self, client_id: &[u8]) -> Option<Lease> {
        let ip = *self.inner.client_id_index.get(client_id)?.value();
        self.inner.leases.get(&ip).map(|r| r.clone())
    }

    /// Remove a lease and clean up all indexes.
    pub fn remove(&self, ip: &IpAddr) -> Option<Lease> {
        if let Some((_, lease)) = self.inner.leases.remove(ip) {
            if lease.is_active() {
                self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
            }
            if let Some(mac) = lease.mac {
                self.inner.mac_index.remove(&mac);
            }
            if let Some(ref cid) = lease.client_id {
                self.inner.client_id_index.remove(cid);
            }
            Some(lease)
        } else {
            None
        }
    }

    /// Update lease state by IP.
    pub fn update_state(&self, ip: &IpAddr, state: LeaseState) -> bool {
        if let Some(mut entry) = self.inner.leases.get_mut(ip) {
            let was_active = entry.is_active();
            entry.state = state;
            let is_active = entry.is_active();

            if is_active && !was_active {
                self.inner.active_count.fetch_add(1, Ordering::Relaxed);
            } else if !is_active && was_active {
                self.inner.active_count.fetch_sub(1, Ordering::Relaxed);
            }
            true
        } else {
            false
        }
    }

    /// Number of active leases — O(1) via atomic counter.
    #[inline]
    pub fn active_count(&self) -> usize {
        self.inner.active_count.load(Ordering::Relaxed)
    }

    /// Total number of leases (all states) — O(1).
    #[inline]
    pub fn total_count(&self) -> usize {
        self.inner.leases.len()
    }

    /// Drain expired leases up to `now_epoch` from the expiry queue.
    /// Returns IPs that have expired. O(k) where k = number expired.
    pub fn drain_expired(&self, now_epoch: u64) -> Vec<IpAddr> {
        let mut eq = self.inner.expiry_queue.lock().unwrap();
        let mut expired = Vec::new();

        // Split off all entries with key <= now_epoch
        let remaining = eq.split_off(&(now_epoch + 1));
        let due = std::mem::replace(&mut *eq, remaining);

        for (_time, ips) in due {
            for ip in ips {
                // Verify the lease is still active and actually expired
                // (it may have been renewed, changing expire_time)
                if let Some(lease) = self.inner.leases.get(&ip) {
                    if lease.is_active() && lease.is_expired_at(now_epoch) {
                        expired.push(ip);
                    }
                }
            }
        }

        expired
    }

    /// Get all leases for a given subnet.
    pub fn leases_for_subnet(&self, subnet: &str) -> Vec<Lease> {
        self.inner
            .leases
            .iter()
            .filter(|r| &*r.value().subnet == subnet)
            .map(|r| r.value().clone())
            .collect()
    }

    /// Check if an IP is currently leased (Offered or Bound) — no clone.
    #[inline]
    pub fn is_allocated(&self, ip: &IpAddr) -> bool {
        self.inner
            .leases
            .get(ip)
            .is_some_and(|r| r.is_active())
    }

    /// Return all active (Offered or Bound) leases. Used for WAL compaction.
    pub fn all_active_leases(&self) -> Vec<Lease> {
        self.inner
            .leases
            .iter()
            .filter(|r| r.value().is_active())
            .map(|r| r.value().clone())
            .collect()
    }
}
