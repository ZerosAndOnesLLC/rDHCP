use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;

use super::types::{Lease, LeaseState};

/// Thread-safe, lock-free lease store backed by DashMap
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
}

impl LeaseStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(LeaseStoreInner {
                leases: DashMap::new(),
                mac_index: DashMap::new(),
                client_id_index: DashMap::new(),
            }),
        }
    }

    /// Insert or update a lease. Updates secondary indexes.
    pub fn upsert(&self, lease: Lease) {
        let ip = lease.ip;

        // Update secondary indexes
        if let Some(mac) = lease.mac {
            self.inner.mac_index.insert(mac, ip);
        }
        if let Some(ref cid) = lease.client_id {
            self.inner.client_id_index.insert(cid.clone(), ip);
        }

        self.inner.leases.insert(ip, lease);
    }

    /// Get a lease by IP address
    pub fn get(&self, ip: &IpAddr) -> Option<Lease> {
        self.inner.leases.get(ip).map(|r| r.clone())
    }

    /// Find a lease by MAC address
    pub fn get_by_mac(&self, mac: &[u8; 6]) -> Option<Lease> {
        self.inner
            .mac_index
            .get(mac)
            .and_then(|ip| self.inner.leases.get(ip.value()).map(|r| r.clone()))
    }

    /// Find a lease by client ID / DUID
    pub fn get_by_client_id(&self, client_id: &[u8]) -> Option<Lease> {
        self.inner
            .client_id_index
            .get(client_id)
            .and_then(|ip| self.inner.leases.get(ip.value()).map(|r| r.clone()))
    }

    /// Remove a lease and clean up secondary indexes
    pub fn remove(&self, ip: &IpAddr) -> Option<Lease> {
        if let Some((_, lease)) = self.inner.leases.remove(ip) {
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

    /// Update lease state by IP
    pub fn update_state(&self, ip: &IpAddr, state: LeaseState) -> bool {
        if let Some(mut entry) = self.inner.leases.get_mut(ip) {
            entry.state = state;
            true
        } else {
            false
        }
    }

    /// Number of active leases
    pub fn active_count(&self) -> usize {
        self.inner
            .leases
            .iter()
            .filter(|r| r.value().is_active())
            .count()
    }

    /// Total number of leases (all states)
    pub fn total_count(&self) -> usize {
        self.inner.leases.len()
    }

    /// Iterate all leases, collecting expired ones.
    /// Returns IPs of leases that have expired.
    pub fn collect_expired(&self, now_epoch: u64) -> Vec<IpAddr> {
        self.inner
            .leases
            .iter()
            .filter(|r| {
                r.value().state == LeaseState::Bound && r.value().is_expired_at(now_epoch)
            })
            .map(|r| *r.key())
            .collect()
    }

    /// Iterate all leases, collecting offered leases that have timed out.
    /// Offers expire much faster (typically 10-60 seconds).
    pub fn collect_stale_offers(&self, now_epoch: u64) -> Vec<IpAddr> {
        self.inner
            .leases
            .iter()
            .filter(|r| {
                r.value().state == LeaseState::Offered && r.value().is_expired_at(now_epoch)
            })
            .map(|r| *r.key())
            .collect()
    }

    /// Get all leases for a given subnet
    pub fn leases_for_subnet(&self, subnet: &str) -> Vec<Lease> {
        self.inner
            .leases
            .iter()
            .filter(|r| r.value().subnet == subnet)
            .map(|r| r.value().clone())
            .collect()
    }

    /// Check if an IP is currently leased (Offered or Bound)
    pub fn is_allocated(&self, ip: &IpAddr) -> bool {
        self.inner
            .leases
            .get(ip)
            .is_some_and(|r| r.value().is_active())
    }
}
