pub mod active_active;
pub mod peer;
pub mod protocol;
pub mod raft;

use std::net::IpAddr;

use crate::lease::types::Lease;

/// HA backend trait — the DHCP engine calls this to commit lease operations.
/// Each HA mode (standalone, active/active, raft) implements this differently.
pub trait HaBackend: Send + Sync {
    /// Propose a lease assignment. Returns Ok when safe to ack the client.
    /// - Standalone: always returns Ok immediately
    /// - Active/Active: syncs to peer asynchronously, returns Ok
    /// - Raft: blocks until quorum ack
    fn commit_lease(
        &self,
        lease: &Lease,
    ) -> impl std::future::Future<Output = Result<(), HaError>> + Send;

    /// Release or expire a lease
    fn release_lease(
        &self,
        ip: &IpAddr,
    ) -> impl std::future::Future<Output = Result<(), HaError>> + Send;

    /// Check if this node should serve a request for the given IP.
    /// - Standalone: always true
    /// - Active/Active: checks split-scope boundary
    /// - Raft: true only on leader
    fn owns_ip(&self, ip: &IpAddr) -> bool;

    /// Current HA status for management API
    fn status(&self) -> HaStatus;
}

#[derive(Debug, thiserror::Error)]
pub enum HaError {
    #[error("no quorum available")]
    NoQuorum,
    #[error("peer unreachable: {0}")]
    PeerUnreachable(String),
    #[error("internal HA error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct HaStatus {
    pub mode: String,
    pub role: String,
    pub peer_state: Option<String>,
    pub healthy: bool,
}

/// Standalone HA backend — no replication, single node
pub struct StandaloneBackend;

impl HaBackend for StandaloneBackend {
    async fn commit_lease(&self, _lease: &Lease) -> Result<(), HaError> {
        Ok(())
    }

    async fn release_lease(&self, _ip: &IpAddr) -> Result<(), HaError> {
        Ok(())
    }

    fn owns_ip(&self, _ip: &IpAddr) -> bool {
        true
    }

    fn status(&self) -> HaStatus {
        HaStatus {
            mode: "standalone".to_string(),
            role: "primary".to_string(),
            peer_state: None,
            healthy: true,
        }
    }
}
