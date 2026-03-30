//! High-availability module providing failover and replication backends.
//!
//! Supports standalone, active/active split-scope, and Raft consensus modes.

/// Active/active split-scope HA backend.
pub mod active_active;
/// Peer-to-peer TLS transport and message framing.
pub mod peer;
/// Wire protocol messages exchanged between HA peers.
pub mod protocol;
/// Raft consensus HA backend.
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

/// Errors that can occur during HA operations.
#[derive(Debug, thiserror::Error)]
pub enum HaError {
    /// Quorum could not be reached (Raft mode).
    #[error("no quorum available")]
    NoQuorum,
    /// The HA peer is unreachable.
    #[error("peer unreachable: {0}")]
    PeerUnreachable(String),
    /// An internal HA subsystem error.
    #[error("internal HA error: {0}")]
    Internal(String),
}

/// Snapshot of the current HA status, exposed via the management API.
#[derive(Debug, Clone)]
pub struct HaStatus {
    /// HA mode name (e.g. "standalone", "active-active", "raft").
    pub mode: String,
    /// Current role of this node (e.g. "primary", "leader", "follower").
    pub role: String,
    /// Human-readable peer state, if a peer is configured.
    pub peer_state: Option<String>,
    /// Whether the HA subsystem considers this node healthy.
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
