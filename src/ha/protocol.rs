use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::lease::types::LeaseState;

/// HA wire protocol messages exchanged between peers.
/// Framed as: [4-byte big-endian length][JSON payload]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HaMessage {
    /// Heartbeat / keepalive
    Heartbeat {
        node_id: String,
        state: PeerState,
        active_leases: u64,
        timestamp: u64,
    },

    /// Lease sync — push a lease to the peer
    LeaseSync {
        ip: String,
        mac: Option<String>,
        client_id: Option<Vec<u8>>,
        hostname: Option<String>,
        lease_time: u32,
        state: u8,
        start_time: u64,
        expire_time: u64,
        subnet: String,
    },

    /// Lease release notification
    LeaseRelease { ip: String },

    /// Request a full lease sync (on reconnection)
    BulkSyncRequest {
        /// Epoch timestamp of last known sync
        since: u64,
    },

    /// A batch of leases for bulk sync
    BulkSyncResponse { leases: Vec<LeaseSyncEntry> },

    /// State transition notification
    StateTransition {
        node_id: String,
        from: PeerState,
        to: PeerState,
        timestamp: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseSyncEntry {
    pub ip: String,
    pub mac: Option<String>,
    pub client_id: Option<Vec<u8>>,
    pub hostname: Option<String>,
    pub lease_time: u32,
    pub state: u8,
    pub start_time: u64,
    pub expire_time: u64,
    pub subnet: String,
}

/// Peer states in the failover state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// Normal operation, peer is reachable
    Normal,
    /// Communication with peer is interrupted
    CommunicationsInterrupted,
    /// We have determined the partner is down
    PartnerDown,
    /// Recovering from a failover event
    Recover,
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerState::Normal => write!(f, "normal"),
            PeerState::CommunicationsInterrupted => write!(f, "communications-interrupted"),
            PeerState::PartnerDown => write!(f, "partner-down"),
            PeerState::Recover => write!(f, "recover"),
        }
    }
}

impl HaMessage {
    /// Encode a message as a length-prefixed JSON frame
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let len = json.len() as u32;
        let mut buf = Vec::with_capacity(4 + json.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&json);
        Ok(buf)
    }

    /// Decode a message from a JSON payload (after length prefix has been stripped)
    pub fn decode(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}
