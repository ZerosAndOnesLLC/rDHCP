
use serde::{Deserialize, Serialize};


/// HA wire protocol messages exchanged between peers.
/// Framed as: [4-byte big-endian length][JSON payload]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HaMessage {
    /// Heartbeat / keepalive
    Heartbeat {
        /// Unique identifier of the sending node.
        node_id: String,
        /// Current failover state of the sender.
        state: PeerState,
        /// Number of active leases on the sender.
        active_leases: u64,
        /// Unix epoch timestamp (seconds) when the heartbeat was generated.
        timestamp: u64,
    },

    /// Lease sync — push a lease to the peer
    LeaseSync {
        /// Leased IP address as a string.
        ip: String,
        /// Client MAC address (colon-separated hex).
        mac: Option<String>,
        /// DHCP client identifier (option 61).
        client_id: Option<Vec<u8>>,
        /// Client-provided hostname.
        hostname: Option<String>,
        /// Granted lease duration in seconds.
        lease_time: u32,
        /// Numeric lease state (see `LeaseState`).
        state: u8,
        /// Epoch timestamp when the lease started.
        start_time: u64,
        /// Epoch timestamp when the lease expires.
        expire_time: u64,
        /// Subnet CIDR this lease belongs to.
        subnet: String,
    },

    /// Lease release notification
    LeaseRelease {
        /// IP address of the released lease.
        ip: String,
    },

    /// Request a full lease sync (on reconnection)
    BulkSyncRequest {
        /// Epoch timestamp of last known sync
        since: u64,
    },

    /// A batch of leases for bulk sync
    BulkSyncResponse {
        /// All lease entries included in the bulk sync.
        leases: Vec<LeaseSyncEntry>,
    },

    /// State transition notification
    StateTransition {
        /// Node that transitioned.
        node_id: String,
        /// Previous peer state.
        from: PeerState,
        /// New peer state.
        to: PeerState,
        /// Epoch timestamp of the transition.
        timestamp: u64,
    },
}

/// A single lease entry used in bulk synchronization between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseSyncEntry {
    /// Leased IP address as a string.
    pub ip: String,
    /// Client MAC address (colon-separated hex).
    pub mac: Option<String>,
    /// DHCP client identifier (option 61).
    pub client_id: Option<Vec<u8>>,
    /// Client-provided hostname.
    pub hostname: Option<String>,
    /// Granted lease duration in seconds.
    pub lease_time: u32,
    /// Numeric lease state (see `LeaseState`).
    pub state: u8,
    /// Epoch timestamp when the lease started.
    pub start_time: u64,
    /// Epoch timestamp when the lease expires.
    pub expire_time: u64,
    /// Subnet CIDR this lease belongs to.
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
        if json.len() > 10 * 1024 * 1024 {
            return Err(serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HA message too large (>10MB)",
            )));
        }
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
