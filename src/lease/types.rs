use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

/// Lease states following the DHCP lifecycle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LeaseState {
    /// IP offered to client, awaiting Request
    Offered = 0,
    /// Lease is active and bound to client
    Bound = 1,
    /// Lease has expired
    Expired = 2,
    /// Client explicitly released the lease
    Released = 3,
    /// Client declined the IP (possible conflict)
    Declined = 4,
}

impl LeaseState {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Offered),
            1 => Some(Self::Bound),
            2 => Some(Self::Expired),
            3 => Some(Self::Released),
            4 => Some(Self::Declined),
            _ => None,
        }
    }
}

/// A DHCP lease record.
/// Uses Arc<str> for hostname/subnet to make clone cheap (pointer bump).
#[derive(Debug, Clone)]
pub struct Lease {
    /// Leased IP address (v4 or v6)
    pub ip: IpAddr,
    /// Client MAC address (6 bytes, DHCPv4)
    pub mac: Option<[u8; 6]>,
    /// Client identifier (DHCPv4 option 61 or DHCPv6 DUID)
    pub client_id: Option<Vec<u8>>,
    /// Client hostname
    pub hostname: Option<Arc<str>>,
    /// Lease duration in seconds
    pub lease_time: u32,
    /// Current state
    pub state: LeaseState,
    /// When the lease was created/last renewed (epoch seconds)
    pub start_time: u64,
    /// When the lease expires (epoch seconds)
    pub expire_time: u64,
    /// Monotonic instant for in-memory expiry tracking
    pub expires_at: Instant,
    /// Subnet identifier (network CIDR string) this lease belongs to
    pub subnet: Arc<str>,
}

impl Lease {
    #[inline]
    pub fn is_active(&self) -> bool {
        matches!(self.state, LeaseState::Offered | LeaseState::Bound)
    }

    #[inline]
    pub fn is_expired_at(&self, now_epoch: u64) -> bool {
        now_epoch >= self.expire_time
    }
}
