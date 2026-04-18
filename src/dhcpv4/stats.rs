//! Atomic counters for DHCPv4 relay observability.

use std::sync::atomic::AtomicU64;

/// Prometheus-exposed counters for DHCPv4 relay handling.
#[derive(Default)]
pub struct DhcpV4Stats {
    /// Total packets received with `giaddr != 0` (before security checks).
    pub relayed_received: AtomicU64,
    /// Relayed packets dropped because `accept_relayed = false`.
    pub relayed_dropped_disabled: AtomicU64,
    /// Relayed packets dropped because `giaddr` is a bogon or does not match any configured subnet.
    pub relayed_dropped_bad_giaddr: AtomicU64,
    /// Relayed packets dropped because the UDP source IP is not in the subnet's `trusted_relays`.
    pub relayed_dropped_untrusted_relay: AtomicU64,
    /// Relayed packets dropped by the per-relay-source rate limiter.
    pub relayed_dropped_rate_limit: AtomicU64,
}

impl DhcpV4Stats {
    /// Create a new zeroed stats counter set.
    pub fn new() -> Self {
        Self::default()
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn counters_start_at_zero() {
        let s = DhcpV4Stats::new();
        assert_eq!(s.relayed_received.load(Ordering::Relaxed), 0);
        assert_eq!(s.relayed_dropped_disabled.load(Ordering::Relaxed), 0);
        assert_eq!(s.relayed_dropped_bad_giaddr.load(Ordering::Relaxed), 0);
        assert_eq!(s.relayed_dropped_untrusted_relay.load(Ordering::Relaxed), 0);
        assert_eq!(s.relayed_dropped_rate_limit.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn counters_increment() {
        let s = DhcpV4Stats::new();
        s.relayed_received.fetch_add(3, Ordering::Relaxed);
        assert_eq!(s.relayed_received.load(Ordering::Relaxed), 3);
    }
}
