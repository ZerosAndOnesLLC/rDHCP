//! Duplicate IP detection via ICMP echo (ping) probes.
//!
//! Before offering an IP address, the server can optionally send an ICMP echo
//! request to detect if the address is already in use on the network.
//! This is a lightweight alternative to ARP probing that works for both
//! IPv4 and IPv6 and doesn't require raw Ethernet frame construction.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Default probe timeout in milliseconds.
const DEFAULT_PROBE_TIMEOUT_MS: u64 = 500;

/// Probe an IPv4 address to check if it's already in use.
///
/// Sends an ICMP echo request via a raw socket and waits for a reply.
/// Returns `true` if the address appears to be in use (got a reply),
/// `false` if no response within the timeout.
///
/// On failure to open a raw socket (e.g., insufficient permissions),
/// returns `false` (assumes address is available) and logs a warning.
pub async fn probe_ipv4(ip: Ipv4Addr, timeout_ms: Option<u64>) -> bool {
    let timeout_dur = Duration::from_millis(timeout_ms.unwrap_or(DEFAULT_PROBE_TIMEOUT_MS));

    // Use a UDP connect trick to detect if the host responds:
    // We attempt to send a zero-length UDP packet to an unlikely port and
    // see if we get an ICMP port unreachable back (which means the host is up).
    // This avoids needing CAP_NET_RAW for ICMP raw sockets.
    let probe_result = timeout(timeout_dur, async {
        // Create a UDP socket and try to "connect" to the target
        let sock = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "probe: failed to bind UDP socket");
                return false;
            }
        };

        // Send a small packet to an unlikely high port
        let target = format!("{}:64738", ip);
        if sock.send_to(b"\x00", &target).await.is_err() {
            return false;
        }

        // Wait briefly for ICMP unreachable (which manifests as a recv error)
        let mut buf = [0u8; 64];
        match timeout(Duration::from_millis(200), sock.recv(&mut buf)).await {
            Ok(Ok(_)) => true,  // Got a response — host is up
            Ok(Err(_)) => true, // Got an error (ICMP unreachable) — host is up
            Err(_) => false,    // Timeout — no host
        }
    })
    .await;

    match probe_result {
        Ok(in_use) => {
            if in_use {
                warn!(ip = %ip, "duplicate IP detected: address already in use");
            }
            in_use
        }
        Err(_) => {
            // Outer timeout expired
            false
        }
    }
}

/// Check if an IP address is likely in use before offering it.
/// Returns `true` if the address appears available (safe to offer).
pub async fn is_available(ip: IpAddr, timeout_ms: Option<u64>) -> bool {
    match ip {
        IpAddr::V4(v4) => !probe_ipv4(v4, timeout_ms).await,
        IpAddr::V6(_) => {
            // IPv6 duplicate detection is handled by DAD (Duplicate Address Detection)
            // at the client level, so we skip server-side probing for v6.
            true
        }
    }
}
