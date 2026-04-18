//! Integration-style tests for the DHCPv4 relay security gates.
//!
//! Requires the `test-helpers` feature to access `DhcpV4Packet::new_discover`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rdhcpd::allocator::build_allocators;
use rdhcpd::config::{Config, GlobalConfig, HaConfig, SubnetConfig};
use rdhcpd::dhcpv4::packet::DhcpV4Packet;
use rdhcpd::dhcpv4::server::{DhcpV4Server, RelayDecision};
use rdhcpd::dhcpv4::stats::DhcpV4Stats;
use rdhcpd::ha::StandaloneBackend;
use rdhcpd::lease::store::LeaseStore;
use rdhcpd::ratelimit::{RateLimiter, RogueDetector};
use rdhcpd::wal::Wal;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tempdir_path() -> String {
    let dir = std::env::temp_dir().join(format!(
        "rdhcpd-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().into_owned()
}

fn make_subnet(
    network: &str,
    pool_start: &str,
    pool_end: &str,
    trusted_relays: Vec<String>,
) -> SubnetConfig {
    SubnetConfig {
        network: network.to_string(),
        pool_start: Some(pool_start.to_string()),
        pool_end: Some(pool_end.to_string()),
        lease_time: 3600,
        max_lease_time: None,
        renewal_time: None,
        rebinding_time: None,
        preferred_time: None,
        subnet_type: "address".to_string(),
        delegated_length: None,
        router: None,
        dns: vec![],
        domain: None,
        ip_probe: false,
        ip_probe_timeout_ms: None,
        max_leases_per_mac: 1,
        mac_allow: vec![],
        mac_deny: vec![],
        trusted_relays,
        reservation: vec![],
    }
}

fn make_global(accept_relayed: bool) -> GlobalConfig {
    GlobalConfig {
        log_level: "info".to_string(),
        log_format: "text".to_string(),
        lease_db: "/tmp/rdhcpd-test".to_string(),
        workers: 1,
        rate_limit_burst: 100,
        rate_limit_pps: 100.0,
        global_rate_limit_pps: 0.0,
        rogue_threshold: 1000,
        rogue_window_secs: 60,
        pool_high_water: 0.9,
        accept_relayed,
        relay_rate_limit_burst: 100,
        relay_rate_limit_pps: 100.0,
    }
}

fn make_config(accept_relayed: bool, subnet: SubnetConfig) -> Config {
    Config {
        global: make_global(accept_relayed),
        api: None,
        ha: HaConfig::Standalone,
        subnet: vec![subnet],
        ddns: None,
    }
}

async fn make_server(
    cfg: Config,
) -> (DhcpV4Server<StandaloneBackend>, Arc<DhcpV4Stats>) {
    let dir = tempdir_path();
    let lease_store = LeaseStore::new();
    let allocators = Arc::new(build_allocators(&cfg, &lease_store).unwrap());
    let wal = Arc::new(Wal::open(&dir).await.unwrap());
    let ha = Arc::new(StandaloneBackend);
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);
    let rate_limiter = Arc::new(RateLimiter::new(100, 100.0));
    let relay_rate_limiter = Arc::new(RateLimiter::new(100, 100.0));
    let rogue_detector = Arc::new(RogueDetector::new(1000, 60));
    let stats = Arc::new(DhcpV4Stats::new());

    let server = DhcpV4Server::new(
        Arc::new(cfg),
        lease_store,
        allocators,
        wal,
        ha,
        server_ip,
        rate_limiter,
        None, // global rate limiter disabled
        rogue_detector,
        relay_rate_limiter,
        Arc::clone(&stats),
    );

    (server, stats)
}

async fn make_server_with_relay_limit(
    cfg: Config,
    burst: u32,
    pps: f64,
) -> (DhcpV4Server<StandaloneBackend>, Arc<DhcpV4Stats>) {
    let dir = tempdir_path();
    let lease_store = LeaseStore::new();
    let allocators = Arc::new(build_allocators(&cfg, &lease_store).unwrap());
    let wal = Arc::new(Wal::open(&dir).await.unwrap());
    let ha = Arc::new(StandaloneBackend);
    let server_ip = Ipv4Addr::new(10, 0, 0, 1);
    let rate_limiter = Arc::new(RateLimiter::new(100, 100.0));
    let relay_rate_limiter = Arc::new(RateLimiter::new(burst, pps));
    let rogue_detector = Arc::new(RogueDetector::new(1000, 60));
    let stats = Arc::new(DhcpV4Stats::new());

    let server = DhcpV4Server::new(
        Arc::new(cfg),
        lease_store,
        allocators,
        wal,
        ha,
        server_ip,
        rate_limiter,
        None, // global rate limiter disabled
        rogue_detector,
        relay_rate_limiter,
        Arc::clone(&stats),
    );

    (server, stats)
}

fn relayed_discover(giaddr: Ipv4Addr) -> DhcpV4Packet {
    let mut p = DhcpV4Packet::new_discover([0xaa; 6]);
    p.giaddr = giaddr;
    p
}

fn src_addr(ip: Ipv4Addr) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), 1234)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Non-relayed packet (giaddr=0.0.0.0) always gets NotRelayed — gates skipped.
#[tokio::test]
async fn direct_broadcast_packets_bypass_relay_gates() {
    let subnet = make_subnet("10.0.0.0/24", "10.0.0.100", "10.0.0.200", vec![]);
    let cfg = make_config(false, subnet); // accept_relayed=false should NOT matter
    let (server, stats) = make_server(cfg).await;

    let packet = DhcpV4Packet::new_discover([0xbb; 6]); // giaddr stays 0.0.0.0
    let decision = server.classify_relayed(&packet, src_addr(Ipv4Addr::new(192, 168, 1, 1)));

    assert_eq!(decision, RelayDecision::NotRelayed);
    // No stats should have been touched
    use std::sync::atomic::Ordering;
    assert_eq!(stats.relayed_received.load(Ordering::Relaxed), 0);
}

/// When `accept_relayed = false`, any relayed packet is dropped.
#[tokio::test]
async fn accept_relayed_disabled_drops_relayed_packets() {
    let subnet = make_subnet("10.0.0.0/24", "10.0.0.100", "10.0.0.200", vec![]);
    let cfg = make_config(false, subnet);
    let (server, stats) = make_server(cfg).await;

    let packet = relayed_discover(Ipv4Addr::new(10, 0, 0, 1));
    let decision = server.classify_relayed(&packet, src_addr(Ipv4Addr::new(10, 0, 0, 5)));

    assert_eq!(decision, RelayDecision::DroppedDisabled);
    use std::sync::atomic::Ordering;
    assert_eq!(stats.relayed_received.load(Ordering::Relaxed), 1);
    assert_eq!(stats.relayed_dropped_disabled.load(Ordering::Relaxed), 1);
}

/// Bogon giaddr (loopback 127.0.0.1) is rejected.
#[tokio::test]
async fn bogon_giaddr_is_dropped() {
    let subnet = make_subnet("10.0.0.0/24", "10.0.0.100", "10.0.0.200", vec![]);
    let cfg = make_config(true, subnet);
    let (server, stats) = make_server(cfg).await;

    let packet = relayed_discover(Ipv4Addr::new(127, 0, 0, 1));
    let decision = server.classify_relayed(&packet, src_addr(Ipv4Addr::new(10, 0, 0, 5)));

    assert_eq!(decision, RelayDecision::DroppedBadGiaddr);
    use std::sync::atomic::Ordering;
    assert_eq!(stats.relayed_received.load(Ordering::Relaxed), 1);
    assert_eq!(stats.relayed_dropped_bad_giaddr.load(Ordering::Relaxed), 1);
}

/// giaddr that doesn't match any configured subnet is dropped.
#[tokio::test]
async fn unknown_subnet_giaddr_is_dropped() {
    let subnet = make_subnet("10.0.0.0/24", "10.0.0.100", "10.0.0.200", vec![]);
    let cfg = make_config(true, subnet);
    let (server, stats) = make_server(cfg).await;

    // giaddr is in 192.168.1.0/24 — not configured
    let packet = relayed_discover(Ipv4Addr::new(192, 168, 1, 50));
    let decision = server.classify_relayed(&packet, src_addr(Ipv4Addr::new(192, 168, 1, 1)));

    assert_eq!(decision, RelayDecision::DroppedBadGiaddr);
    use std::sync::atomic::Ordering;
    assert_eq!(stats.relayed_dropped_bad_giaddr.load(Ordering::Relaxed), 1);
}

/// Source IP not in trusted_relays list → DroppedUntrustedRelay.
#[tokio::test]
async fn untrusted_relay_source_is_dropped_when_whitelist_populated() {
    let subnet = make_subnet(
        "10.0.0.0/24",
        "10.0.0.100",
        "10.0.0.200",
        vec!["10.0.0.5".to_string(), "10.0.0.6".to_string()],
    );
    let cfg = make_config(true, subnet);
    let (server, stats) = make_server(cfg).await;

    // giaddr matches the subnet, but source IP 10.0.0.99 is not trusted
    let packet = relayed_discover(Ipv4Addr::new(10, 0, 0, 1));
    let decision = server.classify_relayed(&packet, src_addr(Ipv4Addr::new(10, 0, 0, 99)));

    assert_eq!(decision, RelayDecision::DroppedUntrustedRelay);
    use std::sync::atomic::Ordering;
    assert_eq!(stats.relayed_received.load(Ordering::Relaxed), 1);
    assert_eq!(stats.relayed_dropped_untrusted_relay.load(Ordering::Relaxed), 1);
}

/// Source IP in trusted_relays → Accept.
#[tokio::test]
async fn trusted_relay_source_is_accepted() {
    let subnet = make_subnet(
        "10.0.0.0/24",
        "10.0.0.100",
        "10.0.0.200",
        vec!["10.0.0.5".to_string()],
    );
    let cfg = make_config(true, subnet);
    let (server, stats) = make_server(cfg).await;

    let packet = relayed_discover(Ipv4Addr::new(10, 0, 0, 1));
    let decision = server.classify_relayed(&packet, src_addr(Ipv4Addr::new(10, 0, 0, 5)));

    assert_eq!(decision, RelayDecision::Accept);
    use std::sync::atomic::Ordering;
    assert_eq!(stats.relayed_received.load(Ordering::Relaxed), 1);
    assert_eq!(stats.relayed_dropped_untrusted_relay.load(Ordering::Relaxed), 0);
}

/// Empty trusted_relays list → any relay source is accepted.
#[tokio::test]
async fn empty_trusted_relays_accepts_any_source() {
    let subnet = make_subnet("10.0.0.0/24", "10.0.0.100", "10.0.0.200", vec![]);
    let cfg = make_config(true, subnet);
    let (server, stats) = make_server(cfg).await;

    let packet = relayed_discover(Ipv4Addr::new(10, 0, 0, 1));
    // Source IP is completely arbitrary — no whitelist
    let decision = server.classify_relayed(&packet, src_addr(Ipv4Addr::new(1, 2, 3, 4)));

    assert_eq!(decision, RelayDecision::Accept);
    use std::sync::atomic::Ordering;
    assert_eq!(stats.relayed_received.load(Ordering::Relaxed), 1);
}

/// Per-relay-source rate limiter exhaustion → DroppedRateLimit.
#[tokio::test]
async fn relayed_packets_are_rate_limited_per_source() {
    let subnet = make_subnet("10.0.0.0/24", "10.0.0.100", "10.0.0.200", vec![]);
    let cfg = make_config(true, subnet);
    // burst=1, very slow refill — second packet will exhaust the bucket
    let (server, stats) = make_server_with_relay_limit(cfg, 1, 0.01).await;

    let pkt = relayed_discover(Ipv4Addr::new(10, 0, 0, 5));
    let relay_src = src_addr(Ipv4Addr::new(10, 0, 0, 5));

    // First packet: consumes the single token → accepted
    assert_eq!(server.classify_relayed(&pkt, relay_src), RelayDecision::Accept);
    // Second packet: limiter empty → rate-limit drop
    assert_eq!(server.classify_relayed(&pkt, relay_src), RelayDecision::DroppedRateLimit);
    use std::sync::atomic::Ordering;
    assert_eq!(
        stats.relayed_dropped_rate_limit.load(Ordering::Relaxed),
        1
    );
}
