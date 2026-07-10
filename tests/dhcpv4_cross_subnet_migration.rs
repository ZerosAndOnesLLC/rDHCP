//! Integration tests for DHCPv4 cross-subnet MAC migration handling.
//!
//! Issue #63: when a MAC with an active lease in subnet A shows up on
//! subnet B (via relay), the server should release the stale subnet-A
//! lease rather than silently refuse. Requires the `test-helpers` feature.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rdhcpd::allocator::build_allocators;
use rdhcpd::config::{Config, GlobalConfig, HaConfig, SubnetConfig};
use rdhcpd::dhcpv4::server::DhcpV4Server;
use rdhcpd::dhcpv4::stats::DhcpV4Stats;
use rdhcpd::ha::StandaloneBackend;
use rdhcpd::lease::store::LeaseStore;
use rdhcpd::lease::types::{Lease, LeaseState};
use rdhcpd::ratelimit::{RateLimiter, RogueDetector};
use rdhcpd::wal::Wal;

fn tempdir_path() -> String {
    let dir = std::env::temp_dir().join(format!(
        "rdhcpd-xsubnet-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().into_owned()
}

fn make_subnet(network: &str, pool_start: &str, pool_end: &str) -> SubnetConfig {
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
        ntp: vec![],
        domain: None,
        option: vec![],
        ip_probe: false,
        ip_probe_timeout_ms: None,
        max_leases_per_mac: 1,
        mac_allow: vec![],
        mac_deny: vec![],
        trusted_relays: vec![],
        reservation: vec![],
    }
}

fn make_global() -> GlobalConfig {
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
        accept_relayed: true,
        relay_rate_limit_burst: 100,
        relay_rate_limit_pps: 100.0,
        recv_buffer_bytes: 0,
    }
}

async fn make_server_two_subnets() -> (
    DhcpV4Server<StandaloneBackend>,
    LeaseStore,
    Arc<std::collections::HashMap<String, rdhcpd::allocator::SubnetAllocator>>,
) {
    let subnet_a = make_subnet("10.0.0.0/24", "10.0.0.100", "10.0.0.200");
    let subnet_b = make_subnet("10.1.0.0/24", "10.1.0.100", "10.1.0.200");

    let cfg = Config {
        global: make_global(),
        api: None,
        ha: HaConfig::Standalone,
        subnet: vec![subnet_a, subnet_b],
        ddns: None,
    };

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
        lease_store.clone(),
        Arc::clone(&allocators),
        wal,
        ha,
        server_ip,
        rate_limiter,
        None,
        rogue_detector,
        relay_rate_limiter,
        stats,
    );

    (server, lease_store, allocators)
}

fn seed_bound_lease(
    lease_store: &LeaseStore,
    allocators: &std::collections::HashMap<String, rdhcpd::allocator::SubnetAllocator>,
    mac: [u8; 6],
    ip: Ipv4Addr,
    subnet: &str,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let lease = Lease {
        ip: IpAddr::V4(ip),
        mac: Some(mac),
        client_id: None,
        hostname: None,
        lease_time: 3600,
        state: LeaseState::Bound,
        start_time: now,
        expire_time: now + 3600,
        expires_at: Instant::now() + Duration::from_secs(3600),
        subnet: Arc::from(subnet),
    };
    // Mark allocator as holding this IP too so tests can check freeing
    if let Some(alloc) = allocators.get(subnet) {
        alloc.allocate_specific(&IpAddr::V4(ip));
    }
    lease_store.upsert(lease);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// MAC with an active lease in subnet A, seen on subnet B:
/// the stale subnet-A lease should be released.
#[tokio::test]
async fn cross_subnet_migration_releases_stale_lease() {
    let (server, lease_store, allocators) = make_server_two_subnets().await;
    let mac: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let stale_ip = Ipv4Addr::new(10, 0, 0, 150);

    seed_bound_lease(&lease_store, &allocators, mac, stale_ip, "10.0.0.0/24");
    assert!(
        lease_store.get_by_mac(&mac).is_some(),
        "precondition: lease exists"
    );
    assert!(
        allocators
            .get("10.0.0.0/24")
            .unwrap()
            .is_allocated(&IpAddr::V4(stale_ip)),
        "precondition: IP is marked allocated"
    );

    let released = server
        .release_stale_cross_subnet_lease(&mac, "10.1.0.0/24")
        .await;

    assert_eq!(
        released,
        Some(IpAddr::V4(stale_ip)),
        "method should return the released IP"
    );
    assert!(
        lease_store.get_by_mac(&mac).is_none(),
        "lease must be removed from store"
    );
    assert!(
        !allocators
            .get("10.0.0.0/24")
            .unwrap()
            .is_allocated(&IpAddr::V4(stale_ip)),
        "IP must be released back to allocator"
    );
}

/// Same-subnet lease should not be touched — this is a normal renewal path.
#[tokio::test]
async fn same_subnet_lease_is_not_released() {
    let (server, lease_store, allocators) = make_server_two_subnets().await;
    let mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let ip = Ipv4Addr::new(10, 0, 0, 150);

    seed_bound_lease(&lease_store, &allocators, mac, ip, "10.0.0.0/24");

    // Called with the *same* subnet as the existing lease.
    let released = server
        .release_stale_cross_subnet_lease(&mac, "10.0.0.0/24")
        .await;

    assert_eq!(released, None, "same-subnet must not trigger release");
    assert!(
        lease_store.get_by_mac(&mac).is_some(),
        "existing lease must survive"
    );
    assert!(
        allocators
            .get("10.0.0.0/24")
            .unwrap()
            .is_allocated(&IpAddr::V4(ip)),
        "IP must stay allocated"
    );
}

/// MAC with no lease: method is a harmless no-op.
#[tokio::test]
async fn no_lease_is_noop() {
    let (server, _lease_store, _allocators) = make_server_two_subnets().await;
    let mac: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];

    let released = server
        .release_stale_cross_subnet_lease(&mac, "10.0.0.0/24")
        .await;

    assert_eq!(released, None);
}

/// Lease in subnet A with an inactive state (Released) should not be released
/// again — the IP is already not held.
#[tokio::test]
async fn inactive_lease_is_not_released() {
    let (server, lease_store, _allocators) = make_server_two_subnets().await;
    let mac: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let ip = Ipv4Addr::new(10, 0, 0, 150);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let lease = Lease {
        ip: IpAddr::V4(ip),
        mac: Some(mac),
        client_id: None,
        hostname: None,
        lease_time: 3600,
        state: LeaseState::Released,
        start_time: now,
        expire_time: now + 3600,
        expires_at: Instant::now() + Duration::from_secs(3600),
        subnet: Arc::from("10.0.0.0/24"),
    };
    lease_store.upsert(lease);

    let released = server
        .release_stale_cross_subnet_lease(&mac, "10.1.0.0/24")
        .await;

    assert_eq!(
        released, None,
        "inactive lease should not trigger a release"
    );
}
