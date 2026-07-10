//! Integration tests for lease stickiness across expiry and client_id rotation.
//!
//! Covers issues:
//! - #66: client_id miss falls back to MAC
//! - #67: re-offer the previous IP per RFC 2131 §4.3.1 even when expired
//! - #68: expiry releases the IP back to the allocator bitmap
//!
//! Requires the `test-helpers` feature to access `handle_discover_for_test`.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rdhcpd::allocator::{build_allocators, SubnetAllocator};
use rdhcpd::config::{Config, GlobalConfig, HaConfig, SubnetConfig};
use rdhcpd::dhcpv4::options::{DhcpOption, MessageType};
use rdhcpd::dhcpv4::packet::DhcpV4Packet;
use rdhcpd::dhcpv4::server::DhcpV4Server;
use rdhcpd::dhcpv4::stats::DhcpV4Stats;
use rdhcpd::ha::StandaloneBackend;
use rdhcpd::lease::expiry::process_expired_once;
use rdhcpd::lease::store::LeaseStore;
use rdhcpd::lease::types::{Lease, LeaseState};
use rdhcpd::ratelimit::{RateLimiter, RogueDetector};
use rdhcpd::wal::Wal;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn tempdir_path() -> String {
    let dir = std::env::temp_dir().join(format!(
        "rdhcpd-stickiness-{}-{}",
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

async fn make_server() -> (
    DhcpV4Server<StandaloneBackend>,
    LeaseStore,
    Arc<HashMap<String, SubnetAllocator>>,
) {
    let subnet = make_subnet("10.0.0.0/24", "10.0.0.100", "10.0.0.200");

    let cfg = Config {
        global: make_global(),
        api: None,
        ha: HaConfig::Standalone,
        subnet: vec![subnet],
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[allow(clippy::too_many_arguments)]
fn seed_lease(
    lease_store: &LeaseStore,
    allocators: &HashMap<String, SubnetAllocator>,
    mac: [u8; 6],
    client_id: Option<Vec<u8>>,
    ip: Ipv4Addr,
    state: LeaseState,
    expire_in_secs: i64,
    subnet: &str,
) {
    let now = now_secs();
    let expire_time = (now as i64 + expire_in_secs).max(0) as u64;
    let lease = Lease {
        ip: IpAddr::V4(ip),
        mac: Some(mac),
        client_id,
        hostname: None,
        lease_time: 3600,
        state,
        start_time: now,
        expire_time,
        expires_at: Instant::now() + Duration::from_secs(expire_in_secs.max(0) as u64),
        subnet: Arc::from(subnet),
    };
    if matches!(state, LeaseState::Offered | LeaseState::Bound)
        && let Some(alloc) = allocators.get(subnet) {
            alloc.allocate_specific(&IpAddr::V4(ip));
        }
    lease_store.upsert(lease);
}

fn discover_with(mac: [u8; 6], cid: Option<&[u8]>) -> DhcpV4Packet {
    let mut packet = DhcpV4Packet::new_discover(mac);
    if let Some(cid) = cid {
        packet
            .options
            .push(DhcpOption::ClientIdentifier(cid.to_vec()));
    }
    packet
}

fn offered_ip(reply: &DhcpV4Packet) -> Ipv4Addr {
    assert_eq!(reply.message_type(), Some(MessageType::Offer));
    reply.yiaddr
}

// ---------------------------------------------------------------------------
// Issue #68: lease expiry releases the IP back to the allocator bitmap.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expiry_releases_ip_to_allocator() {
    let (_server, lease_store, allocators) = make_server().await;
    let mac: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    let ip = Ipv4Addr::new(10, 0, 0, 150);

    // Seed a lease that expired 60 seconds ago.
    seed_lease(
        &lease_store,
        &allocators,
        mac,
        None,
        ip,
        LeaseState::Bound,
        -60,
        "10.0.0.0/24",
    );

    let alloc = allocators.get("10.0.0.0/24").unwrap();
    assert!(
        alloc.is_allocated(&IpAddr::V4(ip)),
        "precondition: bitmap holds the bit"
    );

    let count = process_expired_once(&lease_store, &allocators, now_secs());
    assert_eq!(count, 1, "exactly one lease expired");

    assert!(
        !alloc.is_allocated(&IpAddr::V4(ip)),
        "bitmap bit must be released after expiry"
    );

    let lease = lease_store.get(&IpAddr::V4(ip)).expect("record preserved");
    assert_eq!(
        lease.state,
        LeaseState::Expired,
        "lease record stays for stickiness lookup"
    );
    assert_eq!(
        lease_store.get_by_mac(&mac).map(|l| l.ip),
        Some(IpAddr::V4(ip)),
        "MAC index intact for re-offer"
    );
}

// ---------------------------------------------------------------------------
// Issue #66: cid miss falls back to MAC.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discover_falls_back_to_mac_when_client_id_changes() {
    let (server, lease_store, allocators) = make_server().await;
    let mac: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    let ip = Ipv4Addr::new(10, 0, 0, 150);
    let original_cid = b"old-os-installation".to_vec();

    // Bound lease with the original client_id.
    seed_lease(
        &lease_store,
        &allocators,
        mac,
        Some(original_cid),
        ip,
        LeaseState::Bound,
        3600,
        "10.0.0.0/24",
    );

    // Same MAC, fresh client_id (e.g. OS reinstall picks a new option-61).
    let packet = discover_with(mac, Some(b"new-os-installation"));
    let reply = server
        .handle_discover_for_test(&packet)
        .await
        .unwrap()
        .expect("server must reply");

    assert_eq!(
        offered_ip(&reply),
        ip,
        "MAC fallback must recover the previous IP"
    );
}

// ---------------------------------------------------------------------------
// Issue #67: re-offer the same IP after lease expiry.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discover_reoffers_expired_ip_to_same_client() {
    let (server, lease_store, allocators) = make_server().await;
    let mac: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
    let ip = Ipv4Addr::new(10, 0, 0, 150);

    // Seed an already-expired lease and run the expiry cycle so the bitmap
    // reflects the post-#68 state (bit cleared, record kept).
    seed_lease(
        &lease_store,
        &allocators,
        mac,
        None,
        ip,
        LeaseState::Bound,
        -1,
        "10.0.0.0/24",
    );
    process_expired_once(&lease_store, &allocators, now_secs());

    let alloc = allocators.get("10.0.0.0/24").unwrap();
    assert!(
        !alloc.is_allocated(&IpAddr::V4(ip)),
        "precondition: bit released by expiry"
    );

    let packet = discover_with(mac, None);
    let reply = server
        .handle_discover_for_test(&packet)
        .await
        .unwrap()
        .expect("server must reply");

    assert_eq!(
        offered_ip(&reply),
        ip,
        "client should be re-offered its previous IP per RFC 2131 §4.3.1"
    );
    assert!(
        alloc.is_allocated(&IpAddr::V4(ip)),
        "re-offer must reclaim the allocator bit"
    );
    let lease = lease_store.get(&IpAddr::V4(ip)).unwrap();
    assert_eq!(
        lease.state,
        LeaseState::Offered,
        "record refreshed to Offered"
    );
}

/// If the previously-held IP has been taken by another active client, fall
/// through to fresh allocation rather than re-offering a conflicting IP.
#[tokio::test]
async fn discover_does_not_steal_active_lease_for_returning_client() {
    let (server, lease_store, allocators) = make_server().await;
    let original_mac: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03];
    let new_mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let contested_ip = Ipv4Addr::new(10, 0, 0, 150);

    // Original client's lease is expired and released by the expiry pass.
    seed_lease(
        &lease_store,
        &allocators,
        original_mac,
        None,
        contested_ip,
        LeaseState::Bound,
        -1,
        "10.0.0.0/24",
    );
    process_expired_once(&lease_store, &allocators, now_secs());

    // A different MAC then takes the same IP via a fresh active lease.
    seed_lease(
        &lease_store,
        &allocators,
        new_mac,
        None,
        contested_ip,
        LeaseState::Bound,
        3600,
        "10.0.0.0/24",
    );

    // Original client returns — must not be offered the contested IP.
    let packet = discover_with(original_mac, None);
    let reply = server
        .handle_discover_for_test(&packet)
        .await
        .unwrap()
        .expect("server must reply");

    assert_ne!(
        offered_ip(&reply),
        contested_ip,
        "must not steal an active lease from another client"
    );
}
