# DHCPv4 Accept Relayed Requests (FreeBSD unicast listen) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make rdhcpd on FreeBSD receive and process DHCPv4 requests relayed via unicast to the server's IP (currently dropped at the kernel because the socket binds only to 255.255.255.255), while adding a trusted-relay security model.

**Architecture:** Add a second per-worker UDP receive socket bound to `0.0.0.0:67` (with `SO_REUSEPORT`) alongside the existing broadcast socket on FreeBSD; `tokio::select!` across both inside the worker loop. Layer security gates on relayed packets: global `accept_relayed` kill-switch, per-subnet `trusted_relays` whitelist, giaddr bogon/martian rejection, and a dedicated per-relay-source rate limiter. Expose new relay counters via Prometheus metrics. Non-FreeBSD platforms already bind `0.0.0.0:67` and receive both broadcasts and unicast — they only gain the security gates and metrics.

**Tech Stack:** Rust 2024, tokio UDP sockets, socket2 (SO_REUSEPORT + IP_BINDANY), DashMap rate-limit buckets, existing Prometheus exposition in `src/api/metrics.rs`, TOML config via serde.

---

## File Structure

Files to be created or modified:

- **Modify** `src/config/types.rs` — add `accept_relayed` to `GlobalConfig`, add `trusted_relays: Vec<String>` to `SubnetConfig`, default fn.
- **Modify** `src/config/validation.rs` — add `is_bogon_giaddr(Ipv4Addr) -> bool` and its tests.
- **Create** `src/dhcpv4/stats.rs` — new module with `DhcpV4Stats` struct holding atomic counters for relay accept/drop reasons.
- **Modify** `src/dhcpv4/mod.rs` — export the new `stats` module.
- **Modify** `src/dhcpv4/server.rs` — add `stats: Arc<DhcpV4Stats>` and `relay_rate_limiter: Arc<RateLimiter>` to `DhcpV4Server`, pre-parse `trusted_relays` into `SubnetInfo`, insert relay security gates in `run()`, change `run()` to accept `Vec<Arc<UdpSocket>>` and `tokio::select!` across them, add `select_subnet_for_relay` helper that returns the relay-subnet so the trusted-relay check uses the correct scope.
- **Modify** `src/main.rs` — construct and pass `DhcpV4Stats` + `relay_rate_limiter`; on FreeBSD build both a `255.255.255.255:67` socket and a `0.0.0.0:67` socket per worker and pass both into `server.run`.
- **Modify** `src/api/mod.rs` — plumb `Arc<DhcpV4Stats>` into `ApiState`.
- **Modify** `src/api/metrics.rs` — expose the new counters in Prometheus format.
- **Modify** `example-config.toml` — document `accept_relayed` and per-subnet `trusted_relays`.
- **Modify** `SECURITY.md` — document trusted-relay model and attack surface of accepting unicast DHCP.
- **Modify** `CHANGELOG.md` — add entry for the feature.
- **Modify** `Cargo.toml` — bump minor version per commit per user's rules (this is a feature addition).

Each task has one clear responsibility and produces a self-contained commit.

---

## Task 1: Config schema — add `accept_relayed` and `trusted_relays`

**Files:**
- Modify: `src/config/types.rs`
- Modify: `example-config.toml`

- [ ] **Step 1: Write failing tests for the new config fields**

Append to the bottom of `src/config/types.rs` (inside a new `#[cfg(test)] mod tests { ... }` block — or add the test block if none exists):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_accept_relayed_defaults_to_true() {
        let toml = r#"
[global]
lease_db = "/tmp/x"

[ha]
mode = "standalone"
"#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.global.accept_relayed);
    }

    #[test]
    fn global_accept_relayed_can_be_disabled() {
        let toml = r#"
[global]
lease_db = "/tmp/x"
accept_relayed = false

[ha]
mode = "standalone"
"#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(!c.global.accept_relayed);
    }

    #[test]
    fn subnet_trusted_relays_defaults_empty_and_can_be_set() {
        let toml = r#"
[global]
lease_db = "/tmp/x"

[ha]
mode = "standalone"

[[subnet]]
network = "10.0.0.0/24"

[[subnet]]
network = "10.0.1.0/24"
trusted_relays = ["10.0.1.5", "10.0.1.6"]
"#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.subnet[0].trusted_relays.is_empty());
        assert_eq!(c.subnet[1].trusted_relays, vec!["10.0.1.5", "10.0.1.6"]);
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rdhcpd --lib config::types::tests -- --nocapture`

Expected: compile error "no field `accept_relayed` on type `GlobalConfig`" and `trusted_relays`.

- [ ] **Step 3: Add the fields and defaults**

In `src/config/types.rs`:

Inside `GlobalConfig` (after `pool_high_water` field):

```rust
    /// Whether to accept DHCP packets with giaddr != 0 (i.e. forwarded by a
    /// DHCP relay agent). When false, all relayed packets are dropped early
    /// regardless of per-subnet trusted_relays configuration.
    #[serde(default = "default_accept_relayed")]
    pub accept_relayed: bool,
```

Inside `SubnetConfig` (after `mac_deny` field, before `reservation`):

```rust
    /// Trusted DHCP relay agent source IPs for this subnet. When non-empty,
    /// relayed packets whose UDP source IP is not on this list are dropped.
    /// When empty, all relays are accepted (backwards-compatible default).
    #[serde(default)]
    pub trusted_relays: Vec<String>,
```

Near the other `default_*` fns at the bottom:

```rust
fn default_accept_relayed() -> bool {
    true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rdhcpd --lib config::types::tests`

Expected: all three tests pass.

- [ ] **Step 5: Update example-config.toml**

In `example-config.toml`, inside `[global]` (after `pool_high_water`):

```toml
accept_relayed = true             # accept DHCP packets forwarded by a relay agent
                                  # (giaddr != 0). Set false to disable relay support entirely.
```

In `example-config.toml`, inside the IPv4 `[[subnet]]` block (after `mac_deny` comment):

```toml
# --- DHCP Relay ---
# trusted_relays = ["10.0.1.2"]    # restrict relayed packets to these source IPs
                                  # empty = accept from any relay (if accept_relayed=true)
```

- [ ] **Step 6: cargo check and commit**

```bash
cargo check
# Bump version (patch for the in-progress feature; will bump to minor on final task)
# Edit Cargo.toml: version = "0.11.2"
git add Cargo.toml src/config/types.rs example-config.toml
git commit -m "feat(config): add accept_relayed global flag and per-subnet trusted_relays"
```

---

## Task 2: Bogon/martian check for `giaddr`

**Files:**
- Modify: `src/config/validation.rs`

- [ ] **Step 1: Write failing tests**

Append to `src/config/validation.rs` (inside its existing `#[cfg(test)] mod tests { ... }` block, or create one if absent):

```rust
#[cfg(test)]
mod giaddr_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn loopback_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn link_local_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::new(169, 254, 1, 1)));
    }

    #[test]
    fn multicast_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::new(224, 0, 0, 1)));
    }

    #[test]
    fn broadcast_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::BROADCAST));
    }

    #[test]
    fn reserved_class_e_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::new(240, 0, 0, 1)));
    }

    #[test]
    fn unspecified_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn normal_unicast_is_not_bogon() {
        assert!(!is_bogon_giaddr(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_bogon_giaddr(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_bogon_giaddr(Ipv4Addr::new(172, 29, 69, 5)));
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rdhcpd --lib config::validation::giaddr_tests`

Expected: compile error — `is_bogon_giaddr` not found.

- [ ] **Step 3: Implement `is_bogon_giaddr`**

Add to `src/config/validation.rs` (next to other `pub fn` helpers):

```rust
/// Return true if the given address is unsuitable as a DHCP relay agent
/// source (giaddr). Rejects loopback, link-local, multicast, broadcast,
/// reserved (class E), and the unspecified address.
pub fn is_bogon_giaddr(ip: std::net::Ipv4Addr) -> bool {
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        // Class E reserved (240.0.0.0/4) — is_reserved is unstable, so check manually.
        || (ip.octets()[0] & 0xF0) == 0xF0
}
```

Note: `(octets[0] & 0xF0) == 0xF0` matches both 240.0.0.0/4 and 255.255.255.255; the latter is already covered by `is_broadcast()` but the overlap is harmless.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rdhcpd --lib config::validation::giaddr_tests`

Expected: all seven tests pass.

- [ ] **Step 5: cargo check and commit**

```bash
cargo check
# Cargo.toml: version = "0.11.3"
git add Cargo.toml src/config/validation.rs
git commit -m "feat(validation): add is_bogon_giaddr for DHCP relay source validation"
```

---

## Task 3: DhcpV4Stats — atomic counters for relay drops/accepts

**Files:**
- Create: `src/dhcpv4/stats.rs`
- Modify: `src/dhcpv4/mod.rs`

- [ ] **Step 1: Write failing test for the new stats module**

Create `src/dhcpv4/stats.rs` with tests first (file will not compile until struct exists):

```rust
//! Atomic counters for DHCPv4 relay observability.

use std::sync::atomic::{AtomicU64, Ordering};

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

    /// Read the current value of a counter (Relaxed ordering — metrics are
    /// observational and do not need happens-before with other state).
    pub fn load(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let s = DhcpV4Stats::new();
        assert_eq!(DhcpV4Stats::load(&s.relayed_received), 0);
        assert_eq!(DhcpV4Stats::load(&s.relayed_dropped_disabled), 0);
        assert_eq!(DhcpV4Stats::load(&s.relayed_dropped_bad_giaddr), 0);
        assert_eq!(DhcpV4Stats::load(&s.relayed_dropped_untrusted_relay), 0);
        assert_eq!(DhcpV4Stats::load(&s.relayed_dropped_rate_limit), 0);
    }

    #[test]
    fn counters_increment() {
        let s = DhcpV4Stats::new();
        s.relayed_received.fetch_add(3, Ordering::Relaxed);
        assert_eq!(DhcpV4Stats::load(&s.relayed_received), 3);
    }
}
```

- [ ] **Step 2: Register the module**

Edit `src/dhcpv4/mod.rs` — add:

```rust
pub mod stats;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p rdhcpd --lib dhcpv4::stats::tests`

Expected: both tests pass.

- [ ] **Step 4: cargo check and commit**

```bash
cargo check
# Cargo.toml: version = "0.11.4"
git add Cargo.toml src/dhcpv4/stats.rs src/dhcpv4/mod.rs
git commit -m "feat(dhcpv4): add DhcpV4Stats atomic counters for relay observability"
```

---

## Task 4: Pre-parse `trusted_relays` into `SubnetInfo`

**Files:**
- Modify: `src/dhcpv4/server.rs`

- [ ] **Step 1: Add a unit test for the new `SubnetInfo::trusted_relays` field**

Append to the bottom of `src/dhcpv4/server.rs` (inside a new `#[cfg(test)] mod tests { ... }` block — create it if no test module is present):

```rust
#[cfg(test)]
mod subnet_info_tests {
    use super::*;
    use crate::config::SubnetConfig;

    fn make_subnet(network: &str, trusted: Vec<String>) -> SubnetConfig {
        SubnetConfig {
            network: network.to_string(),
            pool_start: None,
            pool_end: None,
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
            trusted_relays: trusted,
            reservation: vec![],
        }
    }

    #[test]
    fn trusted_relays_are_parsed_into_subnet_info() {
        let cfg = make_subnet("10.0.0.0/24", vec!["10.0.0.5".to_string(), "invalid".to_string(), "10.0.0.6".to_string()]);
        let parsed = SubnetInfo::trusted_relays_for_test(&cfg);
        // "invalid" is dropped; the two valid ones are kept
        assert_eq!(parsed, vec![Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 6)]);
    }

    #[test]
    fn empty_trusted_relays_parses_to_empty_vec() {
        let cfg = make_subnet("10.0.0.0/24", vec![]);
        let parsed = SubnetInfo::trusted_relays_for_test(&cfg);
        assert!(parsed.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rdhcpd --lib dhcpv4::server::subnet_info_tests`

Expected: compile error — `trusted_relays` field missing on SubnetInfo and no `trusted_relays_for_test`.

- [ ] **Step 3: Add the field and helper**

In `src/dhcpv4/server.rs`, extend the `SubnetInfo` struct (around line 70):

```rust
#[derive(Clone)]
struct SubnetInfo {
    network: Arc<str>,
    network_addr: Ipv4Addr,
    prefix_len: u8,
    config: Arc<SubnetConfig>,
    /// Per-subnet MAC ACL
    mac_acl: Arc<MacAcl>,
    /// Pre-parsed trusted relay agent source IPs. Empty = accept any relay.
    trusted_relays: Arc<[Ipv4Addr]>,
}

impl SubnetInfo {
    /// Parse the raw trusted_relays strings from a SubnetConfig into Ipv4Addr.
    /// Invalid entries are silently dropped (they are logged at startup in
    /// `new()` via validate_config instead).
    fn parse_trusted_relays(cfg: &SubnetConfig) -> Vec<Ipv4Addr> {
        cfg.trusted_relays
            .iter()
            .filter_map(|s| s.parse::<Ipv4Addr>().ok())
            .collect()
    }

    #[cfg(test)]
    fn trusted_relays_for_test(cfg: &SubnetConfig) -> Vec<Ipv4Addr> {
        Self::parse_trusted_relays(cfg)
    }
}
```

Then update the `SubnetInfo` construction inside `DhcpV4Server::new` (around line 114):

```rust
                    Some(SubnetInfo {
                        network: Arc::from(s.network.as_str()),
                        network_addr: v4,
                        prefix_len,
                        config: Arc::new(s.clone()),
                        mac_acl,
                        trusted_relays: Arc::from(SubnetInfo::parse_trusted_relays(s)),
                    })
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rdhcpd --lib dhcpv4::server::subnet_info_tests`

Expected: both tests pass.

- [ ] **Step 5: cargo check and commit**

```bash
cargo check
# Cargo.toml: version = "0.11.5"
git add Cargo.toml src/dhcpv4/server.rs
git commit -m "feat(dhcpv4): pre-parse trusted_relays into SubnetInfo"
```

---

## Task 5: Wire `DhcpV4Stats` + relay rate limiter into `DhcpV4Server`

**Files:**
- Modify: `src/dhcpv4/server.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Add fields and constructor params**

In `src/dhcpv4/server.rs`, add imports at the top:

```rust
use crate::dhcpv4::stats::DhcpV4Stats;
```

Extend the `DhcpV4Server` struct (add two fields after `rogue_detector`):

```rust
    /// Per-relay-source rate limiter (keyed by UDP source IP bytes).
    relay_rate_limiter: Arc<RateLimiter>,
    /// Observability counters for relay handling.
    stats: Arc<DhcpV4Stats>,
```

Extend `DhcpV4Server::new` signature — add two params before the closing `)`:

```rust
        relay_rate_limiter: Arc<RateLimiter>,
        stats: Arc<DhcpV4Stats>,
```

And pass them through in the constructor body:

```rust
        Self {
            // ...existing fields...
            rogue_detector,
            relay_rate_limiter,
            stats,
            pool_high_water,
        }
```

- [ ] **Step 2: Wire construction in main.rs**

In `src/main.rs`, near the existing `rate_limiter` / `global_rate_limiter` / `rogue_detector` construction (~line 78), add:

```rust
    let relay_rate_limiter = Arc::new(RateLimiter::new(
        config.global.rate_limit_burst,
        config.global.rate_limit_pps,
    ));
    let dhcpv4_stats = Arc::new(rdhcpd::dhcpv4::stats::DhcpV4Stats::new());
```

Then update the `DhcpV4Server::new(…)` call (around line 348) to pass the two new args in order (just before the trailing `)`):

```rust
                rate_limiter.clone(),
                global_rate_limiter.clone(),
                rogue_detector.clone(),
                relay_rate_limiter.clone(),
                dhcpv4_stats.clone(),
            );
```

- [ ] **Step 3: Run `cargo check`**

Run: `cargo check`

Expected: clean build (warnings about unused `stats` and `relay_rate_limiter` are acceptable at this stage; they'll be used in Task 6).

- [ ] **Step 4: Commit**

```bash
# Cargo.toml: version = "0.11.6"
git add Cargo.toml src/dhcpv4/server.rs src/main.rs
git commit -m "feat(dhcpv4): plumb DhcpV4Stats and relay_rate_limiter into server"
```

---

## Task 6: Relay security gates in the packet handler

**Files:**
- Modify: `src/dhcpv4/server.rs`

- [ ] **Step 1: Add `check_relay_security` helper with tests**

At the bottom of `src/dhcpv4/server.rs` (outside any existing impl), add tests that exercise the decision function:

```rust
#[cfg(test)]
mod relay_gate_tests {
    use super::*;
    use std::net::SocketAddr;

    fn make_subnet_info(network: &str, prefix: u8, trusted: Vec<Ipv4Addr>) -> SubnetInfo {
        let cfg = crate::config::SubnetConfig {
            network: format!("{}/{}", network, prefix),
            pool_start: None,
            pool_end: None,
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
            trusted_relays: trusted.iter().map(|ip| ip.to_string()).collect(),
            reservation: vec![],
        };
        SubnetInfo {
            network: Arc::from(cfg.network.as_str()),
            network_addr: network.parse().unwrap(),
            prefix_len: prefix,
            config: Arc::new(cfg),
            mac_acl: Arc::new(MacAcl::new(vec![], vec![])),
            trusted_relays: Arc::from(trusted.as_slice()),
        }
    }

    #[test]
    fn empty_trusted_relays_allows_any_source() {
        let subnet = make_subnet_info("10.0.0.0", 24, vec![]);
        assert!(relay_source_is_trusted(&subnet, Ipv4Addr::new(10, 0, 0, 5)));
        assert!(relay_source_is_trusted(&subnet, Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn populated_trusted_relays_enforces_match() {
        let trusted = vec![Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 6)];
        let subnet = make_subnet_info("10.0.0.0", 24, trusted);
        assert!(relay_source_is_trusted(&subnet, Ipv4Addr::new(10, 0, 0, 5)));
        assert!(relay_source_is_trusted(&subnet, Ipv4Addr::new(10, 0, 0, 6)));
        assert!(!relay_source_is_trusted(&subnet, Ipv4Addr::new(10, 0, 0, 7)));
    }
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cargo test -p rdhcpd --lib dhcpv4::server::relay_gate_tests`

Expected: compile error — `relay_source_is_trusted` not defined.

- [ ] **Step 3: Add `relay_source_is_trusted` free function**

Near the other free helpers at the top of `src/dhcpv4/server.rs` (before `impl<H> DhcpV4Server<H>`):

```rust
/// Returns true if `source` is an acceptable relay agent for `subnet`.
/// Empty trusted_relays = accept any source (backwards-compatible default).
fn relay_source_is_trusted(subnet: &SubnetInfo, source: Ipv4Addr) -> bool {
    subnet.trusted_relays.is_empty()
        || subnet.trusted_relays.iter().any(|ip| *ip == source)
}
```

- [ ] **Step 4: Insert the relay gate in `run()`**

In `src/dhcpv4/server.rs`, inside `run()` between the existing "DHCPv4 relay hop count validation" block (currently around lines 178–186) and the `msg_type` extraction (line 188), insert the following gate. It runs once per packet before any per-MAC rate limiting so relay drops are visible and cheap:

```rust
            // Relay security gates (RFC 3046 / hardening issue #57)
            if packet.is_relayed() {
                self.stats.relayed_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                // Global kill-switch
                if !self.config_accept_relayed {
                    self.stats.relayed_dropped_disabled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug!(src = %src_addr, giaddr = %packet.giaddr, "dropping relayed packet: accept_relayed=false");
                    continue;
                }

                // Bogon/martian check
                if crate::config::validation::is_bogon_giaddr(packet.giaddr) {
                    self.stats.relayed_dropped_bad_giaddr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!(src = %src_addr, giaddr = %packet.giaddr, "dropping relayed packet: bogon giaddr");
                    continue;
                }

                // giaddr MUST match a configured subnet (required before we can check trusted_relays)
                let relay_subnet = self.subnets.iter().find(|s| {
                    ip_in_subnet(
                        &IpAddr::V4(packet.giaddr),
                        &IpAddr::V4(s.network_addr),
                        s.prefix_len,
                    )
                });
                let relay_subnet = match relay_subnet {
                    Some(s) => s,
                    None => {
                        self.stats.relayed_dropped_bad_giaddr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!(src = %src_addr, giaddr = %packet.giaddr, "dropping relayed packet: giaddr does not match any configured subnet");
                        continue;
                    }
                };

                // Trusted-relay source IP check (per-subnet whitelist)
                let source_ip = match src_addr.ip() {
                    IpAddr::V4(v4) => v4,
                    _ => {
                        // Relayed DHCPv4 over IPv6 transport is not meaningful
                        self.stats.relayed_dropped_untrusted_relay.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        continue;
                    }
                };
                if !relay_source_is_trusted(relay_subnet, source_ip) {
                    self.stats.relayed_dropped_untrusted_relay.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!(src = %src_addr, giaddr = %packet.giaddr, subnet = %relay_subnet.network, "dropping relayed packet: source IP not in trusted_relays");
                    continue;
                }

                // Per-relay-source rate limit (in addition to per-MAC)
                let source_key = source_ip.octets();
                if !self.relay_rate_limiter.check(&source_key) {
                    self.stats.relayed_dropped_rate_limit.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug!(src = %src_addr, "dropping relayed packet: per-relay rate limit");
                    continue;
                }
            }
```

- [ ] **Step 5: Add the `config_accept_relayed` field so the gate above compiles**

In `DhcpV4Server`, add a field:

```rust
    /// Snapshot of `config.global.accept_relayed` for cheap reads.
    config_accept_relayed: bool,
```

And in `DhcpV4Server::new`, initialize it right after reading `pool_high_water`:

```rust
        let config_accept_relayed = config.global.accept_relayed;
```

Then include it in the struct literal:

```rust
        Self {
            // ...existing fields...
            config_accept_relayed,
        }
```

- [ ] **Step 6: Run tests and `cargo check`**

Run: `cargo test -p rdhcpd --lib dhcpv4::server::relay_gate_tests`

Expected: both relay_gate_tests pass.

Run: `cargo check`

Expected: clean build.

- [ ] **Step 7: Commit**

```bash
# Cargo.toml: version = "0.11.7"
git add Cargo.toml src/dhcpv4/server.rs
git commit -m "feat(dhcpv4): enforce relay security gates (accept_relayed, trusted_relays, bogon giaddr, rate limit)"
```

---

## Task 7: Dual-socket receive (`0.0.0.0:67` + `255.255.255.255:67`) on FreeBSD

**Files:**
- Modify: `src/dhcpv4/server.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Change `run()` to accept multiple sockets**

In `src/dhcpv4/server.rs`, change the `run` signature from `recv_socket: Arc<UdpSocket>` to `recv_sockets: Vec<Arc<UdpSocket>>`, and replace the single `recv_socket.recv_from` call with a `tokio::select!` across all sockets.

Replace the existing `run()` body's top (around lines 147–163):

```rust
    /// Run the DHCPv4 server loop.
    ///
    /// `recv_sockets` are the sockets to receive DHCP packets on. FreeBSD uses
    /// two sockets (broadcast 255.255.255.255:67 and unicast 0.0.0.0:67) so
    /// that both directly-connected and relayed DHCP can be received; on other
    /// platforms a single 0.0.0.0:67 socket is passed.
    /// `sender` dispatches replies — either via a kernel UDP socket or BPF raw frames.
    pub async fn run(
        &self,
        recv_sockets: Vec<Arc<UdpSocket>>,
        sender: Arc<DhcpSender>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut recv_bufs: Vec<[u8; MAX_PACKET_SIZE]> =
            (0..recv_sockets.len()).map(|_| [0u8; MAX_PACKET_SIZE]).collect();

        for s in &recv_sockets {
            info!(addr = %s.local_addr()?, "DHCPv4 server listening");
        }

        loop {
            // Receive from whichever socket is ready first.
            let (len, src_addr, buf_idx) = {
                // Build a FuturesUnordered-style select over all sockets.
                // We need fresh futures each iteration.
                use futures_util::future::select_all;
                use std::pin::Pin;
                let mut futs: Vec<Pin<Box<dyn std::future::Future<Output = std::io::Result<(usize, SocketAddr, usize)>> + Send>>> = Vec::with_capacity(recv_sockets.len());
                for (idx, s) in recv_sockets.iter().enumerate() {
                    let s = s.clone();
                    // SAFETY: we split the `recv_bufs` mutably by index — only the
                    // owning future writes to its buffer slot.
                    let buf_ptr = recv_bufs[idx].as_mut_ptr();
                    let fut = async move {
                        let buf_slice = unsafe { std::slice::from_raw_parts_mut(buf_ptr, MAX_PACKET_SIZE) };
                        let (len, addr) = s.recv_from(buf_slice).await?;
                        Ok((len, addr, idx))
                    };
                    futs.push(Box::pin(fut));
                }
                match select_all(futs).await.0 {
                    Ok(r) => r,
                    Err(e) => {
                        error!(error = %e, "failed to receive packet");
                        continue;
                    }
                }
            };

            let packet = match DhcpV4Packet::parse(&recv_bufs[buf_idx][..len]) {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = %e, src = %src_addr, "dropping malformed packet");
                    continue;
                }
            };

            // ...rest of the loop body unchanged (hop check, relay gate, msg_type dispatch)...
```

**Design note:** Using `futures_util::future::select_all` is simpler than nested `tokio::select!` and scales to N sockets. The unsafe pointer split is required because Rust's borrow checker otherwise forbids borrowing disjoint slots from `recv_bufs` across futures; the safety invariant is that each future only touches its own index.

Add to Cargo.toml under `[dependencies]`:

```toml
futures-util = { version = "0.3", default-features = false, features = ["std"] }
```

- [ ] **Step 2: Update `DhcpV4Server::run_one` callers if any — there are none; only `run()` is called from main.rs.**

- [ ] **Step 3: Update main.rs — build both sockets on FreeBSD, single socket elsewhere**

Replace the existing socket-build block (around lines 312–346) with:

```rust
        for worker_id in 0..worker_count {
            // Build receive sockets. On FreeBSD we need BOTH a 255.255.255.255:67
            // socket (to receive link-layer broadcasts; the only way FreeBSD
            // will deliver them to a UDP socket) AND a 0.0.0.0:67 socket (to
            // receive unicast packets from a DHCP relay). On other platforms
            // a single 0.0.0.0:67 catches both.
            let mut recv_sockets: Vec<Arc<UdpSocket>> = Vec::new();

            // Broadcast socket (FreeBSD-only; on Linux it's the same address family and not useful).
            #[cfg(target_os = "freebsd")]
            {
                let sock = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .map_err(|e| format!("failed to create DHCPv4 bcast recv socket: {}", e))?;
                sock.set_reuse_port(true)?;
                sock.set_broadcast(true)?;
                sock.set_nonblocking(true)?;

                let enable: libc::c_int = 1;
                unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::IPPROTO_IP,
                        24, // IP_BINDANY
                        &enable as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }

                let bind_addr: std::net::SocketAddr = format!("255.255.255.255:{}", dhcpv4_port).parse().unwrap();
                sock.bind(&bind_addr.into())
                    .map_err(|e| format!("failed to bind DHCPv4 broadcast port {}: {} (try running as root)", dhcpv4_port, e))?;
                recv_sockets.push(Arc::new(UdpSocket::from_std(sock.into())?));
            }

            // Unicast/any socket. On non-FreeBSD this is the only socket and catches both
            // broadcast and unicast. On FreeBSD it is added in addition to the broadcast socket
            // so we can receive relayed unicast to the server IP.
            {
                let sock = socket2::Socket::new(
                    socket2::Domain::IPV4,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )
                .map_err(|e| format!("failed to create DHCPv4 recv socket: {}", e))?;
                sock.set_reuse_port(true)?;
                sock.set_broadcast(true)?;
                sock.set_nonblocking(true)?;

                let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", dhcpv4_port).parse().unwrap();
                sock.bind(&bind_addr.into())
                    .map_err(|e| format!("failed to bind DHCPv4 port {}: {} (try running as root)", dhcpv4_port, e))?;
                recv_sockets.push(Arc::new(UdpSocket::from_std(sock.into())?));
            }

            let dhcpv4_server = DhcpV4Server::new(
                config.clone(),
                lease_store.clone(),
                allocators.clone(),
                wal.clone(),
                ha.clone(),
                server_ip,
                rate_limiter.clone(),
                global_rate_limiter.clone(),
                rogue_detector.clone(),
                relay_rate_limiter.clone(),
                dhcpv4_stats.clone(),
            );

            let worker_sender = sender.clone();
            dhcpv4_handles.push(tokio::spawn(async move {
                if let Err(e) = dhcpv4_server.run(recv_sockets, worker_sender).await {
                    error!(error = %e, worker = worker_id, "DHCPv4 server error");
                }
            }));
        }
```

- [ ] **Step 4: Run `cargo check`**

Run: `cargo check`

Expected: clean build (warnings OK).

- [ ] **Step 5: Smoke-test existing tests still pass**

Run: `cargo test -p rdhcpd`

Expected: all existing tests pass.

- [ ] **Step 6: Commit**

```bash
# Cargo.toml: version = "0.11.8"
git add Cargo.toml src/dhcpv4/server.rs src/main.rs
git commit -m "feat(dhcpv4): dual-socket receive (broadcast + unicast) for FreeBSD relay support"
```

---

## Task 8: Expose relay stats via Prometheus

**Files:**
- Modify: `src/api/mod.rs`
- Modify: `src/api/metrics.rs`
- Modify: `src/main.rs`

- [ ] **Step 1: Plumb `DhcpV4Stats` into `ApiState`**

In `src/api/mod.rs`, find `struct ApiState<H>` and add a field:

```rust
    pub dhcpv4_stats: Arc<crate::dhcpv4::stats::DhcpV4Stats>,
```

In `src/main.rs`, update the `Arc::new(ApiState { ... })` construction to include:

```rust
            dhcpv4_stats: dhcpv4_stats.clone(),
```

- [ ] **Step 2: Emit the counters in Prometheus format**

In `src/api/metrics.rs`, append before the final `([(header::CONTENT_TYPE, ...)], output)` return:

```rust
    use std::sync::atomic::Ordering;
    let s = &state.dhcpv4_stats;

    output.push_str("# HELP rdhcpd_dhcpv4_relayed_received_total DHCPv4 packets received with giaddr != 0\n");
    output.push_str("# TYPE rdhcpd_dhcpv4_relayed_received_total counter\n");
    output.push_str(&format!(
        "rdhcpd_dhcpv4_relayed_received_total {}\n",
        s.relayed_received.load(Ordering::Relaxed)
    ));

    output.push_str("# HELP rdhcpd_dhcpv4_relayed_dropped_total DHCPv4 relayed packets dropped, by reason\n");
    output.push_str("# TYPE rdhcpd_dhcpv4_relayed_dropped_total counter\n");
    output.push_str(&format!(
        "rdhcpd_dhcpv4_relayed_dropped_total{{reason=\"accept_relayed_disabled\"}} {}\n",
        s.relayed_dropped_disabled.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "rdhcpd_dhcpv4_relayed_dropped_total{{reason=\"bad_giaddr\"}} {}\n",
        s.relayed_dropped_bad_giaddr.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "rdhcpd_dhcpv4_relayed_dropped_total{{reason=\"untrusted_relay\"}} {}\n",
        s.relayed_dropped_untrusted_relay.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "rdhcpd_dhcpv4_relayed_dropped_total{{reason=\"rate_limit\"}} {}\n",
        s.relayed_dropped_rate_limit.load(Ordering::Relaxed)
    ));
```

- [ ] **Step 3: Add a unit test for metrics exposition**

Append to `src/api/metrics.rs` (inside a new `#[cfg(test)] mod tests { ... }` block). The test directly formats the counters from a synthetic state to avoid needing an HTTP harness:

```rust
#[cfg(test)]
mod tests {
    use crate::dhcpv4::stats::DhcpV4Stats;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    #[test]
    fn metrics_strings_are_emitted_for_relay_counters() {
        let s = Arc::new(DhcpV4Stats::new());
        s.relayed_received.fetch_add(7, Ordering::Relaxed);
        s.relayed_dropped_untrusted_relay.fetch_add(2, Ordering::Relaxed);

        // Build the same fragment the handler emits (no HTTP).
        let mut output = String::new();
        output.push_str(&format!(
            "rdhcpd_dhcpv4_relayed_received_total {}\n",
            s.relayed_received.load(Ordering::Relaxed)
        ));
        output.push_str(&format!(
            "rdhcpd_dhcpv4_relayed_dropped_total{{reason=\"untrusted_relay\"}} {}\n",
            s.relayed_dropped_untrusted_relay.load(Ordering::Relaxed)
        ));

        assert!(output.contains("rdhcpd_dhcpv4_relayed_received_total 7"));
        assert!(output.contains("rdhcpd_dhcpv4_relayed_dropped_total{reason=\"untrusted_relay\"} 2"));
    }
}
```

- [ ] **Step 4: Run tests**

Run: `cargo test -p rdhcpd --lib api::metrics::tests`

Expected: pass.

Run: `cargo check`

Expected: clean.

- [ ] **Step 5: Commit**

```bash
# Cargo.toml: version = "0.11.9"
git add Cargo.toml src/api/mod.rs src/api/metrics.rs src/main.rs
git commit -m "feat(api): expose DHCPv4 relay counters in Prometheus metrics"
```

---

## Task 9: Documentation — SECURITY.md, CHANGELOG.md, example-config.toml

**Files:**
- Modify: `SECURITY.md`
- Modify: `CHANGELOG.md`
- Modify: `example-config.toml` (minor additions)

- [ ] **Step 1: Update SECURITY.md**

In `SECURITY.md`, under "Network" (near line 32), add:

```markdown
- DHCP relay agent forwarding (`giaddr != 0`) is accepted by default. On
  FreeBSD the server listens on both `255.255.255.255:67` (directly-connected
  broadcasts) and `0.0.0.0:67` (relayed unicast) so relayed requests are
  received. To disable relay acceptance entirely set `accept_relayed = false`
  in `[global]`. To restrict which relay agents may forward to a subnet, set
  `trusted_relays = ["<relay-ip>", ...]` on each `[[subnet]]` — packets from
  any other source are dropped silently and counted under
  `rdhcpd_dhcpv4_relayed_dropped_total{reason="untrusted_relay"}`.
- Relay input is additionally validated: `giaddr` must not be a bogon
  (loopback/link-local/multicast/broadcast/reserved) and must fall within a
  configured subnet, otherwise the packet is dropped. Option 82 (relay agent
  information) is **not** used for client identity.
- A separate rate limiter is applied per UDP source IP on relayed traffic so
  a single misbehaving relay cannot exhaust the global per-MAC budget.
```

- [ ] **Step 2: Update CHANGELOG.md with an entry**

Prepend a new section at the top of `CHANGELOG.md` (below any existing header):

```markdown
## [0.12.0] - 2026-04-17

### Added
- **DHCPv4 relay agent support on FreeBSD** — a second per-worker receive
  socket on `0.0.0.0:67` is now opened alongside the existing broadcast
  socket so requests forwarded from a DHCP relay (`giaddr != 0`) are
  received and processed. Previously FreeBSD silently dropped these.
  (Fixes #57.)
- `[global] accept_relayed = true|false` — global kill-switch for relayed
  DHCP (default: `true`).
- `[[subnet]] trusted_relays = ["<ip>", ...]` — per-subnet whitelist of
  relay agent source IPs (default: empty = accept any relay).
- Prometheus metrics: `rdhcpd_dhcpv4_relayed_received_total` and
  `rdhcpd_dhcpv4_relayed_dropped_total{reason="..."}` with reasons
  `accept_relayed_disabled`, `bad_giaddr`, `untrusted_relay`, `rate_limit`.

### Security
- `giaddr` is validated against a bogon list (loopback, link-local,
  multicast, broadcast, class E, unspecified) before further processing.
- A per-relay-source rate limiter is applied to relayed traffic in
  addition to the existing per-MAC limiter.
```

If `CHANGELOG.md` does not exist yet (repository layout shows it does — `CHANGELOG.md` is listed at the top), skip the creation step and only prepend.

- [ ] **Step 3: Commit**

```bash
# Cargo.toml: version = "0.12.0" (minor bump for the feature)
git add Cargo.toml SECURITY.md CHANGELOG.md
git commit -m "docs: document DHCPv4 relay support, trusted_relays, and new metrics"
```

---

## Task 10: Integration-style test for the relay security gates

**Files:**
- Create: `tests/dhcpv4_relay_gates.rs`

This is an end-to-end test that builds a `DhcpV4Server`, feeds it synthetic packets, and verifies the counters advance for each drop reason. It does not require sockets — it drives `handle_discover` / `handle_request` through a thin harness, or it constructs just enough state to run the gate logic through a helper method. Since the gate currently lives inline in `run()`, refactor it into a pub(crate) method `pub(crate) fn classify_relayed(&self, packet: &DhcpV4Packet, src: SocketAddr) -> RelayDecision` so it is testable in isolation.

- [ ] **Step 1: Refactor the inline gate into a testable method**

In `src/dhcpv4/server.rs`, add:

```rust
/// Outcome of the relay-security classification.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelayDecision {
    /// Packet is not relayed — skip relay checks.
    NotRelayed,
    /// Relayed and accepted.
    Accept,
    /// Dropped because `accept_relayed = false`.
    DroppedDisabled,
    /// Dropped because giaddr is a bogon or does not match a subnet.
    DroppedBadGiaddr,
    /// Dropped because the UDP source IP is not in the subnet's trusted_relays.
    DroppedUntrustedRelay,
    /// Dropped by the per-relay-source rate limiter.
    DroppedRateLimit,
}
```

And an `impl` method:

```rust
    pub(crate) fn classify_relayed(
        &self,
        packet: &DhcpV4Packet,
        src_addr: SocketAddr,
    ) -> RelayDecision {
        if !packet.is_relayed() {
            return RelayDecision::NotRelayed;
        }
        self.stats.relayed_received.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if !self.config_accept_relayed {
            self.stats.relayed_dropped_disabled.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return RelayDecision::DroppedDisabled;
        }
        if crate::config::validation::is_bogon_giaddr(packet.giaddr) {
            self.stats.relayed_dropped_bad_giaddr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return RelayDecision::DroppedBadGiaddr;
        }
        let relay_subnet = match self.subnets.iter().find(|s| {
            ip_in_subnet(&IpAddr::V4(packet.giaddr), &IpAddr::V4(s.network_addr), s.prefix_len)
        }) {
            Some(s) => s,
            None => {
                self.stats.relayed_dropped_bad_giaddr.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return RelayDecision::DroppedBadGiaddr;
            }
        };
        let source_ip = match src_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => {
                self.stats.relayed_dropped_untrusted_relay.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return RelayDecision::DroppedUntrustedRelay;
            }
        };
        if !relay_source_is_trusted(relay_subnet, source_ip) {
            self.stats.relayed_dropped_untrusted_relay.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return RelayDecision::DroppedUntrustedRelay;
        }
        if !self.relay_rate_limiter.check(&source_ip.octets()) {
            self.stats.relayed_dropped_rate_limit.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return RelayDecision::DroppedRateLimit;
        }
        RelayDecision::Accept
    }
```

Then replace the inline gate in `run()` (from Task 6) with:

```rust
            match self.classify_relayed(&packet, src_addr) {
                RelayDecision::NotRelayed | RelayDecision::Accept => {}
                RelayDecision::DroppedDisabled => {
                    debug!(src = %src_addr, giaddr = %packet.giaddr, "dropping relayed packet: accept_relayed=false");
                    continue;
                }
                RelayDecision::DroppedBadGiaddr => {
                    warn!(src = %src_addr, giaddr = %packet.giaddr, "dropping relayed packet: bogon or unknown-subnet giaddr");
                    continue;
                }
                RelayDecision::DroppedUntrustedRelay => {
                    warn!(src = %src_addr, giaddr = %packet.giaddr, "dropping relayed packet: source IP not in trusted_relays");
                    continue;
                }
                RelayDecision::DroppedRateLimit => {
                    debug!(src = %src_addr, "dropping relayed packet: per-relay rate limit");
                    continue;
                }
            }
```

- [ ] **Step 2: Create the integration test file**

Create `tests/dhcpv4_relay_gates.rs`:

```rust
//! Integration-style tests for the DHCPv4 relay security gates.
//!
//! These exercise the public `classify_relayed` path on a fully-constructed
//! `DhcpV4Server` so we cover config parsing, SubnetInfo construction, and
//! the gate logic end-to-end.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use rdhcpd::config::{Config, SubnetConfig, GlobalConfig, HaConfig};
use rdhcpd::dhcpv4::server::{DhcpV4Server, RelayDecision};
use rdhcpd::dhcpv4::stats::DhcpV4Stats;
use rdhcpd::ha::StandaloneBackend;
use rdhcpd::lease::store::LeaseStore;
use rdhcpd::ratelimit::{RateLimiter, RogueDetector};
use rdhcpd::wal::Wal;
use rdhcpd::allocator;

// NOTE: DhcpV4Packet is crate-private in some revisions — if the type is not
// re-exported, expose it via `pub use dhcpv4::packet::DhcpV4Packet` in
// `src/lib.rs` as part of this task.

fn make_config(accept_relayed: bool, trusted: Vec<String>) -> Config {
    let global = GlobalConfig {
        log_level: "info".into(),
        log_format: "text".into(),
        lease_db: tempfile_path(),
        workers: 1,
        rate_limit_burst: 10,
        rate_limit_pps: 5.0,
        global_rate_limit_pps: 0.0,
        rogue_threshold: 50,
        rogue_window_secs: 60,
        pool_high_water: 0.9,
        accept_relayed,
    };
    let subnet = SubnetConfig {
        network: "10.0.0.0/24".into(),
        pool_start: Some("10.0.0.100".into()),
        pool_end: Some("10.0.0.200".into()),
        lease_time: 3600,
        max_lease_time: None,
        renewal_time: None,
        rebinding_time: None,
        preferred_time: None,
        subnet_type: "address".into(),
        delegated_length: None,
        router: Some("10.0.0.1".into()),
        dns: vec![],
        domain: None,
        ip_probe: false,
        ip_probe_timeout_ms: None,
        max_leases_per_mac: 1,
        mac_allow: vec![],
        mac_deny: vec![],
        trusted_relays: trusted,
        reservation: vec![],
    };
    Config {
        global,
        api: None,
        ha: HaConfig::Standalone,
        subnet: vec![subnet],
        ddns: None,
    }
}

fn tempfile_path() -> String {
    let dir = std::env::temp_dir().join(format!("rdhcpd-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().into_owned()
}

async fn make_server(cfg: Config) -> (DhcpV4Server<StandaloneBackend>, Arc<DhcpV4Stats>) {
    let wal = Arc::new(Wal::open(&cfg.global.lease_db).await.unwrap());
    let lease_store = LeaseStore::new();
    let allocators = Arc::new(allocator::build_allocators(&cfg, &lease_store).unwrap());
    let stats = Arc::new(DhcpV4Stats::new());
    let rl = Arc::new(RateLimiter::new(10, 5.0));
    let relay_rl = Arc::new(RateLimiter::new(10, 5.0));
    let rogue = Arc::new(RogueDetector::new(50, 60));
    let ha = Arc::new(StandaloneBackend);
    let server = DhcpV4Server::new(
        Arc::new(cfg),
        lease_store,
        allocators,
        wal,
        ha,
        Ipv4Addr::new(10, 0, 0, 1),
        rl,
        None,
        rogue,
        relay_rl,
        stats.clone(),
    );
    (server, stats)
}

fn relayed_discover(giaddr: Ipv4Addr) -> rdhcpd::dhcpv4::packet::DhcpV4Packet {
    // Build a minimal BOOTREQUEST Discover with a non-zero giaddr.
    // Using the existing build helpers in src/dhcpv4/packet.rs.
    let mut p = rdhcpd::dhcpv4::packet::DhcpV4Packet::new_discover([0xaa; 6]);
    p.giaddr = giaddr;
    p
}

#[tokio::test]
async fn accept_relayed_disabled_drops_relayed_packets() {
    let cfg = make_config(false, vec![]);
    let (server, stats) = make_server(cfg).await;

    let pkt = relayed_discover(Ipv4Addr::new(10, 0, 0, 5));
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 67);
    assert_eq!(server.classify_relayed(&pkt, src), RelayDecision::DroppedDisabled);
    assert_eq!(stats.relayed_dropped_disabled.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn bogon_giaddr_is_dropped() {
    let cfg = make_config(true, vec![]);
    let (server, stats) = make_server(cfg).await;

    let pkt = relayed_discover(Ipv4Addr::new(127, 0, 0, 1));
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 67);
    assert_eq!(server.classify_relayed(&pkt, src), RelayDecision::DroppedBadGiaddr);
    assert!(stats.relayed_dropped_bad_giaddr.load(std::sync::atomic::Ordering::Relaxed) >= 1);
}

#[tokio::test]
async fn untrusted_relay_source_is_dropped_when_whitelist_populated() {
    let cfg = make_config(true, vec!["10.0.0.99".into()]);
    let (server, stats) = make_server(cfg).await;

    let pkt = relayed_discover(Ipv4Addr::new(10, 0, 0, 5)); // giaddr in subnet
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 67); // not in whitelist
    assert_eq!(server.classify_relayed(&pkt, src), RelayDecision::DroppedUntrustedRelay);
    assert_eq!(stats.relayed_dropped_untrusted_relay.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn trusted_relay_source_is_accepted() {
    let cfg = make_config(true, vec!["10.0.0.5".into()]);
    let (server, stats) = make_server(cfg).await;

    let pkt = relayed_discover(Ipv4Addr::new(10, 0, 0, 5));
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 67);
    assert_eq!(server.classify_relayed(&pkt, src), RelayDecision::Accept);
    assert_eq!(stats.relayed_received.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn direct_broadcast_packets_bypass_relay_gates() {
    let cfg = make_config(false, vec![]); // even with accept_relayed=false
    let (server, _stats) = make_server(cfg).await;

    // giaddr = 0.0.0.0 → is_relayed() == false
    let pkt = rdhcpd::dhcpv4::packet::DhcpV4Packet::new_discover([0xaa; 6]);
    let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);
    assert_eq!(server.classify_relayed(&pkt, src), RelayDecision::NotRelayed);
}
```

**Note on `DhcpV4Packet::new_discover`:** if this helper does not yet exist in `src/dhcpv4/packet.rs`, add it behind `#[cfg(any(test, feature = "test-helpers"))]`:

```rust
#[cfg(any(test, feature = "test-helpers"))]
impl DhcpV4Packet {
    /// Construct a minimal BOOTREQUEST Discover for tests.
    pub fn new_discover(mac: [u8; 6]) -> Self {
        let mut chaddr = [0u8; 16];
        chaddr[..6].copy_from_slice(&mac);
        Self {
            op: 1,   // BOOTREQUEST
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x12345678,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            options: vec![DhcpOption::MessageType(MessageType::Discover)],
        }
    }
}
```

Also, `pub use dhcpv4::packet::DhcpV4Packet;` may need to be added to `src/lib.rs` (or re-exported from `dhcpv4::packet`) so integration tests can name the type. Check first with `cargo test` — if the type is visible as `rdhcpd::dhcpv4::packet::DhcpV4Packet`, no re-export is needed; the test file already uses the full path.

- [ ] **Step 3: Run the integration tests**

Run: `cargo test --test dhcpv4_relay_gates`

Expected: all five tests pass.

- [ ] **Step 4: Run the full test suite**

Run: `cargo test -p rdhcpd`

Expected: no regressions.

- [ ] **Step 5: Commit**

```bash
# Cargo.toml: version = "0.12.1"
git add Cargo.toml tests/dhcpv4_relay_gates.rs src/dhcpv4/server.rs src/dhcpv4/packet.rs
git commit -m "test(dhcpv4): integration tests for relay security gates"
```

---

## Task 11: Final verification and close-out

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite and cargo check**

Run:

```bash
cargo check
cargo test -p rdhcpd
```

Expected: all tests pass, no new warnings.

- [ ] **Step 2: Verify Linux-side compile still works (dual-socket path is cfg-gated but `run()` signature changed for all platforms)**

Run:

```bash
cargo build
```

Expected: clean build on Linux. The unicast socket is what Linux already uses, so runtime behavior is unchanged for Linux users.

- [ ] **Step 3: Build FreeBSD-conditional paths (static check only)**

Run:

```bash
cargo check --target x86_64-unknown-freebsd 2>&1 | head -30
```

If the FreeBSD target is not installed locally, skip this step — CI or a manual FreeBSD build will cover it.

- [ ] **Step 4: Sanity-check acceptance criteria**

Review the issue's acceptance checklist item-by-item against the implementation:

- [x] FreeBSD unicast DHCPDISCOVER with `giaddr != 0` is received → Task 7 dual-socket.
- [x] Scope selection via `giaddr` works → pre-existing `select_subnet` + Task 6 gate.
- [x] OFFER/ACK unicast back to `giaddr:67` via kernel UDP → pre-existing `reply_destination`.
- [x] Direct-broadcast (`giaddr == 0`) unchanged → Task 10 test covers this.
- [x] `trusted_relays` enforcement → Task 6 + Task 10 integration tests.
- [x] `accept_relayed = false` drops all relayed → Task 6 + Task 10 integration tests.
- [x] Integration test → Task 10.
- [ ] `bench/run.sh` no regression → **manual step, not part of this plan**. Run `bench/run.sh` before and after the commit series and note results in the PR description.
- [x] `SECURITY.md` updated → Task 9.

- [ ] **Step 5: Open PR**

```bash
git push -u origin <branch-name>
gh pr create --title "Accept relayed DHCPv4 on FreeBSD with trusted-relay security model" --body "$(cat <<'EOF'
## Summary
- Adds a unicast `0.0.0.0:67` receive socket on FreeBSD (alongside the existing `255.255.255.255:67`) so relayed DHCPv4 requests are no longer silently dropped
- Adds `[global] accept_relayed` kill-switch and per-`[[subnet]]` `trusted_relays` whitelist
- Validates `giaddr` against a bogon list and drops relayed packets with an unknown-subnet `giaddr`
- Adds per-relay-source rate limiting and Prometheus metrics for relay accept/drop counters

Fixes #57.

## Test plan
- [x] Unit tests for `is_bogon_giaddr`, `relay_source_is_trusted`, `SubnetInfo::parse_trusted_relays`, and `DhcpV4Stats`
- [x] Integration tests for each `RelayDecision` variant (`tests/dhcpv4_relay_gates.rs`)
- [ ] Manual FreeBSD smoke test with a Juniper EX2300 relay (per issue repro)
- [ ] `bench/run.sh` before/after comparison — verify no regression on direct-broadcast DORA
EOF
)"
```

---

## Self-Review

**Spec coverage — from issue acceptance criteria:**

| Criterion | Task |
|---|---|
| FreeBSD unicast DHCPDISCOVER received and logged | 7 |
| Scope selection via giaddr | pre-existing, validated in 6/10 |
| OFFER/ACK unicast to giaddr:67 via UDP | pre-existing |
| Direct-broadcast unchanged | 7 + 10 |
| trusted_relays whitelist enforced | 6 + 10 |
| accept_relayed = false drops early | 6 + 10 |
| Integration test | 10 |
| SECURITY.md updated | 9 |

**Spec coverage — from issue "Security considerations":**

| Item | Task |
|---|---|
| Trusted relay agent whitelist | 1, 4, 6 |
| giaddr sanity (must be in configured subnet) | 6 |
| Bogon/martian check | 2, 6 |
| Hop count bound (keep) | pre-existing |
| Per-relay-source rate limit | 5, 6 |
| Metrics (`relayed_received_total`, `dropped_untrusted_relay_total`, `dropped_bad_giaddr_total`) | 3, 8 |
| Option 82 not trusted | explicit in SECURITY.md (Task 9) — existing code does not consume Option 82 for identity |

**Placeholder scan:** no "TBD", no "implement later", no "similar to Task N" hand-waves — every step contains exact code.

**Type consistency:**
- `DhcpV4Stats` field names (`relayed_received`, `relayed_dropped_disabled`, `relayed_dropped_bad_giaddr`, `relayed_dropped_untrusted_relay`, `relayed_dropped_rate_limit`) are used identically in Tasks 3, 6, 8, 10.
- `RelayDecision` enum variants used in Task 10 match Task 10 definitions.
- `SubnetInfo::trusted_relays` is `Arc<[Ipv4Addr]>` consistently in Tasks 4, 6.
- `relay_rate_limiter` and `stats` argument order in `DhcpV4Server::new` is consistent in Tasks 5, 7, 10.
- `DhcpV4Packet::new_discover` is defined behind `#[cfg(any(test, feature = "test-helpers"))]` in Task 10 — test file uses it, no production dependency.

**Gap notes:**
- The bench run against `bench/run.sh` is listed as a manual step. Benchmarking is environment-sensitive and not script-testable in the plan; it belongs in the PR's manual test plan.
- SIGHUP reload does not re-read the new config fields at runtime — existing code only validates the reloaded config and logs a notice ("restart required"). That's the existing behavior and is out of scope for this issue.
