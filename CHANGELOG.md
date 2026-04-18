# Changelog

All notable changes to rDHCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.5] - 2026-04-17

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

### Changed (post-merge polish)
- Dedicated `relay_rate_limit_burst` / `relay_rate_limit_pps` (defaults 200 / 100.0) — the previous behavior reused per-MAC defaults which were too restrictive for a relay.
- Bad-giaddr and untrusted-relay drops now log at `debug!` (they fire before the per-relay rate limiter — counters remain authoritative).
- Malformed `trusted_relays` entries are now logged as warnings at startup instead of being silently dropped.

## [0.8.0] - 2026-03-29

### Added
- Full DHCPv4 server (RFC 2131/2132) with DORA state machine
- Full DHCPv6 server (RFC 8415) with IA_NA, IA_PD, relay support
- Active/Active HA with split-scope and failover state machine
- Raft HA with leader election and log replication
- mTLS for all HA peer communication (rustls)
- REST management API (axum) with lease/subnet CRUD
- Prometheus metrics endpoint
- DDNS integration (RFC 2136) with TSIG authentication
- Write-ahead log with CRC32 checksums for lease durability
- Bitmap allocator with O(1) free-IP lookup
- DashMap-backed lease store with atomic counters
- BTreeMap expiry queue for O(k) lease cleanup
- SO_REUSEPORT multi-core receive workers
- Per-client rate limiting (token bucket)
- MAC allow/deny lists
- SIGHUP config reload
- Systemd unit file with security hardening
- Docker image (FROM scratch, static musl binary)
- Health check endpoints (/health, /healthz)
- Benchmark suite with perfdhcp

### Performance
- 18,000 DORA/sec peak throughput
- 0.087ms average latency at sustained 1,000/sec
- 3.8 MB RSS with 20k active leases
- Zero-allocation hot path (Arc<str>, stack buffers, MacDisplay)
