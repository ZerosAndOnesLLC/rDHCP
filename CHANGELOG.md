# Changelog

All notable changes to rDHCP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
