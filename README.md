# rDHCP

[![CI](https://github.com/ZerosAndOnesLLC/rDHCP/actions/workflows/ci.yml/badge.svg)](https://github.com/ZerosAndOnesLLC/rDHCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/ZerosAndOnesLLC/rDHCP)](https://github.com/ZerosAndOnesLLC/rDHCP/releases)

A high-performance, dual-stack DHCP server written in Rust. Drop-in replacement for ISC DHCP and Kea with built-in high availability, no external database, and a single static binary.

## Why rDHCP

| | ISC DHCP | Kea | rDHCP |
|---|---|---|---|
| Language | C | C++ | Rust |
| Binary | daemon + config tools | daemon + Python hooks + DB drivers | single static binary |
| External DB required | no | yes (MySQL/Postgres/Cassandra for HA) | no |
| Config format | custom DSL | JSON (no comments) | TOML |
| HA built-in | failover protocol | requires external DB replication | active/active or Raft |
| Memory (20k leases) | ~30 MB | ~40-100 MB | ~4 MB |
| Dependencies | libssl, etc | libboost, libmysql, python3 | none |
| Status | EOL | active | active |

## Performance

Benchmarked with `perfdhcp` on loopback (WSL2, 8-core):

| Metric | rDHCP | Kea (published) |
|--------|-------|-----------------|
| Sustained throughput | 1,000 DORA/sec (0% drops) | 1,000 DORA/sec |
| Peak throughput | **~18,000 DORA/sec** | ~4,000-10,000 DORA/sec |
| Avg latency (sustained) | **0.087 ms** | 1-5 ms |
| Memory (20k leases) | **3.8 MB** | 40-100 MB |

Key design choices behind these numbers:

- **Bitmap allocator** with O(1) free-IP lookup via 64-bit word scanning
- **DashMap** lock-free concurrent lease store with atomic counters
- **BTreeMap expiry queue** — O(k) expired lease cleanup instead of O(n) table scan
- **SO_REUSEPORT** with multiple receive workers across CPU cores
- **Zero-allocation hot path** — `Arc<str>` for lease fields, stack buffers for packets, `MacDisplay` writer for logging
- **Write-ahead log** with CRC32 checksums for durability without database overhead

## Features

- **Dual-stack** — Full DHCPv4 (RFC 2131/2132) and DHCPv6 (RFC 8415)
- **High Availability** — Active/Active split-scope (2 nodes) or Raft consensus (3+ nodes)
- **Prefix Delegation** — DHCPv6 IA_PD with configurable delegated prefix lengths
- **Relay Support** — Option 82 (DHCPv4), Relay-forward/reply (DHCPv6) with hop count validation
- **DDNS** — RFC 2136 dynamic DNS updates with TSIG (HMAC-SHA256) authentication
- **REST API** — Lease/subnet CRUD, pool utilization stats, HA status, with API key authentication
- **Prometheus Metrics** — Pool utilization, lease state counters, HA health
- **Security Hardening** — Rate limiting, MAC ACLs, rogue client detection, duplicate IP probing, max lease enforcement (see [Security](#security) section)
- **Operational** — SIGHUP config reload, systemd integration, structured JSON logging

## Quick Start

```bash
# Build
cargo build --release

# Run (requires root for port 67/547)
sudo ./target/release/rdhcpd /etc/rdhcpd/config.toml

# Or with example config
sudo ./target/release/rdhcpd example-config.toml
```

## Configuration

All configuration is in a single TOML file. See [`example-config.toml`](example-config.toml) for a full reference with comments.

### Minimal IPv4

```toml
[global]
lease_db = "/var/lib/rdhcpd/leases"

[ha]
mode = "standalone"

[[subnet]]
network = "192.168.1.0/24"
pool_start = "192.168.1.100"
pool_end = "192.168.1.250"
lease_time = 86400
router = "192.168.1.1"
dns = ["8.8.8.8", "8.8.4.4"]
domain = "example.com"
```

### Dual-Stack with Reservations

```toml
[global]
log_level = "info"
log_format = "json"
lease_db = "/var/lib/rdhcpd/leases"

[api]
listen = "127.0.0.1:8080"
api_key = "my-secret-key"

[ha]
mode = "standalone"

# IPv4
[[subnet]]
network = "10.0.1.0/24"
pool_start = "10.0.1.100"
pool_end = "10.0.1.250"
lease_time = 86400
router = "10.0.1.1"
dns = ["10.0.0.53"]
domain = "corp.example.com"

[[subnet.reservation]]
mac = "aa:bb:cc:dd:ee:f1"
ip = "10.0.1.10"
hostname = "printer"

[[subnet.reservation]]
mac = "aa:bb:cc:dd:ee:f2"
ip = "10.0.1.11"
hostname = "server"

# IPv6
[[subnet]]
network = "2001:db8:1::/64"
pool_start = "2001:db8:1::1000"
pool_end = "2001:db8:1::ffff"
lease_time = 86400
preferred_time = 43200
dns = ["2001:db8::53"]
domain = "corp.example.com"

# IPv6 Prefix Delegation
[[subnet]]
network = "2001:db8:pd::/48"
type = "prefix-delegation"
delegated_length = 56
lease_time = 604800
```

### High Availability

**Active/Active** — Two nodes, split-scope with automatic failover:

```toml
[ha]
mode = "active-active"
peer = "10.0.0.2:9000"
listen = "0.0.0.0:9000"
scope_split = 0.5
mclt = 3600
partner_down_delay = 3600
tls_cert = "/etc/rdhcpd/cert.pem"
tls_key = "/etc/rdhcpd/key.pem"
tls_ca = "/etc/rdhcpd/ca.pem"
```

Each node owns half the pool. If a peer fails, the surviving node takes over the full scope after `partner_down_delay` seconds. Failover state machine: Normal -> Communications-Interrupted -> Partner-Down -> Recover.

**Raft** — Three or more nodes, consensus-based:

```toml
[ha]
mode = "raft"
node_id = 1
peers = ["10.0.0.2:9000", "10.0.0.3:9000"]
tls_cert = "/etc/rdhcpd/cert.pem"
tls_key = "/etc/rdhcpd/key.pem"
tls_ca = "/etc/rdhcpd/ca.pem"
```

All lease operations go through the Raft log. The leader serves DHCP requests; followers replicate and take over via election if the leader fails. Provides strong consistency — no duplicate IP assignments, even during split-brain.

### Dynamic DNS

```toml
[ddns]
enabled = true
forward_zone = "example.com"
reverse_zone_v4 = "1.0.10.in-addr.arpa"
dns_server = "10.0.0.53"
tsig_key = "dhcp-key"
tsig_algorithm = "hmac-sha256"
tsig_secret = "base64encodedkey=="
ttl = 300
```

Creates/removes A, AAAA, and PTR records automatically on lease assignment and expiry.

## Security

rDHCP includes multiple layers of defense against common DHCP attacks and misconfigurations.

### Rate Limiting

Per-client and global rate limiting using token bucket algorithms to prevent DHCP starvation:

```toml
[global]
rate_limit_burst = 10           # max packets in a burst per client
rate_limit_pps = 5.0            # sustained packets/sec per client
global_rate_limit_pps = 1000.0  # total server-wide packets/sec (0 = disabled)
```

- **Per-client** — Keyed by MAC (DHCPv4) or DUID (DHCPv6). A client exceeding its limit has packets silently dropped until tokens refill.
- **Global** — Applies before per-client checks. Protects against distributed attacks where many clients each stay under the per-client limit.

### MAC Access Control Lists

Per-subnet allow/deny lists to restrict which clients can obtain leases:

```toml
[[subnet]]
network = "10.0.1.0/24"
mac_allow = ["aa:bb:cc:dd:ee:f1", "aa:bb:cc:dd:ee:f2"]  # empty = allow all
mac_deny = ["00:11:22:33:44:55"]                          # deny list wins
```

The deny list is checked first. If the allow list is non-empty, only listed MACs receive leases. Denied clients are logged at WARN level.

### Rogue Client Detection

Sliding window anomaly detection alerts on suspicious client behavior:

```toml
[global]
rogue_threshold = 50      # requests per window before warning
rogue_window_secs = 60    # detection window
pool_high_water = 0.9     # warn at 90% pool utilization
```

When a client exceeds the threshold, a WARN log is emitted with the client identifier and request count. Pool utilization warnings fire when allocation crosses the high-water mark.

### Max Leases Per MAC

Prevents a single client (or spoofed MAC) from accumulating multiple leases:

```toml
[[subnet]]
max_leases_per_mac = 1    # default: 1, set to 0 for unlimited
```

### Duplicate IP Detection

Optional probing before offering an address to detect conflicts proactively:

```toml
[[subnet]]
ip_probe = true
ip_probe_timeout_ms = 500
```

When enabled, the server sends a probe to the candidate IP before offering it. If a response is received (indicating the address is already in use), the IP is skipped and a warning is logged.

### Relay Hop Count Validation

- **DHCPv4**: Packets with `hops > 16` are dropped (per RFC 1542 recommendation)
- **DHCPv6**: Relay-forward messages with `hop_count > 32` are dropped (per RFC 8415 section 5.2)

### Client ID Consistency

When a DHCPv4 client sends option 61 (Client Identifier), it is used as the primary lookup key for lease deduplication (per RFC 2131 section 4.2). This prevents a client from holding multiple leases by varying its client ID while keeping the same MAC.

### Max Lease Time Enforcement

Clients can request a shorter lease time, but the server caps it at the configured maximum:

```toml
[[subnet]]
lease_time = 86400          # default offered lease time
max_lease_time = 172800     # absolute cap (optional)
```

### API Authentication

The REST API supports API key authentication via the `X-API-Key` header:

```toml
[api]
listen = "127.0.0.1:8080"
api_key = "my-secret-key"
```

- All `/api/v1/*` endpoints require the `X-API-Key` header when `api_key` is configured
- `/health`, `/healthz`, and `/metrics` endpoints are exempt (always accessible)
- A startup warning is logged if the API is bound to a non-loopback address without an API key

### HA Communication

All HA peer communication (active/active and Raft) uses mutual TLS (mTLS) via rustls. No OpenSSL dependency.

### Summary

| Protection | Layer | Default |
|---|---|---|
| Per-client rate limiting | Global | 10 burst / 5 pps |
| Global rate limiting | Global | Disabled |
| MAC ACLs (allow/deny) | Per-subnet | Disabled |
| Max leases per MAC | Per-subnet | 1 |
| Rogue client detection | Global | 50 req/60s window |
| Pool high-water alerting | Global | 90% |
| Duplicate IP probing | Per-subnet | Disabled |
| DHCPv4 hop count limit | Protocol | 16 hops |
| DHCPv6 hop count limit | Protocol | 32 hops |
| Client ID dedup (option 61) | Protocol | Always on |
| Max lease time cap | Per-subnet | Disabled |
| API key authentication | API | Disabled |
| Lease ownership validation | Protocol | Always on |
| Declined IP quarantine | Protocol | 24 hours |
| mTLS for HA peers | HA | Required when HA enabled |

## REST API

The management API is enabled by adding an `[api]` section to the config.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/leases` | List leases. Query params: `subnet`, `mac`, `state`, `limit`, `offset` |
| `GET` | `/api/v1/leases/{ip}` | Get a specific lease by IP |
| `DELETE` | `/api/v1/leases/{ip}` | Force-release a lease |
| `GET` | `/api/v1/leases/stats` | Per-subnet pool utilization |
| `GET` | `/api/v1/subnets` | List all subnets with capacity info |
| `GET` | `/api/v1/ha/status` | HA mode, role, peer state, health |
| `GET` | `/health` | Health check (returns `{"status": "ok"}`) |
| `GET` | `/metrics` | Prometheus exposition format |

### Examples

```bash
# List all bound leases in a subnet
curl -H "X-API-Key: my-secret-key" \
  "http://localhost:8080/api/v1/leases?subnet=10.0.1.0/24&state=bound"

# Check pool utilization
curl -H "X-API-Key: my-secret-key" \
  http://localhost:8080/api/v1/leases/stats

# Force-release a lease
curl -X DELETE -H "X-API-Key: my-secret-key" \
  http://localhost:8080/api/v1/leases/10.0.1.150

# Health check (no auth required)
curl http://localhost:8080/health

# Prometheus scrape (no auth required)
curl http://localhost:8080/metrics
```

### Prometheus Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `rdhcpd_pool_total` | gauge | `subnet` | Total IPs in pool |
| `rdhcpd_pool_allocated` | gauge | `subnet` | Currently allocated IPs |
| `rdhcpd_pool_available` | gauge | `subnet` | Available IPs |
| `rdhcpd_pool_utilization` | gauge | `subnet` | Utilization percentage |
| `rdhcpd_leases_by_state` | gauge | `subnet`, `state` | Lease count by state |
| `rdhcpd_ha_healthy` | gauge | `mode` | HA health (1=healthy, 0=unhealthy) |

## Deployment

### Systemd

```bash
sudo cp target/release/rdhcpd /usr/local/bin/
sudo mkdir -p /etc/rdhcpd /var/lib/rdhcpd
sudo cp example-config.toml /etc/rdhcpd/config.toml
# Edit config as needed

sudo cp rdhcpd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rdhcpd
```

The systemd unit includes security hardening (NoNewPrivileges, ProtectSystem, capability bounding) and supports:
- `systemctl reload rdhcpd` — sends SIGHUP for config reload
- Watchdog monitoring
- Automatic restart on failure

### Docker

```bash
docker build -t rdhcpd .
docker run -d --net=host \
  -v /etc/rdhcpd:/etc/rdhcpd \
  -v /var/lib/rdhcpd:/var/lib/rdhcpd \
  rdhcpd
```

The Docker image uses `FROM scratch` with a static musl binary — no OS, no shell, no attack surface.

### Static Binary

```bash
# Build for musl (fully static, no libc dependency)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Result: a single ~5MB binary with zero runtime dependencies
```

## Architecture

```
src/
├── main.rs           Entry point, signal handling, worker spawning
├── config/           TOML parsing, validation, hot-reload
├── lease/
│   ├── store.rs      DashMap lease store, atomic counters, BTreeMap expiry queue
│   ├── types.rs      Lease struct (Arc<str> fields for zero-copy clone)
│   └── expiry.rs     Background expiry task (O(k) drain, not O(n) scan)
├── wal/              Write-ahead log: binary format, CRC32, replay on startup
├── allocator/        Bitmap allocator: O(1) alloc, trailing-bit boundary guard
├── dhcpv4/
│   ├── packet.rs     Zero-copy parse/serialize, RFC 2131 offsets with tests
│   ├── options.rs    TLV parser for 17 option types (RFC 2132)
│   └── server.rs     DORA state machine, subnet selection, relay support
├── dhcpv6/
│   ├── packet.rs     Client/server and relay message parsing (RFC 8415)
│   ├── options.rs    Nested TLV: IA_NA, IA_PD, IA_Addr, IA_Prefix, DUID
│   └── server.rs     Solicit/Advertise/Request/Reply, prefix delegation
├── ha/
│   ├── mod.rs        HaBackend trait, standalone implementation
│   ├── active_active.rs  Split-scope, failover state machine, peer sync
│   ├── raft.rs       Leader election, log replication, commit tracking
│   ├── peer.rs       mTLS connection management (rustls)
│   └── protocol.rs   Length-prefixed JSON wire protocol
├── api/
│   ├── mod.rs        REST API server, authentication middleware
│   ├── handlers.rs   REST endpoints (axum)
│   └── metrics.rs    Prometheus exposition
├── ddns/
│   ├── dns.rs        RFC 2136 UPDATE message builder
│   └── tsig.rs       HMAC-SHA256 TSIG signing (pure Rust, no crypto dep)
├── probe.rs          Duplicate IP detection via network probes
└── ratelimit.rs      Token bucket rate limiters, MAC ACLs, rogue detection
```

## Benchmarking

A benchmark suite using `perfdhcp` (from Kea) is included:

```bash
# Install perfdhcp
sudo apt install kea-admin

# Run benchmarks
sudo ./bench/run.sh
```

## Configuration Reference

### `[global]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `log_level` | string | `"info"` | Log level: trace, debug, info, warn, error |
| `log_format` | string | `"text"` | Log format: `text` or `json` |
| `lease_db` | string | `"/var/lib/rdhcpd/leases"` | Directory for WAL and snapshots |
| `workers` | int | `1` | Receive workers per protocol (DHCPv4/v6) |
| `rate_limit_burst` | int | `10` | Per-client max burst (packets) |
| `rate_limit_pps` | float | `5.0` | Per-client sustained rate (packets/sec) |
| `global_rate_limit_pps` | float | `0.0` | Global rate limit (0 = disabled) |
| `rogue_threshold` | int | `50` | Requests per window before rogue alert |
| `rogue_window_secs` | int | `60` | Rogue detection sliding window (seconds) |
| `pool_high_water` | float | `0.9` | Pool utilization warning threshold (0.0-1.0) |

### `[api]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | string | required | Bind address (e.g. `"127.0.0.1:8080"`) |
| `api_key` | string | none | API key for `X-API-Key` header authentication |

### `[ha]`

| Key | Type | Modes | Description |
|-----|------|-------|-------------|
| `mode` | string | all | `"standalone"`, `"active-active"`, or `"raft"` |
| `peer` | string | active-active | Peer address (`"host:port"`) |
| `listen` | string | active-active | Listen address for peer connections |
| `scope_split` | float | active-active | Pool split ratio (0.0-1.0, default 0.5) |
| `mclt` | int | active-active | Max Client Lead Time in seconds (default 3600) |
| `partner_down_delay` | int | active-active | Seconds before taking over peer's scope (default 3600) |
| `node_id` | int | raft | This node's unique ID |
| `peers` | string[] | raft | List of peer addresses |
| `tls_cert` | string | active-active, raft | Path to TLS certificate (PEM) |
| `tls_key` | string | active-active, raft | Path to TLS private key (PEM) |
| `tls_ca` | string | active-active, raft | Path to CA certificate for peer verification |

### `[[subnet]]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `network` | string | required | CIDR notation (e.g. `"10.0.1.0/24"`) |
| `pool_start` | string | none | First IP in dynamic pool |
| `pool_end` | string | none | Last IP in dynamic pool |
| `lease_time` | int | `86400` | Lease duration in seconds |
| `max_lease_time` | int | none | Cap on client-requested lease time |
| `renewal_time` | int | none | T1 renewal time (default: 50% of lease_time) |
| `rebinding_time` | int | none | T2 rebinding time (default: 87.5% of lease_time) |
| `preferred_time` | int | none | DHCPv6 preferred lifetime |
| `type` | string | `"address"` | `"address"` or `"prefix-delegation"` |
| `delegated_length` | int | none | Prefix length for PD (e.g. 56) |
| `router` | string | none | Default gateway (DHCPv4 option 3) |
| `dns` | string[] | `[]` | DNS servers (option 6 / option 23) |
| `domain` | string | none | Domain name (option 15 / option 24) |
| `max_leases_per_mac` | int | `1` | Max active leases per MAC (0 = unlimited) |
| `ip_probe` | bool | `false` | Probe IP before offering (duplicate detection) |
| `ip_probe_timeout_ms` | int | `500` | Probe timeout in milliseconds |
| `mac_allow` | string[] | `[]` | MAC allow list (empty = allow all) |
| `mac_deny` | string[] | `[]` | MAC deny list (checked before allow list) |

### `[[subnet.reservation]]`

| Key | Type | Description |
|-----|------|-------------|
| `mac` | string | MAC address (e.g. `"aa:bb:cc:dd:ee:ff"`) |
| `client_id` | string | Client identifier (hex string) |
| `duid` | string | DHCPv6 DUID (hex string) |
| `ip` | string | Reserved IP address |
| `hostname` | string | Client hostname |

### `[ddns]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable dynamic DNS updates |
| `forward_zone` | string | none | Forward DNS zone |
| `reverse_zone_v4` | string | none | IPv4 reverse zone |
| `reverse_zone_v6` | string | none | IPv6 reverse zone |
| `dns_server` | string | none | DNS server address |
| `tsig_key` | string | none | TSIG key name |
| `tsig_algorithm` | string | `"hmac-sha256"` | TSIG algorithm |
| `tsig_secret` | string | none | Base64-encoded TSIG secret |
| `ttl` | int | `300` | TTL for dynamic records |

## License

MIT
