# rDHCP

High-performance DHCP server written in Rust. Supports DHCPv4, DHCPv6, prefix delegation, and built-in HA — no external database required.

## Features

- **Dual-stack**: Full DHCPv4 (RFC 2131/2132) and DHCPv6 (RFC 8415) support
- **High Availability**: Active/Active split-scope or Raft consensus — configurable per deployment
- **Zero dependencies**: Single static binary, in-memory lease store with WAL, no external DB
- **Performance**: Bitmap allocator for O(1) IP allocation, DashMap for lock-free concurrent access
- **Prefix Delegation**: DHCPv6 IA_PD with configurable delegated prefix lengths
- **DDNS**: RFC 2136 dynamic DNS updates with TSIG authentication
- **Management API**: REST API for lease/subnet management, Prometheus metrics
- **Security**: mTLS for HA peer communication, rate limiting, MAC allow/deny lists
- **Operational**: SIGHUP config reload, systemd integration, structured logging

## Quick Start

```bash
# Build
cargo build --release

# Run with example config
sudo ./target/release/rdhcpd example-config.toml
```

## Configuration

See `example-config.toml` for a complete example. Key sections:

```toml
[global]
log_level = "info"
lease_db = "/var/lib/rdhcpd/leases"

[ha]
mode = "standalone"  # or "active-active" or "raft"

[[subnet]]
network = "10.0.1.0/24"
pool_start = "10.0.1.100"
pool_end = "10.0.1.250"
lease_time = 86400
router = "10.0.1.1"
dns = ["10.0.0.53"]
```

### HA Modes

**Standalone** — single node, no replication:
```toml
[ha]
mode = "standalone"
```

**Active/Active** — two nodes, split-scope with failover:
```toml
[ha]
mode = "active-active"
peer = "10.0.0.2:9000"
listen = "0.0.0.0:9000"
scope_split = 0.5
tls_cert = "/etc/rdhcpd/cert.pem"
tls_key = "/etc/rdhcpd/key.pem"
tls_ca = "/etc/rdhcpd/ca.pem"
```

**Raft** — 3+ nodes, consensus-based:
```toml
[ha]
mode = "raft"
node_id = 1
peers = ["10.0.0.2:9000", "10.0.0.3:9000"]
tls_cert = "/etc/rdhcpd/cert.pem"
tls_key = "/etc/rdhcpd/key.pem"
tls_ca = "/etc/rdhcpd/ca.pem"
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/leases` | List leases (filter by subnet, MAC, state) |
| GET | `/api/v1/leases/{ip}` | Get specific lease |
| DELETE | `/api/v1/leases/{ip}` | Force-release a lease |
| GET | `/api/v1/leases/stats` | Per-subnet utilization |
| GET | `/api/v1/subnets` | List subnets with pool info |
| GET | `/api/v1/ha/status` | HA mode, role, peer state |
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |

## Deployment

### Systemd
```bash
sudo cp rdhcpd.service /etc/systemd/system/
sudo systemctl enable rdhcpd
sudo systemctl start rdhcpd
```

### Docker
```bash
docker build -t rdhcpd .
docker run --net=host -v /etc/rdhcpd:/etc/rdhcpd rdhcpd
```

## Architecture

```
rdhcpd
├── config/       TOML config parsing and validation
├── lease/        DashMap-backed lease store with expiry
├── wal/          Write-ahead log for lease durability
├── allocator/    Bitmap-based O(1) IP allocation
├── dhcpv4/       DHCPv4 packet parsing, DORA, relay
├── dhcpv6/       DHCPv6 parsing, IA_NA/IA_PD, relay
├── ha/           HA backends (standalone, active/active, raft)
├── api/          axum REST API and Prometheus metrics
├── ddns/         RFC 2136 dynamic DNS updates
└── ratelimit/    Per-client rate limiting and MAC ACLs
```

## License

MIT
