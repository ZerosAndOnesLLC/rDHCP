# rDHCP — Rust DHCP Server with HA

A high-performance, zero-dependency DHCP server written in Rust. Supports IPv4 (DHCPv4) and IPv6 (DHCPv6), scales from a single subnet to enterprise-level deployments with millions of leases. Built-in HA via active/active split-scope or Raft consensus — no external database required.

## Design Principles

- Single static binary, no runtime dependencies
- In-memory lease store with WAL for durability — no external DB
- Bitmap-based allocation for O(1) free-IP lookup
- Zero-copy packet parsing, pre-allocated buffers
- Pluggable HA backend: standalone, active/active, or Raft
- TOML configuration
- Async (Tokio) networking

---

## Phase 1: Core Foundation

### 1.1 Project Setup
- [ ] Initialize Cargo workspace
- [ ] Set up directory structure (config/, lease/, dhcpv4/, dhcpv6/, ha/, api/, net/)
- [ ] Add core dependencies: tokio, serde, toml, tracing, thiserror
- [ ] Set up tracing/logging infrastructure

### 1.2 Configuration
- [ ] Define TOML config schema (global, interfaces, subnets, pools, options, ha, api)
- [ ] Config structs with serde deserialization
- [ ] Validation (overlapping subnets, pool ranges within subnets, option correctness)
- [ ] Support for IPv4 and IPv6 subnets in unified config
- [ ] Hot-reload support (SIGHUP)

### 1.3 Lease Store
- [ ] `Lease` struct: IP, client ID, MAC, hostname, lease time, state, timestamps
- [ ] In-memory `HashMap<IpAddr, Lease>` store behind `RwLock`/`DashMap`
- [ ] `LeaseStore` trait with async CRUD operations
- [ ] Lease state machine: Available → Offered → Bound → Expired/Released
- [ ] Expiry tracking with timer wheel or `BTreeMap<Instant, IpAddr>`
- [ ] Background task for lease cleanup

### 1.4 Write-Ahead Log (WAL)
- [ ] Binary WAL format: operation type, lease data, checksum
- [ ] Append-only writes, fsync policy (configurable: every write, batched, or OS)
- [ ] Recovery: replay WAL on startup to rebuild in-memory state
- [ ] WAL compaction: periodic snapshot + truncate
- [ ] Configurable WAL path

### 1.5 Bitmap Allocator
- [ ] Bitmap per subnet/pool for tracking allocated IPs
- [ ] O(1) next-free-IP lookup using leading-zeros intrinsics
- [ ] Support for excluded ranges and reservations (pre-marked bits)
- [ ] Rebuild bitmap from lease store on startup
- [ ] Thread-safe allocation (atomic ops or lock per subnet)

### 1.6 Reservation Store
- [ ] Static IP reservations by MAC address or client ID (v4) / DUID (v6)
- [ ] Loaded from config, queryable by identifier
- [ ] Per-reservation option overrides

---

## Phase 2: DHCPv4

### 2.1 Packet Parsing
- [ ] DHCPv4 packet struct (RFC 2131): op, htype, hlen, hops, xid, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr
- [ ] Zero-copy parsing from `&[u8]` with bounds checking
- [ ] Serialization back to `&mut [u8]` (pre-allocated buffer)
- [ ] DHCP message type detection (Discover, Offer, Request, Ack, Nak, Release, Decline, Inform)

### 2.2 Options Parsing
- [ ] TLV option parser (RFC 2132)
- [ ] Common options: subnet mask, router, DNS, domain name, lease time, server ID, requested IP, message type, parameter request list
- [ ] Option overloading (sname/file fields)
- [ ] Vendor-specific options (option 43)
- [ ] Option 82 (relay agent information) parsing and forwarding

### 2.3 DORA State Machine
- [ ] **Discover** → select subnet (based on giaddr or receiving interface), allocate IP from pool or reservation, build Offer
- [ ] **Offer** → mark lease as Offered with short timeout
- [ ] **Request** → validate (correct server ID, IP matches offer), transition to Bound, commit via HA backend, send Ack
- [ ] **Ack** → include all requested options, set lease duration
- [ ] **Nak** — wrong subnet, IP unavailable, send Nak
- [ ] **Release** → free the lease, update store
- [ ] **Decline** → mark IP as unavailable (possible conflict), log
- [ ] **Inform** → respond with options only, no lease

### 2.4 Subnet Selection
- [ ] Match by giaddr (relayed requests)
- [ ] Match by receiving interface IP (direct requests)
- [ ] Shared network support (multiple subnets on one link)
- [ ] Pool exhaustion handling and logging

### 2.5 Relay Agent Support
- [ ] Detect relayed packets (giaddr != 0)
- [ ] Respond via unicast to relay agent
- [ ] Preserve and echo option 82 sub-options
- [ ] Support multiple relay hops

### 2.6 Network I/O
- [ ] Raw socket or UDP socket on port 67
- [ ] Bind to specific interfaces (configurable)
- [ ] Broadcast send for direct-connected clients
- [ ] Unicast send for relayed responses
- [ ] Packet receive loop with pre-allocated buffer pool

### 2.7 Lease Renewal
- [ ] T1 (50%) and T2 (87.5%) renewal timers communicated to client
- [ ] Handle renew (unicast Request) and rebind (broadcast Request)
- [ ] Extend lease on successful renewal

---

## Phase 3: DHCPv6

### 3.1 Packet Parsing
- [ ] DHCPv6 message struct (RFC 8415): msg-type, transaction-id
- [ ] Message types: Solicit, Advertise, Request, Confirm, Renew, Rebind, Reply, Release, Decline, Information-Request
- [ ] Relay-forward / Relay-reply message wrapping
- [ ] Zero-copy parsing with bounds checking

### 3.2 Options Parsing
- [ ] TLV options (type: 16-bit, length: 16-bit)
- [ ] Core options: Client ID (DUID), Server ID (DUID), IA_NA, IA_TA, IA_PD, IA_Address, IA_Prefix, Status Code, Option Request, Preference, DNS Recursive Name Server, Domain Search List
- [ ] Nested options within IA containers
- [ ] DUID generation and persistence for server identity

### 3.3 Address Assignment (IA_NA)
- [ ] **Solicit** → select pool, allocate address, build Advertise (or Rapid Commit Reply)
- [ ] **Request** → validate, commit lease, send Reply with IA_NA + IA_Address
- [ ] **Renew** → extend lease times, send Reply
- [ ] **Rebind** → re-validate, extend or Nak
- [ ] **Release** → free address
- [ ] **Decline** → mark address unusable
- [ ] **Confirm** → validate address is still on-link
- [ ] Rapid Commit support (2-message exchange)

### 3.4 Prefix Delegation (IA_PD)
- [ ] Prefix pool configuration (e.g., 2001:db8::/32 delegated as /48s or /56s)
- [ ] Prefix allocation from pool with bitmap tracking
- [ ] IA_PD + IA_Prefix options in Reply
- [ ] Prefix renewal and rebind
- [ ] Configurable delegated prefix length

### 3.5 Relay Support
- [ ] Parse Relay-forward messages (hop-count, link-address, peer-address)
- [ ] Use link-address for subnet/pool selection
- [ ] Wrap Reply in Relay-reply
- [ ] Interface-ID option preservation
- [ ] Multiple relay hop support

### 3.6 Network I/O
- [ ] UDP socket on port 547 (server), responses to port 546 (client)
- [ ] Multicast group ff02::1:2 (All_DHCP_Relay_Agents_and_Servers)
- [ ] Link-local and global address handling
- [ ] Interface binding

---

## Phase 4: Active/Active HA

### 4.1 HA Backend Trait
- [ ] Define `HaBackend` trait: `commit_lease()`, `release_lease()`, `owns_scope()`, `status()`
- [ ] Standalone implementation (no-op, always owns everything)
- [ ] HA mode selection from config
- [ ] Graceful degradation interface (what to do when peer is unreachable)

### 4.2 Peer Communication
- [ ] TCP connection between peers with TLS (rustls)
- [ ] Binary protocol: lease sync messages, heartbeats, state transitions
- [ ] Connection management: auto-reconnect with backoff
- [ ] Heartbeat interval (configurable, default 1s)
- [ ] Peer state detection: up, down, unreachable

### 4.3 Split-Scope Allocation
- [ ] Configurable split ratio (default 50/50)
- [ ] Each node owns a contiguous portion of each pool
- [ ] `owns_scope()` checks if IP falls in this node's range
- [ ] On peer failure: optionally take over peer's range after configurable delay (MCLT — Maximum Client Lead Time)

### 4.4 Lease Synchronization
- [ ] Async lease push to peer on every commit
- [ ] Peer stores synced leases as authoritative (for failover takeover)
- [ ] Bulk sync on reconnection (delta since last sync)
- [ ] Conflict resolution: most-recent-timestamp wins

### 4.5 Failover State Machine
- [ ] States: Normal, Communications-Interrupted, Partner-Down, Recover
- [ ] Configurable partner-down transition delay (default: 1 hour)
- [ ] MCLT enforcement: don't extend lease beyond MCLT when partner is unknown
- [ ] Recovery: gradual handback when partner returns

---

## Phase 5: Raft HA

### 5.1 Raft Implementation
- [ ] Evaluate `openraft` crate or implement core Raft (leader election, log replication, snapshotting)
- [ ] Raft node identity from config
- [ ] Cluster membership from config (static initially)
- [ ] RPC transport over TCP with TLS

### 5.2 Lease Operations via Raft
- [ ] `commit_lease()` proposes entry to Raft log
- [ ] Leader replicates to majority, then applies to lease store
- [ ] Followers apply committed entries to their local lease store
- [ ] Read operations served from local state (leader lease or follower with read index)

### 5.3 Snapshotting
- [ ] Periodic snapshot of full lease store state
- [ ] Snapshot transfer to new/recovering nodes
- [ ] Log compaction after snapshot

### 5.4 Leader Failover
- [ ] Automatic leader election on leader failure
- [ ] New leader immediately serves DHCP requests
- [ ] Client-facing: brief pause during election (typically < 1s)
- [ ] Configurable election timeout

### 5.5 Degraded Mode
- [ ] When quorum is lost: optionally continue serving renewals from local state
- [ ] Reject new allocations without quorum (configurable)
- [ ] Alert/log when operating in degraded mode
- [ ] Auto-recover when quorum restores

---

## Phase 6: Management API

### 6.1 REST API (axum)
- [ ] Bind to configurable address/port
- [ ] JSON request/response
- [ ] Optional API key authentication

### 6.2 Lease Endpoints
- [ ] `GET /api/v1/leases` — list/search leases (filter by subnet, MAC, state)
- [ ] `GET /api/v1/leases/{ip}` — get specific lease
- [ ] `DELETE /api/v1/leases/{ip}` — force-release a lease
- [ ] `GET /api/v1/leases/stats` — per-subnet utilization (total, used, available, %)

### 6.3 Reservation Endpoints
- [ ] `GET /api/v1/reservations` — list all
- [ ] `POST /api/v1/reservations` — add reservation (MAC/DUID → IP + options)
- [ ] `DELETE /api/v1/reservations/{id}` — remove reservation
- [ ] Reservations persisted to disk, survive restart

### 6.4 Subnet/Pool Endpoints
- [ ] `GET /api/v1/subnets` — list subnets with pool info
- [ ] `GET /api/v1/subnets/{id}/utilization` — bitmap-based utilization stats

### 6.5 HA Status Endpoints
- [ ] `GET /api/v1/ha/status` — current mode, peer state, role (leader/follower/active)
- [ ] `POST /api/v1/ha/failover` — manual failover trigger (Raft: step down leader)

### 6.6 Metrics
- [ ] Prometheus exposition format at `/metrics`
- [ ] Counters: packets received/sent by type, leases allocated/renewed/released/expired
- [ ] Gauges: active leases per subnet, pool utilization, peer status
- [ ] Histograms: packet processing latency

---

## Phase 7: DDNS Integration

### 7.1 DNS Update Client
- [ ] RFC 2136 dynamic DNS update messages
- [ ] A/AAAA record creation on lease assignment
- [ ] PTR record creation in reverse zone
- [ ] Record removal on lease expiry/release

### 7.2 Configuration
- [ ] Per-subnet DDNS settings: enable/disable, forward zone, reverse zone, DNS server
- [ ] TSIG authentication (RFC 2845) for secure updates
- [ ] Configurable TTL for dynamic records
- [ ] Hostname conflict resolution policy (client wins, server wins, skip)

### 7.3 Integration
- [ ] Async DNS updates (don't block DHCP response)
- [ ] Retry failed updates with backoff
- [ ] FQDN option (v4: option 81, v6: option 39) handling

---

## Phase 8: Operational Polish

### 8.1 Graceful Operations
- [ ] SIGHUP: reload config (subnets, pools, options) without dropping leases
- [ ] SIGTERM: graceful shutdown, flush WAL
- [ ] Systemd notify integration (sd_notify ready, watchdog)
- [ ] Systemd unit file

### 8.2 Security
- [ ] Drop privileges after binding to ports 67/547
- [ ] Configurable chroot
- [ ] Rate limiting per-client (prevent DHCP starvation attacks)
- [ ] MAC allow/deny lists per subnet
- [ ] TLS for all peer and API communication

### 8.3 Observability
- [ ] Structured logging (JSON or text, configurable)
- [ ] Log levels: per-component verbosity
- [ ] Packet dump mode for debugging (configurable per-subnet)
- [ ] Health check endpoint

### 8.4 Packaging & Distribution
- [ ] Static binary (musl target)
- [ ] Docker image (FROM scratch)
- [ ] deb/rpm packaging
- [ ] Example configs for common scenarios (small office, campus, data center)
- [ ] Man page

---

## Config Example

```toml
[global]
log_level = "info"
log_format = "json"                 # "json" or "text"
lease_db = "/var/lib/rdhcp/leases"  # WAL + snapshot directory

[api]
listen = "127.0.0.1:8080"
api_key = "change-me"

[ha]
mode = "standalone"                 # "standalone", "active-active", "raft"

# Active/Active example:
# [ha]
# mode = "active-active"
# peer = "10.0.0.2:9000"
# scope_split = 0.5
# mclt = 3600
# partner_down_delay = 3600

# Raft example:
# [ha]
# mode = "raft"
# node_id = 1
# peers = ["10.0.0.2:9000", "10.0.0.3:9000"]

[[subnet]]
network = "10.0.1.0/24"
pool_start = "10.0.1.100"
pool_end = "10.0.1.250"
lease_time = 86400
router = "10.0.1.1"
dns = ["10.0.0.53", "10.0.0.54"]
domain = "example.com"

[[subnet.reservation]]
mac = "aa:bb:cc:dd:ee:f1"
ip = "10.0.1.10"
hostname = "printer"

[[subnet]]
network = "2001:db8:1::/64"
pool_start = "2001:db8:1::1000"
pool_end = "2001:db8:1::ffff"
lease_time = 86400
preferred_time = 43200
dns = ["2001:db8::53"]
domain = "example.com"

[[subnet]]
network = "2001:db8:pd::/48"
type = "prefix-delegation"
delegated_length = 56
lease_time = 604800

[ddns]
enabled = false
# forward_zone = "example.com"
# reverse_zone_v4 = "1.0.10.in-addr.arpa"
# dns_server = "10.0.0.53"
# tsig_key = "dhcp-key"
# tsig_algorithm = "hmac-sha256"
# tsig_secret = "base64secret=="
```
