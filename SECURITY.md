# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.8.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in rDHCP, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email support@zerosandones.us with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Security Considerations

rDHCP is a network infrastructure service that typically runs as root. Key security properties:

### Network
- DHCP operates on privileged ports (67, 547) requiring root or `CAP_NET_BIND_SERVICE`
- HA peer communication uses mutual TLS (mTLS) with certificate verification
- The management API should be bound to localhost or a management network, not public interfaces
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
- A misbehaving trusted relay can cycle the per-MAC rate-limiter bucket
  table (bounded at 100,000 entries) by forwarding packets with many
  fabricated MACs. The per-relay-source rate limit caps throughput but not
  uniqueness — restrict `trusted_relays` to known-good relay agents.

### Input Validation
- All DHCP packet fields are bounds-checked before access
- Option lengths are validated against RFC limits (255 bytes for DHCPv4, 65535 for DHCPv6)
- Magic cookie verification prevents processing non-DHCP traffic
- Hop count validation prevents relay loops (DHCPv4: >16 rejected per RFC 1542; DHCPv6: >32 rejected per RFC 8415)

### Denial of Service
- Per-client rate limiting prevents DHCP starvation attacks
- MAC allow/deny lists restrict which clients can obtain leases
- API query limits prevent memory exhaustion

### Privilege Reduction
- The systemd unit file drops privileges after binding ports
- `NoNewPrivileges`, `ProtectSystem=strict`, and capability bounding are enabled
- The Docker image runs FROM scratch with no shell or OS tools

### Data
- The WAL uses CRC32 checksums to detect corruption
- TSIG keys for DDNS are stored in the config file — protect file permissions accordingly
- API keys (if configured) are transmitted in plaintext unless behind a TLS reverse proxy
