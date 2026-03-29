# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.8.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in rDHCP, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email security@zerosandones.io with:

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

### Input Validation
- All DHCP packet fields are bounds-checked before access
- Option lengths are validated against RFC limits (255 bytes for DHCPv4, 65535 for DHCPv6)
- Magic cookie verification prevents processing non-DHCP traffic
- Hop count validation (>32 rejected) prevents relay loops

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
