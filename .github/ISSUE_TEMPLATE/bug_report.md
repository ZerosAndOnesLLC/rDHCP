---
name: Bug Report
about: Report a bug in rDHCP
title: ''
labels: bug
assignees: ''
---

## Description

A clear description of the bug.

## Steps to Reproduce

1. Configure rDHCP with...
2. Send a DHCP request...
3. Observe...

## Expected Behavior

What should happen.

## Actual Behavior

What actually happens.

## Environment

- **OS**: (e.g. Ubuntu 24.04)
- **rDHCP version**: (e.g. 0.8.0)
- **Rust version**: (output of `rustc --version`)
- **HA mode**: standalone / active-active / raft
- **Protocol**: DHCPv4 / DHCPv6

## Configuration

Relevant config sections (redact any secrets):

```toml
[ha]
mode = "standalone"

[[subnet]]
network = "..."
```

## Logs

Server logs at debug level (`RUST_LOG=debug`):

```
paste logs here
```
