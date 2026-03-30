#![warn(missing_docs)]

//! High-performance DHCP server with built-in HA support.
//!
//! `rdhcpd` is a dual-stack DHCPv4/DHCPv6 server written in Rust. It supports
//! active/active and Raft-based high availability, all in a single binary with
//! no external database.
//!
//! # Architecture
//!
//! - [`allocator`] — Bitmap-based IP address pool management
//! - [`api`] — REST management API (Axum-based)
//! - [`config`] — TOML configuration loading and validation
//! - [`ddns`] — Dynamic DNS update client (RFC 2136)
//! - [`dhcpv4`] — DHCPv4 protocol implementation (RFC 2131)
//! - [`dhcpv6`] — DHCPv6 protocol implementation (RFC 8415)
//! - [`ha`] — High availability backends (standalone, active/active, Raft)
//! - [`lease`] — Lease storage, indexing, and expiry
//! - [`ratelimit`] — Per-client rate limiting and MAC ACL
//! - [`wal`] — Write-ahead log for durability

pub mod allocator;
pub mod api;
pub mod config;
pub mod ddns;
pub mod dhcpv4;
pub mod dhcpv6;
pub mod ha;
pub mod lease;
pub mod ratelimit;
pub mod wal;
