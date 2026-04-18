//! DHCPv4 protocol implementation (RFC 2131).

/// DHCP option types, codes, and parsing/serialization.
pub mod options;
/// DHCPv4 packet structure and wire-format codec.
pub mod packet;
/// DHCPv4 server request handling and response logic.
pub mod server;
/// Atomic counters for DHCPv4 relay observability.
pub mod stats;
