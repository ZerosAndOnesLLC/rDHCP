//! DHCPv6 protocol implementation (RFC 8415).

/// DHCPv6 option types and serialization.
pub mod options;
/// DHCPv6 packet parsing and message types.
pub mod packet;
/// DHCPv6 server implementation.
pub mod server;
