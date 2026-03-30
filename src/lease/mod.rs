//! DHCP lease management: types, storage, and expiry.

/// Lease expiry background task.
pub mod expiry;
/// Thread-safe lease storage with secondary indexes.
pub mod store;
/// Lease and lease-state type definitions.
pub mod types;
