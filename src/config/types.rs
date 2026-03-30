use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Top-level DHCP server configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Global server settings (logging, lease database).
    pub global: GlobalConfig,
    /// Optional REST API configuration.
    pub api: Option<ApiConfig>,
    /// High-availability mode configuration.
    pub ha: HaConfig,
    /// Configured subnets and their address pools.
    #[serde(default)]
    pub subnet: Vec<SubnetConfig>,
    /// Optional dynamic DNS update configuration.
    pub ddns: Option<DdnsConfig>,
}

/// Global server settings.
#[derive(Debug, Deserialize, Clone)]
pub struct GlobalConfig {
    /// Log verbosity level (e.g. "info", "debug", "warn").
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Log output format ("text" or "json").
    #[serde(default = "default_log_format")]
    pub log_format: String,
    /// Path to the lease database directory.
    #[serde(default = "default_lease_db")]
    pub lease_db: String,
    /// Number of receive workers per protocol (DHCPv4/v6).
    #[serde(default = "default_workers")]
    pub workers: usize,
}

/// REST API server configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct ApiConfig {
    /// Socket address to bind the API server to (e.g. "0.0.0.0:8080").
    pub listen: String,
    /// Optional API key for request authentication.
    pub api_key: Option<String>,
}

/// High-availability mode configuration.
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "mode")]
pub enum HaConfig {
    /// Single-server mode with no replication.
    #[serde(rename = "standalone")]
    Standalone,

    /// Active-active failover with a single peer.
    #[serde(rename = "active-active")]
    ActiveActive {
        /// Address of the HA peer node.
        peer: String,
        /// Address to listen on for peer connections
        listen: Option<String>,
        /// Fraction of the address pool served by this node (0.0-1.0).
        #[serde(default = "default_scope_split")]
        scope_split: f64,
        /// Maximum client lead time in seconds.
        #[serde(default = "default_mclt")]
        mclt: u32,
        /// Seconds to wait before assuming the partner is down.
        #[serde(default = "default_partner_down_delay")]
        partner_down_delay: u32,
        /// TLS certificate file
        tls_cert: Option<String>,
        /// TLS private key file
        tls_key: Option<String>,
        /// TLS CA certificate for peer verification
        tls_ca: Option<String>,
    },

    /// Raft consensus-based replication across multiple nodes.
    #[serde(rename = "raft")]
    Raft {
        /// Unique numeric identifier for this Raft node.
        node_id: u64,
        /// Addresses of all other Raft cluster members.
        peers: Vec<String>,
        /// TLS certificate file
        tls_cert: Option<String>,
        /// TLS private key file
        tls_key: Option<String>,
        /// TLS CA certificate for peer verification
        tls_ca: Option<String>,
    },
}

/// Subnet definition with address pool and DHCP options.
#[derive(Debug, Deserialize, Clone)]
pub struct SubnetConfig {
    /// Network in CIDR notation (e.g. "192.168.1.0/24").
    pub network: String,
    /// First address in the dynamic allocation pool.
    pub pool_start: Option<String>,
    /// Last address in the dynamic allocation pool.
    pub pool_end: Option<String>,
    /// Lease duration in seconds.
    #[serde(default = "default_lease_time")]
    pub lease_time: u32,
    /// DHCPv6 preferred lifetime
    pub preferred_time: Option<u32>,
    /// Subnet type: "address" (default) or "prefix-delegation"
    #[serde(rename = "type", default = "default_subnet_type")]
    pub subnet_type: String,
    /// Delegated prefix length for prefix delegation subnets
    pub delegated_length: Option<u8>,

    // Common options
    /// Default gateway address for clients.
    pub router: Option<String>,
    /// DNS server addresses for clients.
    #[serde(default)]
    pub dns: Vec<String>,
    /// DNS domain name for clients.
    pub domain: Option<String>,

    // Reservations
    /// Static address reservations for specific clients.
    #[serde(default)]
    pub reservation: Vec<ReservationConfig>,
}

/// Static address reservation configuration for a specific client.
#[derive(Debug, Deserialize, Clone)]
pub struct ReservationConfig {
    /// MAC address (DHCPv4)
    pub mac: Option<String>,
    /// Client ID (DHCPv4 alternative)
    pub client_id: Option<String>,
    /// DUID (DHCPv6)
    pub duid: Option<String>,
    /// Reserved IP address
    pub ip: String,
    /// Optional hostname
    pub hostname: Option<String>,
    /// Per-reservation DNS override
    pub dns: Option<Vec<String>>,
    /// Per-reservation router override
    pub router: Option<String>,
}

/// Dynamic DNS update configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct DdnsConfig {
    /// Whether DDNS updates are enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Forward DNS zone for A/AAAA record updates.
    pub forward_zone: Option<String>,
    /// Reverse DNS zone for IPv4 PTR record updates.
    pub reverse_zone_v4: Option<String>,
    /// Reverse DNS zone for IPv6 PTR record updates.
    pub reverse_zone_v6: Option<String>,
    /// DNS server address to send updates to.
    pub dns_server: Option<String>,
    /// TSIG key name for authenticating DNS updates.
    pub tsig_key: Option<String>,
    /// TSIG algorithm (e.g. "hmac-sha256").
    pub tsig_algorithm: Option<String>,
    /// Base64-encoded TSIG shared secret.
    pub tsig_secret: Option<String>,
    /// TTL in seconds for created DNS records.
    #[serde(default = "default_ddns_ttl")]
    pub ttl: u32,
}

/// Parsed subnet with validated IP addresses.
#[derive(Debug, Clone)]
pub struct ParsedSubnet {
    /// Network base address.
    pub network_addr: IpAddr,
    /// CIDR prefix length.
    pub prefix_len: u8,
    /// First address in the dynamic pool.
    pub pool_start: Option<IpAddr>,
    /// Last address in the dynamic pool.
    pub pool_end: Option<IpAddr>,
    /// Lease duration in seconds.
    pub lease_time: u32,
    /// DHCPv6 preferred lifetime.
    pub preferred_time: Option<u32>,
    /// Allocation type (address or prefix delegation).
    pub subnet_type: SubnetType,
    /// Delegated prefix length for PD subnets.
    pub delegated_length: Option<u8>,
    /// Default gateway (IPv4 only).
    pub router: Option<Ipv4Addr>,
    /// IPv4 DNS server addresses.
    pub dns_v4: Vec<Ipv4Addr>,
    /// IPv6 DNS server addresses.
    pub dns_v6: Vec<Ipv6Addr>,
    /// DNS domain name for clients.
    pub domain: Option<String>,
    /// Parsed static reservations.
    pub reservations: Vec<ParsedReservation>,
}

/// Parsed subnet allocation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetType {
    /// Standard address allocation (individual IPs).
    Address,
    /// DHCPv6 prefix delegation.
    PrefixDelegation,
}

/// Parsed reservation with validated identifiers and IP address.
#[derive(Debug, Clone)]
pub struct ParsedReservation {
    /// Parsed MAC address bytes (DHCPv4).
    pub mac: Option<[u8; 6]>,
    /// Parsed client identifier bytes (DHCPv4).
    pub client_id: Option<Vec<u8>>,
    /// Parsed DUID bytes (DHCPv6).
    pub duid: Option<Vec<u8>>,
    /// Reserved IP address.
    pub ip: IpAddr,
    /// Optional hostname for the client.
    pub hostname: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

fn default_lease_db() -> String {
    "/var/lib/rdhcpd/leases".to_string()
}

fn default_workers() -> usize {
    1
}

fn default_scope_split() -> f64 {
    0.5
}

fn default_mclt() -> u32 {
    3600
}

fn default_partner_down_delay() -> u32 {
    3600
}

fn default_lease_time() -> u32 {
    86400
}

fn default_subnet_type() -> String {
    "address".to_string()
}

fn default_ddns_ttl() -> u32 {
    300
}
