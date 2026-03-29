use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub global: GlobalConfig,
    pub api: Option<ApiConfig>,
    pub ha: HaConfig,
    #[serde(default)]
    pub subnet: Vec<SubnetConfig>,
    pub ddns: Option<DdnsConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GlobalConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_log_format")]
    pub log_format: String,
    #[serde(default = "default_lease_db")]
    pub lease_db: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApiConfig {
    pub listen: String,
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "mode")]
pub enum HaConfig {
    #[serde(rename = "standalone")]
    Standalone,

    #[serde(rename = "active-active")]
    ActiveActive {
        peer: String,
        /// Address to listen on for peer connections
        listen: Option<String>,
        #[serde(default = "default_scope_split")]
        scope_split: f64,
        #[serde(default = "default_mclt")]
        mclt: u32,
        #[serde(default = "default_partner_down_delay")]
        partner_down_delay: u32,
        /// TLS certificate file
        tls_cert: Option<String>,
        /// TLS private key file
        tls_key: Option<String>,
        /// TLS CA certificate for peer verification
        tls_ca: Option<String>,
    },

    #[serde(rename = "raft")]
    Raft {
        node_id: u64,
        peers: Vec<String>,
        /// TLS certificate file
        tls_cert: Option<String>,
        /// TLS private key file
        tls_key: Option<String>,
        /// TLS CA certificate for peer verification
        tls_ca: Option<String>,
    },
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubnetConfig {
    pub network: String,
    pub pool_start: Option<String>,
    pub pool_end: Option<String>,
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
    pub router: Option<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    pub domain: Option<String>,

    // Reservations
    #[serde(default)]
    pub reservation: Vec<ReservationConfig>,
}

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

#[derive(Debug, Deserialize, Clone)]
pub struct DdnsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub forward_zone: Option<String>,
    pub reverse_zone_v4: Option<String>,
    pub reverse_zone_v6: Option<String>,
    pub dns_server: Option<String>,
    pub tsig_key: Option<String>,
    pub tsig_algorithm: Option<String>,
    pub tsig_secret: Option<String>,
    #[serde(default = "default_ddns_ttl")]
    pub ttl: u32,
}

/// Parsed subnet with validated IP addresses
#[derive(Debug, Clone)]
pub struct ParsedSubnet {
    pub network_addr: IpAddr,
    pub prefix_len: u8,
    pub pool_start: Option<IpAddr>,
    pub pool_end: Option<IpAddr>,
    pub lease_time: u32,
    pub preferred_time: Option<u32>,
    pub subnet_type: SubnetType,
    pub delegated_length: Option<u8>,
    pub router: Option<Ipv4Addr>,
    pub dns_v4: Vec<Ipv4Addr>,
    pub dns_v6: Vec<Ipv6Addr>,
    pub domain: Option<String>,
    pub reservations: Vec<ParsedReservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetType {
    Address,
    PrefixDelegation,
}

#[derive(Debug, Clone)]
pub struct ParsedReservation {
    pub mac: Option<[u8; 6]>,
    pub client_id: Option<Vec<u8>>,
    pub duid: Option<Vec<u8>>,
    pub ip: IpAddr,
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
