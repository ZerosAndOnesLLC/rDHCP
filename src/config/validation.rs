use std::net::{IpAddr, Ipv4Addr};

use tracing::warn;

use super::types::OptionOverride;
use super::{Config, ConfigError};

/// Decode a hex string (without separators) into bytes.
/// Rejects odd-length strings and non-hex characters.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!(
            "hex string must have even length, got {}",
            s.len()
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex char".to_string())?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex char".to_string())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Serialize an `OptionOverride` value into the raw bytes that will be placed
/// in the DHCP option payload (excluding code and length bytes).
///
/// Exactly one of the value fields (`ip`, `ips`, `string`, `u8_val`,
/// `u16_val`, `u32_val`, `hex`) must be `Some`; all others must be `None`.
pub fn serialize_option_override(o: &OptionOverride) -> Result<Vec<u8>, String> {
    // Count how many value fields are set
    let set_count = [
        o.ip.is_some(),
        o.ips.is_some(),
        o.string.is_some(),
        o.u8_val.is_some(),
        o.u16_val.is_some(),
        o.u32_val.is_some(),
        o.hex.is_some(),
    ]
    .iter()
    .filter(|&&v| v)
    .count();

    if set_count == 0 {
        return Err("exactly one value field must be set (none found)".to_string());
    }
    if set_count > 1 {
        return Err(format!(
            "exactly one value field must be set ({} found)",
            set_count
        ));
    }

    if let Some(ref s) = o.ip {
        let addr: Ipv4Addr = s
            .parse()
            .map_err(|_| format!("ip '{}' is not a valid IPv4 address", s))?;
        return Ok(addr.octets().to_vec());
    }

    if let Some(ref list) = o.ips {
        let mut bytes = Vec::with_capacity(list.len() * 4);
        for s in list {
            let addr: Ipv4Addr = s
                .parse()
                .map_err(|_| format!("ips entry '{}' is not a valid IPv4 address", s))?;
            bytes.extend_from_slice(&addr.octets());
        }
        return Ok(bytes);
    }

    if let Some(ref s) = o.string {
        if s.len() > 255 {
            return Err(format!(
                "string value is {} bytes, maximum is 255",
                s.len()
            ));
        }
        if !s.bytes().all(|b| b.is_ascii_graphic() || b == b' ') {
            return Err("string value must contain only printable ASCII characters".to_string());
        }
        return Ok(s.as_bytes().to_vec());
    }

    if let Some(v) = o.u8_val {
        return Ok(vec![v]);
    }

    if let Some(v) = o.u16_val {
        return Ok(v.to_be_bytes().to_vec());
    }

    if let Some(v) = o.u32_val {
        return Ok(v.to_be_bytes().to_vec());
    }

    if let Some(ref s) = o.hex {
        let bytes = decode_hex(s)?;
        if bytes.len() > 255 {
            return Err(format!(
                "hex value is {} bytes, maximum is 255",
                bytes.len()
            ));
        }
        return Ok(bytes);
    }

    unreachable!("set_count == 1 but no field matched")
}

pub fn validate(config: &Config) -> Result<(), ConfigError> {
    validate_subnets(config)?;
    validate_ha(config)?;
    Ok(())
}

fn validate_subnets(config: &Config) -> Result<(), ConfigError> {
    for (i, subnet) in config.subnet.iter().enumerate() {
        // Parse network CIDR
        let (net_addr, prefix_len) = parse_cidr(&subnet.network).map_err(|e| {
            ConfigError::Validation(format!("subnet[{}] network '{}': {}", i, subnet.network, e))
        })?;

        // Validate subnet type
        match subnet.subnet_type.as_str() {
            "address" => {}
            "prefix-delegation" => {
                if !net_addr.is_ipv6() {
                    return Err(ConfigError::Validation(format!(
                        "subnet[{}]: prefix-delegation requires an IPv6 network",
                        i
                    )));
                }
                if subnet.delegated_length.is_none() {
                    return Err(ConfigError::Validation(format!(
                        "subnet[{}]: prefix-delegation requires delegated_length",
                        i
                    )));
                }
                if let Some(dl) = subnet.delegated_length {
                    if dl <= prefix_len || dl > 128 {
                        return Err(ConfigError::Validation(format!(
                            "subnet[{}]: delegated_length {} must be > prefix_len {} and <= 128",
                            i, dl, prefix_len
                        )));
                    }
                }
            }
            other => {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}]: unknown type '{}'",
                    i, other
                )));
            }
        }

        // Validate pool range if present
        if let (Some(start_str), Some(end_str)) = (&subnet.pool_start, &subnet.pool_end) {
            let start: IpAddr = start_str.parse().map_err(|_| {
                ConfigError::Validation(format!(
                    "subnet[{}] pool_start '{}' is not a valid IP",
                    i, start_str
                ))
            })?;
            let end: IpAddr = end_str.parse().map_err(|_| {
                ConfigError::Validation(format!(
                    "subnet[{}] pool_end '{}' is not a valid IP",
                    i, end_str
                ))
            })?;

            // Ensure same address family
            if std::mem::discriminant(&start) != std::mem::discriminant(&end) {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}]: pool_start and pool_end must be same address family",
                    i
                )));
            }

            if std::mem::discriminant(&start) != std::mem::discriminant(&net_addr) {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}]: pool addresses must match network address family",
                    i
                )));
            }

            // Ensure start <= end
            if !ip_lte(&start, &end) {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}]: pool_start must be <= pool_end",
                    i
                )));
            }

            // Ensure pool is within subnet
            if !ip_in_subnet(&start, &net_addr, prefix_len)
                || !ip_in_subnet(&end, &net_addr, prefix_len)
            {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}]: pool range must be within network {}",
                    i, subnet.network
                )));
            }
        }

        // Validate generic DHCP option overrides
        let mut seen_codes = std::collections::HashSet::new();
        for (k, opt) in subnet.option.iter().enumerate() {
            // Reserved codes the server controls
            const RESERVED: &[u8] = &[0, 1, 28, 51, 53, 54, 58, 59, 255];
            if RESERVED.contains(&opt.code) {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}] option[{}]: code {} is reserved and managed by the server",
                    i, k, opt.code
                )));
            }
            // No duplicates within a subnet
            if !seen_codes.insert(opt.code) {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}] option[{}]: duplicate entry for code {}",
                    i, k, opt.code
                )));
            }
            // Collision with typed fields only if the typed field is non-empty
            match opt.code {
                3 /* router */ if subnet.router.is_some() =>
                    return Err(ConfigError::Validation(format!(
                        "subnet[{}] option[{}]: code 3 conflicts with `router` (set one, not both)",
                        i, k
                    ))),
                6 /* dns */ if !subnet.dns.is_empty() =>
                    return Err(ConfigError::Validation(format!(
                        "subnet[{}] option[{}]: code 6 conflicts with `dns` (set one, not both)",
                        i, k
                    ))),
                15 /* domain */ if subnet.domain.is_some() =>
                    return Err(ConfigError::Validation(format!(
                        "subnet[{}] option[{}]: code 15 conflicts with `domain` (set one, not both)",
                        i, k
                    ))),
                42 /* ntp */ if !subnet.ntp.is_empty() =>
                    return Err(ConfigError::Validation(format!(
                        "subnet[{}] option[{}]: code 42 conflicts with `ntp` (set one, not both)",
                        i, k
                    ))),
                _ => {}
            }
            // Value form + bytes validation
            serialize_option_override(opt).map_err(|e| {
                ConfigError::Validation(format!("subnet[{}] option[{}]: {}", i, k, e))
            })?;
        }

        // Validate reservations
        for (j, res) in subnet.reservation.iter().enumerate() {
            if res.mac.is_none() && res.client_id.is_none() && res.duid.is_none() {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}] reservation[{}]: must specify mac, client_id, or duid",
                    i, j
                )));
            }

            let res_ip: IpAddr = res.ip.parse().map_err(|_| {
                ConfigError::Validation(format!(
                    "subnet[{}] reservation[{}]: '{}' is not a valid IP",
                    i, j, res.ip
                ))
            })?;

            if !ip_in_subnet(&res_ip, &net_addr, prefix_len) {
                return Err(ConfigError::Validation(format!(
                    "subnet[{}] reservation[{}]: IP {} is not within network {}",
                    i, j, res.ip, subnet.network
                )));
            }

            // Validate MAC format if present
            if let Some(mac) = &res.mac {
                parse_mac(mac).map_err(|e| {
                    ConfigError::Validation(format!(
                        "subnet[{}] reservation[{}] mac '{}': {}",
                        i, j, mac, e
                    ))
                })?;
            }
        }
    }

    // Check for overlapping subnets
    let parsed: Vec<(IpAddr, u8)> = config
        .subnet
        .iter()
        .filter_map(|s| parse_cidr(&s.network).ok())
        .collect();

    for i in 0..parsed.len() {
        for j in (i + 1)..parsed.len() {
            if subnets_overlap(parsed[i].0, parsed[i].1, parsed[j].0, parsed[j].1) {
                return Err(ConfigError::Validation(format!(
                    "subnets '{}' and '{}' overlap",
                    config.subnet[i].network, config.subnet[j].network
                )));
            }
        }
    }

    Ok(())
}

fn validate_ha(config: &Config) -> Result<(), ConfigError> {
    match &config.ha {
        super::HaConfig::Standalone => Ok(()),
        super::HaConfig::ActiveActive {
            scope_split,
            tls_cert,
            tls_key,
            tls_ca,
            tls_insecure,
            ..
        } => {
            if *scope_split <= 0.0 || *scope_split >= 1.0 {
                return Err(ConfigError::Validation(
                    "ha scope_split must be between 0.0 and 1.0 exclusive".to_string(),
                ));
            }
            validate_tls_config(tls_cert, tls_key, tls_ca, *tls_insecure, "active-active")?;
            Ok(())
        }
        super::HaConfig::Raft {
            peers,
            tls_cert,
            tls_key,
            tls_ca,
            tls_insecure,
            ..
        } => {
            if peers.is_empty() {
                return Err(ConfigError::Validation(
                    "ha raft mode requires at least one peer".to_string(),
                ));
            }
            validate_tls_config(tls_cert, tls_key, tls_ca, *tls_insecure, "raft")?;
            Ok(())
        }
    }
}

fn validate_tls_config(
    cert: &Option<String>,
    key: &Option<String>,
    ca: &Option<String>,
    insecure: bool,
    mode: &str,
) -> Result<(), ConfigError> {
    // All three must be present together, or none
    let has_cert = cert.is_some();
    let has_key = key.is_some();
    let has_ca = ca.is_some();

    if has_cert || has_key || has_ca {
        if !has_cert || !has_key || !has_ca {
            return Err(ConfigError::Validation(format!(
                "ha {} mode: tls_cert, tls_key, and tls_ca must all be specified together",
                mode
            )));
        }
    } else if insecure {
        // Explicit opt-in to insecure mode
        warn!(
            mode,
            "HA {} mode running WITHOUT TLS (tls_insecure=true) — lease sync traffic \
             (MACs, IPs, hostnames) will travel unencrypted between peers.",
            mode
        );
    } else {
        // No TLS and no explicit opt-in — refuse to start
        return Err(ConfigError::Validation(format!(
            "ha {} mode: TLS is required for peer communication. \
             Configure tls_cert, tls_key, and tls_ca, or set tls_insecure=true \
             to explicitly allow unencrypted peer traffic (not recommended).",
            mode
        )));
    }

    Ok(())
}

pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8), String> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("expected CIDR notation (e.g., 10.0.0.0/24)".to_string());
    }
    let addr: IpAddr = parts[0]
        .parse()
        .map_err(|_| format!("invalid IP address: {}", parts[0]))?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| format!("invalid prefix length: {}", parts[1]))?;

    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        return Err(format!(
            "prefix length {} exceeds maximum {} for address family",
            prefix, max_prefix
        ));
    }

    Ok((addr, prefix))
}

pub fn parse_mac(mac: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return Err("expected 6 colon-separated hex octets".to_string());
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] =
            u8::from_str_radix(part, 16).map_err(|_| format!("invalid hex octet: {}", part))?;
    }
    Ok(bytes)
}

fn ip_to_u128(ip: &IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()) as u128,
        IpAddr::V6(v6) => u128::from_be_bytes(v6.octets()),
    }
}

fn ip_lte(a: &IpAddr, b: &IpAddr) -> bool {
    ip_to_u128(a) <= ip_to_u128(b)
}

pub fn ip_in_subnet(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
    if std::mem::discriminant(ip) != std::mem::discriminant(network) {
        return false;
    }
    let bits = if ip.is_ipv4() { 32u8 } else { 128u8 };
    if prefix_len == 0 {
        return true;
    }
    let shift = bits - prefix_len;
    let ip_val = ip_to_u128(ip);
    let net_val = ip_to_u128(network);
    (ip_val >> shift) == (net_val >> shift)
}

fn subnets_overlap(a_addr: IpAddr, a_prefix: u8, b_addr: IpAddr, b_prefix: u8) -> bool {
    if std::mem::discriminant(&a_addr) != std::mem::discriminant(&b_addr) {
        return false;
    }
    let shorter_prefix = a_prefix.min(b_prefix);
    let bits = if a_addr.is_ipv4() { 32u8 } else { 128u8 };
    if shorter_prefix == 0 {
        return true;
    }
    let shift = bits - shorter_prefix;
    let a_val = ip_to_u128(&a_addr);
    let b_val = ip_to_u128(&b_addr);
    (a_val >> shift) == (b_val >> shift)
}

/// Return true if the given address is unsuitable as a DHCP relay agent
/// source (giaddr). Rejects loopback, link-local, multicast, broadcast,
/// reserved (class E), and the unspecified address.
pub fn is_bogon_giaddr(ip: Ipv4Addr) -> bool {
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        // Class E reserved (240.0.0.0/4) — is_reserved is unstable, so check manually.
        || (ip.octets()[0] & 0xF0) == 0xF0
}

#[cfg(test)]
mod giaddr_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn loopback_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn link_local_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::new(169, 254, 1, 1)));
    }

    #[test]
    fn multicast_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::new(224, 0, 0, 1)));
    }

    #[test]
    fn broadcast_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::BROADCAST));
    }

    #[test]
    fn reserved_class_e_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::new(240, 0, 0, 1)));
    }

    #[test]
    fn unspecified_is_bogon() {
        assert!(is_bogon_giaddr(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn normal_unicast_is_not_bogon() {
        assert!(!is_bogon_giaddr(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_bogon_giaddr(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_bogon_giaddr(Ipv4Addr::new(172, 29, 69, 5)));
    }
}

#[cfg(test)]
mod option_override_tests {
    use super::*;
    use crate::config::types::OptionOverride;

    fn base() -> OptionOverride {
        OptionOverride {
            code: 42,
            ip: None,
            ips: None,
            string: None,
            u8_val: None,
            u16_val: None,
            u32_val: None,
            hex: None,
        }
    }

    #[test]
    fn exactly_one_value_required() {
        let o = base();
        assert!(serialize_option_override(&o).is_err()); // none
        let o = OptionOverride {
            ip: Some("1.2.3.4".to_string()),
            string: Some("x".to_string()),
            ..base()
        };
        assert!(serialize_option_override(&o).is_err()); // two
    }

    #[test]
    fn ip_serializes_to_4_bytes() {
        let o = OptionOverride {
            ip: Some("10.0.0.1".to_string()),
            ..base()
        };
        let bytes = serialize_option_override(&o).unwrap();
        assert_eq!(bytes, vec![10, 0, 0, 1]);
    }

    #[test]
    fn ips_serializes_to_n_times_4_bytes() {
        let o = OptionOverride {
            ips: Some(vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()]),
            ..base()
        };
        let bytes = serialize_option_override(&o).unwrap();
        assert_eq!(bytes, vec![10, 0, 0, 1, 10, 0, 0, 2]);
    }

    #[test]
    fn string_must_be_ascii_printable_and_255_max() {
        let o = OptionOverride {
            string: Some("hello".to_string()),
            ..base()
        };
        assert_eq!(serialize_option_override(&o).unwrap(), b"hello".to_vec());
        let long = "x".repeat(256);
        let o = OptionOverride {
            string: Some(long),
            ..base()
        };
        assert!(serialize_option_override(&o).is_err());
    }

    #[test]
    fn u8_u16_u32_big_endian() {
        let o = OptionOverride {
            u8_val: Some(64),
            ..base()
        };
        assert_eq!(serialize_option_override(&o).unwrap(), vec![64]);
        let o = OptionOverride {
            u16_val: Some(0x1234),
            ..base()
        };
        assert_eq!(serialize_option_override(&o).unwrap(), vec![0x12, 0x34]);
        let o = OptionOverride {
            u32_val: Some(0xdeadbeef),
            ..base()
        };
        assert_eq!(
            serialize_option_override(&o).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn hex_decodes_lowercase_and_uppercase() {
        let o = OptionOverride {
            hex: Some("deadBEEF".to_string()),
            ..base()
        };
        assert_eq!(
            serialize_option_override(&o).unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn hex_rejects_odd_length_and_nonhex() {
        let o = OptionOverride {
            hex: Some("abc".to_string()),
            ..base()
        };
        assert!(serialize_option_override(&o).is_err());
        let o = OptionOverride {
            hex: Some("xx".to_string()),
            ..base()
        };
        assert!(serialize_option_override(&o).is_err());
    }
}

#[cfg(test)]
mod config_option_tests {
    use super::*;
    use crate::config::{Config, ConfigError};

    fn validate_toml(s: &str) -> Result<(), ConfigError> {
        let c: Config = toml::from_str(s).map_err(ConfigError::Parse)?;
        validate(&c)
    }

    #[test]
    fn single_option_entry_parses_correctly() {
        let result = validate_toml(
            r#"
[global]
lease_db = "/tmp/x"

[ha]
mode = "standalone"

[[subnet]]
network = "10.0.0.0/24"

[[subnet.option]]
code = 72
ip = "10.0.0.1"
"#,
        );
        assert!(result.is_ok(), "unexpected error: {:?}", result);
    }

    #[test]
    fn reserved_code_is_rejected() {
        let result = validate_toml(
            r#"
[global]
lease_db = "/tmp/x"

[ha]
mode = "standalone"

[[subnet]]
network = "10.0.0.0/24"

[[subnet.option]]
code = 53
u8 = 1
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("reserved"), "expected 'reserved' in: {}", msg);
    }

    #[test]
    fn duplicate_codes_are_rejected() {
        let result = validate_toml(
            r#"
[global]
lease_db = "/tmp/x"

[ha]
mode = "standalone"

[[subnet]]
network = "10.0.0.0/24"

[[subnet.option]]
code = 72
ip = "10.0.0.1"

[[subnet.option]]
code = 72
ip = "10.0.0.2"
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("duplicate"), "expected 'duplicate' in: {}", msg);
    }

    #[test]
    fn code_42_conflicts_with_ntp_field() {
        let result = validate_toml(
            r#"
[global]
lease_db = "/tmp/x"

[ha]
mode = "standalone"

[[subnet]]
network = "10.0.0.0/24"
ntp = ["10.0.0.1"]

[[subnet.option]]
code = 42
ips = ["10.0.0.2"]
"#,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("ntp"), "expected 'ntp' in: {}", msg);
    }
}
