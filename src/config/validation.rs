use std::net::IpAddr;

use tracing::warn;

use super::{Config, ConfigError};

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
