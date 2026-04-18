use std::net::Ipv4Addr;

use super::packet::PacketError;

/// DHCP message types (option 53)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Client broadcast to locate available servers.
    Discover = 1,
    /// Server response to a Discover with an IP offer.
    Offer = 2,
    /// Client request to accept an offered IP or renew a lease.
    Request = 3,
    /// Client indicates the offered address is already in use.
    Decline = 4,
    /// Server acknowledgement confirming a lease.
    Ack = 5,
    /// Server negative acknowledgement refusing a request.
    Nak = 6,
    /// Client gracefully relinquishes its lease.
    Release = 7,
    /// Client requests configuration parameters without a lease.
    Inform = 8,
}

impl MessageType {
    /// Convert a raw byte value to a `MessageType`, returning `None` for unknown values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Discover),
            2 => Some(Self::Offer),
            3 => Some(Self::Request),
            4 => Some(Self::Decline),
            5 => Some(Self::Ack),
            6 => Some(Self::Nak),
            7 => Some(Self::Release),
            8 => Some(Self::Inform),
            _ => None,
        }
    }
}

/// Well-known DHCP option codes (RFC 2132).
pub mod code {
    //! Numeric constants for standard DHCP option codes.

    /// Padding byte (option 0).
    pub const PAD: u8 = 0;
    /// Subnet mask (option 1).
    pub const SUBNET_MASK: u8 = 1;
    /// Default gateway routers (option 3).
    pub const ROUTER: u8 = 3;
    /// DNS server addresses (option 6).
    pub const DNS: u8 = 6;
    /// Client hostname (option 12).
    pub const HOSTNAME: u8 = 12;
    /// Domain name for DNS resolution (option 15).
    pub const DOMAIN_NAME: u8 = 15;
    /// Broadcast address (option 28).
    pub const BROADCAST_ADDR: u8 = 28;
    /// Client-requested IP address (option 50).
    pub const REQUESTED_IP: u8 = 50;
    /// IP address lease time in seconds (option 51).
    pub const LEASE_TIME: u8 = 51;
    /// DHCP message type (option 53).
    pub const MESSAGE_TYPE: u8 = 53;
    /// Server identifier (option 54).
    pub const SERVER_ID: u8 = 54;
    /// Parameter request list (option 55).
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    /// Maximum DHCP message size the client will accept (option 57).
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    /// Renewal (T1) time in seconds (option 58).
    pub const RENEWAL_TIME: u8 = 58;
    /// Rebinding (T2) time in seconds (option 59).
    pub const REBINDING_TIME: u8 = 59;
    /// Vendor class identifier (option 60).
    pub const VENDOR_CLASS_ID: u8 = 60;
    /// Client identifier (option 61).
    pub const CLIENT_ID: u8 = 61;
    /// NTP server addresses (option 42).
    pub const NTP: u8 = 42;
    /// Relay agent information (option 82).
    pub const RELAY_AGENT_INFO: u8 = 82;
    /// End-of-options marker (option 255).
    pub const END: u8 = 255;
}

/// Parsed DHCP options
#[derive(Debug, Clone)]
pub enum DhcpOption {
    /// Subnet mask (option 1).
    SubnetMask(Ipv4Addr),
    /// Default gateway router(s) (option 3).
    Router(Vec<Ipv4Addr>),
    /// DNS server address(es) (option 6).
    DnsServers(Vec<Ipv4Addr>),
    /// Client hostname (option 12).
    Hostname(String),
    /// Domain name for DNS resolution (option 15).
    DomainName(String),
    /// Broadcast address for the subnet (option 28).
    BroadcastAddr(Ipv4Addr),
    /// IP address requested by the client (option 50).
    RequestedIp(Ipv4Addr),
    /// Lease duration in seconds (option 51).
    LeaseTime(u32),
    /// DHCP message type (option 53).
    MessageType(MessageType),
    /// Server identifier address (option 54).
    ServerIdentifier(Ipv4Addr),
    /// List of option codes the client is requesting (option 55).
    ParameterRequestList(Vec<u8>),
    /// Maximum DHCP message size the client will accept (option 57).
    MaxMessageSize(u16),
    /// Renewal (T1) time in seconds (option 58).
    RenewalTime(u32),
    /// Rebinding (T2) time in seconds (option 59).
    RebindingTime(u32),
    /// Vendor class identifier (option 60).
    VendorClassId(Vec<u8>),
    /// Client identifier (option 61).
    ClientIdentifier(Vec<u8>),
    /// NTP server address(es) (option 42).
    NtpServers(Vec<Ipv4Addr>),
    /// Relay agent information sub-options (option 82).
    RelayAgentInfo(Vec<u8>),
    /// Unknown option: (code, data)
    Unknown(u8, Vec<u8>),
}

impl DhcpOption {
    /// Parse all options from the options section of a DHCP packet
    pub fn parse_all(data: &[u8]) -> Result<Vec<DhcpOption>, PacketError> {
        let mut options = Vec::with_capacity(16);
        let mut pos = 0;

        while pos < data.len() {
            let opt_code = data[pos];

            match opt_code {
                code::PAD => {
                    pos += 1;
                    continue;
                }
                code::END => break,
                _ => {}
            }

            // Need at least code + length
            if pos + 1 >= data.len() {
                return Err(PacketError::MalformedOption(pos));
            }

            let opt_len = data[pos + 1] as usize;
            let opt_start = pos + 2;
            let opt_end = opt_start + opt_len;

            if opt_end > data.len() {
                return Err(PacketError::MalformedOption(pos));
            }

            let opt_data = &data[opt_start..opt_end];

            let option = match opt_code {
                code::SUBNET_MASK => {
                    if opt_len != 4 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    DhcpOption::SubnetMask(Ipv4Addr::new(
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ))
                }
                code::ROUTER => {
                    if opt_len % 4 != 0 || opt_len == 0 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    let addrs = opt_data
                        .chunks_exact(4)
                        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                        .collect();
                    DhcpOption::Router(addrs)
                }
                code::DNS => {
                    if opt_len % 4 != 0 || opt_len == 0 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    let addrs = opt_data
                        .chunks_exact(4)
                        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                        .collect();
                    DhcpOption::DnsServers(addrs)
                }
                code::NTP => {
                    if opt_len % 4 != 0 || opt_len == 0 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    let addrs = opt_data
                        .chunks_exact(4)
                        .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                        .collect();
                    DhcpOption::NtpServers(addrs)
                }
                code::HOSTNAME => {
                    // Only accept printable ASCII hostnames; reject binary/non-ASCII data
                    if opt_data.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                        DhcpOption::Hostname(String::from_utf8_lossy(opt_data).into_owned())
                    } else {
                        DhcpOption::Unknown(opt_code, opt_data.to_vec())
                    }
                }
                code::DOMAIN_NAME => {
                    if opt_data.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                        DhcpOption::DomainName(String::from_utf8_lossy(opt_data).into_owned())
                    } else {
                        DhcpOption::Unknown(opt_code, opt_data.to_vec())
                    }
                }
                code::BROADCAST_ADDR => {
                    if opt_len != 4 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    DhcpOption::BroadcastAddr(Ipv4Addr::new(
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ))
                }
                code::REQUESTED_IP => {
                    if opt_len != 4 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    DhcpOption::RequestedIp(Ipv4Addr::new(
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ))
                }
                code::LEASE_TIME => {
                    if opt_len != 4 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    DhcpOption::LeaseTime(u32::from_be_bytes([
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ]))
                }
                code::MESSAGE_TYPE => {
                    if opt_len != 1 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    let mt = MessageType::from_u8(opt_data[0]).ok_or(PacketError::MalformedOption(pos))?;
                    DhcpOption::MessageType(mt)
                }
                code::SERVER_ID => {
                    if opt_len != 4 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    DhcpOption::ServerIdentifier(Ipv4Addr::new(
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ))
                }
                code::PARAMETER_REQUEST_LIST => {
                    DhcpOption::ParameterRequestList(opt_data.to_vec())
                }
                code::MAX_MESSAGE_SIZE => {
                    if opt_len != 2 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    DhcpOption::MaxMessageSize(u16::from_be_bytes([opt_data[0], opt_data[1]]))
                }
                code::RENEWAL_TIME => {
                    if opt_len != 4 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    DhcpOption::RenewalTime(u32::from_be_bytes([
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ]))
                }
                code::REBINDING_TIME => {
                    if opt_len != 4 {
                        return Err(PacketError::MalformedOption(pos));
                    }
                    DhcpOption::RebindingTime(u32::from_be_bytes([
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ]))
                }
                code::VENDOR_CLASS_ID => DhcpOption::VendorClassId(opt_data.to_vec()),
                code::CLIENT_ID => DhcpOption::ClientIdentifier(opt_data.to_vec()),
                code::RELAY_AGENT_INFO => DhcpOption::RelayAgentInfo(opt_data.to_vec()),
                _ => DhcpOption::Unknown(opt_code, opt_data.to_vec()),
            };

            options.push(option);
            pos = opt_end;
        }

        Ok(options)
    }

    /// Serialize all options into a buffer. Returns bytes written.
    /// Stops writing if the buffer is too small for the next option.
    pub fn serialize_all(options: &[DhcpOption], buf: &mut [u8]) -> usize {
        let mut pos = 0;

        for opt in options {
            let needed = opt.serialized_len();
            if pos + needed > buf.len() {
                tracing::warn!(
                    option_code = opt.code(),
                    remaining_bytes = buf.len() - pos,
                    needed_bytes = needed,
                    "DHCPv4 option truncated: buffer too small"
                );
                break;
            }
            pos += opt.serialize(&mut buf[pos..]);
        }

        pos
    }

    /// Returns the number of bytes this option will occupy when serialized.
    fn serialized_len(&self) -> usize {
        match self {
            DhcpOption::SubnetMask(_)
            | DhcpOption::BroadcastAddr(_)
            | DhcpOption::RequestedIp(_)
            | DhcpOption::ServerIdentifier(_) => 6,
            DhcpOption::Router(addrs) => 2 + addrs.len().min(63) * 4,
            DhcpOption::DnsServers(addrs) => 2 + addrs.len().min(63) * 4,
            DhcpOption::NtpServers(addrs) => 2 + addrs.len().min(63) * 4,
            DhcpOption::Hostname(name) => 2 + name.len().min(255),
            DhcpOption::DomainName(name) => 2 + name.len().min(255),
            DhcpOption::LeaseTime(_)
            | DhcpOption::RenewalTime(_)
            | DhcpOption::RebindingTime(_) => 6,
            DhcpOption::MessageType(_) => 3,
            DhcpOption::ParameterRequestList(list) => 2 + list.len().min(255),
            DhcpOption::MaxMessageSize(_) => 4,
            DhcpOption::VendorClassId(data)
            | DhcpOption::ClientIdentifier(data)
            | DhcpOption::RelayAgentInfo(data) => 2 + data.len().min(255),
            DhcpOption::Unknown(_, data) => 2 + data.len().min(255),
        }
    }

    /// Serialize a single option into a buffer. Returns bytes written.
    /// Caller must ensure `buf` has at least `serialized_len()` bytes available.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        match self {
            DhcpOption::SubnetMask(addr) => {
                buf[0] = code::SUBNET_MASK;
                buf[1] = 4;
                buf[2..6].copy_from_slice(&addr.octets());
                6
            }
            DhcpOption::Router(addrs) => {
                buf[0] = code::ROUTER;
                let count = addrs.len().min(63);
                let len = (count * 4) as u8;
                buf[1] = len;
                for (i, addr) in addrs.iter().take(count).enumerate() {
                    buf[2 + i * 4..6 + i * 4].copy_from_slice(&addr.octets());
                }
                2 + len as usize
            }
            DhcpOption::DnsServers(addrs) => {
                buf[0] = code::DNS;
                let count = addrs.len().min(63);
                let len = (count * 4) as u8;
                buf[1] = len;
                for (i, addr) in addrs.iter().take(count).enumerate() {
                    buf[2 + i * 4..6 + i * 4].copy_from_slice(&addr.octets());
                }
                2 + len as usize
            }
            DhcpOption::NtpServers(addrs) => {
                buf[0] = code::NTP;
                let count = addrs.len().min(63);
                let len = (count * 4) as u8;
                buf[1] = len;
                for (i, addr) in addrs.iter().take(count).enumerate() {
                    buf[2 + i * 4..6 + i * 4].copy_from_slice(&addr.octets());
                }
                2 + len as usize
            }
            DhcpOption::Hostname(name) => {
                let bytes = name.as_bytes();
                let len = bytes.len().min(255);
                buf[0] = code::HOSTNAME;
                buf[1] = len as u8;
                buf[2..2 + len].copy_from_slice(&bytes[..len]);
                2 + len
            }
            DhcpOption::DomainName(name) => {
                let bytes = name.as_bytes();
                let len = bytes.len().min(255);
                buf[0] = code::DOMAIN_NAME;
                buf[1] = len as u8;
                buf[2..2 + len].copy_from_slice(&bytes[..len]);
                2 + len
            }
            DhcpOption::BroadcastAddr(addr) => {
                buf[0] = code::BROADCAST_ADDR;
                buf[1] = 4;
                buf[2..6].copy_from_slice(&addr.octets());
                6
            }
            DhcpOption::RequestedIp(addr) => {
                buf[0] = code::REQUESTED_IP;
                buf[1] = 4;
                buf[2..6].copy_from_slice(&addr.octets());
                6
            }
            DhcpOption::LeaseTime(t) => {
                buf[0] = code::LEASE_TIME;
                buf[1] = 4;
                buf[2..6].copy_from_slice(&t.to_be_bytes());
                6
            }
            DhcpOption::MessageType(mt) => {
                buf[0] = code::MESSAGE_TYPE;
                buf[1] = 1;
                buf[2] = *mt as u8;
                3
            }
            DhcpOption::ServerIdentifier(addr) => {
                buf[0] = code::SERVER_ID;
                buf[1] = 4;
                buf[2..6].copy_from_slice(&addr.octets());
                6
            }
            DhcpOption::ParameterRequestList(list) => {
                let len = list.len().min(255);
                buf[0] = code::PARAMETER_REQUEST_LIST;
                buf[1] = len as u8;
                buf[2..2 + len].copy_from_slice(&list[..len]);
                2 + len
            }
            DhcpOption::MaxMessageSize(size) => {
                buf[0] = code::MAX_MESSAGE_SIZE;
                buf[1] = 2;
                buf[2..4].copy_from_slice(&size.to_be_bytes());
                4
            }
            DhcpOption::RenewalTime(t) => {
                buf[0] = code::RENEWAL_TIME;
                buf[1] = 4;
                buf[2..6].copy_from_slice(&t.to_be_bytes());
                6
            }
            DhcpOption::RebindingTime(t) => {
                buf[0] = code::REBINDING_TIME;
                buf[1] = 4;
                buf[2..6].copy_from_slice(&t.to_be_bytes());
                6
            }
            DhcpOption::VendorClassId(data) => {
                let len = data.len().min(255);
                buf[0] = code::VENDOR_CLASS_ID;
                buf[1] = len as u8;
                buf[2..2 + len].copy_from_slice(&data[..len]);
                2 + len
            }
            DhcpOption::ClientIdentifier(data) => {
                let len = data.len().min(255);
                buf[0] = code::CLIENT_ID;
                buf[1] = len as u8;
                buf[2..2 + len].copy_from_slice(&data[..len]);
                2 + len
            }
            DhcpOption::RelayAgentInfo(data) => {
                let len = data.len().min(255);
                buf[0] = code::RELAY_AGENT_INFO;
                buf[1] = len as u8;
                buf[2..2 + len].copy_from_slice(&data[..len]);
                2 + len
            }
            DhcpOption::Unknown(opt_code, data) => {
                let len = data.len().min(255);
                buf[0] = *opt_code;
                buf[1] = len as u8;
                buf[2..2 + len].copy_from_slice(&data[..len]);
                2 + len
            }
        }
    }

    /// Get the option code
    pub fn code(&self) -> u8 {
        match self {
            DhcpOption::SubnetMask(_) => code::SUBNET_MASK,
            DhcpOption::Router(_) => code::ROUTER,
            DhcpOption::DnsServers(_) => code::DNS,
            DhcpOption::Hostname(_) => code::HOSTNAME,
            DhcpOption::DomainName(_) => code::DOMAIN_NAME,
            DhcpOption::BroadcastAddr(_) => code::BROADCAST_ADDR,
            DhcpOption::RequestedIp(_) => code::REQUESTED_IP,
            DhcpOption::LeaseTime(_) => code::LEASE_TIME,
            DhcpOption::MessageType(_) => code::MESSAGE_TYPE,
            DhcpOption::ServerIdentifier(_) => code::SERVER_ID,
            DhcpOption::ParameterRequestList(_) => code::PARAMETER_REQUEST_LIST,
            DhcpOption::MaxMessageSize(_) => code::MAX_MESSAGE_SIZE,
            DhcpOption::RenewalTime(_) => code::RENEWAL_TIME,
            DhcpOption::RebindingTime(_) => code::REBINDING_TIME,
            DhcpOption::VendorClassId(_) => code::VENDOR_CLASS_ID,
            DhcpOption::ClientIdentifier(_) => code::CLIENT_ID,
            DhcpOption::NtpServers(_) => code::NTP,
            DhcpOption::RelayAgentInfo(_) => code::RELAY_AGENT_INFO,
            DhcpOption::Unknown(c, _) => *c,
        }
    }
}

/// Compute the subnet mask from a prefix length
pub fn prefix_to_mask(prefix_len: u8) -> Ipv4Addr {
    if prefix_len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    if prefix_len >= 32 {
        return Ipv4Addr::new(255, 255, 255, 255);
    }
    let mask = !((1u32 << (32 - prefix_len)) - 1);
    Ipv4Addr::from(mask.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_servers_roundtrip() {
        let opt = DhcpOption::NtpServers(vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        ]);
        let mut buf = [0u8; 16];
        let len = opt.serialize(&mut buf);
        assert_eq!(&buf[..len], &[42, 8, 10, 0, 0, 1, 10, 0, 0, 2]);
        let parsed = DhcpOption::parse_all(&buf[..len]).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(matches!(parsed[0], DhcpOption::NtpServers(_)));
    }

    #[test]
    fn ntp_servers_code_is_42() {
        let opt = DhcpOption::NtpServers(vec![Ipv4Addr::new(1, 2, 3, 4)]);
        assert_eq!(opt.code(), 42);
    }
}

/// Compute the broadcast address for a network
pub fn broadcast_addr(network: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let net = u32::from_be_bytes(network.octets());
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let bcast = net | !mask;
    Ipv4Addr::from(bcast.to_be_bytes())
}
