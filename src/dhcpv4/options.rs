use std::net::Ipv4Addr;

use super::packet::PacketError;

/// DHCP message types (option 53)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
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

/// Well-known DHCP option codes
pub mod code {
    pub const PAD: u8 = 0;
    pub const SUBNET_MASK: u8 = 1;
    pub const ROUTER: u8 = 3;
    pub const DNS: u8 = 6;
    pub const HOSTNAME: u8 = 12;
    pub const DOMAIN_NAME: u8 = 15;
    pub const BROADCAST_ADDR: u8 = 28;
    pub const REQUESTED_IP: u8 = 50;
    pub const LEASE_TIME: u8 = 51;
    pub const MESSAGE_TYPE: u8 = 53;
    pub const SERVER_ID: u8 = 54;
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;
    pub const VENDOR_CLASS_ID: u8 = 60;
    pub const CLIENT_ID: u8 = 61;
    pub const RELAY_AGENT_INFO: u8 = 82;
    pub const END: u8 = 255;
}

/// Parsed DHCP options
#[derive(Debug, Clone)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DnsServers(Vec<Ipv4Addr>),
    Hostname(String),
    DomainName(String),
    BroadcastAddr(Ipv4Addr),
    RequestedIp(Ipv4Addr),
    LeaseTime(u32),
    MessageType(MessageType),
    ServerIdentifier(Ipv4Addr),
    ParameterRequestList(Vec<u8>),
    MaxMessageSize(u16),
    RenewalTime(u32),
    RebindingTime(u32),
    VendorClassId(Vec<u8>),
    ClientIdentifier(Vec<u8>),
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
                code::HOSTNAME => {
                    DhcpOption::Hostname(String::from_utf8_lossy(opt_data).into_owned())
                }
                code::DOMAIN_NAME => {
                    DhcpOption::DomainName(String::from_utf8_lossy(opt_data).into_owned())
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
    pub fn serialize_all(options: &[DhcpOption], buf: &mut [u8]) -> usize {
        let mut pos = 0;

        for opt in options {
            pos += opt.serialize(&mut buf[pos..]);
        }

        pos
    }

    /// Serialize a single option into a buffer. Returns bytes written.
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
                let len = (addrs.len() * 4) as u8;
                buf[1] = len;
                for (i, addr) in addrs.iter().enumerate() {
                    buf[2 + i * 4..6 + i * 4].copy_from_slice(&addr.octets());
                }
                2 + len as usize
            }
            DhcpOption::DnsServers(addrs) => {
                buf[0] = code::DNS;
                let len = (addrs.len() * 4) as u8;
                buf[1] = len;
                for (i, addr) in addrs.iter().enumerate() {
                    buf[2 + i * 4..6 + i * 4].copy_from_slice(&addr.octets());
                }
                2 + len as usize
            }
            DhcpOption::Hostname(name) => {
                let bytes = name.as_bytes();
                buf[0] = code::HOSTNAME;
                buf[1] = bytes.len() as u8;
                buf[2..2 + bytes.len()].copy_from_slice(bytes);
                2 + bytes.len()
            }
            DhcpOption::DomainName(name) => {
                let bytes = name.as_bytes();
                buf[0] = code::DOMAIN_NAME;
                buf[1] = bytes.len() as u8;
                buf[2..2 + bytes.len()].copy_from_slice(bytes);
                2 + bytes.len()
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
                buf[0] = code::PARAMETER_REQUEST_LIST;
                buf[1] = list.len() as u8;
                buf[2..2 + list.len()].copy_from_slice(list);
                2 + list.len()
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
                buf[0] = code::VENDOR_CLASS_ID;
                buf[1] = data.len() as u8;
                buf[2..2 + data.len()].copy_from_slice(data);
                2 + data.len()
            }
            DhcpOption::ClientIdentifier(data) => {
                buf[0] = code::CLIENT_ID;
                buf[1] = data.len() as u8;
                buf[2..2 + data.len()].copy_from_slice(data);
                2 + data.len()
            }
            DhcpOption::RelayAgentInfo(data) => {
                buf[0] = code::RELAY_AGENT_INFO;
                buf[1] = data.len() as u8;
                buf[2..2 + data.len()].copy_from_slice(data);
                2 + data.len()
            }
            DhcpOption::Unknown(opt_code, data) => {
                buf[0] = *opt_code;
                buf[1] = data.len() as u8;
                buf[2..2 + data.len()].copy_from_slice(data);
                2 + data.len()
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
