use std::net::Ipv6Addr;

use super::packet::Dhcpv6PacketError;

/// DHCPv6 option codes (RFC 8415 and related)
pub mod code {
    /// Client Identifier option (DUID).
    pub const CLIENT_ID: u16 = 1;
    /// Server Identifier option (DUID).
    pub const SERVER_ID: u16 = 2;
    /// Identity Association for Non-temporary Addresses.
    pub const IA_NA: u16 = 3;
    /// Identity Association for Temporary Addresses.
    pub const IA_TA: u16 = 4;
    /// IA Address option carried inside IA_NA or IA_TA.
    pub const IA_ADDR: u16 = 5;
    /// Option Request Option -- lists option codes the client wants.
    pub const ORO: u16 = 6;
    /// Server preference value (0-255).
    pub const PREFERENCE: u16 = 7;
    /// Elapsed time since the client began the current exchange (in 10ms units).
    pub const ELAPSED_TIME: u16 = 8;
    /// Relay Message option encapsulating a relayed client/server message.
    pub const RELAY_MSG: u16 = 9;
    /// Status Code indicating the outcome of an operation.
    pub const STATUS_CODE: u16 = 13;
    /// Rapid Commit option for two-message exchange.
    pub const RAPID_COMMIT: u16 = 14;
    /// DNS Recursive Name Server option (RFC 3646).
    pub const DNS_SERVERS: u16 = 23;
    /// Domain Search List option (RFC 3646).
    pub const DOMAIN_LIST: u16 = 24;
    /// Identity Association for Prefix Delegation (RFC 3633).
    pub const IA_PD: u16 = 25;
    /// IA Prefix option carried inside IA_PD (RFC 3633).
    pub const IA_PREFIX: u16 = 26;
    /// Interface-Id option used by relay agents.
    pub const INTERFACE_ID: u16 = 18;
}

/// DHCPv6 status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StatusCode {
    /// Operation completed successfully.
    Success = 0,
    /// Unspecified failure.
    UnspecFail = 1,
    /// Server has no addresses available to assign.
    NoAddrsAvail = 2,
    /// Client record (binding) unavailable.
    NoBinding = 3,
    /// The prefix in the IA is not appropriate for the link.
    NotOnLink = 4,
    /// Client must use the multicast All_DHCP_Relay_Agents_and_Servers address.
    UseMulticast = 5,
    /// Server has no prefixes available to delegate.
    NoPrefixAvail = 6,
}

impl StatusCode {
    /// Convert a raw `u16` to a status code, returning `None` for unknown values.
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::Success),
            1 => Some(Self::UnspecFail),
            2 => Some(Self::NoAddrsAvail),
            3 => Some(Self::NoBinding),
            4 => Some(Self::NotOnLink),
            5 => Some(Self::UseMulticast),
            6 => Some(Self::NoPrefixAvail),
            _ => None,
        }
    }
}

/// Identity Association for Non-temporary Addresses
#[derive(Debug, Clone)]
pub struct IaNa {
    /// Identity Association Identifier chosen by the client.
    pub iaid: u32,
    /// Seconds before the client contacts the server to extend lifetimes (T1).
    pub t1: u32,
    /// Seconds before the client contacts any server to extend lifetimes (T2).
    pub t2: u32,
    /// Sub-options (typically IA_ADDR and/or StatusCode).
    pub options: Vec<Dhcpv6Option>,
}

/// Identity Association for Prefix Delegation
#[derive(Debug, Clone)]
pub struct IaPd {
    /// Identity Association Identifier chosen by the requesting router.
    pub iaid: u32,
    /// Seconds before the client contacts the delegating router to extend lifetimes (T1).
    pub t1: u32,
    /// Seconds before the client contacts any delegating router to extend lifetimes (T2).
    pub t2: u32,
    /// Sub-options (typically IA_PREFIX and/or StatusCode).
    pub options: Vec<Dhcpv6Option>,
}

/// An address within IA_NA
#[derive(Debug, Clone)]
pub struct IaAddr {
    /// The IPv6 address being offered or assigned.
    pub addr: Ipv6Addr,
    /// Preferred lifetime in seconds.
    pub preferred_lifetime: u32,
    /// Valid lifetime in seconds.
    pub valid_lifetime: u32,
    /// Sub-options (e.g. StatusCode).
    pub options: Vec<Dhcpv6Option>,
}

/// A prefix within IA_PD
#[derive(Debug, Clone)]
pub struct IaPrefix {
    /// Preferred lifetime in seconds.
    pub preferred_lifetime: u32,
    /// Valid lifetime in seconds.
    pub valid_lifetime: u32,
    /// Length of the delegated prefix in bits.
    pub prefix_len: u8,
    /// The delegated IPv6 prefix.
    pub prefix: Ipv6Addr,
    /// Sub-options (e.g. StatusCode).
    pub options: Vec<Dhcpv6Option>,
}

/// Parsed DHCPv6 options
#[derive(Debug, Clone)]
pub enum Dhcpv6Option {
    /// Client Identifier (DUID).
    ClientId(Vec<u8>),
    /// Server Identifier (DUID).
    ServerId(Vec<u8>),
    /// Identity Association for Non-temporary Addresses.
    IaNa(IaNa),
    /// IA Address carried inside an IA_NA.
    IaAddr(IaAddr),
    /// Identity Association for Prefix Delegation.
    IaPd(IaPd),
    /// IA Prefix carried inside an IA_PD.
    IaPrefix(IaPrefix),
    /// Option Request Option -- list of option codes requested by the client.
    OptionRequest(Vec<u16>),
    /// Server preference value (0-255).
    Preference(u8),
    /// Elapsed time in hundredths of a second since the client began the exchange.
    ElapsedTime(u16),
    /// Status code with an optional human-readable message.
    StatusCode(StatusCode, String),
    /// Signals use of the two-message Solicit/Reply exchange.
    RapidCommit,
    /// Recursive DNS server addresses (RFC 3646).
    DnsServers(Vec<Ipv6Addr>),
    /// DNS domain search list (RFC 3646).
    DomainList(Vec<String>),
    /// Encapsulated relay message bytes.
    RelayMessage(Vec<u8>),
    /// Interface identifier set by the relay agent.
    InterfaceId(Vec<u8>),
    /// Unknown option: (code, data)
    Unknown(u16, Vec<u8>),
}

impl Dhcpv6Option {
    /// Parse all options from a byte slice
    pub fn parse_all(data: &[u8]) -> Result<Vec<Dhcpv6Option>, Dhcpv6PacketError> {
        let mut options = Vec::with_capacity(8);
        let mut pos = 0;

        while pos + 4 <= data.len() {
            let opt_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let opt_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            let opt_start = pos + 4;
            let opt_end = opt_start + opt_len;

            if opt_end > data.len() {
                return Err(Dhcpv6PacketError::MalformedOption(pos));
            }

            let opt_data = &data[opt_start..opt_end];

            let option = match opt_type {
                code::CLIENT_ID => Dhcpv6Option::ClientId(opt_data.to_vec()),
                code::SERVER_ID => Dhcpv6Option::ServerId(opt_data.to_vec()),
                code::IA_NA => {
                    if opt_len < 12 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    let iaid = u32::from_be_bytes([
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ]);
                    let t1 = u32::from_be_bytes([
                        opt_data[4],
                        opt_data[5],
                        opt_data[6],
                        opt_data[7],
                    ]);
                    let t2 = u32::from_be_bytes([
                        opt_data[8],
                        opt_data[9],
                        opt_data[10],
                        opt_data[11],
                    ]);
                    let sub_opts = Self::parse_all(&opt_data[12..])?;
                    Dhcpv6Option::IaNa(IaNa {
                        iaid,
                        t1,
                        t2,
                        options: sub_opts,
                    })
                }
                code::IA_ADDR => {
                    if opt_len < 24 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    let mut addr_bytes = [0u8; 16];
                    addr_bytes.copy_from_slice(&opt_data[0..16]);
                    let addr = Ipv6Addr::from(addr_bytes);
                    let preferred = u32::from_be_bytes([
                        opt_data[16],
                        opt_data[17],
                        opt_data[18],
                        opt_data[19],
                    ]);
                    let valid = u32::from_be_bytes([
                        opt_data[20],
                        opt_data[21],
                        opt_data[22],
                        opt_data[23],
                    ]);
                    let sub_opts = Self::parse_all(&opt_data[24..])?;
                    Dhcpv6Option::IaAddr(IaAddr {
                        addr,
                        preferred_lifetime: preferred,
                        valid_lifetime: valid,
                        options: sub_opts,
                    })
                }
                code::IA_PD => {
                    if opt_len < 12 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    let iaid = u32::from_be_bytes([
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ]);
                    let t1 = u32::from_be_bytes([
                        opt_data[4],
                        opt_data[5],
                        opt_data[6],
                        opt_data[7],
                    ]);
                    let t2 = u32::from_be_bytes([
                        opt_data[8],
                        opt_data[9],
                        opt_data[10],
                        opt_data[11],
                    ]);
                    let sub_opts = Self::parse_all(&opt_data[12..])?;
                    Dhcpv6Option::IaPd(IaPd {
                        iaid,
                        t1,
                        t2,
                        options: sub_opts,
                    })
                }
                code::IA_PREFIX => {
                    if opt_len < 25 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    let preferred = u32::from_be_bytes([
                        opt_data[0],
                        opt_data[1],
                        opt_data[2],
                        opt_data[3],
                    ]);
                    let valid = u32::from_be_bytes([
                        opt_data[4],
                        opt_data[5],
                        opt_data[6],
                        opt_data[7],
                    ]);
                    let prefix_len = opt_data[8];
                    let mut prefix_bytes = [0u8; 16];
                    prefix_bytes.copy_from_slice(&opt_data[9..25]);
                    let prefix = Ipv6Addr::from(prefix_bytes);
                    let sub_opts = Self::parse_all(&opt_data[25..])?;
                    Dhcpv6Option::IaPrefix(IaPrefix {
                        preferred_lifetime: preferred,
                        valid_lifetime: valid,
                        prefix_len,
                        prefix,
                        options: sub_opts,
                    })
                }
                code::ORO => {
                    if opt_len % 2 != 0 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    let codes = opt_data
                        .chunks_exact(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    Dhcpv6Option::OptionRequest(codes)
                }
                code::PREFERENCE => {
                    if opt_len != 1 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    Dhcpv6Option::Preference(opt_data[0])
                }
                code::ELAPSED_TIME => {
                    if opt_len != 2 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    Dhcpv6Option::ElapsedTime(u16::from_be_bytes([opt_data[0], opt_data[1]]))
                }
                code::STATUS_CODE => {
                    if opt_len < 2 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    let status = u16::from_be_bytes([opt_data[0], opt_data[1]]);
                    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::UnspecFail);
                    let msg = if opt_len > 2 {
                        String::from_utf8_lossy(&opt_data[2..]).into_owned()
                    } else {
                        String::new()
                    };
                    Dhcpv6Option::StatusCode(status, msg)
                }
                code::RAPID_COMMIT => Dhcpv6Option::RapidCommit,
                code::DNS_SERVERS => {
                    if opt_len % 16 != 0 {
                        return Err(Dhcpv6PacketError::MalformedOption(pos));
                    }
                    let addrs = opt_data
                        .chunks_exact(16)
                        .map(|c| {
                            let mut bytes = [0u8; 16];
                            bytes.copy_from_slice(c);
                            Ipv6Addr::from(bytes)
                        })
                        .collect();
                    Dhcpv6Option::DnsServers(addrs)
                }
                code::DOMAIN_LIST => {
                    // RFC 1035 compressed domain names
                    let domains = parse_domain_list(opt_data);
                    Dhcpv6Option::DomainList(domains)
                }
                code::RELAY_MSG => Dhcpv6Option::RelayMessage(opt_data.to_vec()),
                code::INTERFACE_ID => Dhcpv6Option::InterfaceId(opt_data.to_vec()),
                _ => Dhcpv6Option::Unknown(opt_type, opt_data.to_vec()),
            };

            options.push(option);
            pos = opt_end;
        }

        Ok(options)
    }

    /// Serialize all options into a buffer. Returns bytes written.
    pub fn serialize_all(options: &[Dhcpv6Option], buf: &mut [u8]) -> usize {
        let mut pos = 0;
        for opt in options {
            pos += opt.serialize(&mut buf[pos..]);
        }
        pos
    }

    /// Serialize a single option. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        match self {
            Dhcpv6Option::ClientId(data) | Dhcpv6Option::ServerId(data) => {
                let opt_type = match self {
                    Dhcpv6Option::ClientId(_) => code::CLIENT_ID,
                    Dhcpv6Option::ServerId(_) => code::SERVER_ID,
                    _ => unreachable!(),
                };
                buf[0..2].copy_from_slice(&opt_type.to_be_bytes());
                buf[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
                buf[4..4 + data.len()].copy_from_slice(data);
                4 + data.len()
            }
            Dhcpv6Option::IaNa(ia) => {
                buf[0..2].copy_from_slice(&code::IA_NA.to_be_bytes());
                // Write sub-options first to know length
                let mut sub_buf = [0u8; 1024];
                let sub_len = Self::serialize_all(&ia.options, &mut sub_buf);
                let total_len = 12 + sub_len;
                buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
                buf[4..8].copy_from_slice(&ia.iaid.to_be_bytes());
                buf[8..12].copy_from_slice(&ia.t1.to_be_bytes());
                buf[12..16].copy_from_slice(&ia.t2.to_be_bytes());
                buf[16..16 + sub_len].copy_from_slice(&sub_buf[..sub_len]);
                4 + total_len
            }
            Dhcpv6Option::IaAddr(ia_addr) => {
                buf[0..2].copy_from_slice(&code::IA_ADDR.to_be_bytes());
                let mut sub_buf = [0u8; 512];
                let sub_len = Self::serialize_all(&ia_addr.options, &mut sub_buf);
                let total_len = 24 + sub_len;
                buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
                buf[4..20].copy_from_slice(&ia_addr.addr.octets());
                buf[20..24].copy_from_slice(&ia_addr.preferred_lifetime.to_be_bytes());
                buf[24..28].copy_from_slice(&ia_addr.valid_lifetime.to_be_bytes());
                buf[28..28 + sub_len].copy_from_slice(&sub_buf[..sub_len]);
                4 + total_len
            }
            Dhcpv6Option::IaPd(ia) => {
                buf[0..2].copy_from_slice(&code::IA_PD.to_be_bytes());
                let mut sub_buf = [0u8; 1024];
                let sub_len = Self::serialize_all(&ia.options, &mut sub_buf);
                let total_len = 12 + sub_len;
                buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
                buf[4..8].copy_from_slice(&ia.iaid.to_be_bytes());
                buf[8..12].copy_from_slice(&ia.t1.to_be_bytes());
                buf[12..16].copy_from_slice(&ia.t2.to_be_bytes());
                buf[16..16 + sub_len].copy_from_slice(&sub_buf[..sub_len]);
                4 + total_len
            }
            Dhcpv6Option::IaPrefix(ia_prefix) => {
                buf[0..2].copy_from_slice(&code::IA_PREFIX.to_be_bytes());
                let mut sub_buf = [0u8; 512];
                let sub_len = Self::serialize_all(&ia_prefix.options, &mut sub_buf);
                let total_len = 25 + sub_len;
                buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
                buf[4..8].copy_from_slice(&ia_prefix.preferred_lifetime.to_be_bytes());
                buf[8..12].copy_from_slice(&ia_prefix.valid_lifetime.to_be_bytes());
                buf[12] = ia_prefix.prefix_len;
                buf[13..29].copy_from_slice(&ia_prefix.prefix.octets());
                buf[29..29 + sub_len].copy_from_slice(&sub_buf[..sub_len]);
                4 + total_len
            }
            Dhcpv6Option::OptionRequest(codes) => {
                buf[0..2].copy_from_slice(&code::ORO.to_be_bytes());
                let len = codes.len() * 2;
                buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                for (i, c) in codes.iter().enumerate() {
                    buf[4 + i * 2..6 + i * 2].copy_from_slice(&c.to_be_bytes());
                }
                4 + len
            }
            Dhcpv6Option::Preference(pref) => {
                buf[0..2].copy_from_slice(&code::PREFERENCE.to_be_bytes());
                buf[2..4].copy_from_slice(&1u16.to_be_bytes());
                buf[4] = *pref;
                5
            }
            Dhcpv6Option::ElapsedTime(t) => {
                buf[0..2].copy_from_slice(&code::ELAPSED_TIME.to_be_bytes());
                buf[2..4].copy_from_slice(&2u16.to_be_bytes());
                buf[4..6].copy_from_slice(&t.to_be_bytes());
                6
            }
            Dhcpv6Option::StatusCode(status, msg) => {
                buf[0..2].copy_from_slice(&code::STATUS_CODE.to_be_bytes());
                let msg_bytes = msg.as_bytes();
                let len = 2 + msg_bytes.len();
                buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                buf[4..6].copy_from_slice(&(*status as u16).to_be_bytes());
                buf[6..6 + msg_bytes.len()].copy_from_slice(msg_bytes);
                4 + len
            }
            Dhcpv6Option::RapidCommit => {
                buf[0..2].copy_from_slice(&code::RAPID_COMMIT.to_be_bytes());
                buf[2..4].copy_from_slice(&0u16.to_be_bytes());
                4
            }
            Dhcpv6Option::DnsServers(addrs) => {
                buf[0..2].copy_from_slice(&code::DNS_SERVERS.to_be_bytes());
                let len = addrs.len() * 16;
                buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
                for (i, addr) in addrs.iter().enumerate() {
                    buf[4 + i * 16..20 + i * 16].copy_from_slice(&addr.octets());
                }
                4 + len
            }
            Dhcpv6Option::DomainList(domains) => {
                buf[0..2].copy_from_slice(&code::DOMAIN_LIST.to_be_bytes());
                let encoded = encode_domain_list(domains);
                buf[2..4].copy_from_slice(&(encoded.len() as u16).to_be_bytes());
                buf[4..4 + encoded.len()].copy_from_slice(&encoded);
                4 + encoded.len()
            }
            Dhcpv6Option::RelayMessage(data) => {
                buf[0..2].copy_from_slice(&code::RELAY_MSG.to_be_bytes());
                buf[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
                buf[4..4 + data.len()].copy_from_slice(data);
                4 + data.len()
            }
            Dhcpv6Option::InterfaceId(data) => {
                buf[0..2].copy_from_slice(&code::INTERFACE_ID.to_be_bytes());
                buf[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
                buf[4..4 + data.len()].copy_from_slice(data);
                4 + data.len()
            }
            Dhcpv6Option::Unknown(opt_type, data) => {
                buf[0..2].copy_from_slice(&opt_type.to_be_bytes());
                buf[2..4].copy_from_slice(&(data.len() as u16).to_be_bytes());
                buf[4..4 + data.len()].copy_from_slice(data);
                4 + data.len()
            }
        }
    }
}

/// Parse RFC 1035 encoded domain name list
fn parse_domain_list(data: &[u8]) -> Vec<String> {
    let mut domains = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let mut labels = Vec::new();
        loop {
            if pos >= data.len() {
                break;
            }
            let label_len = data[pos] as usize;
            pos += 1;
            if label_len == 0 {
                break;
            }
            if pos + label_len > data.len() {
                break;
            }
            labels.push(String::from_utf8_lossy(&data[pos..pos + label_len]).into_owned());
            pos += label_len;
        }
        if !labels.is_empty() {
            domains.push(labels.join("."));
        }
    }

    domains
}

/// Encode domain names in RFC 1035 format
fn encode_domain_list(domains: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for domain in domains {
        for label in domain.split('.') {
            let bytes = label.as_bytes();
            buf.push(bytes.len() as u8);
            buf.extend_from_slice(bytes);
        }
        buf.push(0); // Terminating zero-length label
    }
    buf
}
