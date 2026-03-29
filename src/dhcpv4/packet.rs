use std::net::Ipv4Addr;

use super::options::{DhcpOption, MessageType};

/// DHCPv4 packet offsets (RFC 2131)
const OP_OFFSET: usize = 0;
const HTYPE_OFFSET: usize = 1;
const HLEN_OFFSET: usize = 2;
const HOPS_OFFSET: usize = 3;
const XID_OFFSET: usize = 4;
const SECS_OFFSET: usize = 8;
const FLAGS_OFFSET: usize = 10;
const CIADDR_OFFSET: usize = 12;
const YIADDR_OFFSET: usize = 16;
const SIADDR_OFFSET: usize = 20;
const GIADDR_OFFSET: usize = 24;
const CHADDR_OFFSET: usize = 28;
const SNAME_OFFSET: usize = 44;
const FILE_OFFSET: usize = 108;
/// Magic cookie starts at byte 236 (after 236 bytes of fixed fields)
const COOKIE_OFFSET: usize = 236;
/// Options start after the 4-byte magic cookie
const OPTIONS_OFFSET: usize = 240;

/// Minimum DHCP packet size (fixed fields + magic cookie)
const MIN_PACKET_SIZE: usize = 240;

/// DHCP magic cookie: 99.130.83.99
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// BOOTP op codes
const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;

/// Hardware type: Ethernet
const HTYPE_ETHERNET: u8 = 1;

/// Broadcast flag
const FLAG_BROADCAST: u16 = 0x8000;

/// Maximum DHCP packet size we'll handle
pub const MAX_PACKET_SIZE: usize = 1500;

/// A parsed DHCPv4 packet. References the original buffer for zero-copy field access
/// where possible, but copies variable-length data (options) for safe ownership.
#[derive(Debug)]
pub struct DhcpV4Packet {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: [u8; 64],
    pub file: [u8; 128],
    pub options: Vec<DhcpOption>,
}

#[derive(Debug, thiserror::Error)]
pub enum PacketError {
    #[error("packet too short: {0} bytes (minimum {MIN_PACKET_SIZE})")]
    TooShort(usize),
    #[error("invalid magic cookie")]
    BadMagicCookie,
    #[error("invalid op code: {0}")]
    BadOpCode(u8),
    #[error("malformed option at offset {0}")]
    MalformedOption(usize),
    #[error("missing message type option")]
    MissingMessageType,
}

impl DhcpV4Packet {
    /// Parse a DHCPv4 packet from a byte buffer
    pub fn parse(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::TooShort(data.len()));
        }

        // Verify magic cookie at bytes 236-239
        if data[COOKIE_OFFSET..COOKIE_OFFSET + 4] != MAGIC_COOKIE {
            return Err(PacketError::BadMagicCookie);
        }

        let op = data[OP_OFFSET];
        if op != BOOTREQUEST && op != BOOTREPLY {
            return Err(PacketError::BadOpCode(op));
        }

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&data[CHADDR_OFFSET..CHADDR_OFFSET + 16]);

        let mut sname = [0u8; 64];
        sname.copy_from_slice(&data[SNAME_OFFSET..SNAME_OFFSET + 64]);

        let mut file = [0u8; 128];
        file.copy_from_slice(&data[FILE_OFFSET..FILE_OFFSET + 128]);

        // Parse options
        let options = DhcpOption::parse_all(&data[OPTIONS_OFFSET..])?;

        Ok(Self {
            op,
            htype: data[HTYPE_OFFSET],
            hlen: data[HLEN_OFFSET],
            hops: data[HOPS_OFFSET],
            xid: u32::from_be_bytes([
                data[XID_OFFSET],
                data[XID_OFFSET + 1],
                data[XID_OFFSET + 2],
                data[XID_OFFSET + 3],
            ]),
            secs: u16::from_be_bytes([data[SECS_OFFSET], data[SECS_OFFSET + 1]]),
            flags: u16::from_be_bytes([data[FLAGS_OFFSET], data[FLAGS_OFFSET + 1]]),
            ciaddr: Ipv4Addr::new(
                data[CIADDR_OFFSET],
                data[CIADDR_OFFSET + 1],
                data[CIADDR_OFFSET + 2],
                data[CIADDR_OFFSET + 3],
            ),
            yiaddr: Ipv4Addr::new(
                data[YIADDR_OFFSET],
                data[YIADDR_OFFSET + 1],
                data[YIADDR_OFFSET + 2],
                data[YIADDR_OFFSET + 3],
            ),
            siaddr: Ipv4Addr::new(
                data[SIADDR_OFFSET],
                data[SIADDR_OFFSET + 1],
                data[SIADDR_OFFSET + 2],
                data[SIADDR_OFFSET + 3],
            ),
            giaddr: Ipv4Addr::new(
                data[GIADDR_OFFSET],
                data[GIADDR_OFFSET + 1],
                data[GIADDR_OFFSET + 2],
                data[GIADDR_OFFSET + 3],
            ),
            chaddr,
            sname,
            file,
            options,
        })
    }

    /// Serialize this packet into a pre-allocated buffer.
    /// Returns the number of bytes written.
    pub fn serialize(&self, buf: &mut [u8; MAX_PACKET_SIZE]) -> usize {
        // Zero the buffer
        buf.fill(0);

        buf[OP_OFFSET] = self.op;
        buf[HTYPE_OFFSET] = self.htype;
        buf[HLEN_OFFSET] = self.hlen;
        buf[HOPS_OFFSET] = self.hops;

        buf[XID_OFFSET..XID_OFFSET + 4].copy_from_slice(&self.xid.to_be_bytes());
        buf[SECS_OFFSET..SECS_OFFSET + 2].copy_from_slice(&self.secs.to_be_bytes());
        buf[FLAGS_OFFSET..FLAGS_OFFSET + 2].copy_from_slice(&self.flags.to_be_bytes());

        buf[CIADDR_OFFSET..CIADDR_OFFSET + 4].copy_from_slice(&self.ciaddr.octets());
        buf[YIADDR_OFFSET..YIADDR_OFFSET + 4].copy_from_slice(&self.yiaddr.octets());
        buf[SIADDR_OFFSET..SIADDR_OFFSET + 4].copy_from_slice(&self.siaddr.octets());
        buf[GIADDR_OFFSET..GIADDR_OFFSET + 4].copy_from_slice(&self.giaddr.octets());

        buf[CHADDR_OFFSET..CHADDR_OFFSET + 16].copy_from_slice(&self.chaddr);
        buf[SNAME_OFFSET..SNAME_OFFSET + 64].copy_from_slice(&self.sname);
        buf[FILE_OFFSET..FILE_OFFSET + 128].copy_from_slice(&self.file);

        // Magic cookie at bytes 236-239
        buf[COOKIE_OFFSET..COOKIE_OFFSET + 4].copy_from_slice(&MAGIC_COOKIE);

        // Serialize options
        let opts_len = DhcpOption::serialize_all(&self.options, &mut buf[OPTIONS_OFFSET..]);

        // End option
        buf[OPTIONS_OFFSET + opts_len] = 255;

        OPTIONS_OFFSET + opts_len + 1
    }

    /// Get the 6-byte MAC address from chaddr (assuming Ethernet)
    pub fn mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&self.chaddr[..6]);
        mac
    }

    /// Get the DHCP message type from options
    pub fn message_type(&self) -> Option<MessageType> {
        self.options.iter().find_map(|o| {
            if let DhcpOption::MessageType(mt) = o {
                Some(*mt)
            } else {
                None
            }
        })
    }

    /// Get the requested IP address from options (option 50)
    pub fn requested_ip(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|o| {
            if let DhcpOption::RequestedIp(ip) = o {
                Some(*ip)
            } else {
                None
            }
        })
    }

    /// Get the server identifier from options (option 54)
    pub fn server_id(&self) -> Option<Ipv4Addr> {
        self.options.iter().find_map(|o| {
            if let DhcpOption::ServerIdentifier(ip) = o {
                Some(*ip)
            } else {
                None
            }
        })
    }

    /// Get the parameter request list (option 55)
    pub fn parameter_request_list(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| {
            if let DhcpOption::ParameterRequestList(list) = o {
                Some(list.as_slice())
            } else {
                None
            }
        })
    }

    /// Get the client identifier (option 61)
    pub fn client_id(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| {
            if let DhcpOption::ClientIdentifier(id) = o {
                Some(id.as_slice())
            } else {
                None
            }
        })
    }

    /// Get the hostname (option 12)
    pub fn hostname(&self) -> Option<&str> {
        self.options.iter().find_map(|o| {
            if let DhcpOption::Hostname(name) = o {
                Some(name.as_str())
            } else {
                None
            }
        })
    }

    /// Get relay agent info (option 82)
    pub fn relay_agent_info(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| {
            if let DhcpOption::RelayAgentInfo(data) = o {
                Some(data.as_slice())
            } else {
                None
            }
        })
    }

    /// Check if client requests broadcast responses
    pub fn wants_broadcast(&self) -> bool {
        self.flags & FLAG_BROADCAST != 0
    }

    /// Is this a relayed packet?
    pub fn is_relayed(&self) -> bool {
        !self.giaddr.is_unspecified()
    }

    /// Build a reply packet from this request
    pub fn build_reply(
        &self,
        msg_type: MessageType,
        yiaddr: Ipv4Addr,
        siaddr: Ipv4Addr,
        options: Vec<DhcpOption>,
    ) -> Self {
        let mut reply_options = vec![DhcpOption::MessageType(msg_type)];
        reply_options.extend(options);

        Self {
            op: BOOTREPLY,
            htype: self.htype,
            hlen: self.hlen,
            hops: 0,
            xid: self.xid,
            secs: 0,
            flags: self.flags,
            ciaddr: if msg_type == MessageType::Ack
                && !self.ciaddr.is_unspecified()
            {
                self.ciaddr
            } else {
                Ipv4Addr::UNSPECIFIED
            },
            yiaddr,
            siaddr,
            giaddr: self.giaddr,
            chaddr: self.chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            options: reply_options,
        }
    }
}
