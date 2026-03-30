use super::options::Dhcpv6Option;

/// DHCPv6 message types (RFC 8415)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcpv6MessageType {
    /// Client sends to locate servers.
    Solicit = 1,
    /// Server responds to a Solicit with offered addresses.
    Advertise = 2,
    /// Client requests assigned addresses from a specific server.
    Request = 3,
    /// Client verifies its address is still appropriate for the link.
    Confirm = 4,
    /// Client extends lifetimes on assigned addresses (contacts same server).
    Renew = 5,
    /// Client extends lifetimes when it cannot reach the original server.
    Rebind = 6,
    /// Server responds to a Request, Renew, Rebind, Release, or Decline.
    Reply = 7,
    /// Client releases assigned addresses.
    Release = 8,
    /// Client indicates a duplicate address was detected.
    Decline = 9,
    /// Server triggers the client to initiate a Renew/Reply or Information-request.
    Reconfigure = 10,
    /// Client requests configuration parameters without address assignment.
    InformationRequest = 11,
    /// Relay agent forwards a client message toward a server.
    RelayForward = 12,
    /// Server sends a response back through a relay agent.
    RelayReply = 13,
}

impl Dhcpv6MessageType {
    /// Convert a raw `u8` to a message type, returning `None` for unknown values.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Solicit),
            2 => Some(Self::Advertise),
            3 => Some(Self::Request),
            4 => Some(Self::Confirm),
            5 => Some(Self::Renew),
            6 => Some(Self::Rebind),
            7 => Some(Self::Reply),
            8 => Some(Self::Release),
            9 => Some(Self::Decline),
            10 => Some(Self::Reconfigure),
            11 => Some(Self::InformationRequest),
            12 => Some(Self::RelayForward),
            13 => Some(Self::RelayReply),
            _ => None,
        }
    }

    /// Returns `true` if this is a relay message type (RelayForward or RelayReply).
    pub fn is_relay(&self) -> bool {
        matches!(self, Self::RelayForward | Self::RelayReply)
    }
}

/// A parsed DHCPv6 client/server message
#[derive(Debug)]
pub struct Dhcpv6Message {
    /// The DHCPv6 message type (e.g. Solicit, Request, Reply).
    pub msg_type: Dhcpv6MessageType,
    /// 3-byte transaction ID linking requests to responses.
    pub transaction_id: [u8; 3],
    /// Parsed DHCPv6 options carried in this message.
    pub options: Vec<Dhcpv6Option>,
}

/// A parsed DHCPv6 relay message
#[derive(Debug)]
pub struct Dhcpv6RelayMessage {
    /// The relay message type (RelayForward or RelayReply).
    pub msg_type: Dhcpv6MessageType,
    /// Number of relay agents that have relayed this message.
    pub hop_count: u8,
    /// Address used by the relay to identify the link the client is on.
    pub link_address: [u8; 16],
    /// Source address of the message from the client or relay.
    pub peer_address: [u8; 16],
    /// Parsed DHCPv6 options carried in this relay message.
    pub options: Vec<Dhcpv6Option>,
}

/// Errors that can occur when parsing a DHCPv6 packet.
#[derive(Debug, thiserror::Error)]
pub enum Dhcpv6PacketError {
    /// Packet is too short to contain a valid header.
    #[error("packet too short: {0} bytes")]
    TooShort(usize),
    /// The message-type byte is not a recognized DHCPv6 type.
    #[error("invalid message type: {0}")]
    BadMessageType(u8),
    /// An option TLV is truncated or has an invalid length.
    #[error("malformed option at offset {0}")]
    MalformedOption(usize),
}

/// Minimum DHCPv6 client/server message size (1 byte type + 3 bytes transaction ID)
const MIN_MSG_SIZE: usize = 4;

/// Minimum DHCPv6 relay message size (1 byte type + 1 byte hop + 16 + 16 bytes addresses)
const MIN_RELAY_SIZE: usize = 34;

impl Dhcpv6Message {
    /// Parse a DHCPv6 client/server message from bytes
    pub fn parse(data: &[u8]) -> Result<Self, Dhcpv6PacketError> {
        if data.len() < MIN_MSG_SIZE {
            return Err(Dhcpv6PacketError::TooShort(data.len()));
        }

        let msg_type =
            Dhcpv6MessageType::from_u8(data[0]).ok_or(Dhcpv6PacketError::BadMessageType(data[0]))?;

        if msg_type.is_relay() {
            return Err(Dhcpv6PacketError::BadMessageType(data[0]));
        }

        let mut transaction_id = [0u8; 3];
        transaction_id.copy_from_slice(&data[1..4]);

        let options = Dhcpv6Option::parse_all(&data[4..])?;

        Ok(Self {
            msg_type,
            transaction_id,
            options,
        })
    }

    /// Serialize this message into a buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.msg_type as u8;
        buf[1..4].copy_from_slice(&self.transaction_id);

        let opts_len = Dhcpv6Option::serialize_all(&self.options, &mut buf[4..]);

        4 + opts_len
    }

    /// Get the client ID (DUID) from options
    pub fn client_id(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| {
            if let Dhcpv6Option::ClientId(data) = o {
                Some(data.as_slice())
            } else {
                None
            }
        })
    }

    /// Get the server ID (DUID) from options
    pub fn server_id(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| {
            if let Dhcpv6Option::ServerId(data) = o {
                Some(data.as_slice())
            } else {
                None
            }
        })
    }

    /// Check if rapid commit is requested
    pub fn has_rapid_commit(&self) -> bool {
        self.options
            .iter()
            .any(|o| matches!(o, Dhcpv6Option::RapidCommit))
    }
}

impl Dhcpv6RelayMessage {
    /// Parse a DHCPv6 relay message from bytes
    pub fn parse(data: &[u8]) -> Result<Self, Dhcpv6PacketError> {
        if data.len() < MIN_RELAY_SIZE {
            return Err(Dhcpv6PacketError::TooShort(data.len()));
        }

        let msg_type =
            Dhcpv6MessageType::from_u8(data[0]).ok_or(Dhcpv6PacketError::BadMessageType(data[0]))?;

        if !msg_type.is_relay() {
            return Err(Dhcpv6PacketError::BadMessageType(data[0]));
        }

        let hop_count = data[1];

        let mut link_address = [0u8; 16];
        link_address.copy_from_slice(&data[2..18]);

        let mut peer_address = [0u8; 16];
        peer_address.copy_from_slice(&data[18..34]);

        let options = Dhcpv6Option::parse_all(&data[34..])?;

        Ok(Self {
            msg_type,
            hop_count,
            link_address,
            peer_address,
            options,
        })
    }

    /// Serialize this relay message into a buffer. Returns bytes written.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = self.msg_type as u8;
        buf[1] = self.hop_count;
        buf[2..18].copy_from_slice(&self.link_address);
        buf[18..34].copy_from_slice(&self.peer_address);

        let opts_len = Dhcpv6Option::serialize_all(&self.options, &mut buf[34..]);

        34 + opts_len
    }

    /// Get the relay message option (contains the inner client message)
    pub fn relay_message(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| {
            if let Dhcpv6Option::RelayMessage(data) = o {
                Some(data.as_slice())
            } else {
                None
            }
        })
    }

    /// Get the interface ID option
    pub fn interface_id(&self) -> Option<&[u8]> {
        self.options.iter().find_map(|o| {
            if let Dhcpv6Option::InterfaceId(data) = o {
                Some(data.as_slice())
            } else {
                None
            }
        })
    }
}
