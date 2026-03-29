use super::options::Dhcpv6Option;

/// DHCPv6 message types (RFC 8415)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcpv6MessageType {
    Solicit = 1,
    Advertise = 2,
    Request = 3,
    Confirm = 4,
    Renew = 5,
    Rebind = 6,
    Reply = 7,
    Release = 8,
    Decline = 9,
    Reconfigure = 10,
    InformationRequest = 11,
    RelayForward = 12,
    RelayReply = 13,
}

impl Dhcpv6MessageType {
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

    pub fn is_relay(&self) -> bool {
        matches!(self, Self::RelayForward | Self::RelayReply)
    }
}

/// A parsed DHCPv6 client/server message
#[derive(Debug)]
pub struct Dhcpv6Message {
    pub msg_type: Dhcpv6MessageType,
    pub transaction_id: [u8; 3],
    pub options: Vec<Dhcpv6Option>,
}

/// A parsed DHCPv6 relay message
#[derive(Debug)]
pub struct Dhcpv6RelayMessage {
    pub msg_type: Dhcpv6MessageType,
    pub hop_count: u8,
    pub link_address: [u8; 16],
    pub peer_address: [u8; 16],
    pub options: Vec<Dhcpv6Option>,
}

#[derive(Debug, thiserror::Error)]
pub enum Dhcpv6PacketError {
    #[error("packet too short: {0} bytes")]
    TooShort(usize),
    #[error("invalid message type: {0}")]
    BadMessageType(u8),
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
