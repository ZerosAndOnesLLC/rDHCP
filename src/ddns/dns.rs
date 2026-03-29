/// Minimal DNS message builder for RFC 2136 UPDATE messages.
/// Not a full DNS library — just enough for dynamic updates.

/// DNS record types
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum DnsType {
    A = 1,
    SOA = 6,
    PTR = 12,
    AAAA = 28,
}

/// DNS record classes
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum DnsClass {
    IN = 1,
    ANY = 255,
    NONE = 254,
}

/// DNS opcodes
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum DnsOpcode {
    Query = 0,
    Update = 5,
}

/// DNS response codes
#[derive(Debug, Clone, Copy)]
pub enum DnsRcode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Unknown(u8),
}

impl DnsRcode {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YXDomain,
            7 => Self::YXRRSet,
            8 => Self::NXRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            v => Self::Unknown(v),
        }
    }
}

/// A resource record for the update section
pub struct ResourceRecord {
    pub name: String,
    pub rr_type: DnsType,
    pub class: DnsClass,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// DNS UPDATE message builder
pub struct DnsMessage {
    id: u16,
    opcode: DnsOpcode,
    zones: Vec<(String, DnsType, DnsClass)>,
    prerequisites: Vec<ResourceRecord>,
    updates: Vec<ResourceRecord>,
}

impl DnsMessage {
    pub fn new(id: u16, opcode: DnsOpcode) -> Self {
        Self {
            id,
            opcode,
            zones: Vec::new(),
            prerequisites: Vec::new(),
            updates: Vec::new(),
        }
    }

    /// Add a zone (question section in UPDATE)
    pub fn add_zone(&mut self, name: &str, rr_type: DnsType, class: DnsClass) {
        self.zones.push((name.to_string(), rr_type, class));
    }

    /// Add an update record
    pub fn add_update(
        &mut self,
        name: &str,
        rr_type: DnsType,
        class: DnsClass,
        ttl: u32,
        rdata: &[u8],
    ) {
        self.updates.push(ResourceRecord {
            name: name.to_string(),
            rr_type,
            class,
            ttl,
            rdata: rdata.to_vec(),
        });
    }

    /// Encode the message to wire format
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        // Header (12 bytes)
        buf.extend_from_slice(&self.id.to_be_bytes());

        // Flags: QR=0, Opcode, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
        let flags: u16 = (self.opcode as u16) << 11;
        buf.extend_from_slice(&flags.to_be_bytes());

        // ZOCOUNT (question count)
        buf.extend_from_slice(&(self.zones.len() as u16).to_be_bytes());
        // PRCOUNT (prerequisite/answer count)
        buf.extend_from_slice(&(self.prerequisites.len() as u16).to_be_bytes());
        // UPCOUNT (update/authority count)
        buf.extend_from_slice(&(self.updates.len() as u16).to_be_bytes());
        // ADCOUNT (additional count)
        buf.extend_from_slice(&0u16.to_be_bytes());

        // Zone section
        for (name, rr_type, class) in &self.zones {
            buf.extend_from_slice(&encode_name(name));
            buf.extend_from_slice(&(*rr_type as u16).to_be_bytes());
            buf.extend_from_slice(&(*class as u16).to_be_bytes());
        }

        // Prerequisite section
        for rr in &self.prerequisites {
            encode_rr(&mut buf, rr);
        }

        // Update section
        for rr in &self.updates {
            encode_rr(&mut buf, rr);
        }

        buf
    }
}

/// Encode a domain name in DNS wire format (RFC 1035)
pub fn encode_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let name = name.trim_end_matches('.');

    for label in name.split('.') {
        let bytes = label.as_bytes();
        buf.push(bytes.len() as u8);
        buf.extend_from_slice(bytes);
    }
    buf.push(0); // Root label

    buf
}

/// Encode a resource record
fn encode_rr(buf: &mut Vec<u8>, rr: &ResourceRecord) {
    buf.extend_from_slice(&encode_name(&rr.name));
    buf.extend_from_slice(&(rr.rr_type as u16).to_be_bytes());
    buf.extend_from_slice(&(rr.class as u16).to_be_bytes());
    buf.extend_from_slice(&rr.ttl.to_be_bytes());
    buf.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
    buf.extend_from_slice(&rr.rdata);
}
