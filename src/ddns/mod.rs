mod dns;
mod tsig;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::DdnsConfig;
use dns::{DnsClass, DnsMessage, DnsOpcode, DnsRcode, DnsType, ResourceRecord};

/// DDNS update request
#[derive(Debug)]
pub enum DdnsRequest {
    /// Add records for a new/renewed lease
    Add {
        ip: IpAddr,
        hostname: String,
        ttl: u32,
    },
    /// Remove records for an expired/released lease
    Remove { ip: IpAddr, hostname: String },
}

/// DDNS update client
pub struct DdnsClient {
    config: Arc<DdnsConfig>,
    tx: mpsc::Sender<DdnsRequest>,
}

impl DdnsClient {
    /// Create a new DDNS client. Returns the client handle and starts the background worker.
    pub fn new(config: DdnsConfig) -> Self {
        let config = Arc::new(config);
        let (tx, rx) = mpsc::channel(256);

        let worker_config = config.clone();
        tokio::spawn(async move {
            ddns_worker(worker_config, rx).await;
        });

        Self { config, tx }
    }

    /// Queue an add (forward + reverse) DNS update
    pub async fn add(&self, ip: IpAddr, hostname: &str) {
        if !self.config.enabled {
            return;
        }

        let fqdn = self.make_fqdn(hostname);
        let ttl = self.config.ttl;

        let _ = self.tx.send(DdnsRequest::Add { ip, hostname: fqdn, ttl }).await;
    }

    /// Queue a remove (forward + reverse) DNS update
    pub async fn remove(&self, ip: IpAddr, hostname: &str) {
        if !self.config.enabled {
            return;
        }

        let fqdn = self.make_fqdn(hostname);
        let _ = self.tx.send(DdnsRequest::Remove { ip, hostname: fqdn }).await;
    }

    fn make_fqdn(&self, hostname: &str) -> String {
        if hostname.contains('.') {
            hostname.to_string()
        } else if let Some(ref zone) = self.config.forward_zone {
            format!("{}.{}", hostname, zone)
        } else {
            hostname.to_string()
        }
    }
}

/// Background worker that processes DDNS requests
async fn ddns_worker(config: Arc<DdnsConfig>, mut rx: mpsc::Receiver<DdnsRequest>) {
    let dns_server: SocketAddr = match &config.dns_server {
        Some(s) => match s.parse() {
            Ok(addr) => addr,
            Err(_) => {
                // Try as IP without port
                match s.parse::<IpAddr>() {
                    Ok(ip) => SocketAddr::new(ip, 53),
                    Err(e) => {
                        error!(error = %e, server = %s, "invalid DNS server address");
                        return;
                    }
                }
            }
        },
        None => {
            warn!("DDNS enabled but no dns_server configured");
            return;
        }
    };

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to bind DDNS socket");
            return;
        }
    };

    info!(server = %dns_server, "DDNS worker started");

    let tsig_key = config.tsig_key.as_deref().and_then(|key_name| {
        let secret = config.tsig_secret.as_deref()?;
        let algorithm = config
            .tsig_algorithm
            .as_deref()
            .unwrap_or("hmac-sha256");
        Some(tsig::TsigKey {
            name: key_name.to_string(),
            algorithm: algorithm.to_string(),
            secret: secret.to_string(),
        })
    });

    while let Some(request) = rx.recv().await {
        match request {
            DdnsRequest::Add { ip, hostname, ttl } => {
                // Forward record (A or AAAA)
                let forward_zone = config.forward_zone.as_deref().unwrap_or("");
                if !forward_zone.is_empty() {
                    let rr_type = match ip {
                        IpAddr::V4(_) => DnsType::A,
                        IpAddr::V6(_) => DnsType::AAAA,
                    };

                    let update = build_update(
                        forward_zone,
                        &hostname,
                        rr_type,
                        DnsClass::IN,
                        ttl,
                        &ip_to_rdata(&ip),
                        false,
                        tsig_key.as_ref(),
                    );

                    if let Err(e) = send_update(&socket, &dns_server, &update).await {
                        warn!(hostname = %hostname, ip = %ip, error = %e, "forward DDNS update failed");
                    } else {
                        debug!(hostname = %hostname, ip = %ip, "forward DDNS record added");
                    }
                }

                // Reverse record (PTR)
                let reverse_zone = match ip {
                    IpAddr::V4(_) => config.reverse_zone_v4.as_deref(),
                    IpAddr::V6(_) => config.reverse_zone_v6.as_deref(),
                };

                if let Some(rev_zone) = reverse_zone {
                    let ptr_name = reverse_name(&ip);
                    let ptr_data = dns::encode_name(&format!("{}.", hostname));

                    let update = build_update(
                        rev_zone,
                        &ptr_name,
                        DnsType::PTR,
                        DnsClass::IN,
                        ttl,
                        &ptr_data,
                        false,
                        tsig_key.as_ref(),
                    );

                    if let Err(e) = send_update(&socket, &dns_server, &update).await {
                        warn!(ip = %ip, error = %e, "reverse DDNS update failed");
                    } else {
                        debug!(ip = %ip, hostname = %hostname, "reverse DDNS record added");
                    }
                }
            }
            DdnsRequest::Remove { ip, hostname } => {
                // Remove forward record
                let forward_zone = config.forward_zone.as_deref().unwrap_or("");
                if !forward_zone.is_empty() {
                    let rr_type = match ip {
                        IpAddr::V4(_) => DnsType::A,
                        IpAddr::V6(_) => DnsType::AAAA,
                    };

                    let update = build_update(
                        forward_zone,
                        &hostname,
                        rr_type,
                        DnsClass::ANY,
                        0,
                        &[],
                        true,
                        tsig_key.as_ref(),
                    );

                    if let Err(e) = send_update(&socket, &dns_server, &update).await {
                        warn!(hostname = %hostname, error = %e, "forward DDNS delete failed");
                    } else {
                        debug!(hostname = %hostname, "forward DDNS record removed");
                    }
                }

                // Remove reverse record
                let reverse_zone = match ip {
                    IpAddr::V4(_) => config.reverse_zone_v4.as_deref(),
                    IpAddr::V6(_) => config.reverse_zone_v6.as_deref(),
                };

                if let Some(rev_zone) = reverse_zone {
                    let ptr_name = reverse_name(&ip);

                    let update = build_update(
                        rev_zone,
                        &ptr_name,
                        DnsType::PTR,
                        DnsClass::ANY,
                        0,
                        &[],
                        true,
                        tsig_key.as_ref(),
                    );

                    if let Err(e) = send_update(&socket, &dns_server, &update).await {
                        warn!(ip = %ip, error = %e, "reverse DDNS delete failed");
                    } else {
                        debug!(ip = %ip, "reverse DDNS record removed");
                    }
                }
            }
        }
    }
}

/// Build a DNS UPDATE message (RFC 2136)
fn build_update(
    zone: &str,
    name: &str,
    rr_type: DnsType,
    class: DnsClass,
    ttl: u32,
    rdata: &[u8],
    is_delete: bool,
    tsig_key: Option<&tsig::TsigKey>,
) -> Vec<u8> {
    let id = (epoch_now() & 0xFFFF) as u16;

    let mut msg = DnsMessage::new(id, DnsOpcode::Update);

    // Zone section (question)
    msg.add_zone(zone, DnsType::SOA, DnsClass::IN);

    if is_delete {
        // Delete RRset: class=ANY, ttl=0, rdlength=0
        msg.add_update(name, rr_type, DnsClass::ANY, 0, &[]);
    } else {
        // Add RR: class=IN, ttl, rdata
        msg.add_update(name, rr_type, class, ttl, rdata);
    }

    let mut buf = msg.encode();

    // Sign with TSIG if configured
    if let Some(key) = tsig_key {
        tsig::sign_message(&mut buf, key, id);
    }

    buf
}

/// Send a DNS UPDATE and check the response
async fn send_update(
    socket: &UdpSocket,
    server: &SocketAddr,
    message: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    socket.send_to(message, server).await?;

    let mut response_buf = [0u8; 512];
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut response_buf),
    )
    .await
    .map_err(|_| "DNS update timeout")?;

    let (len, _) = timeout?;

    if len < 12 {
        return Err("DNS response too short".into());
    }

    // Check response code (bits 12-15 of flags)
    let rcode = response_buf[3] & 0x0F;
    match DnsRcode::from_u8(rcode) {
        DnsRcode::NoError => Ok(()),
        DnsRcode::YXRRSet => Ok(()), // Record already exists, acceptable
        other => Err(format!("DNS update failed: {:?}", other).into()),
    }
}

/// Convert IP to reverse DNS name
fn reverse_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mut nibbles = Vec::with_capacity(64);
            for &byte in octets.iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0F));
                nibbles.push(format!("{:x}", (byte >> 4) & 0x0F));
            }
            // Reverse the nibbles (we built them backwards)
            nibbles.reverse();
            // Actually the reverse iteration already gives us the right order for ip6.arpa
            // Re-reverse to fix:
            let octets = v6.octets();
            let mut parts = Vec::with_capacity(32);
            for &byte in octets.iter().rev() {
                parts.push(format!("{:x}", byte & 0x0F));
                parts.push(format!("{:x}", (byte >> 4) & 0x0F));
            }
            format!("{}.ip6.arpa", parts.join("."))
        }
    }
}

fn ip_to_rdata(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
