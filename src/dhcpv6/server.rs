use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use super::options::{
    Dhcpv6Option, IaAddr, IaNa, IaPd, IaPrefix, StatusCode,
};
use super::packet::{Dhcpv6Message, Dhcpv6MessageType, Dhcpv6RelayMessage};
use crate::allocator::SubnetAllocator;
use crate::config::validation::{ip_in_subnet, parse_cidr};
use crate::config::{Config, SubnetConfig};
use crate::ha::HaBackend;
use crate::lease::store::LeaseStore;
use crate::lease::types::{Lease, LeaseState};
use crate::ratelimit::{GlobalRateLimiter, RateLimiter, RogueDetector};
use crate::wal::Wal;

/// Maximum DHCPv6 packet size
const MAX_DHCPV6_SIZE: usize = 1500;

/// DUID type: DUID-EN (Enterprise Number based) — we use type 2 (DUID-EN)
/// with Anthropic's PEN placeholder. In production, use DUID-LLT from the server MAC.
const DUID_TYPE_LLT: u16 = 1;

/// DHCPv6 server
pub struct DhcpV6Server<H: HaBackend> {
    lease_store: LeaseStore,
    allocators: Arc<HashMap<String, SubnetAllocator>>,
    wal: Arc<Wal>,
    ha: Arc<H>,
    /// Server DUID (persistent identity)
    server_duid: Vec<u8>,
    /// Parsed v6 subnet info
    subnets: Vec<V6SubnetInfo>,
    /// Per-client rate limiter (keyed by DUID)
    rate_limiter: Arc<RateLimiter>,
    /// Global rate limiter (None if disabled)
    global_rate_limiter: Option<Arc<GlobalRateLimiter>>,
    /// Rogue client detector
    rogue_detector: Arc<RogueDetector>,
}

#[derive(Clone)]
struct V6SubnetInfo {
    network: Arc<str>,
    network_addr: Ipv6Addr,
    prefix_len: u8,
    config: Arc<SubnetConfig>,
    is_pd: bool,
}

impl<H: HaBackend> DhcpV6Server<H> {
    /// Create a new DHCPv6 server, parsing IPv6 subnets from the config.
    pub fn new(
        config: Arc<Config>,
        lease_store: LeaseStore,
        allocators: Arc<HashMap<String, SubnetAllocator>>,
        wal: Arc<Wal>,
        ha: Arc<H>,
        server_duid: Vec<u8>,
        rate_limiter: Arc<RateLimiter>,
        global_rate_limiter: Option<Arc<GlobalRateLimiter>>,
        rogue_detector: Arc<RogueDetector>,
    ) -> Self {
        let subnets: Vec<V6SubnetInfo> = config
            .subnet
            .iter()
            .filter_map(|s| {
                let (addr, prefix_len) = parse_cidr(&s.network).ok()?;
                if let IpAddr::V6(v6) = addr {
                    Some(V6SubnetInfo {
                        network: Arc::from(s.network.as_str()),
                        network_addr: v6,
                        prefix_len,
                        config: Arc::new(s.clone()),
                        is_pd: s.subnet_type == "prefix-delegation",
                    })
                } else {
                    None
                }
            })
            .collect();

        Self {
            lease_store,
            allocators,
            wal,
            ha,
            server_duid,
            subnets,
            rate_limiter,
            global_rate_limiter,
            rogue_detector,
        }
    }

    /// Run the DHCPv6 server loop
    pub async fn run(
        &self,
        socket: Arc<UdpSocket>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut recv_buf = [0u8; MAX_DHCPV6_SIZE];

        info!(addr = %socket.local_addr()?, "DHCPv6 server listening");

        loop {
            let (len, src_addr) = match socket.recv_from(&mut recv_buf).await {
                Ok(r) => r,
                Err(e) => {
                    error!(error = %e, "failed to receive DHCPv6 packet");
                    continue;
                }
            };

            let data = &recv_buf[..len];

            if data.is_empty() {
                continue;
            }

            // Global rate limiting
            if let Some(ref global_rl) = self.global_rate_limiter {
                if !global_rl.check() {
                    debug!("DHCPv6 packet dropped by global rate limiter");
                    continue;
                }
            }

            // Check if this is a relay message
            let msg_type_byte = data[0];
            let is_relay = msg_type_byte == Dhcpv6MessageType::RelayForward as u8;

            let result = if is_relay {
                self.handle_relay(data, src_addr).await
            } else {
                self.handle_client_message(data, src_addr).await
            };

            match result {
                Ok(Some((reply_data, dest))) => {
                    if let Err(e) = socket.send_to(&reply_data, dest).await {
                        error!(error = %e, dest = %dest, "failed to send DHCPv6 reply");
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(error = %e, src = %src_addr, "error handling DHCPv6 packet");
                }
            }
        }
    }

    /// Handle a direct client message
    async fn handle_client_message(
        &self,
        data: &[u8],
        src_addr: SocketAddr,
    ) -> Result<Option<(Vec<u8>, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
        let msg = Dhcpv6Message::parse(data)?;

        // Per-client rate limiting using DUID
        if let Some(client_id) = msg.client_id() {
            if !self.rate_limiter.check(client_id) {
                debug!("DHCPv6 packet dropped by per-client rate limiter");
                return Ok(None);
            }
            let label = client_id.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            if !self.rogue_detector.record(client_id, &label) {
                debug!("DHCPv6 packet dropped by rogue detector");
                return Ok(None);
            }
        }

        debug!(
            msg_type = ?msg.msg_type,
            "received DHCPv6 {:?}",
            msg.msg_type
        );

        let reply = match msg.msg_type {
            Dhcpv6MessageType::Solicit => self.handle_solicit(&msg, None).await?,
            Dhcpv6MessageType::Request => self.handle_request(&msg).await?,
            Dhcpv6MessageType::Renew => self.handle_renew(&msg).await?,
            Dhcpv6MessageType::Rebind => self.handle_rebind(&msg).await?,
            Dhcpv6MessageType::Release => self.handle_release(&msg).await?,
            Dhcpv6MessageType::Decline => self.handle_decline(&msg).await?,
            Dhcpv6MessageType::Confirm => self.handle_confirm(&msg).await?,
            Dhcpv6MessageType::InformationRequest => self.handle_information_request(&msg).await?,
            _ => return Ok(None),
        };

        match reply {
            Some(reply_msg) => {
                let mut buf = [0u8; MAX_DHCPV6_SIZE];
                let len = reply_msg.serialize(&mut buf);

                let dest = SocketAddr::new(src_addr.ip(), 546);
                Ok(Some((buf[..len].to_vec(), dest)))
            }
            None => Ok(None),
        }
    }

    /// Handle a relay-forward message — unwrap, process, wrap in relay-reply
    async fn handle_relay(
        &self,
        data: &[u8],
        src_addr: SocketAddr,
    ) -> Result<Option<(Vec<u8>, SocketAddr)>, Box<dyn std::error::Error + Send + Sync>> {
        let relay_msg = Dhcpv6RelayMessage::parse(data)?;

        // RFC 8415 §5.2: drop if hop count exceeds 32
        if relay_msg.hop_count > 32 {
            warn!(hop_count = relay_msg.hop_count, "dropping relay with excessive hop count");
            return Ok(None);
        }

        let inner_data = match relay_msg.relay_message() {
            Some(d) => d,
            None => return Ok(None),
        };

        let link_addr = Ipv6Addr::from(relay_msg.link_address);

        // Parse inner client message
        let client_msg = Dhcpv6Message::parse(inner_data)?;

        debug!(
            msg_type = ?client_msg.msg_type,
            link_addr = %link_addr,
            "received relayed DHCPv6 {:?}",
            client_msg.msg_type
        );

        let reply = match client_msg.msg_type {
            Dhcpv6MessageType::Solicit => {
                self.handle_solicit(&client_msg, Some(link_addr)).await?
            }
            Dhcpv6MessageType::Request => self.handle_request(&client_msg).await?,
            Dhcpv6MessageType::Renew => self.handle_renew(&client_msg).await?,
            Dhcpv6MessageType::Rebind => self.handle_rebind(&client_msg).await?,
            Dhcpv6MessageType::Release => self.handle_release(&client_msg).await?,
            Dhcpv6MessageType::Decline => self.handle_decline(&client_msg).await?,
            Dhcpv6MessageType::Confirm => self.handle_confirm(&client_msg).await?,
            Dhcpv6MessageType::InformationRequest => {
                self.handle_information_request(&client_msg).await?
            }
            _ => return Ok(None),
        };

        match reply {
            Some(reply_msg) => {
                // Serialize inner reply on stack
                let mut inner_buf = [0u8; MAX_DHCPV6_SIZE];
                let inner_len = reply_msg.serialize(&mut inner_buf);

                // Wrap in relay-reply — RFC 8415 §5.2: relay-reply copies
                // hop_count, link-address, peer-address from relay-forward
                let relay_reply = Dhcpv6RelayMessage {
                    msg_type: Dhcpv6MessageType::RelayReply,
                    hop_count: relay_msg.hop_count,
                    link_address: relay_msg.link_address,
                    peer_address: relay_msg.peer_address,
                    options: {
                        let mut opts = vec![Dhcpv6Option::RelayMessage(inner_buf[..inner_len].to_vec())];
                        if let Some(iid) = relay_msg.interface_id() {
                            opts.push(Dhcpv6Option::InterfaceId(iid.to_vec()));
                        }
                        opts
                    },
                };

                let mut buf = [0u8; MAX_DHCPV6_SIZE];
                let len = relay_reply.serialize(&mut buf);

                let dest = SocketAddr::new(src_addr.ip(), 547);
                Ok(Some((buf[..len].to_vec(), dest)))
            }
            None => Ok(None),
        }
    }

    /// Handle Solicit — allocate address/prefix, send Advertise (or Reply with rapid commit)
    async fn handle_solicit(
        &self,
        msg: &Dhcpv6Message,
        link_addr: Option<Ipv6Addr>,
    ) -> Result<Option<Dhcpv6Message>, Box<dyn std::error::Error + Send + Sync>> {
        let client_id = match msg.client_id() {
            Some(c) => c.to_vec(),
            None => return Ok(None),
        };

        let rapid_commit = msg.has_rapid_commit();
        let reply_type = if rapid_commit {
            Dhcpv6MessageType::Reply
        } else {
            Dhcpv6MessageType::Advertise
        };

        let mut reply_options: Vec<Dhcpv6Option> = vec![
            Dhcpv6Option::ClientId(client_id.clone()),
            Dhcpv6Option::ServerId(self.server_duid.clone()),
        ];

        if rapid_commit {
            reply_options.push(Dhcpv6Option::RapidCommit);
        }

        // Process each IA_NA in the request
        for opt in &msg.options {
            if let Dhcpv6Option::IaNa(ia) = opt {
                let ia_reply = self
                    .allocate_ia_na(ia, &client_id, link_addr, rapid_commit)
                    .await?;
                reply_options.push(Dhcpv6Option::IaNa(ia_reply));
            }
        }

        // Process each IA_PD in the request
        for opt in &msg.options {
            if let Dhcpv6Option::IaPd(ia) = opt {
                let ia_reply = self
                    .allocate_ia_pd(ia, &client_id, rapid_commit)
                    .await?;
                reply_options.push(Dhcpv6Option::IaPd(ia_reply));
            }
        }

        // Add DNS servers from first matching subnet
        self.add_dns_options(&mut reply_options, link_addr);

        Ok(Some(Dhcpv6Message {
            msg_type: reply_type,
            transaction_id: msg.transaction_id,
            options: reply_options,
        }))
    }

    /// Handle Request — confirm address assignment
    async fn handle_request(
        &self,
        msg: &Dhcpv6Message,
    ) -> Result<Option<Dhcpv6Message>, Box<dyn std::error::Error + Send + Sync>> {
        // Verify server ID matches us
        if let Some(server_id) = msg.server_id() {
            if server_id != self.server_duid {
                return Ok(None); // Not for us
            }
        }

        let client_id = match msg.client_id() {
            Some(c) => c.to_vec(),
            None => return Ok(None),
        };

        let mut reply_options: Vec<Dhcpv6Option> = vec![
            Dhcpv6Option::ClientId(client_id.clone()),
            Dhcpv6Option::ServerId(self.server_duid.clone()),
        ];

        // Process IA_NAs
        for opt in &msg.options {
            if let Dhcpv6Option::IaNa(ia) = opt {
                let ia_reply = self.confirm_ia_na(ia, &client_id).await?;
                reply_options.push(Dhcpv6Option::IaNa(ia_reply));
            }
        }

        // Process IA_PDs
        for opt in &msg.options {
            if let Dhcpv6Option::IaPd(ia) = opt {
                let ia_reply = self.confirm_ia_pd(ia, &client_id).await?;
                reply_options.push(Dhcpv6Option::IaPd(ia_reply));
            }
        }

        Ok(Some(Dhcpv6Message {
            msg_type: Dhcpv6MessageType::Reply,
            transaction_id: msg.transaction_id,
            options: reply_options,
        }))
    }

    /// Handle Renew
    async fn handle_renew(
        &self,
        msg: &Dhcpv6Message,
    ) -> Result<Option<Dhcpv6Message>, Box<dyn std::error::Error + Send + Sync>> {
        // Renew is essentially the same as Request for our purposes
        self.handle_request(msg).await
    }

    /// Handle Rebind
    async fn handle_rebind(
        &self,
        msg: &Dhcpv6Message,
    ) -> Result<Option<Dhcpv6Message>, Box<dyn std::error::Error + Send + Sync>> {
        let client_id = match msg.client_id() {
            Some(c) => c.to_vec(),
            None => return Ok(None),
        };

        let mut reply_options: Vec<Dhcpv6Option> = vec![
            Dhcpv6Option::ClientId(client_id.clone()),
            Dhcpv6Option::ServerId(self.server_duid.clone()),
        ];

        for opt in &msg.options {
            if let Dhcpv6Option::IaNa(ia) = opt {
                let ia_reply = self.confirm_ia_na(ia, &client_id).await?;
                reply_options.push(Dhcpv6Option::IaNa(ia_reply));
            }
        }

        for opt in &msg.options {
            if let Dhcpv6Option::IaPd(ia) = opt {
                let ia_reply = self.confirm_ia_pd(ia, &client_id).await?;
                reply_options.push(Dhcpv6Option::IaPd(ia_reply));
            }
        }

        Ok(Some(Dhcpv6Message {
            msg_type: Dhcpv6MessageType::Reply,
            transaction_id: msg.transaction_id,
            options: reply_options,
        }))
    }

    /// Handle Release
    async fn handle_release(
        &self,
        msg: &Dhcpv6Message,
    ) -> Result<Option<Dhcpv6Message>, Box<dyn std::error::Error + Send + Sync>> {
        let client_id = match msg.client_id() {
            Some(c) => c.to_vec(),
            None => return Ok(None),
        };

        // Release all addresses in IA_NAs
        for opt in &msg.options {
            if let Dhcpv6Option::IaNa(ia) = opt {
                for sub_opt in &ia.options {
                    if let Dhcpv6Option::IaAddr(ia_addr) = sub_opt {
                        let ip = IpAddr::V6(ia_addr.addr);
                        if let Some(existing) = self.lease_store.get(&ip) {
                            if existing.client_id.as_deref() == Some(&client_id) {
                                self.ha.release_lease(&ip).await?;
                                self.wal.log_remove(&ip).await?;
                                self.lease_store.remove(&ip);
                                self.release_ip(&ip);
                                info!(ip = %ia_addr.addr, "DHCPv6 lease released");
                            }
                        }
                    }
                }
            }
        }

        let reply_options = vec![
            Dhcpv6Option::ClientId(client_id),
            Dhcpv6Option::ServerId(self.server_duid.clone()),
            Dhcpv6Option::StatusCode(StatusCode::Success, String::new()),
        ];

        Ok(Some(Dhcpv6Message {
            msg_type: Dhcpv6MessageType::Reply,
            transaction_id: msg.transaction_id,
            options: reply_options,
        }))
    }

    /// Handle Decline
    async fn handle_decline(
        &self,
        msg: &Dhcpv6Message,
    ) -> Result<Option<Dhcpv6Message>, Box<dyn std::error::Error + Send + Sync>> {
        let client_id = match msg.client_id() {
            Some(c) => c.to_vec(),
            None => return Ok(None),
        };

        for opt in &msg.options {
            if let Dhcpv6Option::IaNa(ia) = opt {
                for sub_opt in &ia.options {
                    if let Dhcpv6Option::IaAddr(ia_addr) = sub_opt {
                        warn!(ip = %ia_addr.addr, "DHCPv6 address declined (possible conflict)");
                        // Mark as declined — keep allocated so it's not reassigned
                        let ip = IpAddr::V6(ia_addr.addr);
                        let now_epoch = epoch_now();
                        let lease = Lease {
                            ip,
                            mac: None,
                            client_id: Some(client_id.clone()),
                            hostname: None,
                            lease_time: 86400,
                            state: LeaseState::Declined,
                            start_time: now_epoch,
                            expire_time: now_epoch + 86400,
                            expires_at: Instant::now() + Duration::from_secs(86400),
                            subnet: Arc::from(""),
                        };
                        self.wal.log_upsert(&lease).await?;
                        self.lease_store.upsert(lease);
                    }
                }
            }
        }

        let reply_options = vec![
            Dhcpv6Option::ClientId(client_id),
            Dhcpv6Option::ServerId(self.server_duid.clone()),
            Dhcpv6Option::StatusCode(StatusCode::Success, String::new()),
        ];

        Ok(Some(Dhcpv6Message {
            msg_type: Dhcpv6MessageType::Reply,
            transaction_id: msg.transaction_id,
            options: reply_options,
        }))
    }

    /// Handle Confirm — validate that addresses are still on-link
    async fn handle_confirm(
        &self,
        msg: &Dhcpv6Message,
    ) -> Result<Option<Dhcpv6Message>, Box<dyn std::error::Error + Send + Sync>> {
        let client_id = match msg.client_id() {
            Some(c) => c.to_vec(),
            None => return Ok(None),
        };

        // Check all requested addresses are on-link
        let mut on_link = true;
        for opt in &msg.options {
            if let Dhcpv6Option::IaNa(ia) = opt {
                for sub_opt in &ia.options {
                    if let Dhcpv6Option::IaAddr(ia_addr) = sub_opt {
                        let found = self.subnets.iter().any(|s| {
                            !s.is_pd
                                && ip_in_subnet(
                                    &IpAddr::V6(ia_addr.addr),
                                    &IpAddr::V6(s.network_addr),
                                    s.prefix_len,
                                )
                        });
                        if !found {
                            on_link = false;
                            break;
                        }
                    }
                }
            }
        }

        let status = if on_link {
            StatusCode::Success
        } else {
            StatusCode::NotOnLink
        };

        let reply_options = vec![
            Dhcpv6Option::ClientId(client_id),
            Dhcpv6Option::ServerId(self.server_duid.clone()),
            Dhcpv6Option::StatusCode(status, String::new()),
        ];

        Ok(Some(Dhcpv6Message {
            msg_type: Dhcpv6MessageType::Reply,
            transaction_id: msg.transaction_id,
            options: reply_options,
        }))
    }

    /// Handle Information-Request — config options only, no addresses
    async fn handle_information_request(
        &self,
        msg: &Dhcpv6Message,
    ) -> Result<Option<Dhcpv6Message>, Box<dyn std::error::Error + Send + Sync>> {
        let client_id = msg.client_id().map(|c| c.to_vec());

        let mut reply_options: Vec<Dhcpv6Option> = Vec::new();
        if let Some(cid) = client_id {
            reply_options.push(Dhcpv6Option::ClientId(cid));
        }
        reply_options.push(Dhcpv6Option::ServerId(self.server_duid.clone()));

        self.add_dns_options(&mut reply_options, None);

        Ok(Some(Dhcpv6Message {
            msg_type: Dhcpv6MessageType::Reply,
            transaction_id: msg.transaction_id,
            options: reply_options,
        }))
    }

    /// Allocate an address for IA_NA
    async fn allocate_ia_na(
        &self,
        ia: &IaNa,
        client_id: &[u8],
        link_addr: Option<Ipv6Addr>,
        commit: bool,
    ) -> Result<IaNa, Box<dyn std::error::Error + Send + Sync>> {
        // Find matching address subnet
        let subnet = self
            .subnets
            .iter()
            .find(|s| {
                if s.is_pd {
                    return false;
                }
                if let Some(la) = link_addr {
                    ip_in_subnet(
                        &IpAddr::V6(la),
                        &IpAddr::V6(s.network_addr),
                        s.prefix_len,
                    )
                } else {
                    true // Direct client, use first v6 address subnet
                }
            })
            .cloned();

        let subnet = match subnet {
            Some(s) => s,
            None => {
                return Ok(IaNa {
                    iaid: ia.iaid,
                    t1: 0,
                    t2: 0,
                    options: vec![Dhcpv6Option::StatusCode(
                        StatusCode::NoAddrsAvail,
                        "no matching subnet".to_string(),
                    )],
                });
            }
        };

        // Check for existing lease
        if let Some(existing) = self.lease_store.get_by_client_id(client_id) {
            if existing.is_active() {
                if let IpAddr::V6(v6) = existing.ip {
                    let lease_time = subnet.config.lease_time;
                    let preferred = subnet.config.preferred_time.unwrap_or(lease_time / 2);
                    return Ok(IaNa {
                        iaid: ia.iaid,
                        t1: lease_time / 2,
                        t2: (lease_time as u64 * 7 / 8) as u32,
                        options: vec![Dhcpv6Option::IaAddr(IaAddr {
                            addr: v6,
                            preferred_lifetime: preferred,
                            valid_lifetime: lease_time,
                            options: vec![],
                        })],
                    });
                }
            }
        }

        // Allocate from pool
        let allocator = match self.allocators.get(&*subnet.network) {
            Some(a) => a,
            None => {
                return Ok(IaNa {
                    iaid: ia.iaid,
                    t1: 0,
                    t2: 0,
                    options: vec![Dhcpv6Option::StatusCode(
                        StatusCode::NoAddrsAvail,
                        "no pool configured".to_string(),
                    )],
                });
            }
        };

        let ip = match allocator.allocate() {
            Some(IpAddr::V6(v6)) => v6,
            _ => {
                return Ok(IaNa {
                    iaid: ia.iaid,
                    t1: 0,
                    t2: 0,
                    options: vec![Dhcpv6Option::StatusCode(
                        StatusCode::NoAddrsAvail,
                        "pool exhausted".to_string(),
                    )],
                });
            }
        };

        let lease_time = subnet.config.lease_time;
        let preferred = subnet.config.preferred_time.unwrap_or(lease_time / 2);

        if commit {
            let now_epoch = epoch_now();
            let lease = Lease {
                ip: IpAddr::V6(ip),
                mac: None,
                client_id: Some(client_id.to_vec()),
                hostname: None,
                lease_time,
                state: LeaseState::Bound,
                start_time: now_epoch,
                expire_time: now_epoch + lease_time as u64,
                expires_at: Instant::now() + Duration::from_secs(lease_time as u64),
                subnet: subnet.network.clone(),
            };

            self.ha.commit_lease(&lease).await?;
            self.wal.log_upsert(&lease).await?;
            self.lease_store.upsert(lease);

            info!(ip = %ip, subnet = %subnet.network, "DHCPv6 lease bound");
        }

        Ok(IaNa {
            iaid: ia.iaid,
            t1: lease_time / 2,
            t2: (lease_time as u64 * 7 / 8) as u32,
            options: vec![Dhcpv6Option::IaAddr(IaAddr {
                addr: ip,
                preferred_lifetime: preferred,
                valid_lifetime: lease_time,
                options: vec![],
            })],
        })
    }

    /// Allocate a prefix for IA_PD
    async fn allocate_ia_pd(
        &self,
        ia: &IaPd,
        client_id: &[u8],
        commit: bool,
    ) -> Result<IaPd, Box<dyn std::error::Error + Send + Sync>> {
        let subnet = self.subnets.iter().find(|s| s.is_pd).cloned();

        let subnet = match subnet {
            Some(s) => s,
            None => {
                return Ok(IaPd {
                    iaid: ia.iaid,
                    t1: 0,
                    t2: 0,
                    options: vec![Dhcpv6Option::StatusCode(
                        StatusCode::NoPrefixAvail,
                        "no PD subnet configured".to_string(),
                    )],
                });
            }
        };

        let delegated_length = subnet.config.delegated_length.unwrap_or(56);

        // For prefix delegation, we use the allocator but the "IP" represents
        // the prefix start address. Each allocation represents one delegated prefix.
        let allocator = match self.allocators.get(&*subnet.network) {
            Some(a) => a,
            None => {
                return Ok(IaPd {
                    iaid: ia.iaid,
                    t1: 0,
                    t2: 0,
                    options: vec![Dhcpv6Option::StatusCode(
                        StatusCode::NoPrefixAvail,
                        "no PD pool configured".to_string(),
                    )],
                });
            }
        };

        let prefix_ip = match allocator.allocate() {
            Some(IpAddr::V6(v6)) => v6,
            _ => {
                return Ok(IaPd {
                    iaid: ia.iaid,
                    t1: 0,
                    t2: 0,
                    options: vec![Dhcpv6Option::StatusCode(
                        StatusCode::NoPrefixAvail,
                        "prefix pool exhausted".to_string(),
                    )],
                });
            }
        };

        let lease_time = subnet.config.lease_time;
        let preferred = subnet.config.preferred_time.unwrap_or(lease_time / 2);

        if commit {
            let now_epoch = epoch_now();
            let lease = Lease {
                ip: IpAddr::V6(prefix_ip),
                mac: None,
                client_id: Some(client_id.to_vec()),
                hostname: None,
                lease_time,
                state: LeaseState::Bound,
                start_time: now_epoch,
                expire_time: now_epoch + lease_time as u64,
                expires_at: Instant::now() + Duration::from_secs(lease_time as u64),
                subnet: subnet.network.clone(),
            };

            self.ha.commit_lease(&lease).await?;
            self.wal.log_upsert(&lease).await?;
            self.lease_store.upsert(lease);

            info!(
                prefix = %prefix_ip,
                prefix_len = delegated_length,
                subnet = %subnet.network,
                "DHCPv6 prefix delegated"
            );
        }

        Ok(IaPd {
            iaid: ia.iaid,
            t1: lease_time / 2,
            t2: (lease_time as u64 * 7 / 8) as u32,
            options: vec![Dhcpv6Option::IaPrefix(IaPrefix {
                preferred_lifetime: preferred,
                valid_lifetime: lease_time,
                prefix_len: delegated_length,
                prefix: prefix_ip,
                options: vec![],
            })],
        })
    }

    /// Confirm/renew an IA_NA
    async fn confirm_ia_na(
        &self,
        ia: &IaNa,
        client_id: &[u8],
    ) -> Result<IaNa, Box<dyn std::error::Error + Send + Sync>> {
        let mut addr_options = Vec::new();

        for sub_opt in &ia.options {
            if let Dhcpv6Option::IaAddr(ia_addr) = sub_opt {
                let ip = IpAddr::V6(ia_addr.addr);

                // Find subnet for this address
                let subnet = self.subnets.iter().find(|s| {
                    !s.is_pd
                        && ip_in_subnet(&ip, &IpAddr::V6(s.network_addr), s.prefix_len)
                });

                let subnet = match subnet {
                    Some(s) => s,
                    None => {
                        addr_options.push(Dhcpv6Option::IaAddr(IaAddr {
                            addr: ia_addr.addr,
                            preferred_lifetime: 0,
                            valid_lifetime: 0,
                            options: vec![Dhcpv6Option::StatusCode(
                                StatusCode::NotOnLink,
                                String::new(),
                            )],
                        }));
                        continue;
                    }
                };

                let lease_time = subnet.config.lease_time;
                let preferred = subnet.config.preferred_time.unwrap_or(lease_time / 2);
                let now_epoch = epoch_now();

                let lease = Lease {
                    ip,
                    mac: None,
                    client_id: Some(client_id.to_vec()),
                    hostname: None,
                    lease_time,
                    state: LeaseState::Bound,
                    start_time: now_epoch,
                    expire_time: now_epoch + lease_time as u64,
                    expires_at: Instant::now() + Duration::from_secs(lease_time as u64),
                    subnet: subnet.network.clone(),
                };

                self.ha.commit_lease(&lease).await?;
                self.wal.log_upsert(&lease).await?;
                self.lease_store.upsert(lease);

                // Ensure allocator knows this IP is taken
                if let Some(allocator) = self.allocators.get(&*subnet.network) {
                    allocator.allocate_specific(&ip);
                }

                addr_options.push(Dhcpv6Option::IaAddr(IaAddr {
                    addr: ia_addr.addr,
                    preferred_lifetime: preferred,
                    valid_lifetime: lease_time,
                    options: vec![],
                }));

                info!(ip = %ia_addr.addr, "DHCPv6 lease renewed");
            }
        }

        let lease_time = self
            .subnets
            .iter()
            .find(|s| !s.is_pd)
            .map(|s| s.config.lease_time)
            .unwrap_or(86400);

        Ok(IaNa {
            iaid: ia.iaid,
            t1: lease_time / 2,
            t2: (lease_time as u64 * 7 / 8) as u32,
            options: addr_options,
        })
    }

    /// Confirm/renew an IA_PD
    async fn confirm_ia_pd(
        &self,
        ia: &IaPd,
        client_id: &[u8],
    ) -> Result<IaPd, Box<dyn std::error::Error + Send + Sync>> {
        let mut prefix_options = Vec::new();

        for sub_opt in &ia.options {
            if let Dhcpv6Option::IaPrefix(ia_prefix) = sub_opt {
                let ip = IpAddr::V6(ia_prefix.prefix);

                let subnet = self.subnets.iter().find(|s| s.is_pd);

                let subnet = match subnet {
                    Some(s) => s,
                    None => {
                        prefix_options.push(Dhcpv6Option::IaPrefix(IaPrefix {
                            preferred_lifetime: 0,
                            valid_lifetime: 0,
                            prefix_len: ia_prefix.prefix_len,
                            prefix: ia_prefix.prefix,
                            options: vec![Dhcpv6Option::StatusCode(
                                StatusCode::NoPrefixAvail,
                                String::new(),
                            )],
                        }));
                        continue;
                    }
                };

                let lease_time = subnet.config.lease_time;
                let preferred = subnet.config.preferred_time.unwrap_or(lease_time / 2);
                let now_epoch = epoch_now();

                let lease = Lease {
                    ip,
                    mac: None,
                    client_id: Some(client_id.to_vec()),
                    hostname: None,
                    lease_time,
                    state: LeaseState::Bound,
                    start_time: now_epoch,
                    expire_time: now_epoch + lease_time as u64,
                    expires_at: Instant::now() + Duration::from_secs(lease_time as u64),
                    subnet: subnet.network.clone(),
                };

                self.ha.commit_lease(&lease).await?;
                self.wal.log_upsert(&lease).await?;
                self.lease_store.upsert(lease);

                if let Some(allocator) = self.allocators.get(&*subnet.network) {
                    allocator.allocate_specific(&ip);
                }

                prefix_options.push(Dhcpv6Option::IaPrefix(IaPrefix {
                    preferred_lifetime: preferred,
                    valid_lifetime: lease_time,
                    prefix_len: ia_prefix.prefix_len,
                    prefix: ia_prefix.prefix,
                    options: vec![],
                }));
            }
        }

        let lease_time = self
            .subnets
            .iter()
            .find(|s| s.is_pd)
            .map(|s| s.config.lease_time)
            .unwrap_or(604800);

        Ok(IaPd {
            iaid: ia.iaid,
            t1: lease_time / 2,
            t2: (lease_time as u64 * 7 / 8) as u32,
            options: prefix_options,
        })
    }

    /// Add DNS-related options to a reply
    fn add_dns_options(
        &self,
        options: &mut Vec<Dhcpv6Option>,
        link_addr: Option<Ipv6Addr>,
    ) {
        // Find first matching v6 subnet for DNS config
        let subnet = if let Some(la) = link_addr {
            self.subnets.iter().find(|s| {
                !s.is_pd
                    && ip_in_subnet(
                        &IpAddr::V6(la),
                        &IpAddr::V6(s.network_addr),
                        s.prefix_len,
                    )
            })
        } else {
            self.subnets.iter().find(|s| !s.is_pd)
        };

        if let Some(subnet) = subnet {
            let dns_addrs: Vec<Ipv6Addr> = subnet
                .config
                .dns
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect();
            if !dns_addrs.is_empty() {
                options.push(Dhcpv6Option::DnsServers(dns_addrs));
            }

            if let Some(ref domain) = subnet.config.domain {
                options.push(Dhcpv6Option::DomainList(vec![domain.clone()]));
            }
        }
    }

    /// Release an IP back to the pool allocator
    fn release_ip(&self, ip: &IpAddr) {
        for (_, allocator) in self.allocators.iter() {
            if allocator.contains(ip) {
                allocator.release(ip);
                return;
            }
        }
    }
}

/// Generate a DUID-LLT (Link-Layer + Time) for the server
pub fn generate_server_duid() -> Vec<u8> {
    let mut duid = Vec::with_capacity(14);
    // DUID type: LLT (1)
    duid.extend_from_slice(&DUID_TYPE_LLT.to_be_bytes());
    // Hardware type: Ethernet (1)
    duid.extend_from_slice(&1u16.to_be_bytes());
    // Time: seconds since 2000-01-01 00:00:00 UTC
    let epoch_2000 = 946684800u64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let duid_time = (now - epoch_2000) as u32;
    duid.extend_from_slice(&duid_time.to_be_bytes());
    // Link-layer address: random 6 bytes (locally administered)
    let mut mac = [0u8; 6];
    // Use process ID and time for pseudo-random MAC
    let seed = now ^ std::process::id() as u64;
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = ((seed >> (i * 8)) & 0xFF) as u8;
    }
    mac[0] = (mac[0] & 0xFC) | 0x02; // Set locally administered bit
    duid.extend_from_slice(&mac);
    duid
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
