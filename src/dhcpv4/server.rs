use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use super::options::{broadcast_addr, prefix_to_mask, DhcpOption, MessageType};
use super::packet::{DhcpV4Packet, MAX_PACKET_SIZE};
use crate::allocator::SubnetAllocator;
use crate::config::validation::{ip_in_subnet, parse_cidr};
use crate::config::{Config, SubnetConfig};
use crate::ha::HaBackend;
use crate::lease::store::LeaseStore;
use crate::lease::types::{Lease, LeaseState};
use crate::wal::Wal;

/// Duration to hold an Offer before it expires (seconds)
const OFFER_HOLD_TIME: u64 = 30;

/// DHCPv4 server
pub struct DhcpV4Server<H: HaBackend> {
    config: Arc<Config>,
    lease_store: LeaseStore,
    allocators: Arc<HashMap<String, SubnetAllocator>>,
    wal: Arc<Wal>,
    ha: Arc<H>,
    /// This server's IP address (used as server identifier)
    server_ip: Ipv4Addr,
    /// Parsed subnet info for fast lookup
    subnets: Vec<SubnetInfo>,
}

/// Pre-parsed subnet information for runtime lookups.
/// Wrapped in Arc to avoid cloning on every packet.
#[derive(Clone)]
struct SubnetInfo {
    network: Arc<str>,
    network_addr: Ipv4Addr,
    prefix_len: u8,
    config: Arc<SubnetConfig>,
}

impl<H: HaBackend> DhcpV4Server<H> {
    pub fn new(
        config: Arc<Config>,
        lease_store: LeaseStore,
        allocators: Arc<HashMap<String, SubnetAllocator>>,
        wal: Arc<Wal>,
        ha: Arc<H>,
        server_ip: Ipv4Addr,
    ) -> Self {
        let subnets: Vec<SubnetInfo> = config
            .subnet
            .iter()
            .filter_map(|s| {
                if s.subnet_type == "prefix-delegation" {
                    return None;
                }
                let (addr, prefix_len) = parse_cidr(&s.network).ok()?;
                if let IpAddr::V4(v4) = addr {
                    Some(SubnetInfo {
                        network: Arc::from(s.network.as_str()),
                        network_addr: v4,
                        prefix_len,
                        config: Arc::new(s.clone()),
                    })
                } else {
                    None
                }
            })
            .collect();

        Self {
            config,
            lease_store,
            allocators,
            wal,
            ha,
            server_ip,
            subnets,
        }
    }

    /// Run the DHCPv4 server loop
    pub async fn run(&self, socket: Arc<UdpSocket>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut recv_buf = [0u8; MAX_PACKET_SIZE];

        info!(addr = %socket.local_addr()?, "DHCPv4 server listening");

        loop {
            let (len, src_addr) = match socket.recv_from(&mut recv_buf).await {
                Ok(r) => r,
                Err(e) => {
                    error!(error = %e, "failed to receive packet");
                    continue;
                }
            };

            let packet = match DhcpV4Packet::parse(&recv_buf[..len]) {
                Ok(p) => p,
                Err(e) => {
                    debug!(error = %e, src = %src_addr, "dropping malformed packet");
                    continue;
                }
            };

            // Only handle BOOTREQUEST
            if packet.op != 1 {
                continue;
            }

            let msg_type = match packet.message_type() {
                Some(mt) => mt,
                None => {
                    debug!(src = %src_addr, "dropping packet without message type");
                    continue;
                }
            };

            let mac = packet.mac();
            debug!(
                msg_type = ?msg_type,
                xid = packet.xid,
                mac = %format_mac(&mac),
                "received DHCPv4 {:?}",
                msg_type
            );

            let result = match msg_type {
                MessageType::Discover => self.handle_discover(&packet).await,
                MessageType::Request => self.handle_request(&packet).await,
                MessageType::Release => self.handle_release(&packet).await,
                MessageType::Decline => self.handle_decline(&packet).await,
                MessageType::Inform => self.handle_inform(&packet).await,
                _ => {
                    debug!(msg_type = ?msg_type, "ignoring unexpected message type");
                    continue;
                }
            };

            match result {
                Ok(Some(reply)) => {
                    let dest = self.reply_destination(&packet, &reply, src_addr);
                    let mut send_buf = [0u8; MAX_PACKET_SIZE];
                    let send_len = reply.serialize(&mut send_buf);

                    if let Err(e) = socket.send_to(&send_buf[..send_len], dest).await {
                        error!(error = %e, dest = %dest, "failed to send reply");
                    } else {
                        debug!(
                            msg_type = ?reply.message_type(),
                            dest = %dest,
                            yiaddr = %reply.yiaddr,
                            "sent reply"
                        );
                    }
                }
                Ok(None) => {} // No reply needed (Release, Decline)
                Err(e) => {
                    warn!(error = %e, xid = packet.xid, "error handling packet");
                }
            }
        }
    }

    /// Handle DHCPDISCOVER: find a subnet, allocate an IP, send DHCPOFFER
    async fn handle_discover(
        &self,
        packet: &DhcpV4Packet,
    ) -> Result<Option<DhcpV4Packet>, Box<dyn std::error::Error + Send + Sync>> {
        let subnet = match self.select_subnet(packet) {
            Some(s) => s,
            None => {
                warn!(
                    mac = %format_mac(&packet.mac()),
                    giaddr = %packet.giaddr,
                    "no matching subnet for Discover"
                );
                return Ok(None);
            }
        };

        let mac = packet.mac();

        // Check for existing lease for this client
        if let Some(existing) = self.lease_store.get_by_mac(&mac) {
            if existing.is_active() {
                if let IpAddr::V4(v4) = existing.ip {
                    // Offer the same IP they already have
                    let options = self.build_offer_options(&subnet);
                    let reply = packet.build_reply(MessageType::Offer, v4, self.server_ip, options);
                    return Ok(Some(reply));
                }
            }
        }

        // Check for reservation
        if let Some(reserved_ip) = self.find_reservation(&subnet, &mac, packet.client_id()) {
            let options = self.build_offer_options(&subnet);
            let reply =
                packet.build_reply(MessageType::Offer, reserved_ip, self.server_ip, options);

            // Record the offer
            self.record_offer(&subnet, reserved_ip, packet).await?;
            return Ok(Some(reply));
        }

        // Check if client is requesting a specific IP
        if let Some(requested) = packet.requested_ip() {
            if let Some(allocator) = self.allocators.get(&*subnet.network) {
                if allocator.contains(&IpAddr::V4(requested))
                    && !self.lease_store.is_allocated(&IpAddr::V4(requested))
                    && allocator.allocate_specific(&IpAddr::V4(requested))
                {
                    let options = self.build_offer_options(&subnet);
                    let reply = packet.build_reply(
                        MessageType::Offer,
                        requested,
                        self.server_ip,
                        options,
                    );
                    self.record_offer(&subnet, requested, packet).await?;
                    return Ok(Some(reply));
                }
            }
        }

        // Allocate from pool
        let allocator = match self.allocators.get(&*subnet.network) {
            Some(a) => a,
            None => {
                warn!(subnet = %subnet.network, "no allocator for subnet");
                return Ok(None);
            }
        };

        let ip = match allocator.allocate() {
            Some(IpAddr::V4(v4)) => v4,
            _ => {
                warn!(subnet = %subnet.network, "pool exhausted");
                return Ok(None);
            }
        };

        let options = self.build_offer_options(&subnet);
        let reply = packet.build_reply(MessageType::Offer, ip, self.server_ip, options);

        self.record_offer(&subnet, ip, packet).await?;

        Ok(Some(reply))
    }

    /// Handle DHCPREQUEST: validate and either ACK or NAK
    async fn handle_request(
        &self,
        packet: &DhcpV4Packet,
    ) -> Result<Option<DhcpV4Packet>, Box<dyn std::error::Error + Send + Sync>> {
        // If server_id is present, this is a response to an Offer
        if let Some(server_id) = packet.server_id() {
            if server_id != self.server_ip {
                // Not for us — if we had an offer for this client, release it
                let mac = packet.mac();
                if let Some(existing) = self.lease_store.get_by_mac(&mac) {
                    if existing.state == LeaseState::Offered {
                        self.release_ip(&existing.ip);
                        self.lease_store.remove(&existing.ip);
                    }
                }
                return Ok(None);
            }
        }

        // Determine the IP the client wants
        let requested_ip = if let Some(ip) = packet.requested_ip() {
            ip
        } else if !packet.ciaddr.is_unspecified() {
            // Renew/rebind — client uses ciaddr
            packet.ciaddr
        } else {
            return Ok(Some(self.build_nak(packet, "no IP requested")));
        };

        // Find the subnet
        let subnet = match self.select_subnet(packet) {
            Some(s) => s,
            None => {
                return Ok(Some(self.build_nak(packet, "no matching subnet")));
            }
        };

        // Verify the IP is in the subnet
        if !ip_in_subnet(
            &IpAddr::V4(requested_ip),
            &IpAddr::V4(subnet.network_addr),
            subnet.prefix_len,
        ) {
            return Ok(Some(
                self.build_nak(packet, "requested IP not in subnet"),
            ));
        }

        let mac = packet.mac();
        let ip_addr = IpAddr::V4(requested_ip);

        // Check if there's an existing lease
        if let Some(existing) = self.lease_store.get(&ip_addr) {
            // Verify the lease belongs to this client
            if let Some(existing_mac) = existing.mac {
                if existing_mac != mac {
                    return Ok(Some(
                        self.build_nak(packet, "IP assigned to different client"),
                    ));
                }
            }
        } else {
            // No existing lease — check if this is a reservation or if we need to allocate
            if let Some(allocator) = self.allocators.get(&*subnet.network) {
                if !allocator.is_allocated(&ip_addr) {
                    allocator.allocate_specific(&ip_addr);
                }
            }
        }

        // Commit through HA backend
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let lease_time = subnet.config.lease_time;

        let lease = Lease {
            ip: ip_addr,
            mac: Some(mac),
            client_id: packet.client_id().map(|c| c.to_vec()),
            hostname: packet.hostname().map(|s| Arc::from(s)),
            lease_time,
            state: LeaseState::Bound,
            start_time: now_epoch,
            expire_time: now_epoch + lease_time as u64,
            expires_at: Instant::now() + Duration::from_secs(lease_time as u64),
            subnet: Arc::clone(&subnet.network),
        };

        self.ha.commit_lease(&lease).await?;
        self.wal.log_upsert(&lease).await?;
        self.lease_store.upsert(lease);

        info!(
            ip = %requested_ip,
            mac = %format_mac(&mac),
            lease_time,
            subnet = %subnet.network,
            "lease bound"
        );

        let options = self.build_ack_options(&subnet);
        let reply =
            packet.build_reply(MessageType::Ack, requested_ip, self.server_ip, options);

        Ok(Some(reply))
    }

    /// Handle DHCPRELEASE: free the lease
    async fn handle_release(
        &self,
        packet: &DhcpV4Packet,
    ) -> Result<Option<DhcpV4Packet>, Box<dyn std::error::Error + Send + Sync>> {
        let ip = IpAddr::V4(packet.ciaddr);

        if let Some(existing) = self.lease_store.get(&ip) {
            if let Some(existing_mac) = existing.mac {
                if existing_mac == packet.mac() {
                    self.ha.release_lease(&ip).await?;
                    self.wal.log_remove(&ip).await?;
                    self.lease_store.remove(&ip);
                    self.release_ip(&ip);

                    info!(
                        ip = %packet.ciaddr,
                        mac = %format_mac(&packet.mac()),
                        "lease released"
                    );
                }
            }
        }

        // No reply for Release
        Ok(None)
    }

    /// Handle DHCPDECLINE: mark IP as unusable
    async fn handle_decline(
        &self,
        packet: &DhcpV4Packet,
    ) -> Result<Option<DhcpV4Packet>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(requested_ip) = packet.requested_ip() {
            let ip = IpAddr::V4(requested_ip);

            warn!(
                ip = %requested_ip,
                mac = %format_mac(&packet.mac()),
                "IP declined (possible conflict)"
            );

            // Mark as declined in lease store — don't release from allocator
            // so this IP won't be reassigned
            let now_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let lease = Lease {
                ip,
                mac: Some(packet.mac()),
                client_id: packet.client_id().map(|c| c.to_vec()),
                hostname: None,
                lease_time: 86400, // Hold declined IPs for 24h
                state: LeaseState::Declined,
                start_time: now_epoch,
                expire_time: now_epoch + 86400,
                expires_at: Instant::now() + Duration::from_secs(86400),
                subnet: Arc::from(""),
            };

            self.wal.log_upsert(&lease).await?;
            self.lease_store.upsert(lease);
        }

        // No reply for Decline
        Ok(None)
    }

    /// Handle DHCPINFORM: respond with config options only, no lease
    async fn handle_inform(
        &self,
        packet: &DhcpV4Packet,
    ) -> Result<Option<DhcpV4Packet>, Box<dyn std::error::Error + Send + Sync>> {
        let subnet = match self.select_subnet(packet) {
            Some(s) => s,
            None => return Ok(None),
        };

        let options = self.build_inform_options(&subnet);
        // INFORM response: yiaddr = 0, ciaddr stays
        let mut reply = packet.build_reply(
            MessageType::Ack,
            Ipv4Addr::UNSPECIFIED,
            self.server_ip,
            options,
        );
        reply.ciaddr = packet.ciaddr;

        Ok(Some(reply))
    }

    /// Select the appropriate subnet for a packet.
    /// Tries giaddr (relay) first, then ciaddr (renew), then server IP (direct).
    /// Falls through if a match isn't found at any level.
    fn select_subnet(&self, packet: &DhcpV4Packet) -> Option<SubnetInfo> {
        // Try giaddr first (relayed packets)
        if packet.is_relayed() {
            if let Some(s) = self.subnets.iter().find(|s| {
                ip_in_subnet(
                    &IpAddr::V4(packet.giaddr),
                    &IpAddr::V4(s.network_addr),
                    s.prefix_len,
                )
            }) {
                return Some(s.clone());
            }
            // giaddr didn't match any subnet — fall through
        }

        // Try ciaddr (renew/rebind/inform)
        if !packet.ciaddr.is_unspecified() {
            if let Some(s) = self.subnets.iter().find(|s| {
                ip_in_subnet(
                    &IpAddr::V4(packet.ciaddr),
                    &IpAddr::V4(s.network_addr),
                    s.prefix_len,
                )
            }) {
                return Some(s.clone());
            }
        }

        // Fall back to server IP (direct connected / default subnet)
        self.subnets.iter().find(|s| {
            ip_in_subnet(
                &IpAddr::V4(self.server_ip),
                &IpAddr::V4(s.network_addr),
                s.prefix_len,
            )
        }).cloned()
    }

    /// Find a reservation for this client
    fn find_reservation(
        &self,
        subnet: &SubnetInfo,
        mac: &[u8; 6],
        client_id: Option<&[u8]>,
    ) -> Option<Ipv4Addr> {
        for res in &subnet.config.reservation {
            // Check MAC match
            if let Some(ref res_mac) = res.mac {
                if let Ok(parsed) = crate::config::validation::parse_mac(res_mac) {
                    if &parsed == mac {
                        return res.ip.parse().ok();
                    }
                }
            }

            // Check client ID match
            if let (Some(res_cid), Some(pkt_cid)) = (&res.client_id, client_id) {
                if let Some(parsed) = decode_hex(res_cid) {
                    if parsed == pkt_cid {
                        return res.ip.parse().ok();
                    }
                }
            }
        }
        None
    }

    /// Record an Offer in the lease store with a short hold time
    async fn record_offer(
        &self,
        subnet: &SubnetInfo,
        ip: Ipv4Addr,
        packet: &DhcpV4Packet,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let lease = Lease {
            ip: IpAddr::V4(ip),
            mac: Some(packet.mac()),
            client_id: packet.client_id().map(|c| c.to_vec()),
            hostname: packet.hostname().map(|s| Arc::from(s)),
            lease_time: OFFER_HOLD_TIME as u32,
            state: LeaseState::Offered,
            start_time: now_epoch,
            expire_time: now_epoch + OFFER_HOLD_TIME,
            expires_at: Instant::now() + Duration::from_secs(OFFER_HOLD_TIME),
            subnet: Arc::clone(&subnet.network),
        };

        self.lease_store.upsert(lease);
        Ok(())
    }

    /// Build options for a DHCPOFFER response
    fn build_offer_options(&self, subnet: &SubnetInfo) -> Vec<DhcpOption> {
        let mut opts = Vec::with_capacity(8);

        opts.push(DhcpOption::ServerIdentifier(self.server_ip));
        opts.push(DhcpOption::LeaseTime(subnet.config.lease_time));
        opts.push(DhcpOption::SubnetMask(prefix_to_mask(subnet.prefix_len)));

        // T1 = 50% lease time, T2 = 87.5% lease time
        let t1 = subnet.config.lease_time / 2;
        let t2 = (subnet.config.lease_time as u64 * 7 / 8) as u32;
        opts.push(DhcpOption::RenewalTime(t1));
        opts.push(DhcpOption::RebindingTime(t2));

        if let Some(ref router) = subnet.config.router {
            if let Ok(r) = router.parse::<Ipv4Addr>() {
                opts.push(DhcpOption::Router(vec![r]));
            }
        }

        let dns_addrs: Vec<Ipv4Addr> = subnet
            .config
            .dns
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        if !dns_addrs.is_empty() {
            opts.push(DhcpOption::DnsServers(dns_addrs));
        }

        if let Some(ref domain) = subnet.config.domain {
            opts.push(DhcpOption::DomainName(domain.clone()));
        }

        opts.push(DhcpOption::BroadcastAddr(broadcast_addr(
            subnet.network_addr,
            subnet.prefix_len,
        )));

        opts
    }

    /// Build options for a DHCPACK response
    fn build_ack_options(&self, subnet: &SubnetInfo) -> Vec<DhcpOption> {
        // ACK options are the same as OFFER options
        self.build_offer_options(subnet)
    }

    /// Build options for a DHCPINFORM response (no lease-related options)
    fn build_inform_options(&self, subnet: &SubnetInfo) -> Vec<DhcpOption> {
        let mut opts = Vec::with_capacity(4);

        opts.push(DhcpOption::ServerIdentifier(self.server_ip));
        opts.push(DhcpOption::SubnetMask(prefix_to_mask(subnet.prefix_len)));

        if let Some(ref router) = subnet.config.router {
            if let Ok(r) = router.parse::<Ipv4Addr>() {
                opts.push(DhcpOption::Router(vec![r]));
            }
        }

        let dns_addrs: Vec<Ipv4Addr> = subnet
            .config
            .dns
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        if !dns_addrs.is_empty() {
            opts.push(DhcpOption::DnsServers(dns_addrs));
        }

        if let Some(ref domain) = subnet.config.domain {
            opts.push(DhcpOption::DomainName(domain.clone()));
        }

        opts
    }

    /// Build a DHCPNAK response
    fn build_nak(&self, packet: &DhcpV4Packet, reason: &str) -> DhcpV4Packet {
        debug!(
            xid = packet.xid,
            mac = %format_mac(&packet.mac()),
            reason,
            "sending NAK"
        );

        let options = vec![DhcpOption::ServerIdentifier(self.server_ip)];
        packet.build_reply(
            MessageType::Nak,
            Ipv4Addr::UNSPECIFIED,
            self.server_ip,
            options,
        )
    }

    /// Check if giaddr matches any known subnet (true relay vs perfdhcp loopback)
    fn is_known_relay(&self, giaddr: Ipv4Addr) -> bool {
        self.subnets.iter().any(|s| {
            ip_in_subnet(
                &IpAddr::V4(giaddr),
                &IpAddr::V4(s.network_addr),
                s.prefix_len,
            )
        })
    }

    /// Determine the destination address for a reply (RFC 2131 §4.1).
    fn reply_destination(
        &self,
        request: &DhcpV4Packet,
        reply: &DhcpV4Packet,
        src_addr: SocketAddr,
    ) -> SocketAddr {
        if request.is_relayed() && self.is_known_relay(request.giaddr) {
            // Relayed through a known relay: send back to relay agent on port 67
            SocketAddr::new(IpAddr::V4(request.giaddr), 67)
        } else if !request.ciaddr.is_unspecified() {
            // Renew/rebind: unicast to client's existing IP and source port
            SocketAddr::new(IpAddr::V4(request.ciaddr), src_addr.port())
        } else if request.wants_broadcast() || reply.yiaddr.is_unspecified() {
            // Client requests broadcast
            SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), src_addr.port())
        } else {
            // Default: reply to source address
            src_addr
        }
    }

    /// Release an IP back to the pool allocator
    fn release_ip(&self, ip: &IpAddr) {
        for (network, allocator) in self.allocators.iter() {
            if allocator.contains(ip) {
                allocator.release(ip);
                debug!(%ip, subnet = %network, "IP released to pool");
                return;
            }
        }
    }
}

/// Zero-allocation MAC display wrapper for tracing.
struct MacDisplay([u8; 6]);

impl std::fmt::Display for MacDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[inline]
fn format_mac(mac: &[u8; 6]) -> MacDisplay {
    MacDisplay(*mac)
}

/// Decode a hex string (e.g. "aabbcc") into bytes. Returns None on invalid input.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    // Strip optional separators
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for chunk in clean.as_bytes().chunks(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
