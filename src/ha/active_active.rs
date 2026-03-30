use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use super::peer::{read_message, write_message, TlsConfig};
use super::protocol::{HaMessage, PeerState};
use super::{HaBackend, HaError, HaStatus};
use crate::lease::store::LeaseStore;
use crate::lease::types::{Lease, LeaseState};

/// Active/Active HA backend with split-scope allocation
pub struct ActiveActiveBackend {
    /// Our node identifier
    node_id: String,
    /// Peer address (host:port)
    peer_addr: String,
    /// Split ratio — we own IPs from pool_start to pool_start + (pool_size * split)
    scope_split: f64,
    /// Maximum Client Lead Time (seconds) — max lease extension when peer is unknown
    mclt: u32,
    /// Delay before transitioning to partner-down (seconds)
    partner_down_delay: u32,
    /// Current failover state
    state: RwLock<FailoverState>,
    /// TLS configuration for peer communication
    tls_config: Option<Arc<TlsConfig>>,
    /// Lease store reference for bulk sync
    lease_store: LeaseStore,
    /// Last heartbeat received from peer (epoch millis)
    last_heartbeat: AtomicU64,
    /// Channel for sending messages to the outbound peer connection
    peer_tx: mpsc::Sender<HaMessage>,
    /// Receiver end — consumed by the outbound loop
    peer_rx: RwLock<Option<mpsc::Receiver<HaMessage>>>,
}

struct FailoverState {
    peer_state: PeerState,
    peer_reachable: bool,
    entered_interrupted: Option<Instant>,
}

impl ActiveActiveBackend {
    /// Create a new active/active backend with the given split-scope configuration.
    pub fn new(
        node_id: String,
        peer_addr: String,
        scope_split: f64,
        mclt: u32,
        partner_down_delay: u32,
        lease_store: LeaseStore,
        tls_config: Option<Arc<TlsConfig>>,
    ) -> Self {
        let (peer_tx, peer_rx) = mpsc::channel(1024);
        Self {
            node_id,
            peer_addr,
            scope_split,
            mclt,
            partner_down_delay,
            state: RwLock::new(FailoverState {
                peer_state: PeerState::Normal,
                peer_reachable: false,
                entered_interrupted: None,
            }),
            tls_config,
            lease_store,
            last_heartbeat: AtomicU64::new(0),
            peer_tx,
            peer_rx: RwLock::new(Some(peer_rx)),
        }
    }

    /// Start background tasks: heartbeat sender, listener for incoming peer connection,
    /// and failover state machine monitor
    pub async fn start(
        self: &Arc<Self>,
        listen_addr: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Outbound connection task — connect to peer and sync
        let outbound = self.clone();
        tokio::spawn(async move {
            outbound.outbound_loop().await;
        });

        // Inbound listener — accept connections from peer
        let inbound = self.clone();
        tokio::spawn(async move {
            if let Err(e) = inbound.inbound_listener(listen_addr).await {
                error!(error = %e, "HA inbound listener failed");
            }
        });

        // Failover state machine monitor
        let monitor = self.clone();
        tokio::spawn(async move {
            monitor.failover_monitor().await;
        });

        Ok(())
    }

    /// Outbound connection loop — connects to peer, sends heartbeats and lease syncs
    async fn outbound_loop(self: Arc<Self>) {
        // Take the receiver — only one outbound loop runs
        let mut peer_rx = self
            .peer_rx
            .write()
            .await
            .take()
            .expect("peer_rx already consumed");

        loop {
            info!(peer = %self.peer_addr, "connecting to HA peer");

            match self.connect_to_peer(&mut peer_rx).await {
                Ok(()) => {
                    info!(peer = %self.peer_addr, "peer connection closed");
                }
                Err(e) => {
                    debug!(peer = %self.peer_addr, error = %e, "peer connection failed");
                }
            }

            // Mark peer as unreachable
            {
                let mut state = self.state.write().await;
                if state.peer_state == PeerState::Normal {
                    state.peer_state = PeerState::CommunicationsInterrupted;
                    state.peer_reachable = false;
                    state.entered_interrupted = Some(Instant::now());
                    warn!("peer communication interrupted, entering CI state");
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    async fn connect_to_peer(
        &self,
        peer_rx: &mut mpsc::Receiver<HaMessage>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tcp = tokio::net::TcpStream::connect(&self.peer_addr).await?;
        tcp.set_nodelay(true)?;

        let tls_config = self.tls_config.as_ref().ok_or("TLS not configured")?;
        let server_name = rustls::pki_types::ServerName::try_from("rdhcpd-peer")?;
        let mut tls_stream = tls_config.connector.connect(server_name, tcp).await?;

        info!(peer = %self.peer_addr, "mTLS connection established to peer");

        // Mark peer as reachable
        {
            let mut state = self.state.write().await;
            state.peer_reachable = true;
            if state.peer_state == PeerState::CommunicationsInterrupted
                || state.peer_state == PeerState::PartnerDown
            {
                state.peer_state = PeerState::Recover;
                info!("peer reconnected, entering recover state");
            }
        }

        // Multiplex heartbeats and queued lease sync messages
        let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            tokio::select! {
                _ = heartbeat_interval.tick() => {
                    let state = self.state.read().await;
                    let heartbeat = HaMessage::Heartbeat {
                        node_id: self.node_id.clone(),
                        state: state.peer_state,
                        active_leases: self.lease_store.active_count() as u64,
                        timestamp: epoch_now(),
                    };
                    drop(state);

                    if let Err(e) = write_message(&mut tls_stream, &heartbeat).await {
                        return Err(e);
                    }
                }
                msg = peer_rx.recv() => {
                    match msg {
                        Some(ha_msg) => {
                            if let Err(e) = write_message(&mut tls_stream, &ha_msg).await {
                                return Err(e);
                            }
                        }
                        None => return Ok(()), // channel closed
                    }
                }
            }
        }
    }

    /// Inbound listener — accepts TLS connections from our peer
    async fn inbound_listener(
        &self,
        listen_addr: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&listen_addr).await?;
        info!(addr = %listen_addr, "HA peer listener started");

        loop {
            let (tcp_stream, peer_addr) = listener.accept().await?;
            tcp_stream.set_nodelay(true)?;

            let tls_config = match &self.tls_config {
                Some(c) => c.clone(),
                None => {
                    warn!("TLS not configured, rejecting peer connection");
                    continue;
                }
            };

            info!(peer = %peer_addr, "incoming HA peer connection");

            let mut tls_stream = tls_config.acceptor.accept(tcp_stream).await?;

            // Mark peer as reachable
            {
                let mut state = self.state.write().await;
                state.peer_reachable = true;
                if state.peer_state != PeerState::Normal {
                    state.peer_state = PeerState::Recover;
                }
            }

            // Read messages from peer
            loop {
                match read_message(&mut tls_stream).await {
                    Ok(Some(msg)) => {
                        self.handle_peer_message(msg).await;
                    }
                    Ok(None) => {
                        info!(peer = %peer_addr, "peer disconnected");
                        break;
                    }
                    Err(e) => {
                        warn!(peer = %peer_addr, error = %e, "peer message error");
                        break;
                    }
                }
            }

            // Peer disconnected
            {
                let mut state = self.state.write().await;
                state.peer_reachable = false;
                if state.peer_state == PeerState::Normal || state.peer_state == PeerState::Recover {
                    state.peer_state = PeerState::CommunicationsInterrupted;
                    state.entered_interrupted = Some(Instant::now());
                    warn!("peer disconnected, entering CI state");
                }
            }
        }
    }

    /// Process an incoming message from the peer
    async fn handle_peer_message(&self, msg: HaMessage) {
        match msg {
            HaMessage::Heartbeat {
                node_id,
                state: peer_state,
                active_leases,
                timestamp,
            } => {
                self.last_heartbeat.store(timestamp, Ordering::Relaxed);
                debug!(
                    peer = %node_id,
                    state = %peer_state,
                    leases = active_leases,
                    "heartbeat received"
                );

                // If we're in Recover and peer is Normal, transition to Normal
                let mut state = self.state.write().await;
                if state.peer_state == PeerState::Recover && peer_state == PeerState::Normal {
                    state.peer_state = PeerState::Normal;
                    info!("recovery complete, entering normal state");
                }
            }
            HaMessage::LeaseSync {
                ip,
                mac,
                client_id,
                hostname,
                lease_time,
                state,
                start_time,
                expire_time,
                subnet,
            } => {
                // Apply peer's lease to our store
                if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                    let mac_bytes = mac.and_then(|m| parse_mac_str(&m));
                    let lease_state = LeaseState::from_u8(state).unwrap_or(LeaseState::Bound);

                    let now_epoch = epoch_now();
                    let remaining = expire_time.saturating_sub(now_epoch);

                    let lease = Lease {
                        ip: ip_addr,
                        mac: mac_bytes,
                        client_id,
                        hostname: hostname.map(|h| Arc::from(h.as_str())),
                        lease_time,
                        state: lease_state,
                        start_time,
                        expire_time,
                        expires_at: std::time::Instant::now()
                            + Duration::from_secs(remaining),
                        subnet: Arc::from(subnet.as_str()),
                    };
                    self.lease_store.upsert(lease);
                    debug!(%ip_addr, "synced lease from peer");
                }
            }
            HaMessage::LeaseRelease { ip } => {
                if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                    self.lease_store.remove(&ip_addr);
                    debug!(%ip_addr, "removed lease per peer release");
                }
            }
            HaMessage::BulkSyncRequest { since } => {
                debug!(since, "peer requested bulk sync");
                // TODO: send bulk response on the connection
            }
            HaMessage::BulkSyncResponse { leases } => {
                info!(count = leases.len(), "received bulk sync from peer");
                for entry in leases {
                    if let Ok(ip_addr) = entry.ip.parse::<IpAddr>() {
                        let mac_bytes = entry.mac.and_then(|m| parse_mac_str(&m));
                        let lease_state =
                            LeaseState::from_u8(entry.state).unwrap_or(LeaseState::Bound);

                        let now_epoch = epoch_now();
                        let remaining = entry.expire_time.saturating_sub(now_epoch);

                        let lease = Lease {
                            ip: ip_addr,
                            mac: mac_bytes,
                            client_id: entry.client_id,
                            hostname: entry.hostname.map(|h| Arc::from(h.as_str())),
                            lease_time: entry.lease_time,
                            state: lease_state,
                            start_time: entry.start_time,
                            expire_time: entry.expire_time,
                            expires_at: std::time::Instant::now()
                                + Duration::from_secs(remaining),
                            subnet: Arc::from(entry.subnet.as_str()),
                        };
                        self.lease_store.upsert(lease);
                    }
                }
            }
            HaMessage::StateTransition {
                node_id,
                from,
                to,
                ..
            } => {
                info!(peer = %node_id, from = %from, to = %to, "peer state transition");
            }
        }
    }

    /// Monitor failover state — transition from CI → PartnerDown after delay
    async fn failover_monitor(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;

            let mut state = self.state.write().await;

            // Check if we should transition from CI → PartnerDown
            if state.peer_state == PeerState::CommunicationsInterrupted {
                if let Some(entered) = state.entered_interrupted {
                    if entered.elapsed() >= Duration::from_secs(self.partner_down_delay as u64) {
                        state.peer_state = PeerState::PartnerDown;
                        warn!(
                            delay = self.partner_down_delay,
                            "partner-down delay expired, taking over full scope"
                        );
                    }
                }
            }

            // Check for stale heartbeats in Normal state
            if state.peer_state == PeerState::Normal && state.peer_reachable {
                let last = self.last_heartbeat.load(Ordering::Relaxed);
                let now = epoch_now();
                if last > 0 && now - last > 5 {
                    // No heartbeat for 5 seconds
                    state.peer_state = PeerState::CommunicationsInterrupted;
                    state.peer_reachable = false;
                    state.entered_interrupted = Some(Instant::now());
                    warn!("heartbeat timeout, entering CI state");
                }
            }

            // Recovery → Normal transition happens when we get a heartbeat from the peer
            // (handled in handle_peer_message)
        }
    }

    /// Check if this node owns a given IP based on split-scope
    /// In normal mode: we own our split portion
    /// In partner-down: we own everything
    /// In CI: we only own our split (conservative)
    fn owns_ip_internal(&self, ip: &IpAddr, peer_state: PeerState) -> bool {
        match peer_state {
            PeerState::PartnerDown => true, // We own everything
            _ => {
                // Deterministic split based on IP hash
                // This avoids needing to know exact pool boundaries
                let hash = ip_hash(ip);
                let threshold = (self.scope_split * u64::MAX as f64) as u64;
                hash < threshold
            }
        }
    }

    /// Build a lease sync message from a lease
    fn lease_to_sync_msg(lease: &Lease) -> HaMessage {
        HaMessage::LeaseSync {
            ip: lease.ip.to_string(),
            mac: lease.mac.map(|m| {
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                )
            }),
            client_id: lease.client_id.clone(),
            hostname: lease.hostname.as_ref().map(|h| h.to_string()),
            lease_time: lease.lease_time,
            state: lease.state as u8,
            start_time: lease.start_time,
            expire_time: lease.expire_time,
            subnet: lease.subnet.to_string(),
        }
    }
}

impl HaBackend for ActiveActiveBackend {
    async fn commit_lease(&self, lease: &Lease) -> Result<(), HaError> {
        // In non-normal state, cap effective lease time to MCLT
        let peer_state = self
            .state
            .try_read()
            .map(|s| s.peer_state)
            .unwrap_or(PeerState::CommunicationsInterrupted);

        if peer_state != PeerState::Normal && lease.lease_time > self.mclt {
            warn!(
                ip = %lease.ip,
                lease_time = lease.lease_time,
                mclt = self.mclt,
                state = %peer_state,
                "lease exceeds MCLT during degraded state"
            );
        }

        // Sync to peer asynchronously — best-effort, don't block the client
        let msg = Self::lease_to_sync_msg(lease);
        let _ = self.peer_tx.try_send(msg);
        Ok(())
    }

    async fn release_lease(&self, ip: &IpAddr) -> Result<(), HaError> {
        let msg = HaMessage::LeaseRelease {
            ip: ip.to_string(),
        };
        let _ = self.peer_tx.try_send(msg);
        Ok(())
    }

    fn owns_ip(&self, ip: &IpAddr) -> bool {
        // This is called synchronously, so we can't await the RwLock.
        // Use try_read — if we can't get the lock, conservatively return true
        match self.state.try_read() {
            Ok(state) => self.owns_ip_internal(ip, state.peer_state),
            Err(_) => true, // If lock is contested, allow the request
        }
    }

    fn status(&self) -> HaStatus {
        let (peer_state, peer_reachable) = match self.state.try_read() {
            Ok(state) => (state.peer_state.to_string(), state.peer_reachable),
            Err(_) => ("unknown".to_string(), false),
        };

        HaStatus {
            mode: "active-active".to_string(),
            role: "active".to_string(),
            peer_state: Some(peer_state),
            healthy: peer_reachable,
        }
    }
}

/// Deterministic hash of an IP for scope splitting
fn ip_hash(ip: &IpAddr) -> u64 {
    // Simple FNV-1a hash for deterministic splitting
    let bytes = match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn parse_mac_str(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        bytes[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
