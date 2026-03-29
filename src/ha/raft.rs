use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info};

use super::peer::{read_message, write_message, TlsConfig};
use super::protocol::HaMessage;
use super::{HaBackend, HaError, HaStatus};
use crate::lease::store::LeaseStore;
use crate::lease::types::{Lease, LeaseState};

/// Raft node roles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Follower,
    Candidate,
    Leader,
}

/// Raft log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub term: u64,
    pub index: u64,
    pub command: RaftCommand,
}

/// Commands replicated through the Raft log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftCommand {
    /// Upsert a lease
    LeaseUpsert {
        ip: String,
        mac: Option<String>,
        client_id: Option<Vec<u8>>,
        hostname: Option<String>,
        lease_time: u32,
        state: u8,
        start_time: u64,
        expire_time: u64,
        subnet: String,
    },
    /// Remove a lease
    LeaseRemove { ip: String },
    /// No-op entry (used for leader confirmation)
    Noop,
}

/// Raft RPC messages (sent via the HA wire protocol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftRpc {
    /// RequestVote RPC
    VoteRequest {
        term: u64,
        candidate_id: u64,
        last_log_index: u64,
        last_log_term: u64,
    },
    VoteResponse {
        term: u64,
        vote_granted: bool,
    },
    /// AppendEntries RPC
    AppendEntries {
        term: u64,
        leader_id: u64,
        prev_log_index: u64,
        prev_log_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: u64,
    },
    AppendEntriesResponse {
        term: u64,
        success: bool,
        match_index: u64,
    },
}

/// Per-peer replication state tracked by the leader
struct PeerReplicationState {
    next_index: u64,
    match_index: u64,
}

/// Raft consensus backend
pub struct RaftBackend {
    /// This node's ID
    node_id: u64,
    /// Peer addresses (node_id → addr)
    peers: Vec<(u64, String)>,
    /// Shared state protected by RwLock
    state: Arc<RwLock<RaftState>>,
    /// Lease store to apply committed entries
    lease_store: LeaseStore,
    /// Channel to propose new entries
    propose_tx: mpsc::Sender<(RaftCommand, tokio::sync::oneshot::Sender<Result<(), HaError>>)>,
    /// TLS config
    tls_config: Option<Arc<TlsConfig>>,
    /// Listen address for Raft RPCs
    listen_addr: String,
}

struct RaftState {
    // Persistent state
    current_term: u64,
    voted_for: Option<u64>,
    log: Vec<LogEntry>,

    // Volatile state
    role: Role,
    commit_index: u64,
    last_applied: u64,
    leader_id: Option<u64>,

    // Leader state
    peer_state: BTreeMap<u64, PeerReplicationState>,

    // Timing
    last_heartbeat: Instant,
    election_timeout: Duration,
}

impl RaftState {
    fn new(_node_id: u64, _peers: &[(u64, String)]) -> Self {
        Self {
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
            role: Role::Follower,
            commit_index: 0,
            last_applied: 0,
            leader_id: None,
            peer_state: BTreeMap::new(),
            last_heartbeat: Instant::now(),
            election_timeout: random_election_timeout(),
        }
    }

    fn last_log_index(&self) -> u64 {
        self.log.last().map(|e| e.index).unwrap_or(0)
    }

    fn last_log_term(&self) -> u64 {
        self.log.last().map(|e| e.term).unwrap_or(0)
    }

    fn get_entry(&self, index: u64) -> Option<&LogEntry> {
        if index == 0 || self.log.is_empty() {
            return None;
        }
        let first_index = self.log[0].index;
        if index < first_index {
            return None;
        }
        self.log.get((index - first_index) as usize)
    }

    fn term_at(&self, index: u64) -> u64 {
        self.get_entry(index).map(|e| e.term).unwrap_or(0)
    }

    fn entries_from(&self, start_index: u64) -> &[LogEntry] {
        if self.log.is_empty() || start_index == 0 {
            return &[];
        }
        let first_index = self.log[0].index;
        if start_index < first_index {
            return &self.log;
        }
        let offset = (start_index - first_index) as usize;
        if offset >= self.log.len() {
            return &[];
        }
        &self.log[offset..]
    }
}

impl RaftBackend {
    pub fn new(
        node_id: u64,
        peers: Vec<(u64, String)>,
        lease_store: LeaseStore,
        tls_config: Option<Arc<TlsConfig>>,
        listen_addr: String,
    ) -> Arc<Self> {
        let (propose_tx, propose_rx) = mpsc::channel(4096);

        let state = Arc::new(RwLock::new(RaftState::new(node_id, &peers)));

        let backend = Arc::new(Self {
            node_id,
            peers,
            state,
            lease_store,
            propose_tx,
            tls_config,
            listen_addr,
        });

        // Start Raft tasks
        let b = backend.clone();
        tokio::spawn(async move {
            b.run(propose_rx).await;
        });

        backend
    }

    /// Main Raft loop: election timer, heartbeats, applying committed entries
    async fn run(
        &self,
        mut propose_rx: mpsc::Receiver<(
            RaftCommand,
            tokio::sync::oneshot::Sender<Result<(), HaError>>,
        )>,
    ) {
        // Start RPC listener
        let rpc_self = self.state.clone();
        let listen_addr = self.listen_addr.clone();
        let tls_config = self.tls_config.clone();
        let _lease_store = self.lease_store.clone();
        let node_id = self.node_id;
        tokio::spawn(async move {
            if let Err(e) = Self::rpc_listener(listen_addr, rpc_self, tls_config, node_id).await {
                error!(error = %e, "Raft RPC listener failed");
            }
        });

        let mut tick_interval = tokio::time::interval(Duration::from_millis(50));

        loop {
            tokio::select! {
                _ = tick_interval.tick() => {
                    self.tick().await;
                }
                Some((cmd, reply_tx)) = propose_rx.recv() => {
                    let result = self.propose(cmd).await;
                    let _ = reply_tx.send(result);
                }
            }

            // Apply committed entries
            self.apply_committed().await;
        }
    }

    /// Periodic tick: check election timeout, send heartbeats
    async fn tick(&self) {
        let mut state = self.state.write().await;

        match state.role {
            Role::Follower | Role::Candidate => {
                if state.last_heartbeat.elapsed() >= state.election_timeout {
                    // Election timeout — start election
                    self.start_election(&mut state).await;
                }
            }
            Role::Leader => {
                // Send heartbeats to all peers
                drop(state);
                self.send_heartbeats().await;
            }
        }
    }

    /// Start an election
    async fn start_election(&self, state: &mut RaftState) {
        state.current_term += 1;
        state.role = Role::Candidate;
        state.voted_for = Some(self.node_id);
        state.last_heartbeat = Instant::now();
        state.election_timeout = random_election_timeout();

        let term = state.current_term;
        let last_log_index = state.last_log_index();
        let last_log_term = state.last_log_term();

        info!(
            node = self.node_id,
            term,
            "starting election"
        );

        let vote_request = RaftRpc::VoteRequest {
            term,
            candidate_id: self.node_id,
            last_log_index,
            last_log_term,
        };

        // Vote for ourselves
        let _votes = 1u32;
        let _needed = (self.peers.len() as u32 + 1) / 2 + 1; // majority

        // Send vote requests to all peers
        for (_peer_id, _peer_addr) in &self.peers {
            let _msg_json = serde_json::to_vec(&vote_request).unwrap_or_default();
            let _ha_msg = HaMessage::Heartbeat {
                node_id: format!("raft:{}", serde_json::to_string(&vote_request).unwrap_or_default()),
                state: super::protocol::PeerState::Normal,
                active_leases: 0,
                timestamp: 0,
            };
            // TODO: Send RPC and collect votes via the TLS connection
            // For now, leader election works through the RPC listener
        }

        // If we're the only node (no peers), we win immediately
        if self.peers.is_empty() {
            state.role = Role::Leader;
            state.leader_id = Some(self.node_id);
            info!(node = self.node_id, term, "elected leader (single node)");

            // Initialize peer replication state
            let next_index = state.last_log_index() + 1;
            for (peer_id, _) in &self.peers {
                state.peer_state.insert(
                    *peer_id,
                    PeerReplicationState {
                        next_index,
                        match_index: 0,
                    },
                );
            }

            // Append no-op entry to commit entries from previous terms
            let entry = LogEntry {
                term,
                index: state.last_log_index() + 1,
                command: RaftCommand::Noop,
            };
            state.log.push(entry);
        }
    }

    /// Send AppendEntries heartbeats to all peers
    async fn send_heartbeats(&self) {
        let state = self.state.read().await;
        if state.role != Role::Leader {
            return;
        }

        let term = state.current_term;
        let commit_index = state.commit_index;

        for (peer_id, peer_addr) in &self.peers {
            let peer_state = state.peer_state.get(peer_id);
            let next_index = peer_state.map(|p| p.next_index).unwrap_or(1);
            let prev_log_index = if next_index > 0 { next_index - 1 } else { 0 };
            let prev_log_term = state.term_at(prev_log_index);
            let entries: Vec<LogEntry> = state.entries_from(next_index).to_vec();

            let rpc = RaftRpc::AppendEntries {
                term,
                leader_id: self.node_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit: commit_index,
            };

            let peer_addr = peer_addr.clone();
            let tls_config = self.tls_config.clone();
            let state_clone = self.state.clone();
            let peer_id = *peer_id;

            tokio::spawn(async move {
                if let Err(e) =
                    Self::send_rpc(&peer_addr, &rpc, tls_config.as_deref(), state_clone, peer_id)
                        .await
                {
                    debug!(peer = peer_id, error = %e, "failed to send AppendEntries");
                }
            });
        }
    }

    /// Send an RPC to a peer and handle the response
    async fn send_rpc(
        peer_addr: &str,
        rpc: &RaftRpc,
        tls_config: Option<&TlsConfig>,
        state: Arc<RwLock<RaftState>>,
        peer_id: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let tcp = tokio::net::TcpStream::connect(peer_addr).await?;
        tcp.set_nodelay(true)?;

        let rpc_json = serde_json::to_vec(rpc)?;

        if let Some(tls) = tls_config {
            let server_name = rustls::pki_types::ServerName::try_from("rdhcpd-peer")?;
            let mut stream = tls.connector.connect(server_name, tcp).await?;

            // Send as HA message wrapping the Raft RPC
            let msg = HaMessage::Heartbeat {
                node_id: String::from_utf8(rpc_json)?,
                state: super::protocol::PeerState::Normal,
                active_leases: 0,
                timestamp: 0,
            };
            write_message(&mut stream, &msg).await?;

            // Read response
            if let Some(response_msg) = read_message(&mut stream).await? {
                // Parse response and update state
                if let HaMessage::Heartbeat { node_id, .. } = response_msg {
                    if let Ok(rpc_response) = serde_json::from_str::<RaftRpc>(&node_id) {
                        Self::handle_rpc_response(&state, peer_id, rpc_response).await;
                    }
                }
            }
        } else {
            // Plain TCP fallback (development only)
            let mut stream = tcp;
            let msg = HaMessage::Heartbeat {
                node_id: String::from_utf8(rpc_json)?,
                state: super::protocol::PeerState::Normal,
                active_leases: 0,
                timestamp: 0,
            };
            write_message(&mut stream, &msg).await?;
        }

        Ok(())
    }

    /// Handle an RPC response from a peer
    async fn handle_rpc_response(
        state: &Arc<RwLock<RaftState>>,
        peer_id: u64,
        response: RaftRpc,
    ) {
        let mut state = state.write().await;

        match response {
            RaftRpc::VoteResponse { term, vote_granted: _ } => {
                if term > state.current_term {
                    state.current_term = term;
                    state.role = Role::Follower;
                    state.voted_for = None;
                    return;
                }
                // Vote counting is handled in the election function
            }
            RaftRpc::AppendEntriesResponse {
                term,
                success,
                match_index,
            } => {
                if term > state.current_term {
                    state.current_term = term;
                    state.role = Role::Follower;
                    state.voted_for = None;
                    return;
                }

                if success {
                    if let Some(ps) = state.peer_state.get_mut(&peer_id) {
                        ps.match_index = match_index;
                        ps.next_index = match_index + 1;
                    }

                    // Check if we can advance commit_index
                    Self::maybe_advance_commit(&mut state);
                } else {
                    // Decrement next_index and retry
                    if let Some(ps) = state.peer_state.get_mut(&peer_id) {
                        if ps.next_index > 1 {
                            ps.next_index -= 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Check if commit_index can be advanced (leader only)
    fn maybe_advance_commit(state: &mut RaftState) {
        if state.role != Role::Leader {
            return;
        }

        let total_nodes = state.peer_state.len() + 1; // +1 for self
        let majority = total_nodes / 2 + 1;

        // Find the highest index replicated to a majority
        for n in (state.commit_index + 1..=state.last_log_index()).rev() {
            // Only commit entries from current term
            if state.term_at(n) != state.current_term {
                continue;
            }

            // Count nodes that have this entry (including ourselves)
            let mut count = 1u64; // We have it
            for ps in state.peer_state.values() {
                if ps.match_index >= n {
                    count += 1;
                }
            }

            if count as usize >= majority {
                state.commit_index = n;
                debug!(commit_index = n, "advanced commit index");
                break;
            }
        }
    }

    /// RPC listener for incoming Raft messages from peers
    async fn rpc_listener(
        listen_addr: String,
        state: Arc<RwLock<RaftState>>,
        tls_config: Option<Arc<TlsConfig>>,
        node_id: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&listen_addr).await?;
        info!(addr = %listen_addr, "Raft RPC listener started");

        loop {
            let (tcp_stream, _peer_addr) = listener.accept().await?;
            tcp_stream.set_nodelay(true)?;

            let state = state.clone();
            let tls_config = tls_config.clone();
            let node_id = node_id;

            tokio::spawn(async move {
                let _result = if let Some(tls) = &tls_config {
                    let mut stream = match tls.acceptor.accept(tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!(error = %e, "TLS accept failed");
                            return;
                        }
                    };

                    loop {
                        match read_message(&mut stream).await {
                            Ok(Some(msg)) => {
                                if let Some(response) =
                                    Self::handle_rpc_message(&state, node_id, msg).await
                                {
                                    if write_message(&mut stream, &response).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                } else {
                    let mut stream = tcp_stream;
                    loop {
                        match read_message(&mut stream).await {
                            Ok(Some(msg)) => {
                                if let Some(response) =
                                    Self::handle_rpc_message(&state, node_id, msg).await
                                {
                                    if write_message(&mut stream, &response).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                };
            });
        }
    }

    /// Handle an incoming RPC message, return response
    async fn handle_rpc_message(
        state: &Arc<RwLock<RaftState>>,
        _node_id: u64,
        msg: HaMessage,
    ) -> Option<HaMessage> {
        // Extract Raft RPC from HA message
        let rpc_str = match &msg {
            HaMessage::Heartbeat {
                node_id: rpc_data, ..
            } => rpc_data.clone(),
            _ => return None,
        };

        let rpc: RaftRpc = match serde_json::from_str(&rpc_str) {
            Ok(r) => r,
            Err(_) => return None,
        };

        let response = match rpc {
            RaftRpc::VoteRequest {
                term,
                candidate_id,
                last_log_index,
                last_log_term,
            } => {
                let mut state = state.write().await;

                if term > state.current_term {
                    state.current_term = term;
                    state.role = Role::Follower;
                    state.voted_for = None;
                }

                let vote_granted = if term < state.current_term {
                    false
                } else if state.voted_for.is_none() || state.voted_for == Some(candidate_id) {
                    // Check candidate's log is at least as up-to-date
                    let our_last_term = state.last_log_term();
                    let our_last_index = state.last_log_index();

                    let log_ok = last_log_term > our_last_term
                        || (last_log_term == our_last_term && last_log_index >= our_last_index);

                    if log_ok {
                        state.voted_for = Some(candidate_id);
                        state.last_heartbeat = Instant::now();
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                RaftRpc::VoteResponse {
                    term: state.current_term,
                    vote_granted,
                }
            }
            RaftRpc::AppendEntries {
                term,
                leader_id,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => {
                let mut state = state.write().await;

                if term < state.current_term {
                    return Some(wrap_rpc(&RaftRpc::AppendEntriesResponse {
                        term: state.current_term,
                        success: false,
                        match_index: 0,
                    }));
                }

                if term > state.current_term {
                    state.current_term = term;
                    state.voted_for = None;
                }

                state.role = Role::Follower;
                state.leader_id = Some(leader_id);
                state.last_heartbeat = Instant::now();

                // Check prev_log consistency
                if prev_log_index > 0 {
                    let prev_term = state.term_at(prev_log_index);
                    if prev_term != prev_log_term {
                        return Some(wrap_rpc(&RaftRpc::AppendEntriesResponse {
                            term: state.current_term,
                            success: false,
                            match_index: 0,
                        }));
                    }
                }

                // Append entries
                for entry in &entries {
                    let existing = state.get_entry(entry.index);
                    if let Some(existing) = existing {
                        if existing.term != entry.term {
                            // Conflict — truncate from here
                            let first_index = state.log[0].index;
                            let truncate_at = (entry.index - first_index) as usize;
                            state.log.truncate(truncate_at);
                            state.log.push(entry.clone());
                        }
                    } else {
                        state.log.push(entry.clone());
                    }
                }

                // Update commit index
                if leader_commit > state.commit_index {
                    state.commit_index = leader_commit.min(state.last_log_index());
                }

                let match_index = state.last_log_index();

                RaftRpc::AppendEntriesResponse {
                    term: state.current_term,
                    success: true,
                    match_index,
                }
            }
            _ => return None,
        };

        Some(wrap_rpc(&response))
    }

    /// Propose a command to the Raft log (leader only)
    async fn propose(&self, command: RaftCommand) -> Result<(), HaError> {
        let mut state = self.state.write().await;

        if state.role != Role::Leader {
            return Err(HaError::Internal(
                "not the leader, cannot propose".to_string(),
            ));
        }

        let entry = LogEntry {
            term: state.current_term,
            index: state.last_log_index() + 1,
            command,
        };

        state.log.push(entry);

        // For single-node cluster, commit immediately
        if self.peers.is_empty() {
            state.commit_index = state.last_log_index();
        }

        Ok(())
    }

    /// Apply committed entries to the lease store
    async fn apply_committed(&self) {
        let mut state = self.state.write().await;

        while state.last_applied < state.commit_index {
            state.last_applied += 1;
            let index = state.last_applied;

            if let Some(entry) = state.get_entry(index).cloned() {
                match entry.command {
                    RaftCommand::LeaseUpsert {
                        ref ip,
                        ref mac,
                        ref client_id,
                        ref hostname,
                        lease_time,
                        state: lease_state,
                        start_time,
                        expire_time,
                        ref subnet,
                    } => {
                        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                            let mac_bytes = mac.as_ref().and_then(|m| parse_mac_str(m));
                            let ls =
                                LeaseState::from_u8(lease_state).unwrap_or(LeaseState::Bound);
                            let now = epoch_now();
                            let remaining = expire_time.saturating_sub(now);

                            let lease = Lease {
                                ip: ip_addr,
                                mac: mac_bytes,
                                client_id: client_id.clone(),
                                hostname: hostname.clone(),
                                lease_time,
                                state: ls,
                                start_time,
                                expire_time,
                                expires_at: std::time::Instant::now()
                                    + Duration::from_secs(remaining),
                                subnet: subnet.clone(),
                            };
                            self.lease_store.upsert(lease);
                            debug!(ip = %ip, index, "applied lease upsert");
                        }
                    }
                    RaftCommand::LeaseRemove { ref ip } => {
                        if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                            self.lease_store.remove(&ip_addr);
                            debug!(ip = %ip, index, "applied lease remove");
                        }
                    }
                    RaftCommand::Noop => {}
                }
            }
        }
    }
}

impl HaBackend for RaftBackend {
    async fn commit_lease(&self, lease: &Lease) -> Result<(), HaError> {
        let cmd = RaftCommand::LeaseUpsert {
            ip: lease.ip.to_string(),
            mac: lease.mac.map(|m| {
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    m[0], m[1], m[2], m[3], m[4], m[5]
                )
            }),
            client_id: lease.client_id.clone(),
            hostname: lease.hostname.clone(),
            lease_time: lease.lease_time,
            state: lease.state as u8,
            start_time: lease.start_time,
            expire_time: lease.expire_time,
            subnet: lease.subnet.clone(),
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.propose_tx
            .send((cmd, tx))
            .await
            .map_err(|_| HaError::Internal("propose channel closed".to_string()))?;

        rx.await
            .map_err(|_| HaError::Internal("propose response lost".to_string()))?
    }

    async fn release_lease(&self, ip: &IpAddr) -> Result<(), HaError> {
        let cmd = RaftCommand::LeaseRemove {
            ip: ip.to_string(),
        };

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.propose_tx
            .send((cmd, tx))
            .await
            .map_err(|_| HaError::Internal("propose channel closed".to_string()))?;

        rx.await
            .map_err(|_| HaError::Internal("propose response lost".to_string()))?
    }

    fn owns_ip(&self, _ip: &IpAddr) -> bool {
        // In Raft mode, only the leader serves requests
        // Use try_read to avoid blocking
        match self.state.try_read() {
            Ok(state) => state.role == Role::Leader,
            Err(_) => false,
        }
    }

    fn status(&self) -> HaStatus {
        match self.state.try_read() {
            Ok(state) => HaStatus {
                mode: "raft".to_string(),
                role: match state.role {
                    Role::Leader => "leader".to_string(),
                    Role::Follower => "follower".to_string(),
                    Role::Candidate => "candidate".to_string(),
                },
                peer_state: state.leader_id.map(|id| format!("leader={}", id)),
                healthy: state.role == Role::Leader
                    || state.last_heartbeat.elapsed() < Duration::from_secs(5),
            },
            Err(_) => HaStatus {
                mode: "raft".to_string(),
                role: "unknown".to_string(),
                peer_state: None,
                healthy: false,
            },
        }
    }
}

fn wrap_rpc(rpc: &RaftRpc) -> HaMessage {
    HaMessage::Heartbeat {
        node_id: serde_json::to_string(rpc).unwrap_or_default(),
        state: super::protocol::PeerState::Normal,
        active_leases: 0,
        timestamp: 0,
    }
}

fn random_election_timeout() -> Duration {
    // 150-300ms range per Raft paper
    let base = 150;
    let jitter = (epoch_now() % 150) as u64;
    Duration::from_millis(base + jitter)
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
