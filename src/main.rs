#[cfg(target_os = "freebsd")]
use std::os::unix::io::AsRawFd;
use std::net::Ipv4Addr;
use std::sync::Arc;

use rdhcpd::{allocator, api, lease};
use rdhcpd::api::ApiState;
#[cfg(target_os = "freebsd")]
use rdhcpd::bpf::BpfSender;
use rdhcpd::config::Config;
use rdhcpd::dhcpv4::server::{DhcpSender, DhcpV4Server};
use rdhcpd::dhcpv6::server::{generate_server_duid, DhcpV6Server};
use rdhcpd::ha::StandaloneBackend;
use rdhcpd::lease::store::LeaseStore;
use rdhcpd::ratelimit::{GlobalRateLimiter, RateLimiter, RogueDetector};
use rdhcpd::wal::Wal;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Load configuration
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/rdhcpd/config.toml".to_string());

    let config = match Config::load(&config_path) {
        Ok(c) => {
            info!(path = %config_path, "configuration loaded");
            c
        }
        Err(e) => {
            error!(path = %config_path, error = %e, "failed to load configuration");
            std::process::exit(1);
        }
    };

    // Initialize WAL
    let wal = Arc::new(Wal::open(&config.global.lease_db).await?);
    info!(path = %config.global.lease_db, "WAL opened");

    // Initialize lease store and replay WAL
    let lease_store = LeaseStore::new();
    let replayed = wal.replay(&lease_store).await?;
    info!(replayed, "WAL replay complete");

    // Compact WAL: rewrite with only active leases to reclaim space
    let compacted = wal.compact(&lease_store).await?;
    info!(active_leases = compacted, "WAL compacted");

    // Initialize allocators from config and lease state
    let allocators = Arc::new(allocator::build_allocators(&config, &lease_store)?);
    info!(subnets = allocators.len(), "subnet allocators initialized");

    // Initialize HA backend
    let ha: Arc<StandaloneBackend> = match &config.ha {
        rdhcpd::config::HaConfig::Standalone => Arc::new(StandaloneBackend),
        rdhcpd::config::HaConfig::ActiveActive { .. } => {
            error!("active-active HA mode is not yet implemented — refusing to start in standalone silently");
            std::process::exit(1);
        }
        rdhcpd::config::HaConfig::Raft { .. } => {
            error!("raft HA mode is not yet implemented — refusing to start in standalone silently");
            std::process::exit(1);
        }
    };

    // Initialize security: rate limiters and rogue detector
    let rate_limiter = Arc::new(RateLimiter::new(
        config.global.rate_limit_burst,
        config.global.rate_limit_pps,
    ));
    let global_rate_limiter = if config.global.global_rate_limit_pps > 0.0 {
        Some(Arc::new(GlobalRateLimiter::new(
            config.global.global_rate_limit_pps,
        )))
    } else {
        None
    };
    let rogue_detector = Arc::new(RogueDetector::new(
        config.global.rogue_threshold,
        config.global.rogue_window_secs,
    ));
    let relay_rate_limiter = Arc::new(RateLimiter::new(
        config.global.rate_limit_burst,
        config.global.rate_limit_pps,
    ));
    let dhcpv4_stats = Arc::new(rdhcpd::dhcpv4::stats::DhcpV4Stats::new());
    info!(
        rate_limit_burst = config.global.rate_limit_burst,
        rate_limit_pps = config.global.rate_limit_pps,
        global_rate_limit = config.global.global_rate_limit_pps,
        rogue_threshold = config.global.rogue_threshold,
        "security: rate limiting and rogue detection initialized"
    );

    let config = Arc::new(config);

    // Start lease expiry background task
    let expiry_store = lease_store.clone();
    let expiry_handle = tokio::spawn(async move {
        lease::expiry::run_expiry_task(expiry_store).await;
    });

    // Start management API if configured
    let api_handle = if let Some(ref api_config) = config.api {
        // Warn if API is bound to a non-loopback address without authentication
        if api_config.api_key.is_none() {
            let addr = &api_config.listen;
            let is_loopback = addr.starts_with("127.") || addr.starts_with("localhost") || addr.starts_with("[::1]");
            if !is_loopback {
                warn!(
                    listen = %addr,
                    "API is bound to a non-loopback address without an API key — lease data is world-readable"
                );
            }
        }

        let api_state = Arc::new(ApiState {
            lease_store: lease_store.clone(),
            allocators: allocators.clone(),
            ha: ha.clone(),
            wal: wal.clone(),
            api_key: api_config.api_key.as_deref().map(|s| s.to_string()),
            dhcpv4_stats: dhcpv4_stats.clone(),
        });

        let listen = api_config.listen.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = api::start(&listen, api_state).await {
                error!(error = %e, "management API error");
            }
        }))
    } else {
        None
    };

    // Determine server IP for DHCPv4
    let server_ip = config
        .subnet
        .iter()
        .find_map(|s| {
            s.router
                .as_ref()
                .and_then(|r| r.parse::<Ipv4Addr>().ok())
        })
        .unwrap_or(Ipv4Addr::UNSPECIFIED);

    // Check if we have v4 subnets
    let has_v4 = config
        .subnet
        .iter()
        .any(|s| s.network.contains('.') && s.subnet_type != "prefix-delegation");

    // Check if we have v6 subnets
    let has_v6 = config.subnet.iter().any(|s| s.network.contains(':'));

    // Number of receive workers per protocol
    let worker_count = config.global.workers;

    // DHCPv4 port — default 67
    // RDHCPD_V4_PORT: override for testing/benchmarking only (not for production)
    let dhcpv4_port: u16 = std::env::var("RDHCPD_V4_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(67);
    if dhcpv4_port != 67 {
        warn!(port = dhcpv4_port, "RDHCPD_V4_PORT override active — not for production use");
    }

    // Start DHCPv4 server if v4 subnets configured
    let mut dhcpv4_handles = Vec::new();
    if has_v4 {
        // -----------------------------------------------------------------
        // Detect the network interface that serves our DHCP subnet.
        // On FreeBSD we also capture the interface name and MAC address so
        // we can open a BPF device for raw-frame replies.
        // -----------------------------------------------------------------
        #[cfg(not(target_os = "freebsd"))]
        let send_bind_ip = Ipv4Addr::UNSPECIFIED;
        #[cfg(target_os = "freebsd")]
        let mut send_bind_ip = Ipv4Addr::UNSPECIFIED;
        #[cfg(target_os = "freebsd")]
        let mut detected_iface: Option<String> = None;
        #[cfg(target_os = "freebsd")]
        let mut detected_mac: Option<[u8; 6]> = None;

        #[cfg(target_os = "freebsd")]
        {
            let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
            if unsafe { libc::getifaddrs(&mut ifaddrs_ptr) } == 0 {
                // First pass: find the interface + IP that matches a v4 subnet.
                let mut cur = ifaddrs_ptr;
                while !cur.is_null() {
                    let ifa = unsafe { &*cur };
                    if !ifa.ifa_addr.is_null() {
                        let sa = unsafe { &*ifa.ifa_addr };
                        if sa.sa_family == libc::AF_INET as u8 {
                            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            for subnet in config.subnet.iter().filter(|s| s.network.contains('.')) {
                                let cidr_parts: Vec<&str> = subnet.network.split('/').collect();
                                if cidr_parts.len() == 2 {
                                    if let (Ok(net_v4), Ok(prefix)) = (cidr_parts[0].parse::<Ipv4Addr>(), cidr_parts[1].parse::<u8>()) {
                                        let mask = if prefix >= 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
                                        if (u32::from(ip) & mask) == (u32::from(net_v4) & mask) {
                                            let iface_name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                                                .to_string_lossy()
                                                .into_owned();
                                            info!(
                                                interface = %iface_name,
                                                ip = %ip,
                                                subnet = %subnet.network,
                                                "detected DHCP interface"
                                            );
                                            send_bind_ip = ip;
                                            detected_iface = Some(iface_name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    cur = unsafe { (*cur).ifa_next };
                    if detected_iface.is_some() {
                        break;
                    }
                }

                // Second pass: find the AF_LINK (MAC) entry for that interface.
                if let Some(ref iface_name) = detected_iface {
                    cur = ifaddrs_ptr;
                    while !cur.is_null() {
                        let ifa = unsafe { &*cur };
                        if !ifa.ifa_addr.is_null() {
                            let sa = unsafe { &*ifa.ifa_addr };
                            if sa.sa_family == libc::AF_LINK as u8 {
                                let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                                    .to_string_lossy();
                                if name == iface_name.as_str() {
                                    let sdl = unsafe {
                                        &*(ifa.ifa_addr as *const libc::sockaddr_dl)
                                    };
                                    if sdl.sdl_alen == 6 {
                                        let mac_ptr = unsafe {
                                            (sdl as *const libc::sockaddr_dl as *const u8)
                                                .add(sdl.sdl_nlen as usize
                                                    + std::mem::offset_of!(libc::sockaddr_dl, sdl_data))
                                        };
                                        let mut mac = [0u8; 6];
                                        unsafe {
                                            std::ptr::copy_nonoverlapping(mac_ptr, mac.as_mut_ptr(), 6);
                                        }
                                        info!(
                                            interface = %iface_name,
                                            mac = %format!(
                                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                                            ),
                                            "detected interface MAC"
                                        );
                                        detected_mac = Some(mac);
                                        break;
                                    }
                                }
                            }
                        }
                        cur = unsafe { (*cur).ifa_next };
                    }
                }

                unsafe { libc::freeifaddrs(ifaddrs_ptr); }
            }
        }

        // -----------------------------------------------------------------
        // Build the DhcpSender: prefer BPF on FreeBSD, fall back to UDP.
        // -----------------------------------------------------------------
        #[cfg(target_os = "freebsd")]
        let sender: Arc<DhcpSender> = {
            match (&detected_iface, &detected_mac) {
                (Some(iface), Some(mac)) => {
                    match BpfSender::open(iface, *mac, send_bind_ip) {
                        Ok(bpf) => {
                            info!("using BPF raw-frame sender for DHCPv4 replies");
                            Arc::new(DhcpSender::Bpf(Arc::new(bpf)))
                        }
                        Err(e) => {
                            warn!(error = %e, "BPF open failed, falling back to UDP sender");
                            Arc::new(DhcpSender::Udp(build_udp_send_socket(send_bind_ip, dhcpv4_port)?))
                        }
                    }
                }
                _ => {
                    warn!("could not detect interface/MAC, falling back to UDP sender");
                    Arc::new(DhcpSender::Udp(build_udp_send_socket(send_bind_ip, dhcpv4_port)?))
                }
            }
        };

        #[cfg(not(target_os = "freebsd"))]
        let sender: Arc<DhcpSender> = Arc::new(DhcpSender::Udp(
            build_udp_send_socket(send_bind_ip, dhcpv4_port)?,
        ));

        // -----------------------------------------------------------------
        // Spawn receive workers
        // -----------------------------------------------------------------
        for worker_id in 0..worker_count {
            let bcast_bind = format!("255.255.255.255:{}", dhcpv4_port);
            let any_bind = format!("0.0.0.0:{}", dhcpv4_port);

            // Build sockets. On FreeBSD we need BOTH a 255.255.255.255:67
            // socket (to receive link-layer broadcasts — the only way FreeBSD
            // will deliver them to a UDP socket) AND a 0.0.0.0:67 socket (to
            // receive unicast packets from a DHCP relay). On other platforms
            // a single 0.0.0.0:67 catches both.
            let mut sockets: Vec<Arc<UdpSocket>> = Vec::new();
            #[cfg(target_os = "freebsd")]
            {
                sockets.push(build_recv_socket(&bcast_bind, true)?);
                sockets.push(build_recv_socket(&any_bind, false)?);
            }
            #[cfg(not(target_os = "freebsd"))]
            {
                let _ = &bcast_bind; // unused on non-FreeBSD
                sockets.push(build_recv_socket(&any_bind, false)?);
            }

            let dhcpv4_server = Arc::new(DhcpV4Server::new(
                config.clone(),
                lease_store.clone(),
                allocators.clone(),
                wal.clone(),
                ha.clone(),
                server_ip,
                rate_limiter.clone(),
                global_rate_limiter.clone(),
                rogue_detector.clone(),
                relay_rate_limiter.clone(),
                dhcpv4_stats.clone(),
            ));

            for (sock_idx, recv_socket) in sockets.into_iter().enumerate() {
                let server = dhcpv4_server.clone();
                let worker_sender = sender.clone();
                dhcpv4_handles.push(tokio::spawn(async move {
                    if let Err(e) = server.run(recv_socket, worker_sender).await {
                        error!(error = %e, worker = worker_id, sock_idx, "DHCPv4 server error");
                    }
                }));
            }
        }
        info!(workers = worker_count, "DHCPv4 workers started");
    } else {
        info!("no IPv4 subnets configured, DHCPv4 disabled");
    }

    // Start DHCPv6 server if v6 subnets configured
    let mut dhcpv6_handles = Vec::new();
    if has_v6 {
        let server_duid = generate_server_duid();
        info!(duid_len = server_duid.len(), "server DUID generated");
        let server_duid: Arc<[u8]> = Arc::from(server_duid);

        for worker_id in 0..worker_count {
            let sock = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .map_err(|e| format!("failed to create DHCPv6 socket: {}", e))?;
            sock.set_reuse_port(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&"[::]:547".parse::<std::net::SocketAddr>().unwrap().into())
                .map_err(|e| format!("failed to bind DHCPv6 port 547: {} (try running as root)", e))?;
            let dhcpv6_socket = Arc::new(UdpSocket::from_std(sock.into())?);

            let dhcpv6_server = DhcpV6Server::new(
                config.clone(),
                lease_store.clone(),
                allocators.clone(),
                wal.clone(),
                ha.clone(),
                server_duid.to_vec(),
                rate_limiter.clone(),
                global_rate_limiter.clone(),
                rogue_detector.clone(),
            );

            dhcpv6_handles.push(tokio::spawn(async move {
                if let Err(e) = dhcpv6_server.run(dhcpv6_socket).await {
                    error!(error = %e, worker = worker_id, "DHCPv6 server error");
                }
            }));
        }
        info!(workers = worker_count, "DHCPv6 workers started");
    } else {
        info!("no IPv6 subnets configured, DHCPv6 disabled");
    }

    info!(
        server_ip = %server_ip,
        v4 = has_v4,
        v6 = has_v6,
        "rdhcpd started"
    );

    // Set up SIGHUP handler for config reload
    let reload_config_path = config_path.clone();
    tokio::spawn(async move {
        let mut sighup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();

        loop {
            sighup.recv().await;
            info!("SIGHUP received, reloading configuration");

            match Config::load(&reload_config_path) {
                Ok(_new_config) => {
                    info!("configuration validated successfully (hot reload not yet implemented — restart required to apply changes)");
                }
                Err(e) => {
                    error!(error = %e, "configuration validation failed");
                }
            }
        }
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("shutting down — flushing WAL before stopping tasks");

    // Flush WAL FIRST while tasks are still alive, so pending writes land
    wal.flush().await?;

    // Then abort tasks
    for h in dhcpv4_handles {
        h.abort();
    }
    for h in dhcpv6_handles {
        h.abort();
    }
    if let Some(h) = api_handle {
        h.abort();
    }
    expiry_handle.abort();

    // Final WAL flush in case any last writes snuck in
    wal.flush().await?;
    info!("WAL flushed, goodbye");

    Ok(())
}

/// Create a UDP receive socket for DHCPv4.
///
/// On FreeBSD, `freebsd_bindany` enables IP_BINDANY so the socket can bind to
/// 255.255.255.255 (broadcast) or 0.0.0.0 (unicast relay) without holding those
/// addresses.  On non-FreeBSD the flag is ignored.
fn build_recv_socket(
    bind_addr: &str,
    freebsd_bindany: bool,
) -> Result<Arc<UdpSocket>, Box<dyn std::error::Error>> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| format!("failed to create DHCPv4 recv socket: {}", e))?;
    sock.set_reuse_port(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;

    #[cfg(target_os = "freebsd")]
    if freebsd_bindany {
        let enable: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                24, // IP_BINDANY
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
    #[cfg(not(target_os = "freebsd"))]
    let _ = freebsd_bindany;

    let addr: std::net::SocketAddr = bind_addr
        .parse()
        .map_err(|e| format!("invalid bind address {}: {}", bind_addr, e))?;
    sock.bind(&addr.into())
        .map_err(|e| format!("failed to bind DHCPv4 {}: {} (try running as root)", bind_addr, e))?;
    Ok(Arc::new(UdpSocket::from_std(sock.into())?))
}

/// Create a UDP send socket for DHCPv4 replies (fallback when BPF is unavailable).
fn build_udp_send_socket(
    bind_ip: Ipv4Addr,
    port: u16,
) -> Result<Arc<UdpSocket>, Box<dyn std::error::Error>> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| format!("failed to create DHCPv4 send socket: {}", e))?;
    sock.set_reuse_port(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;

    let addr: std::net::SocketAddr = format!("{}:{}", bind_ip, port).parse().unwrap();
    sock.bind(&addr.into()).or_else(|_| {
        info!(
            "could not bind send socket to {}, falling back to 0.0.0.0",
            bind_ip
        );
        sock.bind(
            &format!("0.0.0.0:{}", port)
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
    })?;

    Ok(Arc::new(UdpSocket::from_std(sock.into())?))
}
