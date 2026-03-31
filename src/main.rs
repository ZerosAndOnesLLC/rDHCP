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
use rdhcpd::wal::Wal;
use tokio::net::UdpSocket;
#[cfg(target_os = "freebsd")]
use tracing::{error, info, warn};
#[cfg(not(target_os = "freebsd"))]
use tracing::{error, info};

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

    // Initialize allocators from config and lease state
    let allocators = Arc::new(allocator::build_allocators(&config, &lease_store)?);
    info!(subnets = allocators.len(), "subnet allocators initialized");

    // Initialize HA backend
    // TODO: select based on config.ha (active-active / raft)
    let ha: Arc<StandaloneBackend> = Arc::new(StandaloneBackend);

    let config = Arc::new(config);

    // Start lease expiry background task
    let expiry_store = lease_store.clone();
    let expiry_handle = tokio::spawn(async move {
        lease::expiry::run_expiry_task(expiry_store).await;
    });

    // Start management API if configured
    let api_handle = if let Some(ref api_config) = config.api {
        let api_state = Arc::new(ApiState {
            lease_store: lease_store.clone(),
            allocators: allocators.clone(),
            ha: ha.clone(),
            api_key: api_config.api_key.clone(),
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

    // DHCPv4 port — default 67, override with RDHCPD_V4_PORT for benchmarking
    let dhcpv4_port: u16 = std::env::var("RDHCPD_V4_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(67);

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
            let recv_sock = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .map_err(|e| format!("failed to create DHCPv4 recv socket: {}", e))?;
            recv_sock.set_reuse_port(true)?;
            recv_sock.set_broadcast(true)?;
            recv_sock.set_nonblocking(true)?;

            // FreeBSD: enable IP_BINDANY and bind to 255.255.255.255 so the socket
            // receives broadcast DHCP packets (FreeBSD UDP sockets bound to 0.0.0.0
            // don't receive link-layer broadcasts)
            #[cfg(target_os = "freebsd")]
            {
                let enable: libc::c_int = 1;
                unsafe {
                    libc::setsockopt(
                        recv_sock.as_raw_fd(),
                        libc::IPPROTO_IP,
                        24, // IP_BINDANY
                        &enable as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }

            #[cfg(target_os = "freebsd")]
            let bind_addr: std::net::SocketAddr = format!("255.255.255.255:{}", dhcpv4_port).parse().unwrap();
            #[cfg(not(target_os = "freebsd"))]
            let bind_addr: std::net::SocketAddr = format!("0.0.0.0:{}", dhcpv4_port).parse().unwrap();
            recv_sock.bind(&bind_addr.into())
                .map_err(|e| format!("failed to bind DHCPv4 port {}: {} (try running as root)", dhcpv4_port, e))?;
            let recv_socket = Arc::new(UdpSocket::from_std(recv_sock.into())?);

            let dhcpv4_server = DhcpV4Server::new(
                config.clone(),
                lease_store.clone(),
                allocators.clone(),
                wal.clone(),
                ha.clone(),
                server_ip,
            );

            let worker_sender = sender.clone();
            dhcpv4_handles.push(tokio::spawn(async move {
                if let Err(e) = dhcpv4_server.run(recv_socket, worker_sender).await {
                    error!(error = %e, worker = worker_id, "DHCPv4 server error");
                }
            }));
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
                    info!("configuration reloaded successfully");
                    // Note: subnet/pool changes require restart.
                    // SIGHUP reloads options, reservations, and logging config.
                }
                Err(e) => {
                    error!(error = %e, "failed to reload configuration, keeping current");
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
