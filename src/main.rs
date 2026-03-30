#[cfg(target_os = "freebsd")]
use std::os::unix::io::AsRawFd;
use std::net::Ipv4Addr;
use std::sync::Arc;

use rdhcpd::{allocator, api, lease};
use rdhcpd::api::ApiState;
use rdhcpd::config::Config;
use rdhcpd::dhcpv4::server::DhcpV4Server;
use rdhcpd::dhcpv6::server::{generate_server_duid, DhcpV6Server};
use rdhcpd::ha::StandaloneBackend;
use rdhcpd::lease::store::LeaseStore;
use rdhcpd::wal::Wal;
use tokio::net::UdpSocket;
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
        // Create a shared send socket for DHCP replies
        // Bind to port 67 so replies have correct source port, use SO_REUSEPORT
        let send_sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ).map_err(|e| format!("failed to create DHCPv4 send socket: {}", e))?;
        send_sock.set_reuse_port(true)?;
        send_sock.set_broadcast(true)?;
        send_sock.set_nonblocking(true)?;

        // FreeBSD: use IP_BOUND_IF to direct broadcast replies out the correct
        // interface. Without this, broadcasts to 255.255.255.255 may go out the
        // default route interface instead of the DHCP subnet's interface.
        #[cfg(target_os = "freebsd")]
        {
            // Find interface index by iterating getifaddrs and matching against
            // configured subnet ranges
            let mut bound = false;
            let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
            if unsafe { libc::getifaddrs(&mut ifaddrs_ptr) } == 0 {
                let mut cur = ifaddrs_ptr;
                while !cur.is_null() {
                    let ifa = unsafe { &*cur };
                    if !ifa.ifa_addr.is_null() {
                        let sa = unsafe { &*ifa.ifa_addr };
                        if sa.sa_family == libc::AF_INET as u8 {
                            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            // Check if this interface IP falls within any configured subnet
                            for subnet in config.subnet.iter().filter(|s| s.network.contains('.')) {
                                if let Ok((net_addr, prefix)) = rdhcpd::config::validation::parse_cidr(&subnet.network) {
                                    if let std::net::IpAddr::V4(net_v4) = net_addr {
                                        let mask = if prefix >= 32 { u32::MAX } else { u32::MAX << (32 - prefix) };
                                        let ip_u32 = u32::from(ip);
                                        let net_u32 = u32::from(net_v4);
                                        if (ip_u32 & mask) == (net_u32 & mask) {
                                            let iface_name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) };
                                            let idx = unsafe { libc::if_nametoindex(ifa.ifa_name) };
                                            if idx > 0 {
                                                let if_idx = idx as libc::c_int;
                                                unsafe {
                                                    libc::setsockopt(
                                                        send_sock.as_raw_fd(),
                                                        libc::IPPROTO_IP,
                                                        25, // IP_BOUND_IF
                                                        &if_idx as *const _ as *const libc::c_void,
                                                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                                                    );
                                                }
                                                info!(
                                                    interface = %iface_name.to_string_lossy(),
                                                    ip = %ip,
                                                    subnet = %subnet.network,
                                                    "send socket bound to interface via IP_BOUND_IF"
                                                );
                                                bound = true;
                                            }
                                            break;
                                        }
                                    }
                                }
                            }
                            if bound { break; }
                        }
                    }
                    cur = unsafe { (*cur).ifa_next };
                }
                unsafe { libc::freeifaddrs(ifaddrs_ptr); }
            }
            if !bound {
                info!("could not determine DHCP interface for IP_BOUND_IF, broadcasts may go out wrong interface");
            }
        }

        send_sock.bind(&format!("0.0.0.0:{}", dhcpv4_port).parse::<std::net::SocketAddr>().unwrap().into())?;
        let send_socket = Arc::new(UdpSocket::from_std(send_sock.into())?);

        for worker_id in 0..worker_count {
            // Receive socket — platform-specific binding
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

            let worker_send = send_socket.clone();
            dhcpv4_handles.push(tokio::spawn(async move {
                if let Err(e) = dhcpv4_server.run(recv_socket, worker_send).await {
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
