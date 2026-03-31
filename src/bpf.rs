//! BPF raw-frame sender for FreeBSD.
//!
//! Opens `/dev/bpfN`, attaches to a network interface, and sends raw Ethernet
//! frames containing IP/UDP/DHCP payloads.  This bypasses the kernel's IP
//! stack so we can unicast DHCP replies directly to a client's MAC address
//! without needing an ARP entry — essential for clients that don't have an
//! IP address yet (DHCPOFFER / DHCPACK to new clients).

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use tracing::{debug, info};

// ---------------------------------------------------------------------------
// FreeBSD BPF ioctl constants
//
// Computed from <net/bpf.h>:
//   _IOW(g,n,t) = 0x80000000 | ((sizeof(t) & 0x1fff) << 16) | (g << 8) | n
//   _IOR(g,n,t) = 0x40000000 | ((sizeof(t) & 0x1fff) << 16) | (g << 8) | n
// ---------------------------------------------------------------------------

/// `BIOCSETIF` — attach BPF to a network interface.
/// `_IOW('B', 108, struct ifreq)` where `sizeof(struct ifreq) = 32`.
const BIOCSETIF: libc::c_ulong = 0x8020426c;

/// `BIOCSHDRCMPLT` — tell BPF we supply complete Ethernet headers.
/// `_IOW('B', 117, u_int)` where `sizeof(u_int) = 4`.
const BIOCSHDRCMPLT: libc::c_ulong = 0x80044275;

/// `BIOCGBLEN` — query the BPF device's kernel buffer length.
/// `_IOR('B', 102, u_int)`.
#[allow(dead_code)]
const BIOCGBLEN: libc::c_ulong = 0x40044266;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Ethernet header size (dst MAC + src MAC + ethertype).
const ETH_HLEN: usize = 14;
/// IPv4 header size (no options).
const IP_HLEN: usize = 20;
/// UDP header size.
const UDP_HLEN: usize = 8;
/// Total link + transport overhead before the DHCP payload.
const FRAME_OVERHEAD: usize = ETH_HLEN + IP_HLEN + UDP_HLEN;

/// EtherType for IPv4.
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];

/// Broadcast MAC address.
const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// Maximum raw frame size (Ethernet MTU).
const MAX_FRAME: usize = 1514;

// ---------------------------------------------------------------------------
// FreeBSD `struct ifreq` layout for BIOCSETIF
// ---------------------------------------------------------------------------

/// Minimal `ifreq` for BIOCSETIF — only the interface name matters.
/// FreeBSD: IFNAMSIZ = 16, total struct = 32 bytes.
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    _pad: [u8; 16],
}

// ---------------------------------------------------------------------------
// BpfSender
// ---------------------------------------------------------------------------

/// Sends raw Ethernet frames via a FreeBSD BPF device.
///
/// Thread-safety: the underlying `write()` on a BPF fd is atomic for frames
/// that fit in one buffer, so concurrent writes from multiple tokio tasks are
/// safe.  We wrap the fd in `OwnedFd` for RAII cleanup.
pub struct BpfSender {
    fd: OwnedFd,
    /// Source (server) MAC address — used as Ethernet src in every frame.
    src_mac: [u8; 6],
    /// Source (server) IPv4 address — used as IP src in every frame.
    src_ip: Ipv4Addr,
}

impl BpfSender {
    /// Open a BPF device, attach it to `iface`, and configure it for raw
    /// frame injection.
    ///
    /// # Arguments
    /// * `iface` — network interface name (e.g. `"vtnet0"`).
    /// * `src_mac` — the interface's hardware (MAC) address.
    /// * `src_ip` — the server's IPv4 address on this interface.
    pub fn open(iface: &str, src_mac: [u8; 6], src_ip: Ipv4Addr) -> std::io::Result<Self> {
        // Try /dev/bpf0 .. /dev/bpf255 until one opens.
        let fd = Self::open_bpf_device()?;

        // Attach to the requested network interface.
        Self::attach_interface(fd.as_raw_fd(), iface)?;

        // Tell BPF we provide complete Ethernet headers (including src MAC).
        Self::set_hdrcmplt(fd.as_raw_fd())?;

        info!(
            interface = iface,
            src_mac = %format_mac(&src_mac),
            src_ip = %src_ip,
            "BPF sender ready"
        );

        Ok(Self { fd, src_mac, src_ip })
    }

    /// Send a serialized DHCP payload as a raw Ethernet frame.
    ///
    /// Constructs: `Ethernet(14) | IPv4(20) | UDP(8) | dhcp_payload`.
    ///
    /// # Arguments
    /// * `dhcp_payload` — the already-serialized DHCP packet bytes.
    /// * `dest_mac` — destination Ethernet address (client's chaddr or broadcast).
    /// * `dest_ip` — destination IPv4 address (yiaddr or 255.255.255.255).
    pub fn send_dhcp(
        &self,
        dhcp_payload: &[u8],
        dest_mac: [u8; 6],
        dest_ip: Ipv4Addr,
    ) -> std::io::Result<usize> {
        let total_len = FRAME_OVERHEAD + dhcp_payload.len();
        if total_len > MAX_FRAME {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("frame too large: {} bytes (max {})", total_len, MAX_FRAME),
            ));
        }

        let mut frame = [0u8; MAX_FRAME];
        let mut pos = 0;

        // --- Ethernet header (14 bytes) ---
        frame[pos..pos + 6].copy_from_slice(&dest_mac);
        pos += 6;
        frame[pos..pos + 6].copy_from_slice(&self.src_mac);
        pos += 6;
        frame[pos..pos + 2].copy_from_slice(&ETHERTYPE_IPV4);
        pos += 2;

        // --- IPv4 header (20 bytes) ---
        let ip_total_len = (IP_HLEN + UDP_HLEN + dhcp_payload.len()) as u16;

        frame[pos] = 0x45; // version 4, IHL 5 (20 bytes)
        frame[pos + 1] = 0x10; // DSCP: low-delay
        frame[pos + 2..pos + 4].copy_from_slice(&ip_total_len.to_be_bytes());
        // identification = 0
        frame[pos + 6..pos + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag
        frame[pos + 8] = 128; // TTL
        frame[pos + 9] = 17; // protocol: UDP
        // checksum at [pos+10..pos+12] — filled after
        frame[pos + 12..pos + 16].copy_from_slice(&self.src_ip.octets());
        frame[pos + 16..pos + 20].copy_from_slice(&dest_ip.octets());

        // Compute and fill IP header checksum.
        let ip_csum = ip_checksum(&frame[pos..pos + IP_HLEN]);
        frame[pos + 10..pos + 12].copy_from_slice(&ip_csum.to_be_bytes());
        pos += IP_HLEN;

        // --- UDP header (8 bytes) ---
        let udp_len = (UDP_HLEN + dhcp_payload.len()) as u16;

        frame[pos..pos + 2].copy_from_slice(&67u16.to_be_bytes()); // src port (server)
        frame[pos + 2..pos + 4].copy_from_slice(&68u16.to_be_bytes()); // dst port (client)
        frame[pos + 4..pos + 6].copy_from_slice(&udp_len.to_be_bytes());
        // UDP checksum = 0 (optional in IPv4, RFC 768)
        pos += UDP_HLEN;

        // --- DHCP payload ---
        frame[pos..pos + dhcp_payload.len()].copy_from_slice(dhcp_payload);

        // Write the complete frame to the BPF device.
        let written = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                total_len,
            )
        };

        if written < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            debug!(
                dest_mac = %format_mac(&dest_mac),
                dest_ip = %dest_ip,
                frame_len = total_len,
                "BPF frame sent"
            );
            Ok(written as usize)
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Try `/dev/bpf0` through `/dev/bpf255` until one can be opened.
    fn open_bpf_device() -> std::io::Result<OwnedFd> {
        for i in 0..256u32 {
            let path = CString::new(format!("/dev/bpf{}", i)).unwrap();
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY) };
            if fd >= 0 {
                debug!(device = %format!("/dev/bpf{}", i), "opened BPF device");
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
            // EBUSY = already in use, try next.  Anything else = skip.
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EBUSY) && i > 10 {
                // After /dev/bpf10 if we're hitting ENOENT, the system
                // probably doesn't have more devices.
                if err.raw_os_error() == Some(libc::ENOENT) {
                    break;
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no available BPF device (/dev/bpf0../dev/bpf255 all busy or missing)",
        ))
    }

    /// `BIOCSETIF` — attach the BPF descriptor to a network interface.
    fn attach_interface(fd: i32, iface: &str) -> std::io::Result<()> {
        let mut ifr = Ifreq {
            ifr_name: [0u8; 16],
            _pad: [0u8; 16],
        };
        let name_bytes = iface.as_bytes();
        let copy_len = name_bytes.len().min(15); // leave room for null terminator
        ifr.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let ret = unsafe { libc::ioctl(fd, BIOCSETIF, &ifr as *const Ifreq) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// `BIOCSHDRCMPLT` — tell BPF we supply the full Ethernet header.
    fn set_hdrcmplt(fd: i32) -> std::io::Result<()> {
        let enable: libc::c_uint = 1;
        let ret = unsafe {
            libc::ioctl(fd, BIOCSHDRCMPLT, &enable as *const libc::c_uint)
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// RFC 1071 Internet checksum over a byte slice (must be even length).
fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    // Fold 32-bit sum to 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Format a 6-byte MAC for display.
struct MacFmt([u8; 6]);

impl std::fmt::Display for MacFmt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

#[inline]
fn format_mac(mac: &[u8; 6]) -> MacFmt {
    MacFmt(*mac)
}

/// Broadcast MAC constant — re-exported for callers deciding the dest MAC.
pub const BROADCAST_ETH: [u8; 6] = BROADCAST_MAC;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_checksum_rfc_example() {
        // Example from RFC 1071: 20-byte IP header with known checksum.
        // Build a minimal header and verify the checksum is correct.
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45;
        hdr[1] = 0x00;
        // total length = 60
        hdr[2..4].copy_from_slice(&60u16.to_be_bytes());
        // id = 1
        hdr[4..6].copy_from_slice(&1u16.to_be_bytes());
        // flags + frag = 0x4000
        hdr[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        hdr[8] = 64; // TTL
        hdr[9] = 17; // UDP
        // checksum = 0 for computation
        // src = 192.168.1.1
        hdr[12..16].copy_from_slice(&Ipv4Addr::new(192, 168, 1, 1).octets());
        // dst = 10.0.0.1
        hdr[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());

        let csum = ip_checksum(&hdr);

        // Verify: if we put the checksum back in and re-compute, result should be 0.
        hdr[10..12].copy_from_slice(&csum.to_be_bytes());
        let verify = ip_checksum(&hdr);
        assert_eq!(verify, 0, "checksum verification failed");
    }

    #[test]
    fn test_ip_checksum_all_zeros() {
        let hdr = [0u8; 20];
        let csum = ip_checksum(&hdr);
        assert_eq!(csum, 0xffff);
    }

    #[test]
    fn test_frame_too_large() {
        // Attempting to send a payload that exceeds the Ethernet MTU should fail.
        let big_payload = vec![0u8; MAX_FRAME]; // way too big with overhead
        let sender = BpfSender {
            // We can't actually open a BPF device in CI, but we can test the
            // size check without sending.
            fd: unsafe { OwnedFd::from_raw_fd(-1) }, // dummy fd
            src_mac: [0; 6],
            src_ip: Ipv4Addr::UNSPECIFIED,
        };
        let result = sender.send_dhcp(&big_payload, [0xff; 6], Ipv4Addr::BROADCAST);
        assert!(result.is_err());
        // Don't drop the sender — the dummy fd would cause close(-1) which is
        // harmless but noisy.  Leak it instead.
        std::mem::forget(sender);
    }

    #[test]
    fn test_broadcast_mac_constant() {
        assert_eq!(BROADCAST_ETH, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }
}
