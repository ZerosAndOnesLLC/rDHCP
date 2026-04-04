//! Write-ahead log for crash-safe lease persistence.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use thiserror::Error;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::sync::Mutex;
use tracing::warn;

use crate::lease::store::LeaseStore;
use crate::lease::types::{Lease, LeaseState};

/// Errors that can occur during WAL operations.
#[derive(Debug, Error)]
pub enum WalError {
    /// An I/O error occurred while reading or writing the WAL file.
    #[error("WAL I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A corrupt entry was detected during WAL replay.
    #[error("WAL corrupt entry at offset {offset}: {reason}")]
    Corrupt {
        /// Byte offset where corruption was detected
        offset: u64,
        /// Description of the corruption
        reason: String,
    },
}

/// WAL entry operation types
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalOp {
    /// Lease created or renewed
    Upsert = 1,
    /// Lease removed (released/expired)
    Remove = 2,
    /// State change only
    StateChange = 3,
}

impl WalOp {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Upsert),
            2 => Some(Self::Remove),
            3 => Some(Self::StateChange),
            _ => None,
        }
    }
}

/// WAL entry binary layout:
///
/// ```text
/// [op: 1] [ip_version: 1] [ip: 4 or 16] [state: 1]
/// [mac_present: 1] [mac: 0 or 6]
/// [client_id_len: 2] [client_id: 0..N]
/// [hostname_len: 2] [hostname: 0..N]
/// [lease_time: 4] [start_time: 8] [expire_time: 8]
/// [subnet_len: 2] [subnet: 0..N]
/// [crc32: 4]
/// ```
///
/// For Remove/StateChange entries, only [op, ip_version, ip, state, crc32] are written.
///
/// **Security note**: CRC32 detects accidental corruption only. It provides no
/// protection against deliberate tampering — an attacker with filesystem write
/// access can craft entries with valid CRC32 checksums. Protect the WAL directory
/// with filesystem permissions (the systemd unit restricts writes to /var/lib/rdhcpd).

/// Maximum allowed length for variable-length WAL fields.
/// Prevents excessive memory allocation from corrupted/crafted WAL files.
const MAX_CLIENT_ID_LEN: usize = 1024;
const MAX_HOSTNAME_LEN: usize = 255;
const MAX_SUBNET_LEN: usize = 256;

/// Write-ahead log for lease durability
pub struct Wal {
    writer: Mutex<BufWriter<File>>,
    path: PathBuf,
}

impl Wal {
    /// Open or create the WAL file
    pub async fn open(dir: &str) -> Result<Self, WalError> {
        let dir_path = Path::new(dir);
        fs::create_dir_all(dir_path).await?;

        let wal_path = dir_path.join("wal.bin");

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .await?;

        Ok(Self {
            writer: Mutex::new(BufWriter::new(file)),
            path: wal_path,
        })
    }

    /// Replay the WAL to rebuild the lease store. Returns number of entries replayed.
    pub async fn replay(&self, store: &LeaseStore) -> Result<usize, WalError> {
        let file = match File::open(&self.path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };

        let metadata = file.metadata().await?;
        if metadata.len() == 0 {
            return Ok(0);
        }

        let mut reader = BufReader::new(file);
        let mut count = 0u64;

        loop {
            match Self::read_entry(&mut reader).await {
                Ok(Some(entry)) => {
                    Self::apply_entry(store, entry);
                    count += 1;
                }
                Ok(None) => break, // EOF
                Err(WalError::Corrupt {
                    offset: err_offset,
                    reason,
                }) => {
                    warn!(
                        offset = err_offset,
                        reason, "corrupt WAL entry, stopping replay"
                    );
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(count as usize)
    }

    /// Append a lease upsert to the WAL
    pub async fn log_upsert(&self, lease: &Lease) -> Result<(), WalError> {
        let data = Self::encode_upsert(lease);
        let mut writer = self.writer.lock().await;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Append a lease removal to the WAL
    pub async fn log_remove(&self, ip: &IpAddr) -> Result<(), WalError> {
        let data = Self::encode_short(WalOp::Remove, ip, LeaseState::Released);
        let mut writer = self.writer.lock().await;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Append a state change to the WAL
    pub async fn log_state_change(&self, ip: &IpAddr, state: LeaseState) -> Result<(), WalError> {
        let data = Self::encode_short(WalOp::StateChange, ip, state);
        let mut writer = self.writer.lock().await;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Flush buffers to disk
    pub async fn flush(&self) -> Result<(), WalError> {
        let mut writer = self.writer.lock().await;
        writer.flush().await?;
        Ok(())
    }

    /// Compact the WAL by rewriting it with only the current active leases.
    /// Call after replay to reclaim space from expired/released/duplicate entries.
    pub async fn compact(&self, store: &LeaseStore) -> Result<usize, WalError> {
        // Hold the writer lock for the entire operation to prevent new entries
        // from being written to the old WAL between the snapshot and the rename.
        let mut writer = self.writer.lock().await;

        // Flush any buffered writes to the old WAL before replacing it
        writer.flush().await?;

        let tmp_path = self.path.with_extension("bin.tmp");

        // Write all active leases to a temporary file
        let tmp_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .await?;
        let mut tmp_writer = BufWriter::new(tmp_file);

        let leases = store.all_active_leases();
        let count = leases.len();

        for lease in &leases {
            let data = Self::encode_upsert(lease);
            tmp_writer.write_all(&data).await?;
        }
        tmp_writer.flush().await?;
        drop(tmp_writer);

        // Atomically replace the old WAL with the compacted one
        fs::rename(&tmp_path, &self.path).await?;

        // Reopen the writer pointing at the new file (append mode)
        let new_file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .await?;
        *writer = BufWriter::new(new_file);

        Ok(count)
    }

    fn encode_upsert(lease: &Lease) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);

        // Op
        buf.push(WalOp::Upsert as u8);

        // IP
        match lease.ip {
            IpAddr::V4(v4) => {
                buf.push(4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(6);
                buf.extend_from_slice(&v6.octets());
            }
        }

        // State
        buf.push(lease.state as u8);

        // MAC
        if let Some(mac) = lease.mac {
            buf.push(1);
            buf.extend_from_slice(&mac);
        } else {
            buf.push(0);
        }

        // Client ID
        if let Some(ref cid) = lease.client_id {
            let len = cid.len() as u16;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(cid);
        } else {
            buf.extend_from_slice(&0u16.to_le_bytes());
        }

        // Hostname
        if let Some(ref hostname) = lease.hostname {
            let bytes = hostname.as_bytes();
            let len = bytes.len() as u16;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(bytes);
        } else {
            buf.extend_from_slice(&0u16.to_le_bytes());
        }

        // Lease time, start, expire
        buf.extend_from_slice(&lease.lease_time.to_le_bytes());
        buf.extend_from_slice(&lease.start_time.to_le_bytes());
        buf.extend_from_slice(&lease.expire_time.to_le_bytes());

        // Subnet
        let subnet_bytes = lease.subnet.as_bytes();
        let len = subnet_bytes.len() as u16;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(subnet_bytes);

        // CRC32
        let crc = crc32fast::hash(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        buf
    }

    fn encode_short(op: WalOp, ip: &IpAddr, state: LeaseState) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);

        buf.push(op as u8);

        match ip {
            IpAddr::V4(v4) => {
                buf.push(4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(6);
                buf.extend_from_slice(&v6.octets());
            }
        }

        buf.push(state as u8);

        let crc = crc32fast::hash(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        buf
    }

    async fn read_entry(
        reader: &mut BufReader<File>,
    ) -> Result<Option<WalEntry>, WalError> {
        // Read op byte
        let op_byte = match read_u8(reader).await {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let op = WalOp::from_u8(op_byte).ok_or(WalError::Corrupt {
            offset: 0,
            reason: format!("invalid op byte: {}", op_byte),
        })?;

        // Read IP
        let ip_version = read_u8(reader).await?;
        let ip = match ip_version {
            4 => {
                let mut octets = [0u8; 4];
                reader.read_exact(&mut octets).await?;
                IpAddr::V4(octets.into())
            }
            6 => {
                let mut octets = [0u8; 16];
                reader.read_exact(&mut octets).await?;
                IpAddr::V6(octets.into())
            }
            _ => {
                return Err(WalError::Corrupt {
                    offset: 0,
                    reason: format!("invalid ip version: {}", ip_version),
                })
            }
        };

        // State
        let state_byte = read_u8(reader).await?;
        let state = LeaseState::from_u8(state_byte).ok_or(WalError::Corrupt {
            offset: 0,
            reason: format!("invalid state byte: {}", state_byte),
        })?;

        match op {
            WalOp::Remove | WalOp::StateChange => {
                // Read and verify CRC
                let mut crc_bytes = [0u8; 4];
                reader.read_exact(&mut crc_bytes).await?;
                let stored_crc = u32::from_le_bytes(crc_bytes);

                // Reconstruct data for CRC check
                let mut check_buf = Vec::new();
                check_buf.push(op_byte);
                check_buf.push(ip_version);
                match ip {
                    IpAddr::V4(v4) => check_buf.extend_from_slice(&v4.octets()),
                    IpAddr::V6(v6) => check_buf.extend_from_slice(&v6.octets()),
                }
                check_buf.push(state_byte);

                let computed_crc = crc32fast::hash(&check_buf);
                if stored_crc != computed_crc {
                    return Err(WalError::Corrupt {
                        offset: 0,
                        reason: "CRC mismatch".to_string(),
                    });
                }

                Ok(Some(WalEntry {
                    op,
                    ip,
                    state,
                    lease: None,
                }))
            }
            WalOp::Upsert => {
                // Track all bytes for CRC verification
                let mut all_bytes = Vec::new();
                all_bytes.push(op_byte);
                all_bytes.push(ip_version);
                match ip {
                    IpAddr::V4(v4) => all_bytes.extend_from_slice(&v4.octets()),
                    IpAddr::V6(v6) => all_bytes.extend_from_slice(&v6.octets()),
                }
                all_bytes.push(state_byte);

                // MAC
                let mac_present = read_u8(reader).await?;
                all_bytes.push(mac_present);
                let mac = if mac_present == 1 {
                    let mut m = [0u8; 6];
                    reader.read_exact(&mut m).await?;
                    all_bytes.extend_from_slice(&m);
                    Some(m)
                } else {
                    None
                };

                // Client ID
                let mut len_bytes = [0u8; 2];
                reader.read_exact(&mut len_bytes).await?;
                all_bytes.extend_from_slice(&len_bytes);
                let cid_len = u16::from_le_bytes(len_bytes) as usize;
                if cid_len > MAX_CLIENT_ID_LEN {
                    return Err(WalError::Corrupt {
                        offset: 0,
                        reason: format!("client_id length {} exceeds max {}", cid_len, MAX_CLIENT_ID_LEN),
                    });
                }
                let client_id = if cid_len > 0 {
                    let mut cid = vec![0u8; cid_len];
                    reader.read_exact(&mut cid).await?;
                    all_bytes.extend_from_slice(&cid);
                    Some(cid)
                } else {
                    None
                };

                // Hostname
                reader.read_exact(&mut len_bytes).await?;
                all_bytes.extend_from_slice(&len_bytes);
                let hostname_len = u16::from_le_bytes(len_bytes) as usize;
                if hostname_len > MAX_HOSTNAME_LEN {
                    return Err(WalError::Corrupt {
                        offset: 0,
                        reason: format!("hostname length {} exceeds max {}", hostname_len, MAX_HOSTNAME_LEN),
                    });
                }
                let hostname = if hostname_len > 0 {
                    let mut hbuf = vec![0u8; hostname_len];
                    reader.read_exact(&mut hbuf).await?;
                    all_bytes.extend_from_slice(&hbuf);
                    // Only accept valid ASCII hostnames
                    if hbuf.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
                        Some(Arc::from(String::from_utf8_lossy(&hbuf).as_ref()))
                    } else {
                        None // Discard non-ASCII hostnames
                    }
                } else {
                    None
                };

                // Lease time
                let mut u32_bytes = [0u8; 4];
                reader.read_exact(&mut u32_bytes).await?;
                all_bytes.extend_from_slice(&u32_bytes);
                let lease_time = u32::from_le_bytes(u32_bytes);

                // Start time
                let mut u64_bytes = [0u8; 8];
                reader.read_exact(&mut u64_bytes).await?;
                all_bytes.extend_from_slice(&u64_bytes);
                let start_time = u64::from_le_bytes(u64_bytes);

                // Expire time
                reader.read_exact(&mut u64_bytes).await?;
                all_bytes.extend_from_slice(&u64_bytes);
                let expire_time = u64::from_le_bytes(u64_bytes);

                // Subnet
                reader.read_exact(&mut len_bytes).await?;
                all_bytes.extend_from_slice(&len_bytes);
                let subnet_len = u16::from_le_bytes(len_bytes) as usize;
                if subnet_len > MAX_SUBNET_LEN {
                    return Err(WalError::Corrupt {
                        offset: 0,
                        reason: format!("subnet length {} exceeds max {}", subnet_len, MAX_SUBNET_LEN),
                    });
                }
                let mut subnet_buf = vec![0u8; subnet_len];
                reader.read_exact(&mut subnet_buf).await?;
                all_bytes.extend_from_slice(&subnet_buf);
                let subnet: Arc<str> = Arc::from(String::from_utf8_lossy(&subnet_buf).as_ref());

                // CRC
                let mut crc_bytes = [0u8; 4];
                reader.read_exact(&mut crc_bytes).await?;
                let stored_crc = u32::from_le_bytes(crc_bytes);
                let computed_crc = crc32fast::hash(&all_bytes);

                if stored_crc != computed_crc {
                    return Err(WalError::Corrupt {
                        offset: 0,
                        reason: "CRC mismatch".to_string(),
                    });
                }

                // Compute expires_at from remaining time
                let now_epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let remaining = expire_time.saturating_sub(now_epoch);
                let expires_at =
                    std::time::Instant::now() + std::time::Duration::from_secs(remaining);

                Ok(Some(WalEntry {
                    op,
                    ip,
                    state,
                    lease: Some(Lease {
                        ip,
                        mac,
                        client_id,
                        hostname,
                        lease_time,
                        state,
                        start_time,
                        expire_time,
                        expires_at,
                        subnet,
                    }),
                }))
            }
        }
    }

    fn apply_entry(store: &LeaseStore, entry: WalEntry) {
        match entry.op {
            WalOp::Upsert => {
                if let Some(lease) = entry.lease {
                    store.upsert(lease);
                }
            }
            WalOp::Remove => {
                store.remove(&entry.ip);
            }
            WalOp::StateChange => {
                store.update_state(&entry.ip, entry.state);
            }
        }
    }
}

struct WalEntry {
    op: WalOp,
    ip: IpAddr,
    state: LeaseState,
    lease: Option<Lease>,
}

async fn read_u8(reader: &mut BufReader<File>) -> Result<u8, std::io::Error> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).await?;
    Ok(buf[0])
}
