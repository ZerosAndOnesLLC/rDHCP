use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use crate::config::Config;
use crate::lease::store::LeaseStore;

/// Bitmap-based IP address allocator for a single subnet pool.
///
/// Uses a bit vector where each bit represents an IP in the pool range.
/// Bit = 1 means allocated, bit = 0 means available.
/// Finding a free IP is O(N/64) worst case using 64-bit word scanning.
pub struct SubnetAllocator {
    /// First IP in the pool (as u128 for unified v4/v6 handling)
    pool_start: u128,
    /// Last IP in the pool
    pool_end: u128,
    /// Total number of IPs in pool
    pool_size: u64,
    /// Whether this is an IPv4 or IPv6 pool
    is_v4: bool,
    /// Bitmap: each bit represents one IP. Index 0 = pool_start.
    bitmap: Mutex<Vec<u64>>,
    /// Number of currently allocated IPs
    allocated_count: std::sync::atomic::AtomicU64,
    /// Hint for next free search (last allocated index + 1), for sequential allocation
    next_hint: std::sync::atomic::AtomicU64,
}

impl SubnetAllocator {
    /// Create a new allocator for the given pool range
    pub fn new(pool_start: IpAddr, pool_end: IpAddr) -> Self {
        let (start_u128, is_v4) = ip_to_u128(&pool_start);
        let end_u128 = ip_to_u128(&pool_end).0;

        let pool_size = end_u128 - start_u128 + 1;
        let num_words = ((pool_size + 63) / 64) as usize;

        Self {
            pool_start: start_u128,
            pool_end: end_u128,
            pool_size: pool_size as u64,
            is_v4,
            bitmap: Mutex::new(vec![0u64; num_words]),
            allocated_count: std::sync::atomic::AtomicU64::new(0),
            next_hint: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Allocate the next available IP from the pool.
    /// Returns None if pool is exhausted.
    pub fn allocate(&self) -> Option<IpAddr> {
        let mut bitmap = self.bitmap.lock().unwrap();
        let hint = self.next_hint.load(std::sync::atomic::Ordering::Relaxed);

        // Search from hint position, wrapping around
        if let Some(idx) = self.find_free(&bitmap, hint as usize) {
            self.set_bit(&mut bitmap, idx);
            self.allocated_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.next_hint
                .store((idx + 1) as u64, std::sync::atomic::Ordering::Relaxed);
            Some(self.index_to_ip(idx))
        } else if hint > 0 {
            // Wrap around and search from beginning
            if let Some(idx) = self.find_free(&bitmap, 0) {
                self.set_bit(&mut bitmap, idx);
                self.allocated_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.next_hint
                    .store((idx + 1) as u64, std::sync::atomic::Ordering::Relaxed);
                Some(self.index_to_ip(idx))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Allocate a specific IP address. Returns false if already allocated or out of range.
    pub fn allocate_specific(&self, ip: &IpAddr) -> bool {
        let ip_u128 = ip_to_u128(ip).0;
        if ip_u128 < self.pool_start || ip_u128 > self.pool_end {
            return false;
        }
        let idx = (ip_u128 - self.pool_start) as usize;

        let mut bitmap = self.bitmap.lock().unwrap();
        if self.get_bit(&bitmap, idx) {
            return false; // Already allocated
        }
        self.set_bit(&mut bitmap, idx);
        self.allocated_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        true
    }

    /// Release an IP back to the pool
    pub fn release(&self, ip: &IpAddr) {
        let ip_u128 = ip_to_u128(ip).0;
        if ip_u128 < self.pool_start || ip_u128 > self.pool_end {
            return;
        }
        let idx = (ip_u128 - self.pool_start) as usize;

        let mut bitmap = self.bitmap.lock().unwrap();
        if self.get_bit(&bitmap, idx) {
            self.clear_bit(&mut bitmap, idx);
            self.allocated_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Check if a specific IP is allocated
    pub fn is_allocated(&self, ip: &IpAddr) -> bool {
        let ip_u128 = ip_to_u128(ip).0;
        if ip_u128 < self.pool_start || ip_u128 > self.pool_end {
            return false;
        }
        let idx = (ip_u128 - self.pool_start) as usize;
        let bitmap = self.bitmap.lock().unwrap();
        self.get_bit(&bitmap, idx)
    }

    /// Check if a specific IP is within this pool's range
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let ip_u128 = ip_to_u128(ip).0;
        ip_u128 >= self.pool_start && ip_u128 <= self.pool_end
    }

    /// Number of allocated IPs
    pub fn allocated(&self) -> u64 {
        self.allocated_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Total pool capacity
    pub fn capacity(&self) -> u64 {
        self.pool_size
    }

    /// Number of available IPs
    pub fn available(&self) -> u64 {
        self.pool_size - self.allocated()
    }

    /// Utilization percentage (0.0 - 100.0)
    pub fn utilization(&self) -> f64 {
        if self.pool_size == 0 {
            return 0.0;
        }
        (self.allocated() as f64 / self.pool_size as f64) * 100.0
    }

    fn find_free(&self, bitmap: &[u64], start_idx: usize) -> Option<usize> {
        let start_word = start_idx / 64;
        let start_bit = start_idx % 64;
        let num_words = bitmap.len();

        // Check first partial word
        if start_word < num_words {
            let word = bitmap[start_word];
            if word != u64::MAX {
                // Mask off bits before start_bit
                let masked = word | ((1u64 << start_bit) - 1);
                if masked != u64::MAX {
                    let bit = (!masked).trailing_zeros() as usize;
                    let idx = start_word * 64 + bit;
                    if (idx as u64) < self.pool_size {
                        return Some(idx);
                    }
                }
            }
        }

        // Check subsequent full words
        for word_idx in (start_word + 1)..num_words {
            let word = bitmap[word_idx];
            if word != u64::MAX {
                let bit = (!word).trailing_zeros() as usize;
                let idx = word_idx * 64 + bit;
                if (idx as u64) < self.pool_size {
                    return Some(idx);
                }
            }
        }

        None
    }

    fn get_bit(&self, bitmap: &[u64], idx: usize) -> bool {
        let word = idx / 64;
        let bit = idx % 64;
        (bitmap[word] >> bit) & 1 == 1
    }

    fn set_bit(&self, bitmap: &mut [u64], idx: usize) {
        let word = idx / 64;
        let bit = idx % 64;
        bitmap[word] |= 1u64 << bit;
    }

    fn clear_bit(&self, bitmap: &mut [u64], idx: usize) {
        let word = idx / 64;
        let bit = idx % 64;
        bitmap[word] &= !(1u64 << bit);
    }

    fn index_to_ip(&self, idx: usize) -> IpAddr {
        let ip_u128 = self.pool_start + idx as u128;
        u128_to_ip(ip_u128, self.is_v4)
    }
}

fn ip_to_u128(ip: &IpAddr) -> (u128, bool) {
    match ip {
        IpAddr::V4(v4) => (u32::from_be_bytes(v4.octets()) as u128, true),
        IpAddr::V6(v6) => (u128::from_be_bytes(v6.octets()), false),
    }
}

fn u128_to_ip(val: u128, is_v4: bool) -> IpAddr {
    if is_v4 {
        IpAddr::V4(Ipv4Addr::from((val as u32).to_be_bytes()))
    } else {
        IpAddr::V6(Ipv6Addr::from(val.to_be_bytes()))
    }
}

/// Build allocators for all configured subnets, pre-marking IPs from existing leases
pub fn build_allocators(
    config: &Config,
    lease_store: &LeaseStore,
) -> Result<HashMap<String, SubnetAllocator>, Box<dyn std::error::Error>> {
    let mut allocators = HashMap::new();

    for subnet in &config.subnet {
        // Skip prefix delegation subnets for now (Phase 3)
        if subnet.subnet_type == "prefix-delegation" {
            continue;
        }

        let (pool_start, pool_end) = match (&subnet.pool_start, &subnet.pool_end) {
            (Some(s), Some(e)) => {
                let start: IpAddr = s.parse()?;
                let end: IpAddr = e.parse()?;
                (start, end)
            }
            _ => continue, // No pool defined, reservations only
        };

        let alloc = SubnetAllocator::new(pool_start, pool_end);

        // Pre-mark reserved IPs
        for res in &subnet.reservation {
            let res_ip: IpAddr = res.ip.parse()?;
            if alloc.contains(&res_ip) {
                alloc.allocate_specific(&res_ip);
            }
        }

        // Pre-mark existing leases
        let leases = lease_store.leases_for_subnet(&subnet.network);
        for lease in &leases {
            if lease.is_active() && alloc.contains(&lease.ip) {
                alloc.allocate_specific(&lease.ip);
            }
        }

        allocators.insert(subnet.network.clone(), alloc);
    }

    Ok(allocators)
}
