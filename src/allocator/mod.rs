use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::config::Config;
use crate::lease::store::LeaseStore;

/// Bitmap-based IP address allocator for a single subnet pool.
///
/// Uses a bit vector where each bit represents an IP in the pool range.
/// Bit = 1 means allocated, bit = 0 means available.
/// Trailing bits beyond pool_size in the last word are pre-set to 1
/// to prevent out-of-bounds allocation.
pub struct SubnetAllocator {
    /// First IP in the pool (as u128 for unified v4/v6 handling)
    pool_start: u128,
    /// Total number of IPs in pool
    pool_size: u64,
    /// Whether this is an IPv4 or IPv6 pool
    is_v4: bool,
    /// Bitmap: each bit represents one IP. Index 0 = pool_start.
    /// Trailing bits in the last word are pre-set to 1.
    bitmap: Mutex<Vec<u64>>,
    /// Number of currently allocated IPs (atomic for lock-free reads)
    allocated_count: AtomicU64,
    /// Hint for next free search — avoids re-scanning from 0 each time
    next_hint: AtomicU64,
}

impl SubnetAllocator {
    /// Create a new allocator for the given pool range.
    /// Pre-marks trailing bits in the last word to prevent boundary overflow.
    pub fn new(pool_start: IpAddr, pool_end: IpAddr) -> Self {
        let (start_u128, is_v4) = ip_to_u128(&pool_start);
        let end_u128 = ip_to_u128(&pool_end).0;

        let pool_size = end_u128 - start_u128 + 1;
        let num_words = ((pool_size + 63) / 64) as usize;

        let mut bitmap = vec![0u64; num_words];

        // Pre-set trailing bits beyond pool_size in the last word.
        // This prevents find_free from returning an out-of-bounds index.
        let used_bits_in_last_word = (pool_size % 64) as u32;
        if used_bits_in_last_word != 0 && !bitmap.is_empty() {
            let last = bitmap.len() - 1;
            // Set all bits from used_bits_in_last_word..64 to 1
            bitmap[last] = !((1u64 << used_bits_in_last_word) - 1);
        }

        Self {
            pool_start: start_u128,
            pool_size: pool_size as u64,
            is_v4,
            bitmap: Mutex::new(bitmap),
            allocated_count: AtomicU64::new(0),
            next_hint: AtomicU64::new(0),
        }
    }

    /// Allocate the next available IP from the pool.
    /// Returns None if pool is exhausted.
    pub fn allocate(&self) -> Option<IpAddr> {
        let mut bitmap = self.bitmap.lock().unwrap();
        let hint = self.next_hint.load(Ordering::Relaxed) as usize;

        // Search from hint, then wrap around if needed
        let idx = self
            .find_free(&bitmap, hint)
            .or_else(|| if hint > 0 { self.find_free(&bitmap, 0) } else { None })?;

        self.set_bit(&mut bitmap, idx);
        self.allocated_count.fetch_add(1, Ordering::Relaxed);
        self.next_hint.store((idx + 1) as u64, Ordering::Relaxed);
        Some(self.index_to_ip(idx))
    }

    /// Allocate a specific IP address. Returns false if already allocated or out of range.
    pub fn allocate_specific(&self, ip: &IpAddr) -> bool {
        let idx = match self.ip_to_index(ip) {
            Some(i) => i,
            None => return false,
        };

        let mut bitmap = self.bitmap.lock().unwrap();
        if self.get_bit(&bitmap, idx) {
            return false;
        }
        self.set_bit(&mut bitmap, idx);
        self.allocated_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Release an IP back to the pool.
    pub fn release(&self, ip: &IpAddr) {
        let idx = match self.ip_to_index(ip) {
            Some(i) => i,
            None => return,
        };

        let mut bitmap = self.bitmap.lock().unwrap();
        if self.get_bit(&bitmap, idx) {
            self.clear_bit(&mut bitmap, idx);
            self.allocated_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Check if a specific IP is allocated (takes lock briefly).
    pub fn is_allocated(&self, ip: &IpAddr) -> bool {
        let idx = match self.ip_to_index(ip) {
            Some(i) => i,
            None => return false,
        };
        let bitmap = self.bitmap.lock().unwrap();
        self.get_bit(&bitmap, idx)
    }

    /// Check if a specific IP is within this pool's range (lock-free).
    #[inline]
    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ip_to_index(ip).is_some()
    }

    /// Number of allocated IPs (lock-free).
    #[inline]
    pub fn allocated(&self) -> u64 {
        self.allocated_count.load(Ordering::Relaxed)
    }

    /// Total pool capacity (lock-free).
    #[inline]
    pub fn capacity(&self) -> u64 {
        self.pool_size
    }

    /// Number of available IPs (lock-free).
    #[inline]
    pub fn available(&self) -> u64 {
        self.pool_size.saturating_sub(self.allocated())
    }

    /// Utilization percentage 0.0–100.0 (lock-free).
    #[inline]
    pub fn utilization(&self) -> f64 {
        if self.pool_size == 0 {
            return 0.0;
        }
        (self.allocated() as f64 / self.pool_size as f64) * 100.0
    }

    /// Convert an IP to a bitmap index, returning None if out of range.
    #[inline]
    fn ip_to_index(&self, ip: &IpAddr) -> Option<usize> {
        let ip_u128 = ip_to_u128(ip).0;
        if ip_u128 < self.pool_start {
            return None;
        }
        let idx = (ip_u128 - self.pool_start) as u64;
        if idx >= self.pool_size {
            return None;
        }
        Some(idx as usize)
    }

    /// Find the first free (0) bit starting from `start_idx`.
    /// Trailing bits in the last word are pre-set to 1, so no boundary check needed.
    fn find_free(&self, bitmap: &[u64], start_idx: usize) -> Option<usize> {
        let start_word = start_idx / 64;
        let start_bit = start_idx % 64;
        let num_words = bitmap.len();

        if start_word >= num_words {
            return None;
        }

        // Check first partial word — mask off bits before start_bit
        let word = bitmap[start_word];
        if word != u64::MAX {
            let mask = if start_bit == 0 {
                0u64
            } else {
                (1u64 << start_bit) - 1
            };
            let masked = word | mask;
            if masked != u64::MAX {
                let bit = (!masked).trailing_zeros() as usize;
                return Some(start_word * 64 + bit);
            }
        }

        // Check subsequent full words
        for word_idx in (start_word + 1)..num_words {
            let word = bitmap[word_idx];
            if word != u64::MAX {
                let bit = (!word).trailing_zeros() as usize;
                return Some(word_idx * 64 + bit);
            }
        }

        None
    }

    #[inline]
    fn get_bit(&self, bitmap: &[u64], idx: usize) -> bool {
        (bitmap[idx / 64] >> (idx % 64)) & 1 == 1
    }

    #[inline]
    fn set_bit(&self, bitmap: &mut [u64], idx: usize) {
        bitmap[idx / 64] |= 1u64 << (idx % 64);
    }

    #[inline]
    fn clear_bit(&self, bitmap: &mut [u64], idx: usize) {
        bitmap[idx / 64] &= !(1u64 << (idx % 64));
    }

    #[inline]
    fn index_to_ip(&self, idx: usize) -> IpAddr {
        u128_to_ip(self.pool_start + idx as u128, self.is_v4)
    }
}

#[inline]
fn ip_to_u128(ip: &IpAddr) -> (u128, bool) {
    match ip {
        IpAddr::V4(v4) => (u32::from_be_bytes(v4.octets()) as u128, true),
        IpAddr::V6(v6) => (u128::from_be_bytes(v6.octets()), false),
    }
}

#[inline]
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
        if subnet.subnet_type == "prefix-delegation" {
            continue;
        }

        let (pool_start, pool_end) = match (&subnet.pool_start, &subnet.pool_end) {
            (Some(s), Some(e)) => {
                let start: IpAddr = s.parse()?;
                let end: IpAddr = e.parse()?;
                (start, end)
            }
            _ => continue,
        };

        let alloc = SubnetAllocator::new(pool_start, pool_end);

        // Pre-mark reserved IPs
        for res in &subnet.reservation {
            let res_ip: IpAddr = res.ip.parse()?;
            alloc.allocate_specific(&res_ip);
        }

        // Pre-mark existing leases
        let leases = lease_store.leases_for_subnet(&subnet.network);
        for lease in &leases {
            if lease.is_active() {
                alloc.allocate_specific(&lease.ip);
            }
        }

        allocators.insert(subnet.network.clone(), alloc);
    }

    Ok(allocators)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_allocate_sequential() {
        let alloc = SubnetAllocator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        );
        assert_eq!(alloc.capacity(), 10);
        assert_eq!(alloc.allocated(), 0);

        let ip1 = alloc.allocate().unwrap();
        assert_eq!(ip1, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(alloc.allocated(), 1);

        let ip2 = alloc.allocate().unwrap();
        assert_eq!(ip2, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn test_pool_exhaustion() {
        let alloc = SubnetAllocator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
        );
        assert_eq!(alloc.capacity(), 3);

        assert!(alloc.allocate().is_some());
        assert!(alloc.allocate().is_some());
        assert!(alloc.allocate().is_some());
        assert!(alloc.allocate().is_none()); // Pool exhausted
        assert_eq!(alloc.allocated(), 3);
        assert_eq!(alloc.available(), 0);
    }

    #[test]
    fn test_release_and_reallocate() {
        let alloc = SubnetAllocator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        );

        let ip1 = alloc.allocate().unwrap();
        let ip2 = alloc.allocate().unwrap();
        assert!(alloc.allocate().is_none());

        alloc.release(&ip1);
        assert_eq!(alloc.allocated(), 1);

        let ip3 = alloc.allocate().unwrap();
        assert_eq!(ip3, ip1); // Should reuse released IP
    }

    #[test]
    fn test_allocate_specific() {
        let alloc = SubnetAllocator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        );

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert!(alloc.allocate_specific(&target));
        assert!(!alloc.allocate_specific(&target)); // Already allocated
        assert!(alloc.is_allocated(&target));
    }

    #[test]
    fn test_out_of_range_rejected() {
        let alloc = SubnetAllocator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)),
        );

        let outside = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
        assert!(!alloc.allocate_specific(&outside));
        assert!(!alloc.contains(&outside));
    }

    /// Critical test: verify boundary overflow fix.
    /// Pool size 100 fits in 2 words (64+36 bits).
    /// Bits 100-127 in the second word must NOT be allocatable.
    #[test]
    fn test_boundary_no_overflow() {
        let alloc = SubnetAllocator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
        );
        assert_eq!(alloc.capacity(), 100);

        // Allocate all 100 IPs
        for _ in 0..100 {
            assert!(alloc.allocate().is_some());
        }
        // Must be None — no overflow into padding bits
        assert!(alloc.allocate().is_none());
        assert_eq!(alloc.allocated(), 100);
    }

    /// Test with pool size that exactly fills a word (64 IPs)
    #[test]
    fn test_exact_word_boundary() {
        let alloc = SubnetAllocator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 64)),
        );
        assert_eq!(alloc.capacity(), 64);

        for _ in 0..64 {
            assert!(alloc.allocate().is_some());
        }
        assert!(alloc.allocate().is_none());
    }

    /// Test single-IP pool
    #[test]
    fn test_single_ip_pool() {
        let alloc = SubnetAllocator::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );
        assert_eq!(alloc.capacity(), 1);

        let ip = alloc.allocate().unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(alloc.allocate().is_none());

        alloc.release(&ip);
        assert!(alloc.allocate().is_some());
    }
}
