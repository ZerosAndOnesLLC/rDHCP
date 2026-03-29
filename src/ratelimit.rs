use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Per-client rate limiter using token bucket algorithm.
/// Keyed by MAC address (6 bytes) for DHCPv4 or client DUID for DHCPv6.
pub struct RateLimiter {
    /// Max tokens (burst size)
    max_tokens: u32,
    /// Token refill rate (tokens per second)
    refill_rate: f64,
    /// Buckets keyed by client identifier
    buckets: DashMap<Vec<u8>, TokenBucket>,
    /// Cleanup interval tracking
    last_cleanup: Mutex<Instant>,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter.
    /// - `max_burst`: maximum packets allowed in a burst
    /// - `per_second`: sustained rate limit (packets/second)
    pub fn new(max_burst: u32, per_second: f64) -> Self {
        Self {
            max_tokens: max_burst,
            refill_rate: per_second,
            buckets: DashMap::new(),
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// Check if a client is allowed to send a packet.
    /// Returns `true` if allowed, `false` if rate-limited.
    pub fn check(&self, client_id: &[u8]) -> bool {
        let now = Instant::now();

        // Periodic cleanup of stale buckets
        {
            let mut last = self.last_cleanup.lock().unwrap();
            if now.duration_since(*last) > Duration::from_secs(60) {
                *last = now;
                self.cleanup(now);
            }
        }

        let mut entry = self.buckets.entry(client_id.to_vec()).or_insert_with(|| {
            TokenBucket {
                tokens: self.max_tokens as f64,
                last_refill: now,
            }
        });

        let bucket = entry.value_mut();

        // Refill tokens
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate).min(self.max_tokens as f64);
        bucket.last_refill = now;

        // Try to consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Remove buckets that haven't been used in over 5 minutes
    fn cleanup(&self, now: Instant) {
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < Duration::from_secs(300));
    }
}

/// MAC-based access control list
pub struct MacAcl {
    /// Allow list (if non-empty, only these MACs are allowed)
    allow: Vec<[u8; 6]>,
    /// Deny list (these MACs are always denied)
    deny: Vec<[u8; 6]>,
}

impl MacAcl {
    pub fn new(allow: Vec<[u8; 6]>, deny: Vec<[u8; 6]>) -> Self {
        Self { allow, deny }
    }

    /// Check if a MAC address is allowed
    pub fn is_allowed(&self, mac: &[u8; 6]) -> bool {
        // Deny list takes priority
        if self.deny.contains(mac) {
            return false;
        }

        // If allow list is empty, allow everything not denied
        if self.allow.is_empty() {
            return true;
        }

        // If allow list is non-empty, only allow listed MACs
        self.allow.contains(mac)
    }
}
