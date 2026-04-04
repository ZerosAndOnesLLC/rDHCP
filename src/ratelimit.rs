//! Per-client rate limiting, global rate limiting, MAC-based access control,
//! and rogue client detection.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::warn;

/// Maximum number of tracked clients before we start rejecting unknown clients.
/// Prevents memory exhaustion from MAC/DUID spoofing attacks.
const MAX_RATE_LIMIT_BUCKETS: usize = 100_000;

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

        // Try get_mut first to avoid Vec allocation for existing clients (hot path)
        if let Some(mut entry) = self.buckets.get_mut(client_id) {
            let bucket = entry.value_mut();
            let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
            bucket.tokens =
                (bucket.tokens + elapsed * self.refill_rate).min(self.max_tokens as f64);
            bucket.last_refill = now;
            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return true;
            }
            return false;
        }

        // Evict stale buckets if count exceeds cap (anti-spoofing)
        if self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
            self.cleanup(now);
            // If still over cap after cleanup, force-evict oldest 10%
            if self.buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
                let evict_count = MAX_RATE_LIMIT_BUCKETS / 10;
                let mut evicted = 0;
                self.buckets.retain(|_, bucket| {
                    if evicted >= evict_count {
                        return true;
                    }
                    if now.duration_since(bucket.last_refill) > Duration::from_secs(10) {
                        evicted += 1;
                        return false;
                    }
                    true
                });
            }
        }

        // New client — allocate only on first sight
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

/// Global (non-keyed) rate limiter using token bucket.
/// Limits total packets per second across all clients.
pub struct GlobalRateLimiter {
    max_tokens: f64,
    refill_rate: f64,
    tokens: Mutex<(f64, Instant)>,
}

impl GlobalRateLimiter {
    /// Create a new global rate limiter.
    /// - `pps`: maximum sustained packets per second (also used as burst size)
    pub fn new(pps: f64) -> Self {
        Self {
            max_tokens: pps * 2.0, // allow 2-second burst
            refill_rate: pps,
            tokens: Mutex::new((pps * 2.0, Instant::now())),
        }
    }

    /// Check if a packet should be allowed globally. Returns `true` if allowed.
    pub fn check(&self) -> bool {
        let mut guard = self.tokens.lock().unwrap();
        let (ref mut tokens, ref mut last) = *guard;
        let now = Instant::now();
        let elapsed = now.duration_since(*last).as_secs_f64();
        *tokens = (*tokens + elapsed * self.refill_rate).min(self.max_tokens);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
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
    /// Create a new ACL with the given allow and deny lists.
    pub fn new(allow: Vec<[u8; 6]>, deny: Vec<[u8; 6]>) -> Self {
        Self { allow, deny }
    }

    /// Create an empty ACL that permits everything.
    pub fn allow_all() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
        }
    }

    /// Returns true if both allow and deny lists are empty (permits everything).
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
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

/// Rogue client detector — tracks per-client request rates and alerts on anomalies.
pub struct RogueDetector {
    /// Threshold: max requests per client within the window
    threshold: u32,
    /// Window duration
    window: Duration,
    /// Per-client counters: client_id -> (count, window_start)
    counters: DashMap<Vec<u8>, (u32, Instant)>,
    /// Cleanup tracking
    last_cleanup: Mutex<Instant>,
    /// Counter of detected anomalies (for metrics)
    anomaly_count: AtomicU64,
}

impl RogueDetector {
    /// Create a new rogue detector.
    /// - `threshold`: max requests per window before alerting
    /// - `window_secs`: sliding window duration in seconds
    pub fn new(threshold: u32, window_secs: u64) -> Self {
        Self {
            threshold,
            window: Duration::from_secs(window_secs),
            counters: DashMap::new(),
            last_cleanup: Mutex::new(Instant::now()),
            anomaly_count: AtomicU64::new(0),
        }
    }

    /// Record a request from a client. Returns `true` if the client is behaving
    /// normally, `false` if rogue behavior is detected (over threshold).
    /// Logs a warning on first threshold crossing per window.
    pub fn record(&self, client_id: &[u8], label: &str) -> bool {
        let now = Instant::now();

        // Periodic cleanup
        {
            let mut last = self.last_cleanup.lock().unwrap();
            if now.duration_since(*last) > Duration::from_secs(30) {
                *last = now;
                self.counters
                    .retain(|_, (_, start)| now.duration_since(*start) < self.window * 2);
            }
        }

        // Evict stale entries if counter map exceeds cap (anti-spoofing)
        if !self.counters.contains_key(client_id) && self.counters.len() >= MAX_RATE_LIMIT_BUCKETS {
            self.counters
                .retain(|_, (_, start)| now.duration_since(*start) < self.window);
        }

        let mut entry = self.counters.entry(client_id.to_vec()).or_insert((0, now));
        let (ref mut count, ref mut window_start) = *entry.value_mut();

        // Reset window if expired
        if now.duration_since(*window_start) > self.window {
            *count = 0;
            *window_start = now;
        }

        *count += 1;

        if *count == self.threshold {
            self.anomaly_count.fetch_add(1, Ordering::Relaxed);
            warn!(
                client = %label,
                requests = *count,
                window_secs = self.window.as_secs(),
                "rogue client detected: request rate exceeds threshold"
            );
            return false;
        }

        *count < self.threshold
    }

    /// Number of anomalies detected since startup.
    pub fn anomaly_count(&self) -> u64 {
        self.anomaly_count.load(Ordering::Relaxed)
    }
}
