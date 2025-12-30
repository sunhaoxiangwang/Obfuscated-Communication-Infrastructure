//! Rate limiting for connection and request throttling.
//!
//! Uses a sliding window algorithm for accurate rate limiting
//! without storing excessive state.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Rate limiter using sliding window counters.
pub struct RateLimiter {
    /// Per-IP request counts
    counters: RwLock<HashMap<IpAddr, WindowCounter>>,
    /// Maximum requests per window
    max_requests: u32,
    /// Window duration
    window: Duration,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

/// Sliding window counter for a single IP.
struct WindowCounter {
    /// Count in current window
    current: u32,
    /// Count in previous window
    previous: u32,
    /// Start of current window
    window_start: Instant,
}

impl WindowCounter {
    fn new() -> Self {
        Self {
            current: 0,
            previous: 0,
            window_start: Instant::now(),
        }
    }

    /// Get the estimated count using sliding window.
    fn get(&mut self, window: Duration) -> u32 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start);

        if elapsed >= window * 2 {
            // Two windows have passed, reset everything
            self.current = 0;
            self.previous = 0;
            self.window_start = now;
        } else if elapsed >= window {
            // One window has passed, slide
            self.previous = self.current;
            self.current = 0;
            self.window_start = now;
        }

        // Calculate weighted average
        let weight = elapsed.as_secs_f64() / window.as_secs_f64();
        let weight = weight.min(1.0);

        let prev_weight = 1.0 - weight;
        let estimate = (self.previous as f64 * prev_weight) + (self.current as f64);

        estimate.ceil() as u32
    }

    /// Increment the counter.
    fn increment(&mut self, window: Duration) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.window_start);

        if elapsed >= window {
            // Slide the window
            self.previous = self.current;
            self.current = 1;
            self.window_start = now;
        } else {
            self.current += 1;
        }
    }
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            counters: RwLock::new(HashMap::new()),
            max_requests,
            window,
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Check if a request from this IP is allowed.
    pub fn check(&self, ip: &IpAddr) -> bool {
        let mut counters = self.counters.write();

        // Periodic cleanup
        self.maybe_cleanup(&mut counters);

        let counter = counters.entry(*ip).or_insert_with(WindowCounter::new);
        let count = counter.get(self.window);

        if count >= self.max_requests {
            false
        } else {
            counter.increment(self.window);
            true
        }
    }

    /// Get current request count for an IP.
    pub fn current_count(&self, ip: &IpAddr) -> u32 {
        let mut counters = self.counters.write();

        if let Some(counter) = counters.get_mut(ip) {
            counter.get(self.window)
        } else {
            0
        }
    }

    /// Reset counter for an IP.
    pub fn reset(&self, ip: &IpAddr) {
        self.counters.write().remove(ip);
    }

    /// Get number of tracked IPs.
    pub fn tracked_count(&self) -> usize {
        self.counters.read().len()
    }

    fn maybe_cleanup(&self, counters: &mut HashMap<IpAddr, WindowCounter>) {
        let now = Instant::now();
        let mut last_cleanup = self.last_cleanup.write();

        if now.duration_since(*last_cleanup) > self.window * 2 {
            // Remove stale entries
            counters.retain(|_, counter| {
                now.duration_since(counter.window_start) < self.window * 3
            });
            *last_cleanup = now;
        }
    }
}

/// Token bucket rate limiter for bandwidth limiting.
pub struct BandwidthLimiter {
    /// Maximum tokens (burst capacity in bytes)
    capacity: u64,
    /// Current tokens
    tokens: AtomicU64,
    /// Refill rate (bytes per second)
    rate: u64,
    /// Last refill time (encoded as nanos since some epoch)
    last_refill: AtomicU64,
}

impl BandwidthLimiter {
    /// Create a new bandwidth limiter.
    ///
    /// # Arguments
    ///
    /// * `rate_bps` - Rate in bytes per second
    /// * `burst` - Maximum burst size in bytes
    pub fn new(rate_bps: u64, burst: u64) -> Self {
        Self {
            capacity: burst,
            tokens: AtomicU64::new(burst),
            rate: rate_bps,
            last_refill: AtomicU64::new(0),
        }
    }

    /// Try to consume tokens for sending/receiving bytes.
    ///
    /// Returns true if allowed, false if rate limited.
    pub fn try_consume(&self, bytes: u64) -> bool {
        self.refill();

        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < bytes {
                return false;
            }

            let new = current - bytes;
            if self
                .tokens
                .compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Get wait time until tokens are available.
    pub fn wait_time(&self, bytes: u64) -> Duration {
        self.refill();

        let current = self.tokens.load(Ordering::Acquire);
        if current >= bytes {
            return Duration::ZERO;
        }

        let needed = bytes - current;
        let wait_secs = needed as f64 / self.rate as f64;

        Duration::from_secs_f64(wait_secs)
    }

    fn refill(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let last = self.last_refill.load(Ordering::Acquire);

        if last == 0 {
            self.last_refill.store(now, Ordering::Release);
            return;
        }

        let elapsed_ns = now.saturating_sub(last);
        if elapsed_ns == 0 {
            return;
        }

        let elapsed_secs = elapsed_ns as f64 / 1_000_000_000.0;
        let new_tokens = (self.rate as f64 * elapsed_secs) as u64;

        if new_tokens > 0 {
            if self
                .last_refill
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                loop {
                    let current = self.tokens.load(Ordering::Acquire);
                    let new = (current + new_tokens).min(self.capacity);
                    if self
                        .tokens
                        .compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        break;
                    }
                }
            }
        }
    }

    /// Get available tokens.
    pub fn available(&self) -> u64 {
        self.refill();
        self.tokens.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(10, Duration::from_secs(1));
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..10 {
            assert!(limiter.check(&ip));
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(5, Duration::from_secs(1));
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for _ in 0..5 {
            assert!(limiter.check(&ip));
        }

        // Should be blocked now
        assert!(!limiter.check(&ip));
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(2, Duration::from_secs(1));
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Fill up ip1's limit
        assert!(limiter.check(&ip1));
        assert!(limiter.check(&ip1));
        assert!(!limiter.check(&ip1));

        // ip2 should still be allowed
        assert!(limiter.check(&ip2));
        assert!(limiter.check(&ip2));
        assert!(!limiter.check(&ip2));
    }

    #[test]
    fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new(2, Duration::from_secs(1));
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(limiter.check(&ip));
        assert!(limiter.check(&ip));
        assert!(!limiter.check(&ip));

        limiter.reset(&ip);

        // Should be allowed again
        assert!(limiter.check(&ip));
    }

    #[test]
    fn test_bandwidth_limiter() {
        let limiter = BandwidthLimiter::new(1000, 5000); // 1KB/s, 5KB burst

        // Should allow burst
        assert!(limiter.try_consume(5000));

        // Should be blocked now
        assert!(!limiter.try_consume(1));
    }

    #[test]
    fn test_bandwidth_available() {
        let limiter = BandwidthLimiter::new(1000, 5000);

        assert_eq!(limiter.available(), 5000);

        limiter.try_consume(3000);
        assert_eq!(limiter.available(), 2000);
    }
}
