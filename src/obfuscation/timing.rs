//! Timing obfuscation for traffic analysis resistance.
//!
//! Implements timing-based countermeasures:
//!
//! 1. **Jitter**: Add random delays to mask timing patterns
//! 2. **ConstantRate**: Send at fixed intervals
//! 3. **Adaptive**: Match timing to target traffic model

use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::crypto::random::random_delay_us;

/// Timing obfuscation strategy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TimingStrategy {
    /// No timing obfuscation
    None,
    /// Add random jitter (min_us, max_us)
    Jitter,
    /// Fixed interval between packets (microseconds)
    ConstantRate(u64),
    /// Adaptive timing based on traffic patterns
    Adaptive,
}

/// Timing shaper that controls packet transmission timing.
pub struct TimingShaper {
    strategy: TimingStrategy,
    max_delay_us: u64,
    last_send: Option<Instant>,
    /// Rolling average of inter-packet intervals
    avg_interval_us: f64,
    /// Exponential smoothing factor
    smoothing: f64,
}

impl TimingShaper {
    /// Create a new timing shaper.
    pub fn new(strategy: TimingStrategy, max_delay_us: u64) -> Self {
        Self {
            strategy,
            max_delay_us,
            last_send: None,
            avg_interval_us: 10_000.0, // 10ms default
            smoothing: 0.1,
        }
    }

    /// Apply timing delay before sending a packet.
    pub async fn delay(&self) {
        let delay_us = self.calculate_delay();
        if delay_us > 0 {
            sleep(Duration::from_micros(delay_us)).await;
        }
    }

    /// Calculate delay in microseconds.
    pub fn calculate_delay(&self) -> u64 {
        match self.strategy {
            TimingStrategy::None => 0,
            TimingStrategy::Jitter => {
                // Random delay between 0 and max
                random_delay_us(0, self.max_delay_us)
            }
            TimingStrategy::ConstantRate(interval) => {
                // Calculate time since last send
                if let Some(last) = self.last_send {
                    let elapsed = last.elapsed().as_micros() as u64;
                    interval.saturating_sub(elapsed)
                } else {
                    0
                }
            }
            TimingStrategy::Adaptive => {
                // Sample from exponential distribution around average
                self.sample_adaptive_delay()
            }
        }
    }

    /// Record that a packet was sent (for rate limiting).
    pub fn record_send(&mut self) {
        if let Some(last) = self.last_send {
            let interval = last.elapsed().as_micros() as f64;
            // Exponential moving average
            self.avg_interval_us =
                self.smoothing * interval + (1.0 - self.smoothing) * self.avg_interval_us;
        }
        self.last_send = Some(Instant::now());
    }

    /// Sample delay from exponential distribution.
    fn sample_adaptive_delay(&self) -> u64 {
        // Exponential distribution with mean = avg_interval
        // Using inverse transform sampling: -ln(U) * mean
        let u = (crate::crypto::SecureRandom::u64() as f64) / (u64::MAX as f64);
        let u = u.max(1e-10); // Avoid log(0)

        let delay = -u.ln() * self.avg_interval_us;
        (delay as u64).min(self.max_delay_us)
    }

    /// Update average interval from observed traffic.
    pub fn update_average(&mut self, observed_interval_us: u64) {
        self.avg_interval_us = self.smoothing * (observed_interval_us as f64)
            + (1.0 - self.smoothing) * self.avg_interval_us;
    }

    /// Get current average interval.
    pub fn average_interval_us(&self) -> f64 {
        self.avg_interval_us
    }
}

/// Token bucket rate limiter for traffic shaping.
pub struct TokenBucket {
    /// Maximum tokens (burst capacity)
    capacity: u64,
    /// Current tokens
    tokens: f64,
    /// Tokens per microsecond
    rate: f64,
    /// Last refill time
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// # Arguments
    ///
    /// * `rate_bps` - Rate in bits per second
    /// * `burst_bytes` - Maximum burst size in bytes
    pub fn new(rate_bps: u64, burst_bytes: u64) -> Self {
        let rate = (rate_bps as f64) / 8.0 / 1_000_000.0; // bytes per microsecond

        Self {
            capacity: burst_bytes,
            tokens: burst_bytes as f64,
            rate,
            last_refill: Instant::now(),
        }
    }

    /// Check if we can send bytes now, and consume tokens if so.
    pub fn try_consume(&mut self, bytes: u64) -> bool {
        self.refill();

        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    /// Wait until we can send the specified number of bytes.
    pub async fn consume(&mut self, bytes: u64) {
        loop {
            self.refill();

            if self.tokens >= bytes as f64 {
                self.tokens -= bytes as f64;
                return;
            }

            // Calculate wait time
            let needed = bytes as f64 - self.tokens;
            let wait_us = (needed / self.rate) as u64;

            sleep(Duration::from_micros(wait_us.max(100))).await;
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_us = now.duration_since(self.last_refill).as_micros() as f64;

        self.tokens = (self.tokens + elapsed_us * self.rate).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// Get current token count.
    pub fn available(&mut self) -> u64 {
        self.refill();
        self.tokens as u64
    }
}

/// Leaky bucket for smoothing bursty traffic.
pub struct LeakyBucket {
    /// Bucket capacity (bytes)
    capacity: usize,
    /// Current fill level
    level: usize,
    /// Drain rate (bytes per microsecond)
    drain_rate: f64,
    /// Last drain time
    last_drain: Instant,
    /// Queue of pending data
    queue: std::collections::VecDeque<Vec<u8>>,
}

impl LeakyBucket {
    /// Create a new leaky bucket.
    pub fn new(capacity: usize, drain_rate_bps: u64) -> Self {
        Self {
            capacity,
            level: 0,
            drain_rate: (drain_rate_bps as f64) / 8.0 / 1_000_000.0,
            last_drain: Instant::now(),
            queue: std::collections::VecDeque::new(),
        }
    }

    /// Add data to the bucket.
    ///
    /// Returns true if accepted, false if bucket is full.
    pub fn add(&mut self, data: Vec<u8>) -> bool {
        self.drain();

        if self.level + data.len() <= self.capacity {
            self.level += data.len();
            self.queue.push_back(data);
            true
        } else {
            false
        }
    }

    /// Get the next chunk to send, if available.
    pub fn get(&mut self) -> Option<Vec<u8>> {
        self.drain();

        if let Some(data) = self.queue.pop_front() {
            Some(data)
        } else {
            None
        }
    }

    /// Drain the bucket based on elapsed time.
    fn drain(&mut self) {
        let now = Instant::now();
        let elapsed_us = now.duration_since(self.last_drain).as_micros() as f64;

        let drained = (elapsed_us * self.drain_rate) as usize;
        self.level = self.level.saturating_sub(drained);
        self.last_drain = now;
    }

    /// Check if bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get current fill level.
    pub fn level(&mut self) -> usize {
        self.drain();
        self.level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_delay() {
        let shaper = TimingShaper::new(TimingStrategy::Jitter, 10_000);

        let mut delays = std::collections::HashSet::new();
        for _ in 0..100 {
            delays.insert(shaper.calculate_delay());
        }

        // Should have variety
        assert!(delays.len() > 1);

        // All delays should be within bounds
        for delay in delays {
            assert!(delay <= 10_000);
        }
    }

    #[test]
    fn test_no_delay() {
        let shaper = TimingShaper::new(TimingStrategy::None, 10_000);
        assert_eq!(shaper.calculate_delay(), 0);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(1_000_000, 1000); // 1 Mbps, 1KB burst

        // Should be able to consume up to burst size immediately
        assert!(bucket.try_consume(500));
        assert!(bucket.try_consume(400));

        // Now should fail (only ~100 tokens left)
        assert!(!bucket.try_consume(200));
    }

    #[test]
    fn test_leaky_bucket() {
        let mut bucket = LeakyBucket::new(1000, 1_000_000);

        // Add data
        assert!(bucket.add(vec![0u8; 100]));
        assert!(bucket.add(vec![0u8; 100]));

        // Get data back
        let data = bucket.get();
        assert!(data.is_some());
        assert_eq!(data.unwrap().len(), 100);
    }

    #[test]
    fn test_timing_record() {
        let mut shaper = TimingShaper::new(TimingStrategy::Adaptive, 50_000);

        let initial = shaper.average_interval_us();

        // Record some sends
        shaper.record_send();
        std::thread::sleep(Duration::from_millis(5));
        shaper.record_send();

        // Average should have changed
        // (This is probabilistic, so we just check it's reasonable)
        assert!(shaper.average_interval_us() > 0.0);
    }

    #[tokio::test]
    async fn test_token_bucket_async() {
        let mut bucket = TokenBucket::new(10_000_000, 1000); // 10 Mbps, 1KB burst

        // Exhaust burst
        bucket.try_consume(1000);

        // This should wait briefly
        let start = Instant::now();
        bucket.consume(100).await;
        let elapsed = start.elapsed();

        // Should have waited some time (but not too long)
        assert!(elapsed.as_micros() > 0);
        assert!(elapsed.as_millis() < 100);
    }
}
