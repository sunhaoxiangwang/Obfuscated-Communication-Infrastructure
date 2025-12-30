//! Traffic pattern modeling for mimicry.
//!
//! This module defines statistical models of legitimate traffic patterns
//! that SCF aims to mimic. Models are derived from empirical analysis of
//! real-world TLS/HTTPS traffic.

use std::collections::HashMap;

/// Predefined traffic profiles based on empirical observations.
#[derive(Debug, Clone, PartialEq)]
pub enum TrafficProfile {
    /// Standard HTTPS browsing traffic (e.g., Nginx serving web pages)
    Https,
    /// HTTP/2 multiplexed traffic
    Http2,
    /// WebRTC data channel traffic
    WebRtc,
    /// Video streaming traffic (e.g., YouTube, Netflix)
    VideoStream,
    /// Custom profile with user-defined parameters
    Custom(CustomProfile),
}

/// Custom traffic profile parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomProfile {
    /// Packet size buckets and their probabilities
    pub size_distribution: Vec<(usize, f64)>,
    /// Inter-packet interval buckets (microseconds) and probabilities
    pub timing_distribution: Vec<(u64, f64)>,
}

/// Statistical model of traffic patterns.
pub struct TrafficModel {
    profile: TrafficProfile,
    /// Packet size histogram (size_bucket -> count)
    size_histogram: HashMap<usize, u64>,
    /// Timing histogram (interval_bucket_us -> count)
    timing_histogram: HashMap<u64, u64>,
    /// Total packets observed
    total_packets: u64,
}

impl TrafficModel {
    /// Create a new traffic model for the given profile.
    pub fn new(profile: TrafficProfile) -> Self {
        let (size_histogram, timing_histogram) = Self::initialize_from_profile(&profile);

        Self {
            profile,
            size_histogram,
            timing_histogram,
            total_packets: 1000, // Initial observations
        }
    }

    fn initialize_from_profile(profile: &TrafficProfile) -> (HashMap<usize, u64>, HashMap<u64, u64>) {
        match profile {
            TrafficProfile::Https => Self::https_model(),
            TrafficProfile::Http2 => Self::http2_model(),
            TrafficProfile::WebRtc => Self::webrtc_model(),
            TrafficProfile::VideoStream => Self::video_model(),
            TrafficProfile::Custom(custom) => Self::custom_model(custom),
        }
    }

    /// HTTPS traffic model based on empirical observations.
    ///
    /// Characteristics:
    /// - Bimodal size distribution (small requests, larger responses)
    /// - Bursty timing with idle periods
    fn https_model() -> (HashMap<usize, u64>, HashMap<u64, u64>) {
        let mut sizes = HashMap::new();
        let mut timings = HashMap::new();

        // Typical HTTPS packet size distribution (bucket -> count)
        // Based on analysis of Nginx traffic
        sizes.insert(64, 150);    // TCP ACKs, small requests
        sizes.insert(128, 100);   // Small HTTP headers
        sizes.insert(256, 80);    // Medium requests
        sizes.insert(512, 120);   // Typical API responses
        sizes.insert(1024, 200);  // Larger responses
        sizes.insert(1400, 250);  // MTU-sized packets
        sizes.insert(1500, 100);  // Full MTU

        // Timing distribution (microseconds -> count)
        timings.insert(100, 50);      // Very fast (pipelining)
        timings.insert(500, 100);     // Fast
        timings.insert(1000, 200);    // 1ms
        timings.insert(5000, 150);    // 5ms
        timings.insert(10000, 100);   // 10ms
        timings.insert(50000, 200);   // 50ms (RTT)
        timings.insert(100000, 100);  // 100ms
        timings.insert(500000, 100);  // 500ms (idle gaps)

        (sizes, timings)
    }

    /// HTTP/2 multiplexed traffic model.
    fn http2_model() -> (HashMap<usize, u64>, HashMap<u64, u64>) {
        let mut sizes = HashMap::new();
        let mut timings = HashMap::new();

        // HTTP/2 has more consistent framing
        sizes.insert(9, 100);      // Frame headers only
        sizes.insert(64, 150);     // Small frames
        sizes.insert(256, 200);    // Medium frames
        sizes.insert(1024, 250);   // Larger frames
        sizes.insert(4096, 150);   // Max frame size chunks
        sizes.insert(16384, 100);  // Large data frames

        // More consistent timing due to multiplexing
        timings.insert(100, 100);
        timings.insert(500, 200);
        timings.insert(1000, 250);
        timings.insert(5000, 200);
        timings.insert(10000, 150);
        timings.insert(50000, 100);

        (sizes, timings)
    }

    /// WebRTC data channel model.
    fn webrtc_model() -> (HashMap<usize, u64>, HashMap<u64, u64>) {
        let mut sizes = HashMap::new();
        let mut timings = HashMap::new();

        // WebRTC uses DTLS + SCTP
        sizes.insert(40, 100);     // STUN/TURN
        sizes.insert(100, 150);    // Control messages
        sizes.insert(500, 200);    // Small data
        sizes.insert(1200, 300);   // Typical MTU for WebRTC
        sizes.insert(1280, 200);   // Common WebRTC MTU

        // Real-time focused timing
        timings.insert(1000, 200);    // 1ms
        timings.insert(5000, 300);    // 5ms
        timings.insert(10000, 250);   // 10ms
        timings.insert(20000, 150);   // 20ms (typical)
        timings.insert(50000, 100);   // 50ms

        (sizes, timings)
    }

    /// Video streaming model.
    fn video_model() -> (HashMap<usize, u64>, HashMap<u64, u64>) {
        let mut sizes = HashMap::new();
        let mut timings = HashMap::new();

        // Video streams have consistent large packets
        sizes.insert(200, 50);      // Audio packets
        sizes.insert(500, 100);     // Small video frames
        sizes.insert(1200, 300);    // Typical video packets
        sizes.insert(1400, 400);    // Large video packets
        sizes.insert(1500, 150);    // MTU-sized

        // Consistent timing based on frame rate
        timings.insert(16667, 300);   // 60fps
        timings.insert(33333, 250);   // 30fps
        timings.insert(41667, 150);   // 24fps
        timings.insert(100000, 100);  // Buffer gaps

        (sizes, timings)
    }

    /// Custom profile model.
    fn custom_model(profile: &CustomProfile) -> (HashMap<usize, u64>, HashMap<u64, u64>) {
        let mut sizes = HashMap::new();
        let mut timings = HashMap::new();

        for (size, prob) in &profile.size_distribution {
            sizes.insert(*size, (prob * 1000.0) as u64);
        }

        for (timing, prob) in &profile.timing_distribution {
            timings.insert(*timing, (prob * 1000.0) as u64);
        }

        (sizes, timings)
    }

    /// Update the model with new observations.
    pub fn update(&mut self, packet_sizes: &[usize], intervals_us: &[u64]) {
        for &size in packet_sizes {
            let bucket = self.size_bucket(size);
            *self.size_histogram.entry(bucket).or_insert(0) += 1;
            self.total_packets += 1;
        }

        for &interval in intervals_us {
            let bucket = self.timing_bucket(interval);
            *self.timing_histogram.entry(bucket).or_insert(0) += 1;
        }
    }

    /// Get the probability of a given packet size.
    pub fn size_probability(&self, size: usize) -> f64 {
        let bucket = self.size_bucket(size);
        let count = self.size_histogram.get(&bucket).copied().unwrap_or(0);
        count as f64 / self.total_packets as f64
    }

    /// Sample a packet size from the distribution.
    pub fn sample_size(&self) -> usize {
        self.sample_from_histogram(&self.size_histogram)
    }

    /// Sample a timing interval from the distribution.
    pub fn sample_timing(&self) -> u64 {
        self.sample_from_histogram(&self.timing_histogram) as u64
    }

    /// Get ordered size buckets for padding decisions.
    pub fn size_buckets(&self) -> Vec<usize> {
        let mut buckets: Vec<_> = self.size_histogram.keys().copied().collect();
        buckets.sort();
        buckets
    }

    /// Get the cumulative distribution function for sizes.
    pub fn size_cdf(&self) -> Vec<(usize, f64)> {
        let mut buckets = self.size_buckets();
        buckets.sort();

        let mut cumulative = 0.0;
        let mut cdf = Vec::new();

        for bucket in buckets {
            let prob = self.size_probability(bucket);
            cumulative += prob;
            cdf.push((bucket, cumulative));
        }

        cdf
    }

    fn size_bucket(&self, size: usize) -> usize {
        // Bucket sizes into powers of 2 or common MTU boundaries
        match size {
            0..=63 => 64,
            64..=127 => 128,
            128..=255 => 256,
            256..=511 => 512,
            512..=1023 => 1024,
            1024..=1279 => 1200,
            1280..=1399 => 1400,
            _ => 1500,
        }
    }

    fn timing_bucket(&self, interval_us: u64) -> usize {
        // Bucket into logarithmic intervals
        match interval_us {
            0..=99 => 100,
            100..=499 => 500,
            500..=999 => 1000,
            1000..=4999 => 5000,
            5000..=9999 => 10000,
            10000..=49999 => 50000,
            50000..=99999 => 100000,
            _ => 500000,
        }
    }

    fn sample_from_histogram<K: Copy + Into<usize>>(&self, histogram: &HashMap<K, u64>) -> usize {
        use rand::Rng;

        let total: u64 = histogram.values().sum();
        if total == 0 {
            return 0;
        }

        let mut rng = rand::thread_rng();
        let target = rng.gen_range(0..total);

        let mut cumulative = 0;
        for (&bucket, &count) in histogram {
            cumulative += count;
            if cumulative > target {
                return bucket.into();
            }
        }

        // Fallback to first bucket
        histogram.keys().next().map(|k| (*k).into()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_model_creation() {
        let model = TrafficModel::new(TrafficProfile::Https);
        assert!(!model.size_histogram.is_empty());
        assert!(!model.timing_histogram.is_empty());
    }

    #[test]
    fn test_size_sampling() {
        let model = TrafficModel::new(TrafficProfile::Https);

        // Sample multiple times and check distribution
        let mut samples = vec![];
        for _ in 0..1000 {
            samples.push(model.sample_size());
        }

        // Should have variety in samples
        let unique: std::collections::HashSet<_> = samples.iter().collect();
        assert!(unique.len() > 1);
    }

    #[test]
    fn test_model_update() {
        let mut model = TrafficModel::new(TrafficProfile::Https);
        let initial_total = model.total_packets;

        model.update(&[100, 200, 300], &[1000, 2000]);

        assert!(model.total_packets > initial_total);
    }

    #[test]
    fn test_size_cdf() {
        let model = TrafficModel::new(TrafficProfile::Https);
        let cdf = model.size_cdf();

        // CDF should be monotonically increasing
        let mut prev = 0.0;
        for (_, cumulative) in &cdf {
            assert!(*cumulative >= prev);
            prev = *cumulative;
        }

        // Last value should be ~1.0
        if let Some((_, last)) = cdf.last() {
            assert!((*last - 1.0).abs() < 0.01);
        }
    }
}
