//! Packet padding for traffic analysis resistance.
//!
//! Implements various padding strategies to obscure packet size information:
//!
//! 1. **Fixed**: Pad all packets to a fixed size
//! 2. **BlockAligned**: Pad to multiples of a block size
//! 3. **MatchDistribution**: Pad to match target traffic distribution
//! 4. **Randomized**: Add random padding within bounds

use crate::crypto::SecureRandom;
use crate::obfuscation::traffic_model::TrafficModel;

/// Padding strategy to use.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PaddingStrategy {
    /// No padding
    None,
    /// Pad all packets to a fixed maximum size
    Fixed(usize),
    /// Pad to multiples of a block size
    BlockAligned(usize),
    /// Pad to match target traffic distribution
    MatchDistribution,
    /// Add random padding (min, max additional bytes)
    Randomized(usize, usize),
}

/// Padding oracle that determines appropriate padding for packets.
pub struct PaddingOracle {
    strategy: PaddingStrategy,
    max_overhead: f64,
    size_buckets: Vec<usize>,
}

impl PaddingOracle {
    /// Create a new padding oracle.
    pub fn new(strategy: PaddingStrategy, max_overhead: f64, traffic_model: &TrafficModel) -> Self {
        Self {
            strategy,
            max_overhead,
            size_buckets: traffic_model.size_buckets(),
        }
    }

    /// Determine target packet size for given payload.
    pub fn target_size(&self, payload_size: usize) -> usize {
        match self.strategy {
            PaddingStrategy::None => payload_size,
            PaddingStrategy::Fixed(size) => size.max(payload_size),
            PaddingStrategy::BlockAligned(block) => {
                let blocks = (payload_size + block - 1) / block;
                blocks * block
            }
            PaddingStrategy::MatchDistribution => {
                self.match_distribution_size(payload_size)
            }
            PaddingStrategy::Randomized(min, max) => {
                let extra = if max > min {
                    min + (SecureRandom::u64() as usize % (max - min))
                } else {
                    min
                };
                payload_size + extra
            }
        }
    }

    /// Apply padding to data.
    ///
    /// Format: [2-byte length][payload][random padding]
    pub fn pad(&self, data: &[u8]) -> Vec<u8> {
        let payload_len = data.len();
        let target_size = self.target_size(payload_len + 2); // +2 for length prefix

        // Check overhead limit
        let overhead = (target_size as f64 - payload_len as f64) / payload_len as f64;
        let effective_target = if overhead > self.max_overhead {
            ((1.0 + self.max_overhead) * payload_len as f64) as usize
        } else {
            target_size
        };

        let padding_len = effective_target.saturating_sub(payload_len + 2);

        let mut result = Vec::with_capacity(2 + payload_len + padding_len);

        // 2-byte big-endian length prefix
        result.push((payload_len >> 8) as u8);
        result.push((payload_len & 0xff) as u8);

        // Payload
        result.extend_from_slice(data);

        // Random padding
        if padding_len > 0 {
            let mut padding = vec![0u8; padding_len];
            SecureRandom::fill(&mut padding);
            result.extend_from_slice(&padding);
        }

        result
    }

    /// Remove padding from data.
    pub fn unpad(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 2 {
            return None;
        }

        let payload_len = ((data[0] as usize) << 8) | (data[1] as usize);

        if data.len() < 2 + payload_len {
            return None;
        }

        Some(data[2..2 + payload_len].to_vec())
    }

    /// Find the best matching size bucket from the traffic model.
    fn match_distribution_size(&self, payload_size: usize) -> usize {
        // Find smallest bucket that fits the payload
        let min_size = payload_size + 2; // +2 for length prefix

        for &bucket in &self.size_buckets {
            if bucket >= min_size {
                return bucket;
            }
        }

        // If no bucket fits, use largest bucket or payload size
        self.size_buckets.last().copied().unwrap_or(min_size)
    }
}

/// Builder for creating padding configurations.
pub struct PaddingBuilder {
    strategy: PaddingStrategy,
    max_overhead: f64,
}

impl PaddingBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            strategy: PaddingStrategy::MatchDistribution,
            max_overhead: 0.15,
        }
    }

    /// Set the padding strategy.
    pub fn strategy(mut self, strategy: PaddingStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Set the maximum overhead ratio.
    pub fn max_overhead(mut self, overhead: f64) -> Self {
        self.max_overhead = overhead.clamp(0.0, 1.0);
        self
    }

    /// Build the padding oracle.
    pub fn build(self, traffic_model: &TrafficModel) -> PaddingOracle {
        PaddingOracle::new(self.strategy, self.max_overhead, traffic_model)
    }
}

impl Default for PaddingBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::obfuscation::traffic_model::TrafficProfile;

    fn create_oracle(strategy: PaddingStrategy) -> PaddingOracle {
        let model = TrafficModel::new(TrafficProfile::Https);
        PaddingOracle::new(strategy, 0.5, &model)
    }

    #[test]
    fn test_no_padding() {
        let oracle = create_oracle(PaddingStrategy::None);
        assert_eq!(oracle.target_size(100), 100);
    }

    #[test]
    fn test_fixed_padding() {
        let oracle = create_oracle(PaddingStrategy::Fixed(1024));
        assert_eq!(oracle.target_size(100), 1024);
        assert_eq!(oracle.target_size(2000), 2000); // Larger than fixed
    }

    #[test]
    fn test_block_aligned_padding() {
        let oracle = create_oracle(PaddingStrategy::BlockAligned(128));
        assert_eq!(oracle.target_size(100), 128);
        assert_eq!(oracle.target_size(129), 256);
        assert_eq!(oracle.target_size(256), 256);
    }

    #[test]
    fn test_pad_unpad_roundtrip() {
        let oracle = create_oracle(PaddingStrategy::Fixed(256));

        let original = b"Hello, World!";
        let padded = oracle.pad(original);

        assert!(padded.len() >= original.len());

        let unpadded = oracle.unpad(&padded).unwrap();
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_pad_format() {
        let oracle = create_oracle(PaddingStrategy::None);

        let data = b"test";
        let padded = oracle.pad(data);

        // Check length prefix
        let length = ((padded[0] as usize) << 8) | (padded[1] as usize);
        assert_eq!(length, 4);

        // Check payload
        assert_eq!(&padded[2..6], b"test");
    }

    #[test]
    fn test_unpad_invalid() {
        let oracle = create_oracle(PaddingStrategy::None);

        // Too short
        assert!(oracle.unpad(&[0]).is_none());

        // Length exceeds data
        assert!(oracle.unpad(&[0x00, 0x10, 0x01]).is_none());
    }

    #[test]
    fn test_randomized_padding() {
        let oracle = create_oracle(PaddingStrategy::Randomized(10, 50));

        let mut sizes = std::collections::HashSet::new();
        for _ in 0..100 {
            sizes.insert(oracle.target_size(100));
        }

        // Should have variety due to randomization
        assert!(sizes.len() > 1);
    }

    #[test]
    fn test_overhead_limit() {
        let model = TrafficModel::new(TrafficProfile::Https);
        let oracle = PaddingOracle::new(PaddingStrategy::Fixed(10000), 0.1, &model);

        let data = vec![0u8; 100];
        let padded = oracle.pad(&data);

        // With 10% overhead limit, should be much less than 10000
        assert!(padded.len() < 200);
    }

    #[test]
    fn test_builder() {
        let model = TrafficModel::new(TrafficProfile::Https);

        let oracle = PaddingBuilder::new()
            .strategy(PaddingStrategy::BlockAligned(64))
            .max_overhead(0.25)
            .build(&model);

        assert_eq!(oracle.target_size(50), 64);
    }
}
