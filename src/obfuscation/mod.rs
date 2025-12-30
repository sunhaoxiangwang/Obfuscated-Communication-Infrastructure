//! Traffic Obfuscation Engine.
//!
//! This module provides traffic analysis countermeasures:
//!
//! 1. **Padding Oracle**: Adjusts packet sizes to match target distributions
//! 2. **Timing Shaper**: Introduces controlled delays to mask timing patterns
//! 3. **Traffic Morphing**: Transforms traffic to match legitimate patterns
//!
//! ## Statistical Unobservability
//!
//! The goal is to make SCF traffic statistically indistinguishable from
//! legitimate TLS/HTTPS traffic. This is measured using:
//!
//! - KL Divergence between packet size distributions
//! - Entropy analysis of timing intervals
//! - ML classifier accuracy (target: ~50% = random guessing)

mod padding;
mod timing;
mod traffic_model;

pub use padding::{PaddingOracle, PaddingStrategy};
pub use timing::{TimingShaper, TimingStrategy};
pub use traffic_model::{TrafficModel, TrafficProfile};

/// Configuration for the obfuscation engine.
#[derive(Debug, Clone)]
pub struct ObfuscationConfig {
    /// Enable packet padding
    pub enable_padding: bool,
    /// Enable timing obfuscation
    pub enable_timing: bool,
    /// Target traffic profile to mimic
    pub target_profile: TrafficProfile,
    /// Maximum padding overhead (0.0 - 1.0)
    pub max_padding_overhead: f64,
    /// Maximum timing delay in microseconds
    pub max_timing_delay_us: u64,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            enable_padding: true,
            enable_timing: true,
            target_profile: TrafficProfile::Https,
            max_padding_overhead: 0.15, // 15% overhead budget
            max_timing_delay_us: 50_000, // 50ms max delay
        }
    }
}

/// Main obfuscation engine coordinating all countermeasures.
pub struct ObfuscationEngine {
    config: ObfuscationConfig,
    padding_oracle: PaddingOracle,
    timing_shaper: TimingShaper,
    traffic_model: TrafficModel,
}

impl ObfuscationEngine {
    /// Create a new obfuscation engine with the given configuration.
    pub fn new(config: ObfuscationConfig) -> Self {
        let traffic_model = TrafficModel::new(config.target_profile.clone());
        let padding_oracle = PaddingOracle::new(
            PaddingStrategy::MatchDistribution,
            config.max_padding_overhead,
            &traffic_model,
        );
        let timing_shaper = TimingShaper::new(
            TimingStrategy::Jitter,
            config.max_timing_delay_us,
        );

        Self {
            config,
            padding_oracle,
            timing_shaper,
            traffic_model,
        }
    }

    /// Apply padding to outgoing data.
    pub fn pad(&self, data: &[u8]) -> Vec<u8> {
        if !self.config.enable_padding {
            return data.to_vec();
        }
        self.padding_oracle.pad(data)
    }

    /// Remove padding from incoming data.
    pub fn unpad(&self, data: &[u8]) -> Option<Vec<u8>> {
        if !self.config.enable_padding {
            return Some(data.to_vec());
        }
        self.padding_oracle.unpad(data)
    }

    /// Calculate timing delay for the next packet.
    pub async fn apply_timing_delay(&self) {
        if !self.config.enable_timing {
            return;
        }
        self.timing_shaper.delay().await;
    }

    /// Get recommended packet size for current traffic conditions.
    pub fn recommended_packet_size(&self, payload_size: usize) -> usize {
        self.padding_oracle.target_size(payload_size)
    }

    /// Update traffic model with observed legitimate traffic.
    pub fn update_model(&mut self, packet_sizes: &[usize], intervals_us: &[u64]) {
        self.traffic_model.update(packet_sizes, intervals_us);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obfuscation_engine_creation() {
        let config = ObfuscationConfig::default();
        let engine = ObfuscationEngine::new(config);

        // Basic sanity check
        let data = b"test data";
        let padded = engine.pad(data);
        assert!(padded.len() >= data.len());

        let unpadded = engine.unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_disabled_obfuscation() {
        let config = ObfuscationConfig {
            enable_padding: false,
            enable_timing: false,
            ..Default::default()
        };
        let engine = ObfuscationEngine::new(config);

        let data = b"test data";
        let result = engine.pad(data);
        assert_eq!(result, data);
    }
}
