//! Transport Stack Implementation.
//!
//! This module provides a reliable, encrypted transport layer with:
//!
//! 1. **Custom Congestion Control**: BBR-inspired algorithm optimized for
//!    high-loss environments (>20% packet drop)
//!
//! 2. **Forward Error Correction (FEC)**: Reed-Solomon-like codes for
//!    proactive packet loss recovery
//!
//! 3. **Selective Acknowledgment (SACK)**: Efficient retransmission of
//!    only lost packets
//!
//! 4. **Multiplexing**: Multiple logical streams over a single connection
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────┐
//! │                 Application                     │
//! ├────────────────────────────────────────────────┤
//! │  Stream Layer (multiplexing, flow control)     │
//! ├────────────────────────────────────────────────┤
//! │  Reliability Layer (SACK, retransmission)      │
//! ├────────────────────────────────────────────────┤
//! │  FEC Layer (Reed-Solomon encoding)             │
//! ├────────────────────────────────────────────────┤
//! │  Congestion Control (BBR variant)              │
//! ├────────────────────────────────────────────────┤
//! │  Packet Layer (framing, encryption)            │
//! └────────────────────────────────────────────────┘
//! ```

mod congestion;
mod fec;
mod packet;
mod reliability;
mod stream;

pub use congestion::{BbrState, CongestionController};
pub use fec::{FecDecoder, FecEncoder};
pub use packet::{Packet, PacketType};
pub use reliability::{ReliabilityLayer, SackRange};
pub use stream::{Stream, StreamId, StreamManager};

/// Maximum segment size (accounting for encryption overhead)
pub const MSS: usize = 1200;

/// Default receive window size
pub const DEFAULT_RECV_WINDOW: u32 = 256 * 1024; // 256 KB

/// Maximum number of concurrent streams
pub const MAX_STREAMS: usize = 100;

/// Initial RTT estimate (milliseconds)
pub const INITIAL_RTT_MS: u64 = 100;

/// Minimum RTT for congestion control (milliseconds)
pub const MIN_RTT_MS: u64 = 1;

/// Transport layer configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Enable Forward Error Correction
    pub enable_fec: bool,
    /// FEC redundancy ratio (0.0 - 1.0)
    pub fec_ratio: f64,
    /// Initial congestion window (packets)
    pub initial_cwnd: u32,
    /// Maximum congestion window (packets)
    pub max_cwnd: u32,
    /// Receive window size (bytes)
    pub recv_window: u32,
    /// Maximum retransmission attempts
    pub max_retries: u32,
    /// Retransmission timeout multiplier
    pub rto_multiplier: f64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            enable_fec: true,
            fec_ratio: 0.2, // 20% redundancy
            initial_cwnd: 10,
            max_cwnd: 1000,
            recv_window: DEFAULT_RECV_WINDOW,
            max_retries: 5,
            rto_multiplier: 1.5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = TransportConfig::default();
        assert!(config.enable_fec);
        assert!((config.fec_ratio - 0.2).abs() < f64::EPSILON);
        assert_eq!(config.recv_window, DEFAULT_RECV_WINDOW);
    }
}
