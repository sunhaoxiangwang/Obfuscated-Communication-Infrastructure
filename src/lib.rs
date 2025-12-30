//! # Steganographic Communication Framework (SCF)
//!
//! A privacy-preserving transport layer achieving statistical unobservability
//! through TLS 1.3 traffic mimicry and adaptive obfuscation.
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Application Layer                     │
//! ├─────────────────────────────────────────────────────────┤
//! │  Obfuscation Engine (padding, timing, traffic shaping)  │
//! ├─────────────────────────────────────────────────────────┤
//! │  REALITY Protocol (TLS 1.3 mimicry + authentication)    │
//! ├─────────────────────────────────────────────────────────┤
//! │  Transport Stack (QUIC-like, custom congestion control) │
//! ├─────────────────────────────────────────────────────────┤
//! │  Crypto Layer (X25519, ChaCha20-Poly1305, HKDF)        │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Design Goals
//!
//! 1. **Unobservability**: Traffic indistinguishable from legitimate TLS 1.3/HTTPS
//! 2. **Forward Secrecy**: Per-session ephemeral keys with X25519 ECDH
//! 3. **Resilience**: >90% goodput under 20%+ packet loss
//! 4. **Efficiency**: <15% overhead vs standard TLS RTT

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod crypto;
pub mod error;
pub mod obfuscation;
pub mod reality;
pub mod transport;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "ffi")]
pub mod ffi;

pub use error::{Error, Result};

/// Protocol version identifier
pub const PROTOCOL_VERSION: u8 = 0x01;

/// Maximum payload size per packet (fits within typical MTU)
pub const MAX_PAYLOAD_SIZE: usize = 1200;

/// Default timeout for handshake operations (milliseconds)
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// Configuration for the SCF protocol
#[derive(Debug, Clone)]
pub struct Config {
    /// Server's static public key (X25519)
    pub server_public_key: [u8; 32],
    /// Short ID for REALITY authentication (8 bytes)
    pub short_id: [u8; 8],
    /// SNI hostname to impersonate
    pub cover_hostname: String,
    /// Enable padding oracle for traffic shaping
    pub enable_padding: bool,
    /// Enable timing obfuscation
    pub enable_timing_obfuscation: bool,
    /// Target packet loss resilience (0.0 - 1.0)
    pub target_loss_resilience: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_public_key: [0u8; 32],
            short_id: [0u8; 8],
            cover_hostname: String::new(),
            enable_padding: true,
            enable_timing_obfuscation: true,
            target_loss_resilience: 0.2, // 20% packet loss tolerance
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.enable_padding);
        assert!(config.enable_timing_obfuscation);
        assert!((config.target_loss_resilience - 0.2).abs() < f64::EPSILON);
    }
}
