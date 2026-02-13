//! REALITY Protocol Implementation.
//!
//! REALITY is a TLS-based obfuscation protocol that achieves unobservability
//! by leveraging legitimate TLS 1.3 certificates from real "cover" servers.
//!
//! ## Key Features
//!
//! 1. **Perfect TLS Mimicry**: Uses real certificates from cover servers
//! 2. **Zero Fingerprint**: No custom extensions or unusual cipher suites
//! 3. **Embedded Authentication**: Auth tag hidden in ClientHello random field
//! 4. **Forward Secrecy**: Ephemeral X25519 keys per session
//!
//! ## Protocol Flow
//!
//! ```text
//! Client                          Server                         Cover
//!   |                               |                              |
//!   |  ClientHello (with auth)      |                              |
//!   |------------------------------>|                              |
//!   |                               |  Proxy to cover server       |
//!   |                               |----------------------------->|
//!   |                               |  ServerHello + Certificate   |
//!   |                               |<-----------------------------|
//!   |  ServerHello (real cert)      |                              |
//!   |<------------------------------|                              |
//!   |                               |                              |
//!   |  [Verify: auth_tag valid]     |                              |
//!   |                               |                              |
//!   |  Finished                     |                              |
//!   |------------------------------>|                              |
//!   |  Finished                     |                              |
//!   |<------------------------------|                              |
//!   |                               |                              |
//!   |========= Encrypted Application Data ========================|
//! ```

pub mod client;
mod config;
mod handshake;
mod server;

pub use client::{RealityClient, RealityReader, RealityWriter};
pub use config::RealityConfig;
pub use handshake::{ClientHelloBuilder, ServerHelloParser};
pub use server::RealityServer;

/// REALITY protocol version
pub const REALITY_VERSION: u8 = 0x01;

/// Size of the short ID used for authentication
pub const SHORT_ID_SIZE: usize = 8;

/// Position in ClientHello random where auth tag is embedded
pub const AUTH_TAG_OFFSET: usize = 24;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(SHORT_ID_SIZE, 8);
        assert_eq!(AUTH_TAG_OFFSET, 24);
        // Verify auth tag fits in remaining random bytes
        assert!(AUTH_TAG_OFFSET + SHORT_ID_SIZE <= 32);
    }
}
