//! Error types for the SCF protocol.

use thiserror::Error;

/// Result type alias for SCF operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during SCF operations.
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic operation failed
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// Key exchange failed
    #[error("key exchange failed: {0}")]
    KeyExchange(String),

    /// Authentication failed (invalid short_id or auth tag)
    #[error("authentication failed")]
    Authentication,

    /// Handshake protocol error
    #[error("handshake error: {0}")]
    Handshake(String),

    /// Invalid message format
    #[error("invalid message format: {0}")]
    InvalidMessage(String),

    /// Connection timeout
    #[error("connection timeout after {0}ms")]
    Timeout(u64),

    /// Network I/O error
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),

    /// TLS error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Buffer overflow/underflow
    #[error("buffer error: expected {expected} bytes, got {actual}")]
    Buffer { expected: usize, actual: usize },

    /// Protocol version mismatch
    #[error("protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u8, actual: u8 },

    /// Session expired or invalid
    #[error("session expired or invalid")]
    SessionExpired,

    /// Forward Error Correction failure
    #[error("FEC recovery failed: insufficient packets")]
    FecRecoveryFailed,

    /// Congestion control signaled abort
    #[error("congestion control: connection aborted")]
    CongestionAbort,
}

impl Error {
    /// Create a new cryptographic error
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    /// Create a new handshake error
    pub fn handshake(msg: impl Into<String>) -> Self {
        Error::Handshake(msg.into())
    }

    /// Create a new TLS error
    pub fn tls(msg: impl Into<String>) -> Self {
        Error::Tls(msg.into())
    }

    /// Create a new configuration error
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Error::Timeout(_) | Error::FecRecoveryFailed | Error::CongestionAbort
        )
    }

    /// Check if this error indicates authentication failure
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Error::Authentication)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::Authentication;
        assert_eq!(err.to_string(), "authentication failed");

        let err = Error::Timeout(5000);
        assert_eq!(err.to_string(), "connection timeout after 5000ms");
    }

    #[test]
    fn test_error_recoverable() {
        assert!(Error::Timeout(1000).is_recoverable());
        assert!(Error::FecRecoveryFailed.is_recoverable());
        assert!(!Error::Authentication.is_recoverable());
    }
}
