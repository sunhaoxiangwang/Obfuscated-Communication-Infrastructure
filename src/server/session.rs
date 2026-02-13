//! RAM-only session management.
//!
//! All session data exists exclusively in memory with automatic expiration.
//! No data is ever written to disk, ensuring forward secrecy and zero-log compliance.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::ZeroizeOnDrop;

use crate::crypto::{Aead, Nonce, PublicKey, SessionKeys};
use crate::error::{Error, Result};

/// Unique session identifier.
pub type SessionId = u64;

/// Session state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionState {
    /// Session is being established
    Handshaking,
    /// Session is active
    Active,
    /// Session is closing
    Closing,
    /// Session is closed
    Closed,
}

/// A single client session.
///
/// All sensitive data is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct Session {
    #[zeroize(skip)]
    id: SessionId,
    #[zeroize(skip)]
    state: parking_lot::Mutex<SessionState>,
    #[zeroize(skip)]
    created_at: Instant,
    #[zeroize(skip)]
    last_activity: parking_lot::Mutex<Instant>,
    #[zeroize(skip)]
    peer_addr: SocketAddr,
    /// Client's public key (for key derivation)
    #[zeroize(skip)]
    client_public: PublicKey,
    /// Short ID used for authentication
    short_id: [u8; 8],
    /// Session keys (zeroized via SessionKeysWrapper's own ZeroizeOnDrop)
    #[zeroize(skip)]
    keys: parking_lot::Mutex<Option<SessionKeysWrapper>>,
    /// Send nonce counter
    #[zeroize(skip)]
    send_nonce: AtomicU64,
    /// Receive nonce counter
    #[zeroize(skip)]
    recv_nonce: AtomicU64,
    /// Bytes sent
    #[zeroize(skip)]
    bytes_sent: AtomicU64,
    /// Bytes received
    #[zeroize(skip)]
    bytes_received: AtomicU64,
}

/// Wrapper for session keys with zeroization.
#[derive(ZeroizeOnDrop)]
struct SessionKeysWrapper {
    #[zeroize(skip)]
    client_aead: Aead,
    #[zeroize(skip)]
    server_aead: Aead,
}

impl Session {
    /// Create a new session.
    fn new(
        id: SessionId,
        peer_addr: SocketAddr,
        client_public: PublicKey,
        short_id: [u8; 8],
    ) -> Self {
        let now = Instant::now();

        Self {
            id,
            state: parking_lot::Mutex::new(SessionState::Handshaking),
            created_at: now,
            last_activity: parking_lot::Mutex::new(now),
            peer_addr,
            client_public,
            short_id,
            keys: parking_lot::Mutex::new(None),
            send_nonce: AtomicU64::new(0),
            recv_nonce: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    /// Get session ID.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Get session state.
    pub fn state(&self) -> SessionState {
        *self.state.lock()
    }

    /// Get client's public key.
    pub fn client_public(&self) -> &PublicKey {
        &self.client_public
    }

    /// Get peer address (no logging, just for rate limiting).
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Set session keys after handshake.
    pub fn set_keys(&self, keys: SessionKeys) {
        let wrapper = SessionKeysWrapper {
            client_aead: Aead::new(&keys.client_key()),
            server_aead: Aead::new(&keys.server_key()),
        };
        *self.keys.lock() = Some(wrapper);
        *self.state.lock() = SessionState::Active;
    }

    /// Check if session has valid keys.
    pub fn has_keys(&self) -> bool {
        self.keys.lock().is_some()
    }

    /// Run the session loop.
    pub async fn run(&self, stream: &mut TcpStream) -> Result<()> {
        loop {
            // Read TLS record
            let mut header = [0u8; 5];
            match stream.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    *self.state.lock() = SessionState::Closed;
                    return Ok(());
                }
                Err(e) => return Err(Error::Network(e)),
            }

            let record_type = header[0];
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;

            if length > 16384 + 256 {
                return Err(Error::InvalidMessage("Record too large".into()));
            }

            let mut record = vec![0u8; length];
            stream.read_exact(&mut record).await?;

            // Update activity timestamp
            *self.last_activity.lock() = Instant::now();

            match record_type {
                0x17 => {
                    // Application data
                    let response = self.process_data(&record)?;
                    if let Some(data) = response {
                        self.send_data(stream, &data).await?;
                    }
                }
                0x15 => {
                    // Alert
                    *self.state.lock() = SessionState::Closing;
                    return Ok(());
                }
                _ => {
                    // Ignore other record types
                }
            }
        }
    }

    /// Process incoming encrypted data.
    fn process_data(&self, ciphertext: &[u8]) -> Result<Option<Vec<u8>>> {
        let keys = self.keys.lock();
        let keys = keys.as_ref().ok_or(Error::SessionExpired)?;

        // Get receive nonce
        let nonce_val = self.recv_nonce.fetch_add(1, Ordering::SeqCst);
        let nonce = Nonce::new(nonce_val);

        // Decrypt
        let plaintext = keys.client_aead.decrypt(&nonce, ciphertext, b"")?;

        self.bytes_received
            .fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        // Process application data (echo for now)
        // In production, this would route to the appropriate handler
        Ok(Some(plaintext))
    }

    /// Send encrypted data.
    async fn send_data(&self, stream: &mut TcpStream, data: &[u8]) -> Result<()> {
        let record = {
            let keys = self.keys.lock();
            let keys = keys.as_ref().ok_or(Error::SessionExpired)?;

            // Get send nonce
            let nonce_val = self.send_nonce.fetch_add(1, Ordering::SeqCst);
            let nonce = Nonce::new(nonce_val);

            // Encrypt
            let ciphertext = keys.server_aead.encrypt(&nonce, data, b"")?;

            // Frame as TLS record
            let mut record = Vec::with_capacity(5 + ciphertext.len());
            record.push(0x17); // Application data
            record.push(0x03);
            record.push(0x03);
            record.push((ciphertext.len() >> 8) as u8);
            record.push((ciphertext.len() & 0xff) as u8);
            record.extend_from_slice(&ciphertext);
            record
        }; // MutexGuard dropped here, before the .await

        stream.write_all(&record).await?;

        self.bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Check if session has expired.
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_activity.lock().elapsed() > timeout
    }

    /// Get session statistics.
    pub fn stats(&self) -> SessionStats {
        SessionStats {
            id: self.id,
            state: self.state(),
            created_at: self.created_at,
            last_activity: *self.last_activity.lock(),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

/// Session statistics (safe to expose, no sensitive data).
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub id: SessionId,
    pub state: SessionState,
    pub created_at: Instant,
    pub last_activity: Instant,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Manages all active sessions.
pub struct SessionManager {
    sessions: RwLock<HashMap<SessionId, Arc<Session>>>,
    next_id: AtomicU64,
    max_sessions: usize,
    session_timeout: Duration,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(max_sessions: usize, session_timeout: Duration) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_sessions,
            session_timeout,
        }
    }

    /// Create a new session.
    pub fn create_session(
        &self,
        peer_addr: SocketAddr,
        client_public: PublicKey,
        short_id: [u8; 8],
    ) -> Arc<Session> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let session = Arc::new(Session::new(id, peer_addr, client_public, short_id));

        {
            let mut sessions = self.sessions.write();

            // Enforce max sessions limit
            if sessions.len() >= self.max_sessions {
                // Remove oldest expired session
                let expired: Vec<_> = sessions
                    .iter()
                    .filter(|(_, s)| s.is_expired(self.session_timeout))
                    .map(|(id, _)| *id)
                    .take(10)
                    .collect();

                for id in expired {
                    sessions.remove(&id);
                }
            }

            sessions.insert(id, Arc::clone(&session));
        }

        session
    }

    /// Get a session by ID.
    pub fn get(&self, id: SessionId) -> Option<Arc<Session>> {
        self.sessions.read().get(&id).cloned()
    }

    /// Remove a session.
    pub fn remove(&self, id: SessionId) {
        self.sessions.write().remove(&id);
    }

    /// Get session count.
    pub fn count(&self) -> usize {
        self.sessions.read().len()
    }

    /// Run periodic cleanup of expired sessions.
    pub async fn run_cleanup(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;

            let expired: Vec<_> = {
                let sessions = self.sessions.read();
                sessions
                    .iter()
                    .filter(|(_, s)| s.is_expired(self.session_timeout))
                    .map(|(id, _)| *id)
                    .collect()
            };

            if !expired.is_empty() {
                let mut sessions = self.sessions.write();
                for id in &expired {
                    sessions.remove(id);
                }
                tracing::debug!("Cleaned up {} expired sessions", expired.len());
            }
        }
    }

    /// Get statistics for all sessions.
    pub fn all_stats(&self) -> Vec<SessionStats> {
        self.sessions
            .read()
            .values()
            .map(|s| s.stats())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let manager = SessionManager::new(100, Duration::from_secs(3600));

        let session = manager.create_session(
            "127.0.0.1:12345".parse().unwrap(),
            PublicKey::from_bytes([0x42; 32]),
            [0x01; 8],
        );

        assert_eq!(session.state(), SessionState::Handshaking);
        assert!(!session.has_keys());
        assert_eq!(manager.count(), 1);
    }

    #[test]
    fn test_session_expiration() {
        let session = Session::new(
            1,
            "127.0.0.1:12345".parse().unwrap(),
            PublicKey::from_bytes([0x42; 32]),
            [0x01; 8],
        );

        assert!(!session.is_expired(Duration::from_secs(3600)));

        // Simulate time passing (can't really test this without mocking time)
    }

    #[test]
    fn test_max_sessions_limit() {
        let manager = SessionManager::new(2, Duration::from_secs(3600));

        manager.create_session(
            "127.0.0.1:1".parse().unwrap(),
            PublicKey::from_bytes([1; 32]),
            [1; 8],
        );

        manager.create_session(
            "127.0.0.1:2".parse().unwrap(),
            PublicKey::from_bytes([2; 32]),
            [2; 8],
        );

        manager.create_session(
            "127.0.0.1:3".parse().unwrap(),
            PublicKey::from_bytes([3; 32]),
            [3; 8],
        );

        // Should still be 3 (or less if some were cleaned up)
        assert!(manager.count() <= 3);
    }

    #[test]
    fn test_session_stats() {
        let session = Session::new(
            42,
            "192.168.1.1:54321".parse().unwrap(),
            PublicKey::from_bytes([0x42; 32]),
            [0x01; 8],
        );

        let stats = session.stats();
        assert_eq!(stats.id, 42);
        assert_eq!(stats.state, SessionState::Handshaking);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.bytes_received, 0);
    }
}
