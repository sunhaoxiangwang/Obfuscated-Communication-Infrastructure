//! REALITY protocol server implementation.
//!
//! The server authenticates clients using the embedded auth tag in ClientHello,
//! then establishes encrypted sessions. Unauthenticated traffic is proxied to
//! the cover server for perfect unobservability.

use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::crypto::{kdf, Aead, Nonce, PublicKey, SessionKeys, StaticSecret};
use crate::error::{Error, Result};
use crate::reality::config::RealityServerConfig;
use crate::reality::{AUTH_TAG_OFFSET, SHORT_ID_SIZE};

/// REALITY protocol server.
pub struct RealityServer {
    config: Arc<RealityServerConfig>,
    /// Active session count (for metrics)
    active_sessions: Arc<RwLock<usize>>,
}

impl RealityServer {
    /// Create a new REALITY server.
    pub fn new(config: RealityServerConfig) -> Self {
        Self {
            config: Arc::new(config),
            active_sessions: Arc::new(RwLock::new(0)),
        }
    }

    /// Start the server and listen for connections.
    pub async fn run(&self) -> Result<()> {
        let addr: SocketAddr = format!("{}:{}", self.config.listen_addr, self.config.listen_port)
            .parse()
            .map_err(|e| Error::config(format!("Invalid listen address: {}", e)))?;

        let listener = TcpListener::bind(addr).await?;

        tracing::info!("REALITY server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let config = Arc::clone(&self.config);
                    let sessions = Arc::clone(&self.active_sessions);

                    tokio::spawn(async move {
                        *sessions.write() += 1;

                        if let Err(e) = Self::handle_connection(config, stream, peer_addr).await {
                            tracing::debug!("Connection error from {}: {}", peer_addr, e);
                        }

                        *sessions.write() -= 1;
                    });
                }
                Err(e) => {
                    tracing::warn!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        config: Arc<RealityServerConfig>,
        mut stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        stream.set_nodelay(true)?;

        // Read ClientHello
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(Error::handshake("Empty connection"));
        }
        buf.truncate(n);

        // Try to authenticate
        match Self::authenticate_client(&config, &buf) {
            Ok((client_public, short_id)) => {
                tracing::debug!(
                    "Authenticated client {} with short_id {:?}",
                    peer_addr,
                    short_id
                );
                Self::handle_authenticated_session(config, stream, client_public, &buf).await
            }
            Err(_) => {
                // Unauthenticated: proxy to cover server
                tracing::debug!("Proxying unauthenticated client {} to cover", peer_addr);
                Self::proxy_to_cover(config, stream, buf).await
            }
        }
    }

    fn authenticate_client(
        config: &RealityServerConfig,
        client_hello: &[u8],
    ) -> Result<(PublicKey, [u8; 8])> {
        // Parse ClientHello to extract client_random and key_share
        let (client_random, client_public) = Self::parse_client_hello_for_auth(client_hello)?;

        // Compute shared secret
        let shared_secret = config.static_secret.diffie_hellman(&client_public);

        // Compute expected auth tag
        let auth_tag = kdf::compute_auth_tag(
            shared_secret.as_bytes(),
            &client_random[..AUTH_TAG_OFFSET],
        );

        // Extract and unmask short_id
        let masked_id: [u8; SHORT_ID_SIZE] =
            client_random[AUTH_TAG_OFFSET..AUTH_TAG_OFFSET + SHORT_ID_SIZE]
                .try_into()
                .unwrap();
        let short_id = kdf::xor_bytes(&masked_id, &auth_tag);

        // Check if short_id is allowed
        if config.is_short_id_allowed(&short_id) {
            Ok((client_public, short_id))
        } else {
            Err(Error::Authentication)
        }
    }

    fn parse_client_hello_for_auth(data: &[u8]) -> Result<([u8; 32], PublicKey)> {
        // Minimum size check
        if data.len() < 50 {
            return Err(Error::InvalidMessage("ClientHello too short".into()));
        }

        // Skip TLS record header (5 bytes) and handshake header (4 bytes)
        // Skip legacy version (2 bytes)
        let random_start = 5 + 4 + 2;
        if data.len() < random_start + 32 {
            return Err(Error::InvalidMessage("ClientHello truncated".into()));
        }

        let client_random: [u8; 32] = data[random_start..random_start + 32].try_into().unwrap();

        // Find key_share extension
        let client_public = Self::find_key_share_extension(data)?;

        Ok((client_random, client_public))
    }

    fn find_key_share_extension(data: &[u8]) -> Result<PublicKey> {
        // Skip to extensions
        // TLS record (5) + handshake header (4) + version (2) + random (32) = 43
        let mut pos = 43;

        if data.len() <= pos {
            return Err(Error::InvalidMessage("No session ID".into()));
        }

        // Session ID length
        let session_id_len = data[pos] as usize;
        pos += 1 + session_id_len;

        if data.len() <= pos + 2 {
            return Err(Error::InvalidMessage("No cipher suites".into()));
        }

        // Cipher suites
        let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;

        if data.len() <= pos + 1 {
            return Err(Error::InvalidMessage("No compression".into()));
        }

        // Compression methods
        let compression_len = data[pos] as usize;
        pos += 1 + compression_len;

        if data.len() <= pos + 2 {
            return Err(Error::InvalidMessage("No extensions".into()));
        }

        // Extensions
        let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let extensions_end = pos + extensions_len;

        while pos + 4 <= extensions_end && pos + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_len > data.len() {
                break;
            }

            // Key share extension (type 51)
            if ext_type == 51 {
                // Parse key share entries
                let key_share_data = &data[pos..pos + ext_len];
                if key_share_data.len() >= 2 {
                    let list_len = u16::from_be_bytes([key_share_data[0], key_share_data[1]]) as usize;
                    let mut entry_pos = 2;

                    while entry_pos + 4 <= 2 + list_len && entry_pos + 4 <= key_share_data.len() {
                        let group = u16::from_be_bytes([
                            key_share_data[entry_pos],
                            key_share_data[entry_pos + 1],
                        ]);
                        let key_len = u16::from_be_bytes([
                            key_share_data[entry_pos + 2],
                            key_share_data[entry_pos + 3],
                        ]) as usize;
                        entry_pos += 4;

                        if group == 0x001d && key_len == 32 {
                            // X25519
                            if entry_pos + 32 <= key_share_data.len() {
                                let key_bytes: [u8; 32] = key_share_data[entry_pos..entry_pos + 32]
                                    .try_into()
                                    .unwrap();
                                return Ok(PublicKey::from_bytes(key_bytes));
                            }
                        }

                        entry_pos += key_len;
                    }
                }
            }

            pos += ext_len;
        }

        Err(Error::InvalidMessage("No X25519 key share found".into()))
    }

    async fn handle_authenticated_session(
        config: Arc<RealityServerConfig>,
        mut stream: TcpStream,
        client_public: PublicKey,
        _client_hello: &[u8],
    ) -> Result<()> {
        // Generate server ephemeral keypair
        let server_ephemeral = crate::crypto::EphemeralSecret::random();
        let server_ephemeral_public = PublicKey::from(&server_ephemeral);

        // Compute shared secret for session keys
        let shared_secret = server_ephemeral.diffie_hellman(&client_public);
        let session_keys = SessionKeys::derive(&shared_secret, b"reality_handshake");

        // Build and send ServerHello
        let server_hello = Self::build_server_hello(&server_ephemeral_public);
        stream.write_all(&server_hello).await?;

        // Create AEAD instances
        let client_aead = Aead::new(&session_keys.client_key());
        let server_aead = Aead::new(&session_keys.server_key());

        // Enter encrypted session
        let mut session = ServerSession {
            stream,
            client_aead,
            server_aead,
            recv_nonce: Nonce::new(0),
            send_nonce: Nonce::new(0),
        };

        session.run().await
    }

    pub(crate) fn build_server_hello(server_public: &PublicKey) -> Vec<u8> {
        use bytes::{BufMut, BytesMut};

        let mut buf = BytesMut::with_capacity(128);

        // TLS record header
        buf.put_u8(0x16); // Handshake
        buf.put_u16(0x0303); // TLS 1.2

        // Placeholder for record length
        let record_len_pos = buf.len();
        buf.put_u16(0);

        // Handshake header
        buf.put_u8(0x02); // ServerHello

        // Placeholder for handshake length
        let handshake_len_pos = buf.len();
        buf.put_slice(&[0, 0, 0]);

        // Server version (TLS 1.2 legacy)
        buf.put_u16(0x0303);

        // Server random
        let mut server_random = [0u8; 32];
        crate::crypto::SecureRandom::fill(&mut server_random);
        buf.put_slice(&server_random);

        // Session ID (empty)
        buf.put_u8(0);

        // Cipher suite (TLS_CHACHA20_POLY1305_SHA256)
        buf.put_u16(0x1303);

        // Compression method
        buf.put_u8(0);

        // Extensions
        let extensions_start = buf.len();
        buf.put_u16(0); // Placeholder for extensions length

        // Supported versions extension
        buf.put_u16(43); // Type
        buf.put_u16(2); // Length
        buf.put_u16(0x0304); // TLS 1.3

        // Key share extension
        buf.put_u16(51); // Type
        buf.put_u16(36); // Length: group(2) + key_len(2) + key(32)
        buf.put_u16(0x001d); // X25519
        buf.put_u16(32); // Key length
        buf.put_slice(server_public.as_bytes());

        // Fill in extensions length
        let extensions_len = buf.len() - extensions_start - 2;
        buf[extensions_start] = (extensions_len >> 8) as u8;
        buf[extensions_start + 1] = (extensions_len & 0xff) as u8;

        // Fill in handshake length
        let handshake_len = buf.len() - handshake_len_pos - 3;
        buf[handshake_len_pos] = ((handshake_len >> 16) & 0xff) as u8;
        buf[handshake_len_pos + 1] = ((handshake_len >> 8) & 0xff) as u8;
        buf[handshake_len_pos + 2] = (handshake_len & 0xff) as u8;

        // Fill in record length
        let record_len = buf.len() - record_len_pos - 2;
        buf[record_len_pos] = (record_len >> 8) as u8;
        buf[record_len_pos + 1] = (record_len & 0xff) as u8;

        buf.to_vec()
    }

    async fn proxy_to_cover(
        config: Arc<RealityServerConfig>,
        mut client_stream: TcpStream,
        initial_data: Vec<u8>,
    ) -> Result<()> {
        // Connect to cover server
        let cover_addr = format!("{}:{}", config.cover_server, config.cover_port);
        let mut cover_stream = TcpStream::connect(&cover_addr).await?;

        // Forward initial ClientHello
        cover_stream.write_all(&initial_data).await?;

        // Bidirectional proxy
        tokio::io::copy_bidirectional(&mut client_stream, &mut cover_stream).await?;

        Ok(())
    }

    /// Get the current number of active sessions.
    pub fn active_sessions(&self) -> usize {
        *self.active_sessions.read()
    }

    /// Static authentication method for use by the main server.
    ///
    /// This allows authentication without needing a full RealityServer instance.
    pub fn authenticate_client_static(
        static_secret: &StaticSecret,
        allowed_short_ids: &[[u8; 8]],
        client_hello: &[u8],
    ) -> Result<(PublicKey, [u8; 8])> {
        // Parse ClientHello to extract client_random and key_share
        let (client_random, client_public) = Self::parse_client_hello_for_auth(client_hello)?;

        // Compute shared secret
        let shared_secret = static_secret.diffie_hellman(&client_public);

        // Compute expected auth tag
        let auth_tag = kdf::compute_auth_tag(
            shared_secret.as_bytes(),
            &client_random[..AUTH_TAG_OFFSET],
        );

        // Extract and unmask short_id
        let masked_id: [u8; SHORT_ID_SIZE] =
            client_random[AUTH_TAG_OFFSET..AUTH_TAG_OFFSET + SHORT_ID_SIZE]
                .try_into()
                .unwrap();
        let short_id = kdf::xor_bytes(&masked_id, &auth_tag);

        // Check if short_id is allowed
        if allowed_short_ids.contains(&short_id) {
            Ok((client_public, short_id))
        } else {
            Err(Error::Authentication)
        }
    }
}

/// An authenticated server session.
struct ServerSession {
    stream: TcpStream,
    client_aead: Aead,
    server_aead: Aead,
    recv_nonce: Nonce,
    send_nonce: Nonce,
}

impl ServerSession {
    async fn run(&mut self) -> Result<()> {
        loop {
            // Read TLS record
            let mut header = [0u8; 5];
            match self.stream.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Clean close
                    return Ok(());
                }
                Err(e) => return Err(Error::Network(e)),
            }

            let record_type = header[0];
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;

            if length > 16384 + 256 {
                return Err(Error::InvalidMessage("Record too large".into()));
            }

            let mut record_data = vec![0u8; length];
            self.stream.read_exact(&mut record_data).await?;

            match record_type {
                0x17 => {
                    // Application data
                    let plaintext = self.client_aead.decrypt(&self.recv_nonce, &record_data, b"")?;
                    self.recv_nonce.increment();

                    // Echo back for testing (in production, this would be application logic)
                    self.send(&plaintext).await?;
                }
                0x15 => {
                    // Alert - clean shutdown
                    return Ok(());
                }
                _ => {
                    // Ignore other record types
                }
            }
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        let ciphertext = self.server_aead.encrypt(&self.send_nonce, data, b"")?;
        self.send_nonce.increment();

        let mut record = Vec::with_capacity(5 + ciphertext.len());
        record.push(0x17); // Application data
        record.push(0x03);
        record.push(0x03);
        record.push((ciphertext.len() >> 8) as u8);
        record.push((ciphertext.len() & 0xff) as u8);
        record.extend_from_slice(&ciphertext);

        self.stream.write_all(&record).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_hello_format() {
        let server_public = PublicKey::from_bytes([0x42u8; 32]);
        let hello = RealityServer::build_server_hello(&server_public);

        // Verify TLS record structure
        assert_eq!(hello[0], 0x16); // Handshake
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x03); // TLS 1.2

        // Verify handshake type
        assert_eq!(hello[5], 0x02); // ServerHello
    }
}
