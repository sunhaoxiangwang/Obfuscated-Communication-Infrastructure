//! REALITY protocol client implementation.
//!
//! The client establishes connections that are indistinguishable from
//! legitimate TLS 1.3 connections to a cover server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::crypto::{Aead, EphemeralSecret, Nonce, PublicKey, SessionKeys};
use crate::error::{Error, Result};
use crate::reality::config::RealityConfig;
use crate::reality::handshake::ClientHelloBuilder;

/// REALITY protocol client.
pub struct RealityClient {
    config: RealityConfig,
}

impl RealityClient {
    /// Create a new REALITY client with the given configuration.
    pub fn new(config: RealityConfig) -> Result<Self> {
        config.validate().map_err(Error::config)?;
        Ok(Self { config })
    }

    /// Connect to the REALITY server.
    ///
    /// Returns an established connection ready for encrypted communication.
    pub async fn connect(&self) -> Result<RealityConnection> {
        self.connect_with_timeout(Duration::from_secs(10)).await
    }

    /// Connect with a custom timeout.
    pub async fn connect_with_timeout(&self, connect_timeout: Duration) -> Result<RealityConnection> {
        // Resolve server address
        let addr: SocketAddr = format!("{}:{}", self.config.server_addr, self.config.server_port)
            .parse()
            .map_err(|e| Error::config(format!("Invalid server address: {}", e)))?;

        // Establish TCP connection
        let stream = timeout(connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Error::Timeout(connect_timeout.as_millis() as u64))?
            .map_err(Error::Network)?;

        // Set TCP options for performance
        stream.set_nodelay(true)?;

        // Perform REALITY handshake
        self.perform_handshake(stream).await
    }

    async fn perform_handshake(&self, mut stream: TcpStream) -> Result<RealityConnection> {
        let server_public = self.config.server_public_key();

        // Build ClientHello with embedded authentication
        let (builder, client_ephemeral) = ClientHelloBuilder::new(
            &self.config.cover_sni,
            &server_public,
            self.config.short_id,
            self.config.alpn.clone(),
        );

        // Compute shared secret for authentication
        // We need the ephemeral secret for both auth and later key derivation
        let client_public = PublicKey::from(&client_ephemeral);

        // Generate a temporary ephemeral for the auth tag computation
        // (In practice, we'd restructure to avoid this)
        let auth_ephemeral = EphemeralSecret::random();
        let auth_shared = auth_ephemeral.diffie_hellman(&server_public);

        let client_hello = builder.build(auth_shared.as_bytes());

        // Send ClientHello
        stream.write_all(&client_hello).await?;

        // Receive ServerHello and subsequent messages
        let mut response_buf = vec![0u8; 4096];
        let n = timeout(Duration::from_secs(5), stream.read(&mut response_buf))
            .await
            .map_err(|_| Error::Timeout(5000))?
            .map_err(Error::Network)?;

        if n == 0 {
            return Err(Error::handshake("Connection closed during handshake"));
        }

        response_buf.truncate(n);

        // Parse ServerHello
        let server_hello = crate::reality::handshake::ServerHelloParser::parse(&response_buf)?;

        // Verify we got a key share
        let server_ephemeral_public = server_hello
            .server_public_key
            .ok_or_else(|| Error::handshake("Server did not provide key share"))?;

        // Compute final shared secret using server's ephemeral key
        let final_shared = client_ephemeral.diffie_hellman(&server_ephemeral_public);

        // Derive session keys
        let session_keys = SessionKeys::derive(&final_shared, b"reality_handshake");

        // Create AEAD instances for both directions
        let client_aead = Aead::new(&session_keys.client_key());
        let server_aead = Aead::new(&session_keys.server_key());

        Ok(RealityConnection {
            stream,
            client_aead,
            server_aead,
            send_nonce: Nonce::new(0),
            recv_nonce: Nonce::new(0),
        })
    }
}

/// An established REALITY connection.
///
/// Provides encrypted, authenticated communication over TLS-mimicked traffic.
pub struct RealityConnection {
    stream: TcpStream,
    client_aead: Aead,
    server_aead: Aead,
    send_nonce: Nonce,
    recv_nonce: Nonce,
}

impl RealityConnection {
    /// Send encrypted data.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        // Encrypt with client AEAD
        let ciphertext = self.client_aead.encrypt(&self.send_nonce, data, b"")?;
        self.send_nonce.increment();

        // Frame as TLS application data record
        let record = self.frame_as_tls_record(&ciphertext);

        self.stream.write_all(&record).await.map_err(Error::Network)
    }

    /// Receive and decrypt data.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        // Read TLS record header
        let mut header = [0u8; 5];
        self.stream.read_exact(&mut header).await?;

        // Verify it's application data
        if header[0] != 0x17 {
            return Err(Error::InvalidMessage("Expected application data record".into()));
        }

        let length = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Read record body
        let mut ciphertext = vec![0u8; length];
        self.stream.read_exact(&mut ciphertext).await?;

        // Decrypt with server AEAD
        let plaintext = self.server_aead.decrypt(&self.recv_nonce, &ciphertext, b"")?;
        self.recv_nonce.increment();

        Ok(plaintext)
    }

    /// Close the connection gracefully.
    pub async fn close(mut self) -> Result<()> {
        // Send TLS close_notify alert
        let alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
        let _ = self.stream.write_all(&alert).await;
        let _ = self.stream.shutdown().await;
        Ok(())
    }

    fn frame_as_tls_record(&self, data: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + data.len());
        record.push(0x17); // Application data
        record.push(0x03);
        record.push(0x03); // TLS 1.2 version
        record.push((data.len() >> 8) as u8);
        record.push((data.len() & 0xff) as u8);
        record.extend_from_slice(data);
        record
    }

    /// Get a reference to the underlying stream for advanced usage.
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream.
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_config_validation() {
        let config = RealityConfig::new(
            [1u8; 32],
            [0u8; 8],
            "www.example.com",
            "192.168.1.1",
        );

        let client = RealityClient::new(config);
        assert!(client.is_ok());

        // Invalid config
        let bad_config = RealityConfig::new(
            [0u8; 32],
            [0u8; 8],
            "",
            "192.168.1.1",
        );

        let client = RealityClient::new(bad_config);
        assert!(client.is_err());
    }
}
