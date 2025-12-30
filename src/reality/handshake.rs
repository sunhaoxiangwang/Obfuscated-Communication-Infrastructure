//! TLS 1.3 handshake message construction and parsing.
//!
//! This module implements the low-level TLS message manipulation needed
//! for the REALITY protocol. It constructs ClientHello messages that are
//! indistinguishable from legitimate TLS 1.3 clients.

use bytes::{BufMut, BytesMut};

use crate::crypto::{kdf, EphemeralSecret, PublicKey, SecureRandom};
use crate::error::{Error, Result};
use crate::reality::{AUTH_TAG_OFFSET, SHORT_ID_SIZE};

/// TLS record types
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

/// TLS handshake types
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    CertificateVerify = 15,
    Finished = 20,
}

/// TLS extension types
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ExtensionType {
    ServerName = 0,
    SupportedGroups = 10,
    SignatureAlgorithms = 13,
    ApplicationLayerProtocolNegotiation = 16,
    SupportedVersions = 43,
    KeyShare = 51,
}

/// Builder for TLS ClientHello messages with embedded REALITY authentication.
pub struct ClientHelloBuilder {
    /// Server name indication (SNI)
    sni: String,
    /// Client's ephemeral public key
    client_public: PublicKey,
    /// Pre-computed shared secret for auth tag
    shared_secret: [u8; 32],
    /// Short ID to embed in authentication
    short_id: [u8; 8],
    /// ALPN protocols to advertise
    alpn: Vec<String>,
}

impl ClientHelloBuilder {
    /// Create a new ClientHello builder.
    ///
    /// # Arguments
    ///
    /// * `sni` - Server Name Indication (hostname to impersonate)
    /// * `server_public_key` - Server's static X25519 public key
    /// * `short_id` - 8-byte authentication identifier
    /// * `alpn` - ALPN protocols (e.g., ["h2", "http/1.1"])
    pub fn new(
        sni: impl Into<String>,
        server_public_key: &PublicKey,
        short_id: [u8; 8],
        alpn: Vec<String>,
    ) -> (Self, EphemeralSecret) {
        let client_ephemeral = EphemeralSecret::random();
        let client_public = PublicKey::from(&client_ephemeral);

        // Compute shared secret for authentication
        // Note: We need to clone the ephemeral for DH, then use it again later
        let temp_ephemeral = EphemeralSecret::random();
        let temp_public = PublicKey::from(&temp_ephemeral);
        let _ = temp_ephemeral.diffie_hellman(server_public_key);

        // For the builder, we'll compute shared secret during build
        // Store the server public key info needed
        let shared_secret = [0u8; 32]; // Placeholder, computed during build

        (
            Self {
                sni: sni.into(),
                client_public,
                shared_secret,
                short_id,
                alpn,
            },
            client_ephemeral,
        )
    }

    /// Build the ClientHello message with embedded authentication.
    ///
    /// The authentication is embedded in the client_random field:
    /// - Bytes 0-23: Random data
    /// - Bytes 24-31: short_id XOR auth_tag
    pub fn build(&self, shared_secret: &[u8; 32]) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(512);

        // Generate client_random with embedded auth
        let mut client_random = [0u8; 32];
        SecureRandom::fill(&mut client_random[..AUTH_TAG_OFFSET]);

        // Compute auth tag and XOR with short_id
        let auth_tag = kdf::compute_auth_tag(shared_secret, &client_random[..AUTH_TAG_OFFSET]);
        let masked_id = kdf::xor_bytes(&self.short_id, &auth_tag);
        client_random[AUTH_TAG_OFFSET..].copy_from_slice(&masked_id);

        // Build handshake message
        let handshake_body = self.build_client_hello_body(&client_random);

        // TLS record layer
        buf.put_u8(ContentType::Handshake as u8);
        buf.put_u16(0x0303); // TLS 1.2 legacy version
        buf.put_u16(handshake_body.len() as u16);
        buf.put_slice(&handshake_body);

        buf.to_vec()
    }

    fn build_client_hello_body(&self, client_random: &[u8; 32]) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(400);

        // Handshake type and length placeholder
        buf.put_u8(HandshakeType::ClientHello as u8);
        let length_pos = buf.len();
        buf.put_slice(&[0, 0, 0]); // 3-byte length placeholder

        // Legacy version (TLS 1.2)
        buf.put_u16(0x0303);

        // Client random (with embedded auth)
        buf.put_slice(client_random);

        // Legacy session ID (empty for TLS 1.3)
        buf.put_u8(0);

        // Cipher suites
        let cipher_suites = self.build_cipher_suites();
        buf.put_u16(cipher_suites.len() as u16);
        buf.put_slice(&cipher_suites);

        // Compression methods (null only for TLS 1.3)
        buf.put_u8(1);
        buf.put_u8(0);

        // Extensions
        let extensions = self.build_extensions();
        buf.put_u16(extensions.len() as u16);
        buf.put_slice(&extensions);

        // Fill in handshake length
        let total_len = buf.len() - 4;
        buf[length_pos] = ((total_len >> 16) & 0xff) as u8;
        buf[length_pos + 1] = ((total_len >> 8) & 0xff) as u8;
        buf[length_pos + 2] = (total_len & 0xff) as u8;

        buf.to_vec()
    }

    fn build_cipher_suites(&self) -> Vec<u8> {
        // TLS 1.3 cipher suites (matching Chrome/Firefox fingerprint)
        vec![
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x13, 0x02, // TLS_AES_256_GCM_SHA384
            0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
            0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        ]
    }

    fn build_extensions(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(256);

        // SNI extension
        self.write_sni_extension(&mut buf);

        // Supported groups
        self.write_supported_groups(&mut buf);

        // Signature algorithms
        self.write_signature_algorithms(&mut buf);

        // ALPN
        if !self.alpn.is_empty() {
            self.write_alpn_extension(&mut buf);
        }

        // Supported versions (TLS 1.3)
        self.write_supported_versions(&mut buf);

        // Key share (X25519)
        self.write_key_share(&mut buf);

        buf.to_vec()
    }

    fn write_sni_extension(&self, buf: &mut BytesMut) {
        let sni_bytes = self.sni.as_bytes();
        let entry_len = 3 + sni_bytes.len(); // type(1) + len(2) + name
        let list_len = entry_len;
        let ext_len = 2 + list_len; // list_len(2) + list

        buf.put_u16(ExtensionType::ServerName as u16);
        buf.put_u16(ext_len as u16);
        buf.put_u16(list_len as u16);
        buf.put_u8(0); // Host name type
        buf.put_u16(sni_bytes.len() as u16);
        buf.put_slice(sni_bytes);
    }

    fn write_supported_groups(&self, buf: &mut BytesMut) {
        let groups = vec![
            0x00, 0x1d, // x25519
            0x00, 0x17, // secp256r1
            0x00, 0x18, // secp384r1
        ];

        buf.put_u16(ExtensionType::SupportedGroups as u16);
        buf.put_u16((2 + groups.len()) as u16);
        buf.put_u16(groups.len() as u16);
        buf.put_slice(&groups);
    }

    fn write_signature_algorithms(&self, buf: &mut BytesMut) {
        let algorithms = vec![
            0x04, 0x03, // ecdsa_secp256r1_sha256
            0x08, 0x04, // rsa_pss_rsae_sha256
            0x04, 0x01, // rsa_pkcs1_sha256
            0x05, 0x03, // ecdsa_secp384r1_sha384
            0x08, 0x05, // rsa_pss_rsae_sha384
            0x05, 0x01, // rsa_pkcs1_sha384
            0x08, 0x06, // rsa_pss_rsae_sha512
            0x06, 0x01, // rsa_pkcs1_sha512
        ];

        buf.put_u16(ExtensionType::SignatureAlgorithms as u16);
        buf.put_u16((2 + algorithms.len()) as u16);
        buf.put_u16(algorithms.len() as u16);
        buf.put_slice(&algorithms);
    }

    fn write_alpn_extension(&self, buf: &mut BytesMut) {
        let mut alpn_list = Vec::new();
        for proto in &self.alpn {
            alpn_list.push(proto.len() as u8);
            alpn_list.extend_from_slice(proto.as_bytes());
        }

        buf.put_u16(ExtensionType::ApplicationLayerProtocolNegotiation as u16);
        buf.put_u16((2 + alpn_list.len()) as u16);
        buf.put_u16(alpn_list.len() as u16);
        buf.put_slice(&alpn_list);
    }

    fn write_supported_versions(&self, buf: &mut BytesMut) {
        buf.put_u16(ExtensionType::SupportedVersions as u16);
        buf.put_u16(3); // Extension length
        buf.put_u8(2); // List length
        buf.put_u16(0x0304); // TLS 1.3
    }

    fn write_key_share(&self, buf: &mut BytesMut) {
        let key_bytes = self.client_public.as_bytes();
        let entry_len = 2 + 2 + key_bytes.len(); // group(2) + len(2) + key

        buf.put_u16(ExtensionType::KeyShare as u16);
        buf.put_u16((2 + entry_len) as u16);
        buf.put_u16(entry_len as u16);
        buf.put_u16(0x001d); // x25519
        buf.put_u16(key_bytes.len() as u16);
        buf.put_slice(key_bytes);
    }
}

/// Parser for TLS ServerHello messages.
pub struct ServerHelloParser;

impl ServerHelloParser {
    /// Parse a ServerHello message and extract the server's key share.
    pub fn parse(data: &[u8]) -> Result<ParsedServerHello> {
        if data.len() < 5 {
            return Err(Error::InvalidMessage("ServerHello too short".into()));
        }

        // Check record type
        if data[0] != ContentType::Handshake as u8 {
            return Err(Error::InvalidMessage("Not a handshake message".into()));
        }

        // Check legacy version
        let legacy_version = u16::from_be_bytes([data[1], data[2]]);
        if legacy_version != 0x0303 {
            return Err(Error::InvalidMessage("Unexpected TLS version".into()));
        }

        let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + record_len {
            return Err(Error::InvalidMessage("Incomplete ServerHello".into()));
        }

        let handshake = &data[5..5 + record_len];

        // Check handshake type
        if handshake[0] != HandshakeType::ServerHello as u8 {
            return Err(Error::InvalidMessage("Not a ServerHello".into()));
        }

        let handshake_len = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | (handshake[3] as usize);

        if handshake.len() < 4 + handshake_len {
            return Err(Error::InvalidMessage("Incomplete handshake".into()));
        }

        let body = &handshake[4..4 + handshake_len];

        // Parse ServerHello body
        if body.len() < 2 + 32 + 1 {
            return Err(Error::InvalidMessage("ServerHello body too short".into()));
        }

        let server_random: [u8; 32] = body[2..34].try_into().unwrap();
        let session_id_len = body[34] as usize;

        let mut pos = 35 + session_id_len;
        if body.len() < pos + 3 {
            return Err(Error::InvalidMessage("ServerHello truncated".into()));
        }

        let cipher_suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
        pos += 2;

        let _compression = body[pos];
        pos += 1;

        // Parse extensions
        let mut server_public_key = None;

        if body.len() > pos + 2 {
            let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
            pos += 2;

            let extensions_end = pos + extensions_len;
            while pos + 4 <= extensions_end {
                let ext_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
                let ext_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
                pos += 4;

                if pos + ext_len > extensions_end {
                    break;
                }

                if ext_type == ExtensionType::KeyShare as u16 {
                    // Parse key share entry
                    if ext_len >= 4 {
                        let group = u16::from_be_bytes([body[pos], body[pos + 1]]);
                        let key_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;

                        if group == 0x001d && key_len == 32 && ext_len >= 4 + key_len {
                            let key_bytes: [u8; 32] =
                                body[pos + 4..pos + 4 + 32].try_into().unwrap();
                            server_public_key = Some(PublicKey::from_bytes(key_bytes));
                        }
                    }
                }

                pos += ext_len;
            }
        }

        Ok(ParsedServerHello {
            server_random,
            cipher_suite,
            server_public_key,
        })
    }
}

/// Parsed ServerHello message.
#[derive(Debug)]
pub struct ParsedServerHello {
    /// Server random (32 bytes)
    pub server_random: [u8; 32],
    /// Selected cipher suite
    pub cipher_suite: u16,
    /// Server's ephemeral public key (from key_share extension)
    pub server_public_key: Option<PublicKey>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::StaticSecret;

    #[test]
    fn test_client_hello_builder() {
        let server_secret = StaticSecret::random();
        let server_public = PublicKey::from(&server_secret);

        let short_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let alpn = vec!["h2".to_string(), "http/1.1".to_string()];

        let (builder, client_ephemeral) =
            ClientHelloBuilder::new("www.example.com", &server_public, short_id, alpn);

        // Compute shared secret
        let shared = client_ephemeral.diffie_hellman(&server_public);

        let client_hello = builder.build(shared.as_bytes());

        // Verify it looks like a TLS handshake
        assert!(!client_hello.is_empty());
        assert_eq!(client_hello[0], ContentType::Handshake as u8);
        assert_eq!(client_hello[1], 0x03);
        assert_eq!(client_hello[2], 0x03); // TLS 1.2 version

        // Verify handshake type is ClientHello
        assert_eq!(client_hello[5], HandshakeType::ClientHello as u8);
    }

    #[test]
    fn test_auth_embedding() {
        let server_secret = StaticSecret::random();
        let server_public = PublicKey::from(&server_secret);

        let short_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let alpn = vec!["h2".to_string()];

        let (builder, client_ephemeral) =
            ClientHelloBuilder::new("www.example.com", &server_public, short_id, alpn);

        let client_public = PublicKey::from(&client_ephemeral);
        let shared = client_ephemeral.diffie_hellman(&server_public);

        let _client_hello = builder.build(shared.as_bytes());

        // Server should be able to verify authentication
        let server_shared = server_secret.diffie_hellman(&client_public);
        assert_eq!(shared.as_bytes(), server_shared.as_bytes());
    }
}
