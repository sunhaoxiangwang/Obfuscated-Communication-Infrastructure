//! REALITY protocol configuration.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{PublicKey, StaticSecret};

/// Configuration for a REALITY client.
#[derive(Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    /// Server's static public key (X25519, base64-encoded for config files)
    #[serde(with = "base64_bytes")]
    pub server_public_key: [u8; 32],

    /// Short ID for authentication (8 bytes, hex-encoded for config files)
    #[serde(with = "hex_bytes")]
    pub short_id: [u8; 8],

    /// SNI hostname to impersonate (e.g., "www.microsoft.com")
    pub cover_sni: String,

    /// Actual server address to connect to
    pub server_addr: String,

    /// Server port (typically 443)
    #[serde(default = "default_port")]
    pub server_port: u16,

    /// Fingerprint of cover server's certificate (optional validation)
    #[serde(default)]
    pub cover_fingerprint: Option<String>,

    /// Supported ALPN protocols
    #[serde(default = "default_alpn")]
    pub alpn: Vec<String>,
}

fn default_port() -> u16 {
    443
}

fn default_alpn() -> Vec<String> {
    vec!["h2".to_string(), "http/1.1".to_string()]
}

impl RealityConfig {
    /// Create a new configuration.
    pub fn new(
        server_public_key: [u8; 32],
        short_id: [u8; 8],
        cover_sni: impl Into<String>,
        server_addr: impl Into<String>,
    ) -> Self {
        Self {
            server_public_key,
            short_id,
            cover_sni: cover_sni.into(),
            server_addr: server_addr.into(),
            server_port: 443,
            cover_fingerprint: None,
            alpn: default_alpn(),
        }
    }

    /// Get the server's public key.
    pub fn server_public_key(&self) -> PublicKey {
        PublicKey::from_bytes(self.server_public_key)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cover_sni.is_empty() {
            return Err("cover_sni cannot be empty".to_string());
        }
        if self.server_addr.is_empty() {
            return Err("server_addr cannot be empty".to_string());
        }
        if self.server_public_key == [0u8; 32] {
            return Err("server_public_key cannot be all zeros".to_string());
        }
        Ok(())
    }
}

/// Configuration for a REALITY server.
#[derive(ZeroizeOnDrop)]
pub struct RealityServerConfig {
    /// Server's static secret key (X25519)
    #[zeroize(skip)] // StaticSecret handles its own zeroization
    pub static_secret: StaticSecret,

    /// Allowed short IDs for authentication
    pub allowed_short_ids: Vec<[u8; 8]>,

    /// Cover server to proxy unauthenticated traffic to
    pub cover_server: String,

    /// Cover server port
    pub cover_port: u16,

    /// Listen address
    pub listen_addr: String,

    /// Listen port
    pub listen_port: u16,
}

impl RealityServerConfig {
    /// Create a new server configuration with a random keypair.
    pub fn new_random(
        cover_server: impl Into<String>,
        listen_addr: impl Into<String>,
        listen_port: u16,
    ) -> Self {
        Self {
            static_secret: StaticSecret::random(),
            allowed_short_ids: Vec::new(),
            cover_server: cover_server.into(),
            cover_port: 443,
            listen_addr: listen_addr.into(),
            listen_port,
        }
    }

    /// Get the server's public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.static_secret)
    }

    /// Add an allowed short ID.
    pub fn add_short_id(&mut self, short_id: [u8; 8]) {
        if !self.allowed_short_ids.contains(&short_id) {
            self.allowed_short_ids.push(short_id);
        }
    }

    /// Check if a short ID is allowed.
    pub fn is_short_id_allowed(&self, short_id: &[u8; 8]) -> bool {
        self.allowed_short_ids.contains(short_id)
    }

    /// Generate a client configuration for this server.
    pub fn generate_client_config(&self, short_id: [u8; 8]) -> RealityConfig {
        RealityConfig {
            server_public_key: self.public_key().to_bytes(),
            short_id,
            cover_sni: self.cover_server.clone(),
            server_addr: self.listen_addr.clone(),
            server_port: self.listen_port,
            cover_fingerprint: None,
            alpn: default_alpn(),
        }
    }
}

// Custom serde helpers for byte arrays
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    use base64::{engine::general_purpose::STANDARD, Engine};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = STANDARD.decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("invalid length"))
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 8], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes.try_into().map_err(|_| serde::de::Error::custom("invalid length"))
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
        assert!(config.validate().is_ok());

        let bad_config = RealityConfig::new(
            [0u8; 32], // Invalid: all zeros
            [0u8; 8],
            "www.example.com",
            "192.168.1.1",
        );
        assert!(bad_config.validate().is_err());
    }

    #[test]
    fn test_server_config() {
        let mut server_config = RealityServerConfig::new_random(
            "www.microsoft.com",
            "0.0.0.0",
            443,
        );

        let short_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        server_config.add_short_id(short_id);

        assert!(server_config.is_short_id_allowed(&short_id));
        assert!(!server_config.is_short_id_allowed(&[0u8; 8]));

        let client_config = server_config.generate_client_config(short_id);
        assert_eq!(client_config.short_id, short_id);
        assert_eq!(
            client_config.server_public_key,
            server_config.public_key().to_bytes()
        );
    }
}
