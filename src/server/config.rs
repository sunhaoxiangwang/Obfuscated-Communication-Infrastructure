//! Server configuration.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::crypto::StaticSecret;

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    /// Listen address
    pub listen_addr: String,
    /// Listen port
    pub listen_port: u16,
    /// Server's static secret key
    pub static_secret: StaticSecret,
    /// Allowed short IDs for authentication
    pub allowed_short_ids: Vec<[u8; 8]>,
    /// Cover server hostname
    pub cover_server: String,
    /// Cover server port
    pub cover_port: u16,
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Session timeout
    pub session_timeout: Duration,
    /// Rate limit: max requests per window
    pub rate_limit_requests: u32,
    /// Rate limit: window duration
    pub rate_limit_window: Duration,
    /// Enable RAM-only mode (no disk writes)
    pub ram_only: bool,
}

impl ServerConfig {
    /// Create a new configuration with a random keypair.
    pub fn new_random(
        listen_addr: impl Into<String>,
        listen_port: u16,
        cover_server: impl Into<String>,
    ) -> Self {
        Self {
            listen_addr: listen_addr.into(),
            listen_port,
            static_secret: StaticSecret::random(),
            allowed_short_ids: Vec::new(),
            cover_server: cover_server.into(),
            cover_port: 443,
            max_sessions: 10000,
            session_timeout: Duration::from_secs(3600),
            rate_limit_requests: 100,
            rate_limit_window: Duration::from_secs(60),
            ram_only: true,
        }
    }

    /// Get the server's public key.
    pub fn public_key(&self) -> crate::crypto::PublicKey {
        crate::crypto::PublicKey::from(&self.static_secret)
    }

    /// Add an allowed short ID.
    pub fn add_short_id(&mut self, short_id: [u8; 8]) {
        if !self.allowed_short_ids.contains(&short_id) {
            self.allowed_short_ids.push(short_id);
        }
    }

    /// Generate a random short ID and add it.
    pub fn generate_short_id(&mut self) -> [u8; 8] {
        let short_id: [u8; 8] = crate::crypto::SecureRandom::bytes();
        self.add_short_id(short_id);
        short_id
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.listen_addr.is_empty() {
            return Err("listen_addr cannot be empty".into());
        }
        if self.cover_server.is_empty() {
            return Err("cover_server cannot be empty".into());
        }
        if self.allowed_short_ids.is_empty() {
            return Err("at least one short_id must be configured".into());
        }
        Ok(())
    }
}

/// Configuration file format for serialization.
#[derive(Serialize, Deserialize)]
pub struct ServerConfigFile {
    /// Listen address
    pub listen_addr: String,
    /// Listen port
    pub listen_port: u16,
    /// Server's static secret key (base64)
    pub static_secret_b64: String,
    /// Allowed short IDs (hex)
    pub allowed_short_ids: Vec<String>,
    /// Cover server hostname
    pub cover_server: String,
    /// Cover server port
    pub cover_port: u16,
    /// Maximum concurrent sessions
    pub max_sessions: usize,
    /// Session timeout (seconds)
    pub session_timeout_secs: u64,
    /// Rate limit: max requests
    pub rate_limit_requests: u32,
    /// Rate limit: window seconds
    pub rate_limit_window_secs: u64,
}

impl ServerConfigFile {
    /// Convert to runtime configuration.
    pub fn to_config(&self) -> Result<ServerConfig, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let secret_bytes = STANDARD
            .decode(&self.static_secret_b64)
            .map_err(|e| format!("Invalid base64 secret: {}", e))?;

        if secret_bytes.len() != 32 {
            return Err("static_secret must be 32 bytes".into());
        }

        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&secret_bytes);

        let mut short_ids = Vec::new();
        for hex_id in &self.allowed_short_ids {
            let id_bytes = hex::decode(hex_id)
                .map_err(|e| format!("Invalid hex short_id: {}", e))?;
            if id_bytes.len() != 8 {
                return Err("short_id must be 8 bytes".into());
            }
            let mut id_arr = [0u8; 8];
            id_arr.copy_from_slice(&id_bytes);
            short_ids.push(id_arr);
        }

        Ok(ServerConfig {
            listen_addr: self.listen_addr.clone(),
            listen_port: self.listen_port,
            static_secret: StaticSecret::from_bytes(secret_arr),
            allowed_short_ids: short_ids,
            cover_server: self.cover_server.clone(),
            cover_port: self.cover_port,
            max_sessions: self.max_sessions,
            session_timeout: Duration::from_secs(self.session_timeout_secs),
            rate_limit_requests: self.rate_limit_requests,
            rate_limit_window: Duration::from_secs(self.rate_limit_window_secs),
            ram_only: true,
        })
    }

    /// Create from runtime configuration.
    pub fn from_config(config: &ServerConfig) -> Self {
        use base64::{engine::general_purpose::STANDARD, Engine};

        Self {
            listen_addr: config.listen_addr.clone(),
            listen_port: config.listen_port,
            static_secret_b64: STANDARD.encode(config.static_secret.to_bytes()),
            allowed_short_ids: config.allowed_short_ids
                .iter()
                .map(|id| hex::encode(id))
                .collect(),
            cover_server: config.cover_server.clone(),
            cover_port: config.cover_port,
            max_sessions: config.max_sessions,
            session_timeout_secs: config.session_timeout.as_secs(),
            rate_limit_requests: config.rate_limit_requests,
            rate_limit_window_secs: config.rate_limit_window.as_secs(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        let mut config = ServerConfig::new_random("0.0.0.0", 443, "www.example.com");
        let short_id = config.generate_short_id();

        assert!(config.validate().is_ok());
        assert!(config.allowed_short_ids.contains(&short_id));
    }

    #[test]
    fn test_config_serialization() {
        let mut config = ServerConfig::new_random("0.0.0.0", 443, "www.example.com");
        config.generate_short_id();

        let file = ServerConfigFile::from_config(&config);
        let restored = file.to_config().unwrap();

        assert_eq!(config.listen_addr, restored.listen_addr);
        assert_eq!(config.listen_port, restored.listen_port);
        assert_eq!(config.cover_server, restored.cover_server);
    }

    #[test]
    fn test_validation() {
        let config = ServerConfig::new_random("", 443, "www.example.com");
        assert!(config.validate().is_err());

        let mut config = ServerConfig::new_random("0.0.0.0", 443, "");
        config.generate_short_id();
        assert!(config.validate().is_err());
    }
}
