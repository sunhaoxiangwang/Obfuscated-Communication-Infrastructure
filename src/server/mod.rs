//! Server Infrastructure Module.
//!
//! Implements the RAM-only edge proxy architecture with:
//!
//! 1. **Zero-Log Design**: All session data exists only in RAM
//! 2. **Automatic Key Rotation**: Ephemeral keys with configurable lifetime
//! 3. **Health Monitoring**: Metrics collection without logging user data
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Edge Proxy                                │
//! │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
//! │  │   TLS Listener   │  │  REALITY Auth    │  │  Rate Limit  │  │
//! │  │   (Port 443)     │  │  Validator       │  │  Manager     │  │
//! │  └────────┬─────────┘  └────────┬─────────┘  └──────┬───────┘  │
//! │           │                     │                    │          │
//! │           ▼                     ▼                    ▼          │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │                   Session Manager                         │  │
//! │  │  • RAM-only storage                                      │  │
//! │  │  • Automatic expiration                                  │  │
//! │  │  • Forward secrecy via ephemeral keys                    │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! │                              │                                  │
//! │                              ▼                                  │
//! │  ┌──────────────────────────────────────────────────────────┐  │
//! │  │                   Connection Pool                         │  │
//! │  │  • Multiplexed streams                                   │  │
//! │  │  • Per-session encryption                                │  │
//! │  └──────────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

mod config;
mod metrics;
mod rate_limit;
mod session;

pub use config::ServerConfig;
pub use metrics::ServerMetrics;
pub use rate_limit::RateLimiter;
pub use session::{Session, SessionManager};

use std::sync::Arc;
use tokio::net::TcpListener;

use crate::error::Result;

/// Main server instance.
pub struct Server {
    config: Arc<ServerConfig>,
    session_manager: Arc<SessionManager>,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<ServerMetrics>,
}

impl Server {
    /// Create a new server with the given configuration.
    pub fn new(config: ServerConfig) -> Self {
        let config = Arc::new(config);

        Self {
            session_manager: Arc::new(SessionManager::new(
                config.max_sessions,
                config.session_timeout,
            )),
            rate_limiter: Arc::new(RateLimiter::new(
                config.rate_limit_requests,
                config.rate_limit_window,
            )),
            metrics: Arc::new(ServerMetrics::new()),
            config,
        }
    }

    /// Start the server.
    pub async fn run(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        let listener = TcpListener::bind(&addr).await?;

        tracing::info!("SCF server listening on {}", addr);

        // Start background tasks
        let session_manager = Arc::clone(&self.session_manager);
        tokio::spawn(async move {
            session_manager.run_cleanup().await;
        });

        // Accept connections
        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    // Check rate limit
                    if !self.rate_limiter.check(&peer_addr.ip()) {
                        self.metrics.increment_rate_limited();
                        tracing::debug!("Rate limited connection from {}", peer_addr);
                        continue;
                    }

                    let config = Arc::clone(&self.config);
                    let session_manager = Arc::clone(&self.session_manager);
                    let metrics = Arc::clone(&self.metrics);

                    tokio::spawn(async move {
                        metrics.increment_connections();

                        if let Err(e) = Self::handle_connection(
                            config,
                            session_manager,
                            metrics.clone(),
                            stream,
                            peer_addr,
                        )
                        .await
                        {
                            tracing::debug!("Connection error from {}: {}", peer_addr, e);
                        }

                        metrics.decrement_connections();
                    });
                }
                Err(e) => {
                    tracing::warn!("Accept error: {}", e);
                }
            }
        }
    }

    async fn handle_connection(
        config: Arc<ServerConfig>,
        session_manager: Arc<SessionManager>,
        metrics: Arc<ServerMetrics>,
        stream: tokio::net::TcpStream,
        peer_addr: std::net::SocketAddr,
    ) -> Result<()> {
        use tokio::io::AsyncReadExt;

        stream.set_nodelay(true)?;
        let mut stream = stream;

        // Read initial data to determine connection type
        let mut buf = [0u8; 5];
        stream.peek(&mut buf).await?;

        // Check if TLS handshake
        if buf[0] == 0x16 && buf[1] == 0x03 {
            // This is a TLS ClientHello
            Self::handle_tls_connection(config, session_manager, metrics, stream, peer_addr).await
        } else {
            // Not TLS - close connection
            Ok(())
        }
    }

    async fn handle_tls_connection(
        config: Arc<ServerConfig>,
        session_manager: Arc<SessionManager>,
        metrics: Arc<ServerMetrics>,
        mut stream: tokio::net::TcpStream,
        peer_addr: std::net::SocketAddr,
    ) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Read full ClientHello
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        buf.truncate(n);

        // Try REALITY authentication
        match Self::authenticate_reality(&config, &buf) {
            Ok((client_public, short_id)) => {
                metrics.increment_authenticated();

                // Create session
                let session = session_manager.create_session(peer_addr, client_public, short_id);

                // Handle authenticated session
                Self::handle_reality_session(config, session, stream, &buf).await
            }
            Err(_) => {
                // Proxy to cover server
                metrics.increment_proxied();
                Self::proxy_to_cover(&config, stream, buf).await
            }
        }
    }

    fn authenticate_reality(
        config: &ServerConfig,
        client_hello: &[u8],
    ) -> Result<(crate::crypto::PublicKey, [u8; 8])> {
        // Delegate to REALITY server implementation
        crate::reality::RealityServer::authenticate_client_static(
            &config.static_secret,
            &config.allowed_short_ids,
            client_hello,
        )
    }

    async fn handle_reality_session(
        config: Arc<ServerConfig>,
        session: Arc<Session>,
        mut stream: tokio::net::TcpStream,
        _client_hello: &[u8],
    ) -> Result<()> {
        use tokio::io::AsyncWriteExt;

        // Generate server ephemeral
        let server_ephemeral = crate::crypto::EphemeralSecret::random();
        let server_public = crate::crypto::PublicKey::from(&server_ephemeral);

        // Build and send ServerHello
        let server_hello = crate::reality::RealityServer::build_server_hello(&server_public);
        stream.write_all(&server_hello).await?;

        // Derive session keys
        let shared = server_ephemeral.diffie_hellman(session.client_public());
        let keys = crate::crypto::SessionKeys::derive(&shared, b"reality_session");

        // Enter encrypted session loop
        session.set_keys(keys);
        session.run(&mut stream).await
    }

    async fn proxy_to_cover(
        config: &ServerConfig,
        mut client: tokio::net::TcpStream,
        initial_data: Vec<u8>,
    ) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        // Connect to cover server
        let cover_addr = format!("{}:{}", config.cover_server, config.cover_port);
        let mut cover = TcpStream::connect(&cover_addr).await?;

        // Forward initial data
        cover.write_all(&initial_data).await?;

        // Bidirectional copy
        tokio::io::copy_bidirectional(&mut client, &mut cover).await?;

        Ok(())
    }

    /// Get server metrics.
    pub fn metrics(&self) -> &ServerMetrics {
        &self.metrics
    }

    /// Get session count.
    pub fn session_count(&self) -> usize {
        self.session_manager.count()
    }
}
