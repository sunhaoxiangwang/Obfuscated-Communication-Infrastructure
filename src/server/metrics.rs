//! Server metrics collection.
//!
//! Collects operational metrics without storing any user-identifiable information.
//! All metrics are aggregates safe for monitoring and debugging.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Server metrics collector.
pub struct ServerMetrics {
    /// Server start time
    start_time: Instant,
    /// Total connections accepted
    total_connections: AtomicU64,
    /// Current active connections
    active_connections: AtomicU64,
    /// Connections that passed REALITY authentication
    authenticated_connections: AtomicU64,
    /// Connections proxied to cover server
    proxied_connections: AtomicU64,
    /// Connections rejected by rate limiter
    rate_limited_connections: AtomicU64,
    /// Total bytes sent
    bytes_sent: AtomicU64,
    /// Total bytes received
    bytes_received: AtomicU64,
    /// Authentication failures
    auth_failures: AtomicU64,
    /// Handshake errors
    handshake_errors: AtomicU64,
}

impl ServerMetrics {
    /// Create a new metrics collector.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            authenticated_connections: AtomicU64::new(0),
            proxied_connections: AtomicU64::new(0),
            rate_limited_connections: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            handshake_errors: AtomicU64::new(0),
        }
    }

    /// Increment total and active connections.
    pub fn increment_connections(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections.
    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment authenticated connection count.
    pub fn increment_authenticated(&self) {
        self.authenticated_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment proxied connection count.
    pub fn increment_proxied(&self) {
        self.proxied_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment rate limited connection count.
    pub fn increment_rate_limited(&self) {
        self.rate_limited_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Add bytes to sent counter.
    pub fn add_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add bytes to received counter.
    pub fn add_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment auth failure count.
    pub fn increment_auth_failures(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment handshake error count.
    pub fn increment_handshake_errors(&self) {
        self.handshake_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Get uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get total connections.
    pub fn total_connections(&self) -> u64 {
        self.total_connections.load(Ordering::Relaxed)
    }

    /// Get active connections.
    pub fn active_connections(&self) -> u64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Get authenticated connections.
    pub fn authenticated_connections(&self) -> u64 {
        self.authenticated_connections.load(Ordering::Relaxed)
    }

    /// Get proxied connections.
    pub fn proxied_connections(&self) -> u64 {
        self.proxied_connections.load(Ordering::Relaxed)
    }

    /// Get rate limited connections.
    pub fn rate_limited_connections(&self) -> u64 {
        self.rate_limited_connections.load(Ordering::Relaxed)
    }

    /// Get total bytes sent.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    /// Get authentication failures.
    pub fn auth_failures(&self) -> u64 {
        self.auth_failures.load(Ordering::Relaxed)
    }

    /// Get a snapshot of all metrics.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: self.uptime_secs(),
            total_connections: self.total_connections(),
            active_connections: self.active_connections(),
            authenticated_connections: self.authenticated_connections(),
            proxied_connections: self.proxied_connections(),
            rate_limited_connections: self.rate_limited_connections(),
            bytes_sent: self.bytes_sent(),
            bytes_received: self.bytes_received(),
            auth_failures: self.auth_failures(),
            handshake_errors: self.handshake_errors.load(Ordering::Relaxed),
        }
    }

    /// Format metrics as a simple text report.
    pub fn format_report(&self) -> String {
        let snapshot = self.snapshot();

        format!(
            r#"SCF Server Metrics
==================
Uptime: {} seconds

Connections:
  Total:         {}
  Active:        {}
  Authenticated: {}
  Proxied:       {}
  Rate Limited:  {}

Traffic:
  Sent:     {} bytes
  Received: {} bytes

Errors:
  Auth Failures:    {}
  Handshake Errors: {}
"#,
            snapshot.uptime_secs,
            snapshot.total_connections,
            snapshot.active_connections,
            snapshot.authenticated_connections,
            snapshot.proxied_connections,
            snapshot.rate_limited_connections,
            snapshot.bytes_sent,
            snapshot.bytes_received,
            snapshot.auth_failures,
            snapshot.handshake_errors,
        )
    }
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of all metrics at a point in time.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub authenticated_connections: u64,
    pub proxied_connections: u64,
    pub rate_limited_connections: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub auth_failures: u64,
    pub handshake_errors: u64,
}

impl MetricsSnapshot {
    /// Calculate authentication rate.
    pub fn auth_rate(&self) -> f64 {
        if self.total_connections == 0 {
            0.0
        } else {
            self.authenticated_connections as f64 / self.total_connections as f64
        }
    }

    /// Calculate proxy rate.
    pub fn proxy_rate(&self) -> f64 {
        if self.total_connections == 0 {
            0.0
        } else {
            self.proxied_connections as f64 / self.total_connections as f64
        }
    }

    /// Calculate connections per second.
    pub fn connections_per_second(&self) -> f64 {
        if self.uptime_secs == 0 {
            0.0
        } else {
            self.total_connections as f64 / self.uptime_secs as f64
        }
    }

    /// Calculate throughput in bytes per second.
    pub fn throughput_bps(&self) -> f64 {
        if self.uptime_secs == 0 {
            0.0
        } else {
            (self.bytes_sent + self.bytes_received) as f64 / self.uptime_secs as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_new() {
        let metrics = ServerMetrics::new();
        assert_eq!(metrics.total_connections(), 0);
        assert_eq!(metrics.active_connections(), 0);
    }

    #[test]
    fn test_connection_counting() {
        let metrics = ServerMetrics::new();

        metrics.increment_connections();
        metrics.increment_connections();
        assert_eq!(metrics.total_connections(), 2);
        assert_eq!(metrics.active_connections(), 2);

        metrics.decrement_connections();
        assert_eq!(metrics.total_connections(), 2);
        assert_eq!(metrics.active_connections(), 1);
    }

    #[test]
    fn test_bytes_counting() {
        let metrics = ServerMetrics::new();

        metrics.add_bytes_sent(1000);
        metrics.add_bytes_received(2000);

        assert_eq!(metrics.bytes_sent(), 1000);
        assert_eq!(metrics.bytes_received(), 2000);
    }

    #[test]
    fn test_snapshot() {
        let metrics = ServerMetrics::new();

        metrics.increment_connections();
        metrics.increment_authenticated();
        metrics.add_bytes_sent(100);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_connections, 1);
        assert_eq!(snapshot.authenticated_connections, 1);
        assert_eq!(snapshot.bytes_sent, 100);
    }

    #[test]
    fn test_snapshot_rates() {
        let snapshot = MetricsSnapshot {
            uptime_secs: 100,
            total_connections: 200,
            active_connections: 10,
            authenticated_connections: 150,
            proxied_connections: 50,
            rate_limited_connections: 0,
            bytes_sent: 10000,
            bytes_received: 20000,
            auth_failures: 0,
            handshake_errors: 0,
        };

        assert!((snapshot.auth_rate() - 0.75).abs() < 0.01);
        assert!((snapshot.proxy_rate() - 0.25).abs() < 0.01);
        assert!((snapshot.connections_per_second() - 2.0).abs() < 0.01);
        assert!((snapshot.throughput_bps() - 300.0).abs() < 0.01);
    }

    #[test]
    fn test_format_report() {
        let metrics = ServerMetrics::new();
        metrics.increment_connections();

        let report = metrics.format_report();
        assert!(report.contains("SCF Server Metrics"));
        assert!(report.contains("Total:         1"));
    }
}
