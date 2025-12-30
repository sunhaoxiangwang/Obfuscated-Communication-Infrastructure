//! Congestion Control Implementation.
//!
//! Implements a BBR (Bottleneck Bandwidth and Round-trip propagation time)
//! inspired congestion control algorithm, optimized for high-loss environments.
//!
//! ## Key Features
//!
//! - **Bandwidth Probing**: Periodically increases rate to discover available bandwidth
//! - **RTT Estimation**: Maintains min RTT for accurate pacing
//! - **Loss Tolerance**: Distinguishes between congestion loss and random loss
//! - **Pacing**: Smooth packet transmission to avoid bursts
//!
//! ## State Machine
//!
//! ```text
//! ┌──────────┐     bandwidth     ┌──────────┐
//! │ STARTUP  │ ───────────────▶  │ DRAIN    │
//! └──────────┘    saturated      └──────────┘
//!                                     │
//!                                     │ queue drained
//!                                     ▼
//!                               ┌──────────┐
//!                               │ PROBE_BW │ ◀──┐
//!                               └──────────┘    │
//!                                     │         │
//!                              periodic│         │ RTT stable
//!                                     ▼         │
//!                               ┌───────────┐   │
//!                               │ PROBE_RTT │ ──┘
//!                               └───────────┘
//! ```

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::transport::{INITIAL_RTT_MS, MIN_RTT_MS, MSS};

/// BBR state machine states.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BbrState {
    /// Initial state: exponentially increase rate to find bandwidth
    Startup,
    /// Drain the queue built during startup
    Drain,
    /// Steady state: probe for more bandwidth
    ProbeBw,
    /// Periodically probe for lower RTT
    ProbeRtt,
}

/// Congestion controller implementing BBR-like algorithm.
pub struct CongestionController {
    /// Current state
    state: BbrState,
    /// Congestion window (bytes)
    cwnd: u32,
    /// Bytes in flight
    bytes_in_flight: u32,
    /// Pacing rate (bytes per second)
    pacing_rate: u64,
    /// Estimated bandwidth (bytes per second)
    btl_bw: u64,
    /// Minimum RTT observed (microseconds)
    min_rtt_us: u64,
    /// RTT samples for estimation
    rtt_samples: VecDeque<(Instant, u64)>,
    /// Bandwidth samples
    bw_samples: VecDeque<(Instant, u64)>,
    /// Last time we entered PROBE_RTT
    probe_rtt_time: Option<Instant>,
    /// Packets sent since last loss
    packets_since_loss: u32,
    /// Loss events in current window
    loss_events: u32,
    /// Configuration
    config: CongestionConfig,
    /// Pacing tokens available
    pacing_tokens: f64,
    /// Last pacing token update
    last_pacing_update: Instant,
}

/// Congestion control configuration.
#[derive(Debug, Clone)]
pub struct CongestionConfig {
    /// Initial congestion window (packets)
    pub initial_cwnd: u32,
    /// Maximum congestion window (packets)
    pub max_cwnd: u32,
    /// Minimum congestion window (packets)
    pub min_cwnd: u32,
    /// Pacing gain during startup
    pub startup_pacing_gain: f64,
    /// Pacing gain during probe_bw
    pub probe_bw_pacing_gain: f64,
    /// RTT probe interval
    pub probe_rtt_interval: Duration,
    /// Loss threshold before considering congestion
    pub loss_threshold: f64,
    /// Enable loss-tolerant mode for high-loss environments
    pub loss_tolerant: bool,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            initial_cwnd: 10,
            max_cwnd: 1000,
            min_cwnd: 4,
            startup_pacing_gain: 2.885, // 2/ln(2)
            probe_bw_pacing_gain: 1.0,
            probe_rtt_interval: Duration::from_secs(10),
            loss_threshold: 0.02, // 2% loss triggers congestion response
            loss_tolerant: true,  // Enabled for our use case
        }
    }
}

impl CongestionController {
    /// Create a new congestion controller.
    pub fn new(config: CongestionConfig) -> Self {
        let initial_cwnd_bytes = config.initial_cwnd * MSS as u32;

        Self {
            state: BbrState::Startup,
            cwnd: initial_cwnd_bytes,
            bytes_in_flight: 0,
            pacing_rate: (initial_cwnd_bytes as u64 * 1000) / INITIAL_RTT_MS, // Initial pacing
            btl_bw: 0,
            min_rtt_us: INITIAL_RTT_MS * 1000,
            rtt_samples: VecDeque::with_capacity(10),
            bw_samples: VecDeque::with_capacity(10),
            probe_rtt_time: None,
            packets_since_loss: 0,
            loss_events: 0,
            config,
            pacing_tokens: initial_cwnd_bytes as f64,
            last_pacing_update: Instant::now(),
        }
    }

    /// Check if we can send more data.
    pub fn can_send(&self) -> bool {
        self.bytes_in_flight < self.cwnd
    }

    /// Get the number of bytes we can send now.
    pub fn available_cwnd(&self) -> u32 {
        self.cwnd.saturating_sub(self.bytes_in_flight)
    }

    /// Record that we sent bytes.
    pub fn on_send(&mut self, bytes: u32) {
        self.bytes_in_flight += bytes;
        self.packets_since_loss += 1;
    }

    /// Record acknowledgment of bytes.
    pub fn on_ack(&mut self, bytes: u32, rtt_us: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);

        // Update RTT estimate
        self.update_rtt(rtt_us);

        // Update bandwidth estimate
        let now = Instant::now();
        if rtt_us > 0 {
            let bw = (bytes as u64 * 1_000_000) / rtt_us;
            self.bw_samples.push_back((now, bw));
            if self.bw_samples.len() > 10 {
                self.bw_samples.pop_front();
            }
            self.update_bandwidth();
        }

        // State machine transitions
        self.update_state();
    }

    /// Record packet loss.
    pub fn on_loss(&mut self, bytes: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.loss_events += 1;

        // Calculate loss rate
        let loss_rate = if self.packets_since_loss > 0 {
            self.loss_events as f64 / self.packets_since_loss as f64
        } else {
            0.0
        };

        // Only respond to congestion if loss exceeds threshold
        // This is key for high-loss environments
        if !self.config.loss_tolerant || loss_rate > self.config.loss_threshold {
            self.handle_congestion_loss();
        }
    }

    /// Get the current pacing delay for a packet.
    pub fn pacing_delay(&mut self, bytes: u32) -> Duration {
        self.update_pacing_tokens();

        if self.pacing_tokens >= bytes as f64 {
            self.pacing_tokens -= bytes as f64;
            Duration::ZERO
        } else {
            // Calculate wait time
            let needed = bytes as f64 - self.pacing_tokens;
            let wait_us = (needed * 1_000_000.0) / self.pacing_rate as f64;
            Duration::from_micros(wait_us as u64)
        }
    }

    /// Get current congestion window in bytes.
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Get current pacing rate in bytes per second.
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// Get estimated bandwidth in bytes per second.
    pub fn bandwidth(&self) -> u64 {
        self.btl_bw
    }

    /// Get minimum RTT in microseconds.
    pub fn min_rtt_us(&self) -> u64 {
        self.min_rtt_us
    }

    /// Get current state.
    pub fn state(&self) -> BbrState {
        self.state
    }

    /// Get bytes currently in flight.
    pub fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight
    }

    fn update_rtt(&mut self, rtt_us: u64) {
        let rtt_us = rtt_us.max(MIN_RTT_MS * 1000);

        // Update min RTT
        if rtt_us < self.min_rtt_us {
            self.min_rtt_us = rtt_us;
        }

        // Track RTT samples
        let now = Instant::now();
        self.rtt_samples.push_back((now, rtt_us));

        // Keep only recent samples (last 10 seconds)
        while let Some((time, _)) = self.rtt_samples.front() {
            if now.duration_since(*time) > Duration::from_secs(10) {
                self.rtt_samples.pop_front();
            } else {
                break;
            }
        }
    }

    fn update_bandwidth(&mut self) {
        // Use maximum observed bandwidth
        let max_bw = self.bw_samples.iter().map(|(_, bw)| *bw).max().unwrap_or(0);

        if max_bw > self.btl_bw {
            self.btl_bw = max_bw;
        }
    }

    fn update_state(&mut self) {
        let now = Instant::now();

        match self.state {
            BbrState::Startup => {
                // Check if bandwidth growth has slowed
                if self.btl_bw > 0 {
                    let prev_bw = self.bw_samples.front().map(|(_, bw)| *bw).unwrap_or(0);
                    if prev_bw > 0 && self.btl_bw < (prev_bw * 5 / 4) {
                        // Less than 25% growth, transition to Drain
                        self.state = BbrState::Drain;
                    }
                }

                // Update cwnd during startup
                self.cwnd = ((self.btl_bw * self.min_rtt_us / 1_000_000) as u32)
                    .max(self.config.min_cwnd * MSS as u32)
                    .min(self.config.max_cwnd * MSS as u32);

                self.update_pacing_rate(self.config.startup_pacing_gain);
            }

            BbrState::Drain => {
                // Drain queue by pacing slower
                self.update_pacing_rate(0.5);

                // Transition to ProbeBw when queue is drained
                if self.bytes_in_flight <= self.inflight_target() {
                    self.state = BbrState::ProbeBw;
                }
            }

            BbrState::ProbeBw => {
                // Steady state operation
                self.update_pacing_rate(self.config.probe_bw_pacing_gain);

                // Update cwnd based on BDP
                let bdp = self.bandwidth_delay_product();
                self.cwnd = (bdp + 3 * MSS as u32)
                    .max(self.config.min_cwnd * MSS as u32)
                    .min(self.config.max_cwnd * MSS as u32);

                // Periodically probe RTT
                if let Some(probe_time) = self.probe_rtt_time {
                    if now.duration_since(probe_time) > self.config.probe_rtt_interval {
                        self.state = BbrState::ProbeRtt;
                    }
                } else {
                    self.probe_rtt_time = Some(now);
                }
            }

            BbrState::ProbeRtt => {
                // Reduce cwnd to probe for lower RTT
                self.cwnd = self.config.min_cwnd * MSS as u32;

                // Exit after 200ms
                if let Some(probe_time) = self.probe_rtt_time {
                    if now.duration_since(probe_time) > Duration::from_millis(200) {
                        self.probe_rtt_time = Some(now);
                        self.state = BbrState::ProbeBw;
                    }
                }
            }
        }
    }

    fn update_pacing_rate(&mut self, gain: f64) {
        if self.btl_bw > 0 {
            self.pacing_rate = ((self.btl_bw as f64) * gain) as u64;
        } else {
            // Fallback pacing based on cwnd and RTT
            self.pacing_rate = (self.cwnd as u64 * 1_000_000) / self.min_rtt_us;
        }

        // Ensure minimum pacing rate
        self.pacing_rate = self.pacing_rate.max(MSS as u64 * 10);
    }

    fn update_pacing_tokens(&mut self) {
        let now = Instant::now();
        let elapsed_us = now.duration_since(self.last_pacing_update).as_micros() as f64;
        self.last_pacing_update = now;

        // Add tokens based on pacing rate
        let new_tokens = (self.pacing_rate as f64 * elapsed_us) / 1_000_000.0;
        self.pacing_tokens = (self.pacing_tokens + new_tokens).min(self.cwnd as f64);
    }

    fn handle_congestion_loss(&mut self) {
        // Multiplicative decrease
        self.cwnd = (self.cwnd * 7 / 10)
            .max(self.config.min_cwnd * MSS as u32);

        // Reset loss tracking
        self.loss_events = 0;
        self.packets_since_loss = 0;

        // Reduce bandwidth estimate
        self.btl_bw = self.btl_bw * 9 / 10;
    }

    fn bandwidth_delay_product(&self) -> u32 {
        ((self.btl_bw * self.min_rtt_us) / 1_000_000) as u32
    }

    fn inflight_target(&self) -> u32 {
        self.bandwidth_delay_product()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let cc = CongestionController::new(CongestionConfig::default());
        assert_eq!(cc.state(), BbrState::Startup);
        assert!(cc.can_send());
    }

    #[test]
    fn test_send_receive() {
        let mut cc = CongestionController::new(CongestionConfig::default());

        let initial_available = cc.available_cwnd();

        cc.on_send(1000);
        assert_eq!(cc.bytes_in_flight(), 1000);
        assert_eq!(cc.available_cwnd(), initial_available - 1000);

        cc.on_ack(1000, 50000); // 50ms RTT
        assert_eq!(cc.bytes_in_flight(), 0);
    }

    #[test]
    fn test_loss_tolerance() {
        let config = CongestionConfig {
            loss_tolerant: true,
            loss_threshold: 0.02,
            ..Default::default()
        };
        let mut cc = CongestionController::new(config);

        let initial_cwnd = cc.cwnd();

        // Simulate sending 100 packets
        for _ in 0..100 {
            cc.on_send(MSS as u32);
            cc.packets_since_loss += 1;
        }

        // Single loss should not trigger congestion response
        cc.on_loss(MSS as u32);

        // cwnd should not decrease significantly for isolated loss
        assert!(cc.cwnd() >= initial_cwnd * 9 / 10);
    }

    #[test]
    fn test_rtt_tracking() {
        let mut cc = CongestionController::new(CongestionConfig::default());

        cc.on_send(1000);
        cc.on_ack(1000, 20000); // 20ms RTT

        assert_eq!(cc.min_rtt_us(), 20000);

        cc.on_send(1000);
        cc.on_ack(1000, 15000); // 15ms RTT (lower)

        assert_eq!(cc.min_rtt_us(), 15000);

        cc.on_send(1000);
        cc.on_ack(1000, 25000); // 25ms RTT (higher)

        // min RTT should stay at 15ms
        assert_eq!(cc.min_rtt_us(), 15000);
    }

    #[test]
    fn test_pacing() {
        let mut cc = CongestionController::new(CongestionConfig::default());

        // First packet should have no delay
        let delay1 = cc.pacing_delay(1000);
        assert_eq!(delay1, Duration::ZERO);

        // Subsequent packets may have delay based on pacing
        // (depends on timing, so just check it doesn't panic)
        let _delay2 = cc.pacing_delay(1000);
    }
}
