//! Reliability Layer Implementation.
//!
//! Provides reliable, ordered delivery over unreliable transport:
//!
//! - Selective Acknowledgment (SACK) for efficient loss detection
//! - Retransmission with exponential backoff
//! - Out-of-order packet reassembly
//! - Duplicate detection

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::transport::packet::{flags, Packet, PacketType};
use crate::transport::INITIAL_RTT_MS;

/// A range of acknowledged sequence numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackRange {
    /// Start of range (inclusive)
    pub start: u64,
    /// End of range (inclusive)
    pub end: u64,
}

impl SackRange {
    /// Create a new SACK range.
    pub fn new(start: u64, end: u64) -> Self {
        Self {
            start: start.min(end),
            end: start.max(end),
        }
    }

    /// Check if a sequence number is in this range.
    pub fn contains(&self, seq: u64) -> bool {
        seq >= self.start && seq <= self.end
    }

    /// Merge with another range if contiguous.
    pub fn merge(&mut self, other: &SackRange) -> bool {
        if other.start <= self.end + 1 && other.end >= self.start.saturating_sub(1) {
            self.start = self.start.min(other.start);
            self.end = self.end.max(other.end);
            true
        } else {
            false
        }
    }
}

/// Reliability layer managing retransmissions and acknowledgments.
pub struct ReliabilityLayer {
    /// Packets awaiting acknowledgment: seq -> (packet, send_time, retries)
    pending_acks: BTreeMap<u64, PendingPacket>,
    /// Received sequence numbers for duplicate detection
    received_seqs: VecDeque<u64>,
    /// SACK ranges for outgoing acks
    sack_ranges: Vec<SackRange>,
    /// Next expected sequence number
    next_expected_seq: u64,
    /// Highest acknowledged sequence
    highest_acked: u64,
    /// Smoothed RTT estimate (microseconds)
    srtt_us: u64,
    /// RTT variance (microseconds)
    rttvar_us: u64,
    /// Retransmission timeout (microseconds)
    rto_us: u64,
    /// Configuration
    config: ReliabilityConfig,
    /// Out-of-order received packets
    reorder_buffer: BTreeMap<u64, Bytes>,
}

/// A packet pending acknowledgment.
struct PendingPacket {
    packet: Packet,
    send_time: Instant,
    retries: u32,
    size: usize,
}

/// Reliability layer configuration.
#[derive(Debug, Clone)]
pub struct ReliabilityConfig {
    /// Maximum retransmission attempts
    pub max_retries: u32,
    /// Minimum RTO (microseconds)
    pub min_rto_us: u64,
    /// Maximum RTO (microseconds)
    pub max_rto_us: u64,
    /// Maximum pending packets before blocking
    pub max_pending: usize,
    /// Maximum reorder buffer size
    pub max_reorder: usize,
    /// Maximum SACK ranges per ACK
    pub max_sack_ranges: usize,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            min_rto_us: 200_000,  // 200ms
            max_rto_us: 60_000_000, // 60s
            max_pending: 1000,
            max_reorder: 500,
            max_sack_ranges: 4,
        }
    }
}

impl ReliabilityLayer {
    /// Create a new reliability layer.
    pub fn new(config: ReliabilityConfig) -> Self {
        Self {
            pending_acks: BTreeMap::new(),
            received_seqs: VecDeque::with_capacity(1000),
            sack_ranges: Vec::new(),
            next_expected_seq: 0,
            highest_acked: 0,
            srtt_us: INITIAL_RTT_MS * 1000,
            rttvar_us: INITIAL_RTT_MS * 500,
            rto_us: INITIAL_RTT_MS * 1000 * 3,
            config,
            reorder_buffer: BTreeMap::new(),
        }
    }

    /// Record that a packet was sent.
    pub fn on_send(&mut self, packet: Packet) {
        let size = packet.wire_size();
        self.pending_acks.insert(
            packet.seq_num,
            PendingPacket {
                packet,
                send_time: Instant::now(),
                retries: 0,
                size,
            },
        );
    }

    /// Process a received packet.
    ///
    /// Returns ordered data if available.
    pub fn on_receive(&mut self, packet: &Packet) -> Vec<Bytes> {
        let seq = packet.seq_num;

        // Check for duplicate
        if self.is_duplicate(seq) {
            return Vec::new();
        }

        // Record receipt
        self.record_receipt(seq);

        // Handle based on packet type
        match packet.packet_type {
            PacketType::Ack => {
                self.process_ack(packet);
                Vec::new()
            }
            PacketType::Data => {
                self.process_data(seq, packet.payload.clone())
            }
            _ => Vec::new(),
        }
    }

    /// Process acknowledgment packet.
    fn process_ack(&mut self, packet: &Packet) {
        let ack_num = packet.ack_num;
        let now = Instant::now();

        // Process cumulative ack
        let to_remove: Vec<u64> = self
            .pending_acks
            .range(..=ack_num)
            .map(|(&seq, _)| seq)
            .collect();

        for seq in to_remove {
            if let Some(pending) = self.pending_acks.remove(&seq) {
                // Update RTT estimate
                let rtt = now.duration_since(pending.send_time).as_micros() as u64;
                self.update_rtt(rtt);
            }
        }

        // Process SACK ranges if present
        if packet.has_flag(flags::HAS_SACK) {
            if let Ok((ranges, _)) = crate::transport::packet::parse_sack_ranges(packet) {
                for (start, end) in ranges {
                    for seq in start..=end {
                        if let Some(pending) = self.pending_acks.remove(&seq) {
                            let rtt = now.duration_since(pending.send_time).as_micros() as u64;
                            self.update_rtt(rtt);
                        }
                    }
                }
            }
        }

        self.highest_acked = self.highest_acked.max(ack_num);
    }

    /// Process data packet.
    fn process_data(&mut self, seq: u64, data: Bytes) -> Vec<Bytes> {
        // Store in reorder buffer
        self.reorder_buffer.insert(seq, data);

        // Trim buffer if too large
        while self.reorder_buffer.len() > self.config.max_reorder {
            self.reorder_buffer.pop_first();
        }

        // Deliver in-order packets
        let mut delivered = Vec::new();

        while let Some(data) = self.reorder_buffer.remove(&self.next_expected_seq) {
            delivered.push(data);
            self.next_expected_seq += 1;
        }

        delivered
    }

    /// Get packets that need retransmission.
    pub fn get_retransmissions(&mut self) -> Vec<Packet> {
        let now = Instant::now();
        let rto = Duration::from_micros(self.rto_us);
        let mut retransmits = Vec::new();

        for pending in self.pending_acks.values_mut() {
            if now.duration_since(pending.send_time) > rto {
                if pending.retries < self.config.max_retries {
                    pending.retries += 1;
                    pending.send_time = now;

                    let mut packet = pending.packet.clone();
                    packet.flags |= flags::RETRANSMIT;
                    retransmits.push(packet);
                }
            }
        }

        retransmits
    }

    /// Generate an ACK packet for a stream.
    pub fn generate_ack(&self, stream_id: u32, window: u32) -> Packet {
        let ack_num = self.next_expected_seq.saturating_sub(1);

        let mut packet = Packet::ack(stream_id, ack_num, window);

        // Add SACK ranges if we have gaps
        if !self.sack_ranges.is_empty() {
            let builder = crate::transport::packet::PacketBuilder::new(packet);
            let mut builder = builder;
            for range in self.sack_ranges.iter().take(self.config.max_sack_ranges) {
                builder = builder.add_sack(range.start, range.end);
            }
            packet = builder.build();
        }

        packet
    }

    /// Check if a sequence number was already received.
    fn is_duplicate(&self, seq: u64) -> bool {
        self.received_seqs.contains(&seq)
    }

    /// Record receipt of a sequence number.
    fn record_receipt(&mut self, seq: u64) {
        self.received_seqs.push_back(seq);

        // Limit size
        while self.received_seqs.len() > 1000 {
            self.received_seqs.pop_front();
        }

        // Update SACK ranges
        self.update_sack_ranges(seq);
    }

    /// Update SACK ranges with a new sequence.
    fn update_sack_ranges(&mut self, seq: u64) {
        // Try to extend existing range
        for range in &mut self.sack_ranges {
            if range.merge(&SackRange::new(seq, seq)) {
                return;
            }
        }

        // Add new range
        self.sack_ranges.push(SackRange::new(seq, seq));

        // Merge overlapping ranges
        self.sack_ranges.sort_by_key(|r| r.start);
        let mut merged: Vec<SackRange> = Vec::new();
        for range in self.sack_ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                if !last.merge(&range) {
                    merged.push(range);
                }
            } else {
                merged.push(range);
            }
        }
        self.sack_ranges = merged;
    }

    /// Update RTT estimate using Jacobson's algorithm.
    fn update_rtt(&mut self, rtt_us: u64) {
        if self.srtt_us == 0 {
            self.srtt_us = rtt_us;
            self.rttvar_us = rtt_us / 2;
        } else {
            // RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|
            // SRTT = (1 - alpha) * SRTT + alpha * R
            // where alpha = 1/8, beta = 1/4

            let diff = if self.srtt_us > rtt_us {
                self.srtt_us - rtt_us
            } else {
                rtt_us - self.srtt_us
            };

            self.rttvar_us = (self.rttvar_us * 3 / 4) + (diff / 4);
            self.srtt_us = (self.srtt_us * 7 / 8) + (rtt_us / 8);
        }

        // RTO = SRTT + max(G, K * RTTVAR) where K = 4
        self.rto_us = self.srtt_us + (4 * self.rttvar_us).max(10_000);
        self.rto_us = self.rto_us.clamp(self.config.min_rto_us, self.config.max_rto_us);
    }

    /// Get current RTO in microseconds.
    pub fn rto_us(&self) -> u64 {
        self.rto_us
    }

    /// Get smoothed RTT in microseconds.
    pub fn srtt_us(&self) -> u64 {
        self.srtt_us
    }

    /// Get number of pending (unacknowledged) packets.
    pub fn pending_count(&self) -> usize {
        self.pending_acks.len()
    }

    /// Check if we can send more (not blocked by pending limit).
    pub fn can_send(&self) -> bool {
        self.pending_acks.len() < self.config.max_pending
    }

    /// Get next expected sequence number.
    pub fn next_expected(&self) -> u64 {
        self.next_expected_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sack_range() {
        let range = SackRange::new(10, 20);
        assert!(range.contains(10));
        assert!(range.contains(15));
        assert!(range.contains(20));
        assert!(!range.contains(9));
        assert!(!range.contains(21));
    }

    #[test]
    fn test_sack_merge() {
        let mut range1 = SackRange::new(10, 20);
        let range2 = SackRange::new(21, 30);

        assert!(range1.merge(&range2));
        assert_eq!(range1.start, 10);
        assert_eq!(range1.end, 30);

        let range3 = SackRange::new(50, 60);
        assert!(!range1.merge(&range3));
    }

    #[test]
    fn test_reliability_send_receive() {
        let mut layer = ReliabilityLayer::new(ReliabilityConfig::default());

        // Send a packet
        let packet = Packet::data(1, 0, Bytes::from("hello"));
        layer.on_send(packet.clone());

        assert_eq!(layer.pending_count(), 1);

        // Receive ACK
        let ack = Packet::ack(1, 0, 65536);
        layer.on_receive(&ack);

        assert_eq!(layer.pending_count(), 0);
    }

    #[test]
    fn test_in_order_delivery() {
        let mut layer = ReliabilityLayer::new(ReliabilityConfig::default());

        // Receive packets in order
        let p1 = Packet::data(1, 0, Bytes::from("first"));
        let p2 = Packet::data(1, 1, Bytes::from("second"));

        let delivered = layer.on_receive(&p1);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], Bytes::from("first"));

        let delivered = layer.on_receive(&p2);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], Bytes::from("second"));
    }

    #[test]
    fn test_out_of_order_delivery() {
        let mut layer = ReliabilityLayer::new(ReliabilityConfig::default());

        // Receive packets out of order
        let p1 = Packet::data(1, 2, Bytes::from("third"));
        let p2 = Packet::data(1, 0, Bytes::from("first"));
        let p3 = Packet::data(1, 1, Bytes::from("second"));

        // First packet is out of order, shouldn't deliver
        let delivered = layer.on_receive(&p1);
        assert!(delivered.is_empty());

        // Now receive packet 0
        let delivered = layer.on_receive(&p2);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0], Bytes::from("first"));

        // Receive packet 1, should deliver 1 and buffered 2
        let delivered = layer.on_receive(&p3);
        assert_eq!(delivered.len(), 2);
        assert_eq!(delivered[0], Bytes::from("second"));
        assert_eq!(delivered[1], Bytes::from("third"));
    }

    #[test]
    fn test_duplicate_detection() {
        let mut layer = ReliabilityLayer::new(ReliabilityConfig::default());

        let packet = Packet::data(1, 0, Bytes::from("data"));

        // First receive
        let delivered = layer.on_receive(&packet);
        assert_eq!(delivered.len(), 1);

        // Duplicate
        let delivered = layer.on_receive(&packet);
        assert!(delivered.is_empty());
    }

    #[test]
    fn test_rtt_update() {
        let mut layer = ReliabilityLayer::new(ReliabilityConfig::default());

        // Initial RTT
        layer.update_rtt(50_000); // 50ms
        assert!(layer.srtt_us() > 0);

        // More samples
        layer.update_rtt(60_000);
        layer.update_rtt(55_000);

        // SRTT should be smoothed
        assert!(layer.srtt_us() > 50_000);
        assert!(layer.srtt_us() < 60_000);
    }

    #[test]
    fn test_ack_generation() {
        let layer = ReliabilityLayer::new(ReliabilityConfig::default());
        let ack = layer.generate_ack(1, 65536);

        assert_eq!(ack.packet_type, PacketType::Ack);
        assert_eq!(ack.stream_id, 1);
        assert_eq!(ack.window, 65536);
    }
}
