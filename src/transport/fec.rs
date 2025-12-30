//! Forward Error Correction (FEC) Implementation.
//!
//! Provides proactive packet loss recovery using XOR-based FEC codes.
//! This is optimized for low latency rather than maximum efficiency.
//!
//! ## Encoding Scheme
//!
//! For every N data packets, we generate M repair packets where:
//! - Each repair packet is XOR of a subset of data packets
//! - Any single lost packet can be recovered from the repair packet
//!
//! ## Example with N=4, M=2
//!
//! ```text
//! Data packets:    D1  D2  D3  D4
//!                   \   \   \   \
//! Repair 1:         D1 ⊕ D2
//! Repair 2:               D3 ⊕ D4
//! ```

use bytes::{Bytes, BytesMut};
use std::collections::HashMap;

/// FEC encoder for generating repair packets.
pub struct FecEncoder {
    /// Number of data packets per FEC group
    group_size: usize,
    /// Number of repair packets per group
    repair_count: usize,
    /// Current group of data packets
    current_group: Vec<Bytes>,
    /// Starting sequence number of current group
    group_start_seq: u64,
    /// Next FEC sequence number
    next_fec_seq: u64,
}

impl FecEncoder {
    /// Create a new FEC encoder.
    ///
    /// # Arguments
    ///
    /// * `group_size` - Number of data packets before generating repair
    /// * `repair_count` - Number of repair packets to generate
    pub fn new(group_size: usize, repair_count: usize) -> Self {
        Self {
            group_size: group_size.max(2),
            repair_count: repair_count.max(1),
            current_group: Vec::with_capacity(group_size),
            group_start_seq: 0,
            next_fec_seq: 0,
        }
    }

    /// Create encoder with default 20% redundancy.
    pub fn default_redundancy() -> Self {
        Self::new(5, 1) // 1 repair per 5 data packets = 20% overhead
    }

    /// Add a data packet and potentially generate repair packets.
    ///
    /// Returns repair packets if the group is complete.
    pub fn add_packet(&mut self, seq_num: u64, data: Bytes) -> Vec<FecRepairPacket> {
        if self.current_group.is_empty() {
            self.group_start_seq = seq_num;
        }

        self.current_group.push(data);

        if self.current_group.len() >= self.group_size {
            let repairs = self.generate_repairs();
            self.current_group.clear();
            repairs
        } else {
            Vec::new()
        }
    }

    /// Flush any remaining packets (generate partial repair).
    pub fn flush(&mut self) -> Vec<FecRepairPacket> {
        if self.current_group.len() >= 2 {
            let repairs = self.generate_repairs();
            self.current_group.clear();
            repairs
        } else {
            self.current_group.clear();
            Vec::new()
        }
    }

    fn generate_repairs(&mut self) -> Vec<FecRepairPacket> {
        let mut repairs = Vec::with_capacity(self.repair_count);

        // Simple XOR-based repair
        // For repair_count=1, XOR all packets together
        // For repair_count=2, XOR first half and second half separately
        let packets_per_repair = self.current_group.len() / self.repair_count.max(1);

        for i in 0..self.repair_count {
            let start = i * packets_per_repair;
            let end = if i == self.repair_count - 1 {
                self.current_group.len()
            } else {
                (i + 1) * packets_per_repair
            };

            if start >= self.current_group.len() {
                break;
            }

            let repair_data = self.xor_packets(&self.current_group[start..end]);
            let covered: Vec<u64> = (start..end)
                .map(|j| self.group_start_seq + j as u64)
                .collect();

            repairs.push(FecRepairPacket {
                fec_seq: self.next_fec_seq,
                covered_seqs: covered,
                repair_data,
            });

            self.next_fec_seq += 1;
        }

        repairs
    }

    fn xor_packets(&self, packets: &[Bytes]) -> Bytes {
        if packets.is_empty() {
            return Bytes::new();
        }

        // Find max length
        let max_len = packets.iter().map(|p| p.len()).max().unwrap_or(0);

        let mut result = vec![0u8; max_len];

        for packet in packets {
            for (i, byte) in packet.iter().enumerate() {
                result[i] ^= byte;
            }
        }

        Bytes::from(result)
    }
}

/// A FEC repair packet.
#[derive(Debug, Clone)]
pub struct FecRepairPacket {
    /// FEC sequence number
    pub fec_seq: u64,
    /// Sequence numbers of covered data packets
    pub covered_seqs: Vec<u64>,
    /// XOR of covered packets
    pub repair_data: Bytes,
}

impl FecRepairPacket {
    /// Encode the repair packet for transmission.
    pub fn encode(&self) -> Bytes {
        use bytes::BufMut;

        let mut buf = BytesMut::with_capacity(
            8 + 2 + self.covered_seqs.len() * 8 + 2 + self.repair_data.len(),
        );

        buf.put_u64(self.fec_seq);
        buf.put_u16(self.covered_seqs.len() as u16);
        for seq in &self.covered_seqs {
            buf.put_u64(*seq);
        }
        buf.put_u16(self.repair_data.len() as u16);
        buf.put_slice(&self.repair_data);

        buf.freeze()
    }

    /// Decode a repair packet from bytes.
    pub fn decode(mut data: Bytes) -> Option<Self> {
        use bytes::Buf;

        if data.len() < 10 {
            return None;
        }

        let fec_seq = data.get_u64();
        let count = data.get_u16() as usize;

        if data.len() < count * 8 + 2 {
            return None;
        }

        let mut covered_seqs = Vec::with_capacity(count);
        for _ in 0..count {
            covered_seqs.push(data.get_u64());
        }

        let repair_len = data.get_u16() as usize;
        if data.len() < repair_len {
            return None;
        }

        let repair_data = data.split_to(repair_len);

        Some(Self {
            fec_seq,
            covered_seqs,
            repair_data,
        })
    }
}

/// FEC decoder for recovering lost packets.
pub struct FecDecoder {
    /// Received data packets: seq -> data
    received_data: HashMap<u64, Bytes>,
    /// Received repair packets
    received_repairs: Vec<FecRepairPacket>,
    /// Known lost sequence numbers
    lost_seqs: Vec<u64>,
    /// Maximum packets to cache
    max_cache: usize,
}

impl FecDecoder {
    /// Create a new FEC decoder.
    pub fn new(max_cache: usize) -> Self {
        Self {
            received_data: HashMap::with_capacity(max_cache),
            received_repairs: Vec::new(),
            lost_seqs: Vec::new(),
            max_cache,
        }
    }

    /// Add a received data packet.
    pub fn add_data(&mut self, seq_num: u64, data: Bytes) {
        self.received_data.insert(seq_num, data);

        // Remove from lost list if present
        self.lost_seqs.retain(|&s| s != seq_num);

        // Trim cache if too large
        if self.received_data.len() > self.max_cache {
            // Remove oldest entries
            let min_seq = self.received_data.keys().min().copied();
            if let Some(min) = min_seq {
                self.received_data.remove(&min);
            }
        }
    }

    /// Add a received repair packet.
    pub fn add_repair(&mut self, repair: FecRepairPacket) {
        self.received_repairs.push(repair);

        // Limit repair cache
        if self.received_repairs.len() > self.max_cache / 2 {
            self.received_repairs.remove(0);
        }
    }

    /// Mark a sequence number as lost.
    pub fn mark_lost(&mut self, seq_num: u64) {
        if !self.lost_seqs.contains(&seq_num) && !self.received_data.contains_key(&seq_num) {
            self.lost_seqs.push(seq_num);
        }
    }

    /// Attempt to recover lost packets.
    ///
    /// Returns recovered packets as (seq_num, data) pairs.
    pub fn try_recover(&mut self) -> Vec<(u64, Bytes)> {
        let mut recovered = Vec::new();

        for repair in &self.received_repairs {
            // Check if exactly one packet in the group is missing
            let mut missing_seq = None;
            let mut missing_count = 0;

            for &seq in &repair.covered_seqs {
                if !self.received_data.contains_key(&seq) {
                    missing_count += 1;
                    missing_seq = Some(seq);
                }
            }

            if missing_count == 1 {
                if let Some(seq) = missing_seq {
                    // Can recover this packet!
                    let recovered_data = self.recover_packet(&repair.covered_seqs, seq, &repair.repair_data);

                    if let Some(data) = recovered_data {
                        recovered.push((seq, data.clone()));
                        self.received_data.insert(seq, data);
                        self.lost_seqs.retain(|&s| s != seq);
                    }
                }
            }
        }

        // Clean up used repairs
        self.received_repairs.retain(|repair| {
            repair
                .covered_seqs
                .iter()
                .any(|seq| !self.received_data.contains_key(seq))
        });

        recovered
    }

    fn recover_packet(&self, covered: &[u64], missing: u64, repair_data: &Bytes) -> Option<Bytes> {
        // XOR all present packets with repair data to recover missing
        let max_len = repair_data.len();
        let mut result = repair_data.to_vec();

        for &seq in covered {
            if seq != missing {
                if let Some(data) = self.received_data.get(&seq) {
                    for (i, byte) in data.iter().enumerate() {
                        if i < result.len() {
                            result[i] ^= byte;
                        }
                    }
                } else {
                    // Can't recover - missing another packet
                    return None;
                }
            }
        }

        Some(Bytes::from(result))
    }

    /// Check if a sequence number has been received (or recovered).
    pub fn has_data(&self, seq_num: u64) -> bool {
        self.received_data.contains_key(&seq_num)
    }

    /// Get data for a sequence number.
    pub fn get_data(&self, seq_num: u64) -> Option<&Bytes> {
        self.received_data.get(&seq_num)
    }

    /// Get count of cached packets.
    pub fn cached_count(&self) -> usize {
        self.received_data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_basic() {
        let mut encoder = FecEncoder::new(4, 1);

        // Add 3 packets - no repair yet
        let repairs = encoder.add_packet(0, Bytes::from("aaa"));
        assert!(repairs.is_empty());

        let repairs = encoder.add_packet(1, Bytes::from("bbb"));
        assert!(repairs.is_empty());

        let repairs = encoder.add_packet(2, Bytes::from("ccc"));
        assert!(repairs.is_empty());

        // 4th packet triggers repair
        let repairs = encoder.add_packet(3, Bytes::from("ddd"));
        assert_eq!(repairs.len(), 1);
        assert_eq!(repairs[0].covered_seqs, vec![0, 1, 2, 3]);
    }

    #[test]
    fn test_fec_recovery() {
        let mut encoder = FecEncoder::new(4, 1);
        let mut decoder = FecDecoder::new(100);

        // Encode 4 packets
        let packets = vec![
            Bytes::from("packet1"),
            Bytes::from("packet2"),
            Bytes::from("packet3"),
            Bytes::from("packet4"),
        ];

        let mut repairs = Vec::new();
        for (i, pkt) in packets.iter().enumerate() {
            let r = encoder.add_packet(i as u64, pkt.clone());
            repairs.extend(r);
        }

        assert_eq!(repairs.len(), 1);

        // Receive all packets except one
        decoder.add_data(0, packets[0].clone());
        decoder.add_data(1, packets[1].clone());
        // Skip packet 2 (lost)
        decoder.add_data(3, packets[3].clone());

        // Mark as lost and add repair
        decoder.mark_lost(2);
        decoder.add_repair(repairs[0].clone());

        // Try to recover
        let recovered = decoder.try_recover();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].0, 2);
        assert_eq!(recovered[0].1, packets[2]);
    }

    #[test]
    fn test_repair_serialization() {
        let repair = FecRepairPacket {
            fec_seq: 42,
            covered_seqs: vec![10, 11, 12],
            repair_data: Bytes::from("xor_data"),
        };

        let encoded = repair.encode();
        let decoded = FecRepairPacket::decode(encoded).unwrap();

        assert_eq!(decoded.fec_seq, 42);
        assert_eq!(decoded.covered_seqs, vec![10, 11, 12]);
        assert_eq!(decoded.repair_data, Bytes::from("xor_data"));
    }

    #[test]
    fn test_xor_correctness() {
        let a = Bytes::from(vec![0x12, 0x34, 0x56]);
        let b = Bytes::from(vec![0xAB, 0xCD, 0xEF]);

        let mut encoder = FecEncoder::new(2, 1);
        encoder.add_packet(0, a.clone());
        let repairs = encoder.add_packet(1, b.clone());

        assert_eq!(repairs.len(), 1);

        // XOR of a and b
        let expected: Vec<u8> = a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect();
        assert_eq!(repairs[0].repair_data.as_ref(), expected.as_slice());
    }

    #[test]
    fn test_multiple_repairs() {
        let mut encoder = FecEncoder::new(4, 2); // 2 repair packets

        let packets = vec![
            Bytes::from("aaaa"),
            Bytes::from("bbbb"),
            Bytes::from("cccc"),
            Bytes::from("dddd"),
        ];

        let mut repairs = Vec::new();
        for (i, pkt) in packets.iter().enumerate() {
            repairs.extend(encoder.add_packet(i as u64, pkt.clone()));
        }

        // Should have 2 repair packets
        assert_eq!(repairs.len(), 2);
    }

    #[test]
    fn test_encoder_flush() {
        let mut encoder = FecEncoder::new(5, 1);

        // Add only 3 packets
        encoder.add_packet(0, Bytes::from("a"));
        encoder.add_packet(1, Bytes::from("b"));
        encoder.add_packet(2, Bytes::from("c"));

        // Flush should still generate repair
        let repairs = encoder.flush();
        assert_eq!(repairs.len(), 1);
    }
}
