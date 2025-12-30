//! Packet framing and serialization.
//!
//! Defines the wire format for transport packets.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};

/// Packet types in the transport protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Data packet with payload
    Data = 0x00,
    /// Acknowledgment packet
    Ack = 0x01,
    /// FEC repair packet
    Fec = 0x02,
    /// Stream control (open/close/reset)
    StreamControl = 0x03,
    /// Connection control (ping/pong/close)
    ConnectionControl = 0x04,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(PacketType::Data),
            0x01 => Ok(PacketType::Ack),
            0x02 => Ok(PacketType::Fec),
            0x03 => Ok(PacketType::StreamControl),
            0x04 => Ok(PacketType::ConnectionControl),
            _ => Err(Error::InvalidMessage(format!("Unknown packet type: {}", value))),
        }
    }
}

/// A transport packet.
///
/// Wire format:
/// ```text
/// ┌─────────────────────────────────────────────────────────┐
/// │ Type (1) │ Flags (1) │ Stream ID (4) │ Seq Num (8)     │
/// ├─────────────────────────────────────────────────────────┤
/// │ Ack Num (8)          │ Window (4)    │ Payload Len (2) │
/// ├─────────────────────────────────────────────────────────┤
/// │ Payload (variable)                                      │
/// └─────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet type
    pub packet_type: PacketType,
    /// Flags (type-specific)
    pub flags: u8,
    /// Stream identifier
    pub stream_id: u32,
    /// Sequence number
    pub seq_num: u64,
    /// Acknowledgment number (highest received)
    pub ack_num: u64,
    /// Receive window size
    pub window: u32,
    /// Payload data
    pub payload: Bytes,
}

/// Packet flags
pub mod flags {
    /// This packet completes a message
    pub const FIN: u8 = 0x01;
    /// Request acknowledgment
    pub const ACK_REQ: u8 = 0x02;
    /// Packet contains SACK ranges
    pub const HAS_SACK: u8 = 0x04;
    /// High priority packet
    pub const PRIORITY: u8 = 0x08;
    /// Retransmission
    pub const RETRANSMIT: u8 = 0x10;
}

/// Header size in bytes
pub const HEADER_SIZE: usize = 28;

impl Packet {
    /// Create a new data packet.
    pub fn data(stream_id: u32, seq_num: u64, payload: impl Into<Bytes>) -> Self {
        Self {
            packet_type: PacketType::Data,
            flags: 0,
            stream_id,
            seq_num,
            ack_num: 0,
            window: 0,
            payload: payload.into(),
        }
    }

    /// Create an ACK packet.
    pub fn ack(stream_id: u32, ack_num: u64, window: u32) -> Self {
        Self {
            packet_type: PacketType::Ack,
            flags: 0,
            stream_id,
            seq_num: 0,
            ack_num,
            window,
            payload: Bytes::new(),
        }
    }

    /// Create an FEC repair packet.
    pub fn fec(stream_id: u32, seq_num: u64, repair_data: impl Into<Bytes>) -> Self {
        Self {
            packet_type: PacketType::Fec,
            flags: 0,
            stream_id,
            seq_num,
            ack_num: 0,
            window: 0,
            payload: repair_data.into(),
        }
    }

    /// Set a flag on the packet.
    pub fn with_flag(mut self, flag: u8) -> Self {
        self.flags |= flag;
        self
    }

    /// Check if a flag is set.
    pub fn has_flag(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Set the acknowledgment number.
    pub fn with_ack(mut self, ack_num: u64, window: u32) -> Self {
        self.ack_num = ack_num;
        self.window = window;
        self
    }

    /// Serialize the packet to bytes.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_SIZE + self.payload.len());

        buf.put_u8(self.packet_type as u8);
        buf.put_u8(self.flags);
        buf.put_u32(self.stream_id);
        buf.put_u64(self.seq_num);
        buf.put_u64(self.ack_num);
        buf.put_u32(self.window);
        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);

        buf.freeze()
    }

    /// Deserialize a packet from bytes.
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(Error::Buffer {
                expected: HEADER_SIZE,
                actual: data.len(),
            });
        }

        let packet_type = PacketType::try_from(data.get_u8())?;
        let flags = data.get_u8();
        let stream_id = data.get_u32();
        let seq_num = data.get_u64();
        let ack_num = data.get_u64();
        let window = data.get_u32();
        let payload_len = data.get_u16() as usize;

        if data.len() < payload_len {
            return Err(Error::Buffer {
                expected: payload_len,
                actual: data.len(),
            });
        }

        let payload = data.split_to(payload_len);

        Ok(Self {
            packet_type,
            flags,
            stream_id,
            seq_num,
            ack_num,
            window,
            payload,
        })
    }

    /// Get the total wire size of this packet.
    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }
}

/// Builder for constructing packets with SACK ranges.
pub struct PacketBuilder {
    packet: Packet,
    sack_ranges: Vec<(u64, u64)>,
}

impl PacketBuilder {
    /// Start building from a base packet.
    pub fn new(packet: Packet) -> Self {
        Self {
            packet,
            sack_ranges: Vec::new(),
        }
    }

    /// Add a SACK range.
    pub fn add_sack(mut self, start: u64, end: u64) -> Self {
        self.sack_ranges.push((start, end));
        self
    }

    /// Build the final packet.
    pub fn build(mut self) -> Packet {
        if !self.sack_ranges.is_empty() {
            self.packet.flags |= flags::HAS_SACK;

            // Encode SACK ranges into payload
            let mut sack_data = BytesMut::with_capacity(2 + self.sack_ranges.len() * 16);
            sack_data.put_u16(self.sack_ranges.len() as u16);
            for (start, end) in &self.sack_ranges {
                sack_data.put_u64(*start);
                sack_data.put_u64(*end);
            }

            // Prepend SACK data to payload
            let mut new_payload = sack_data;
            new_payload.put_slice(&self.packet.payload);
            self.packet.payload = new_payload.freeze();
        }

        self.packet
    }
}

/// Parse SACK ranges from a packet with HAS_SACK flag.
pub fn parse_sack_ranges(packet: &Packet) -> Result<(Vec<(u64, u64)>, Bytes)> {
    if !packet.has_flag(flags::HAS_SACK) {
        return Ok((Vec::new(), packet.payload.clone()));
    }

    let mut data = packet.payload.clone();

    if data.len() < 2 {
        return Err(Error::InvalidMessage("SACK data too short".into()));
    }

    let count = data.get_u16() as usize;

    if data.len() < count * 16 {
        return Err(Error::InvalidMessage("SACK ranges truncated".into()));
    }

    let mut ranges = Vec::with_capacity(count);
    for _ in 0..count {
        let start = data.get_u64();
        let end = data.get_u64();
        ranges.push((start, end));
    }

    Ok((ranges, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_encode_decode() {
        let original = Packet::data(1, 42, Bytes::from("hello world"))
            .with_flag(flags::FIN)
            .with_ack(100, 65536);

        let encoded = original.encode();
        let decoded = Packet::decode(encoded).unwrap();

        assert_eq!(decoded.packet_type, PacketType::Data);
        assert_eq!(decoded.stream_id, 1);
        assert_eq!(decoded.seq_num, 42);
        assert_eq!(decoded.ack_num, 100);
        assert_eq!(decoded.window, 65536);
        assert!(decoded.has_flag(flags::FIN));
        assert_eq!(decoded.payload.as_ref(), b"hello world");
    }

    #[test]
    fn test_ack_packet() {
        let ack = Packet::ack(5, 1000, 32768);

        assert_eq!(ack.packet_type, PacketType::Ack);
        assert_eq!(ack.stream_id, 5);
        assert_eq!(ack.ack_num, 1000);
        assert_eq!(ack.window, 32768);
    }

    #[test]
    fn test_packet_with_sack() {
        let data = Packet::data(1, 50, Bytes::from("payload"));
        let packet = PacketBuilder::new(data)
            .add_sack(10, 20)
            .add_sack(30, 40)
            .build();

        assert!(packet.has_flag(flags::HAS_SACK));

        let (ranges, payload) = parse_sack_ranges(&packet).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (10, 20));
        assert_eq!(ranges[1], (30, 40));
        assert_eq!(payload.as_ref(), b"payload");
    }

    #[test]
    fn test_wire_size() {
        let packet = Packet::data(1, 1, Bytes::from("12345"));
        assert_eq!(packet.wire_size(), HEADER_SIZE + 5);
    }

    #[test]
    fn test_decode_invalid() {
        // Too short
        let result = Packet::decode(Bytes::from_static(&[0, 1, 2]));
        assert!(result.is_err());

        // Invalid packet type
        let mut bad_type = BytesMut::with_capacity(HEADER_SIZE);
        bad_type.put_u8(0xFF); // Invalid type
        bad_type.put_slice(&[0u8; HEADER_SIZE - 1]);
        let result = Packet::decode(bad_type.freeze());
        assert!(result.is_err());
    }
}
