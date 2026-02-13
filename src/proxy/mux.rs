//! Lightweight stream multiplexing over a message-based channel.
//!
//! Each frame has a 7-byte header: type(1) + stream_id(4) + data_len(2) + payload.

use crate::error::{Error, Result};

/// Stream identifier type.
pub type StreamId = u32;

/// Maximum payload size per frame (fits within TLS record limits).
pub const MAX_FRAME_PAYLOAD: usize = 15000;

/// Frame header size.
pub const FRAME_HEADER_SIZE: usize = 7;

/// Multiplexing frame types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Client requests a new outbound connection.
    /// Payload: addr_type(1) + address + port(2)
    StreamOpen = 0x01,
    /// Server acknowledges a stream open.
    /// Payload: status(1) — 0x00 = success
    StreamOpenAck = 0x02,
    /// Data payload for an existing stream.
    StreamData = 0x03,
    /// Graceful close of a stream.
    StreamClose = 0x04,
    /// Abrupt reset of a stream.
    StreamReset = 0x05,
}

impl FrameType {
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0x01 => Ok(Self::StreamOpen),
            0x02 => Ok(Self::StreamOpenAck),
            0x03 => Ok(Self::StreamData),
            0x04 => Ok(Self::StreamClose),
            0x05 => Ok(Self::StreamReset),
            _ => Err(Error::InvalidMessage(format!("unknown frame type: 0x{:02x}", v))),
        }
    }
}

/// A multiplexing frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub frame_type: FrameType,
    pub stream_id: StreamId,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Encode the frame into bytes for transmission.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        buf.push(self.frame_type as u8);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a frame from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(Error::InvalidMessage(format!(
                "frame too short: {} bytes",
                data.len()
            )));
        }

        let frame_type = FrameType::from_u8(data[0])?;
        let stream_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let data_len = u16::from_be_bytes([data[5], data[6]]) as usize;

        if data.len() < FRAME_HEADER_SIZE + data_len {
            return Err(Error::InvalidMessage(format!(
                "frame truncated: header says {} payload bytes, got {}",
                data_len,
                data.len() - FRAME_HEADER_SIZE
            )));
        }

        Ok(Self {
            frame_type,
            stream_id,
            payload: data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + data_len].to_vec(),
        })
    }

    /// Create a StreamOpen frame.
    /// `addr_payload` is SOCKS5 address format: addr_type(1) + addr + port(2).
    pub fn stream_open(stream_id: StreamId, addr_payload: Vec<u8>) -> Self {
        Self {
            frame_type: FrameType::StreamOpen,
            stream_id,
            payload: addr_payload,
        }
    }

    /// Create a StreamOpenAck frame.
    pub fn stream_open_ack(stream_id: StreamId, status: u8) -> Self {
        Self {
            frame_type: FrameType::StreamOpenAck,
            stream_id,
            payload: vec![status],
        }
    }

    /// Create a StreamData frame.
    pub fn stream_data(stream_id: StreamId, data: &[u8]) -> Self {
        Self {
            frame_type: FrameType::StreamData,
            stream_id,
            payload: data.to_vec(),
        }
    }

    /// Create a StreamClose frame.
    pub fn stream_close(stream_id: StreamId) -> Self {
        Self {
            frame_type: FrameType::StreamClose,
            stream_id,
            payload: Vec::new(),
        }
    }

    /// Create a StreamReset frame.
    pub fn stream_reset(stream_id: StreamId) -> Self {
        Self {
            frame_type: FrameType::StreamReset,
            stream_id,
            payload: Vec::new(),
        }
    }
}

/// Parse a SOCKS5-style target address from a StreamOpen payload.
/// Returns (host, port).
pub fn parse_target_addr(payload: &[u8]) -> Result<(String, u16)> {
    if payload.is_empty() {
        return Err(Error::InvalidMessage("empty address payload".into()));
    }

    let addr_type = payload[0];
    match addr_type {
        // IPv4
        0x01 => {
            if payload.len() < 7 {
                return Err(Error::InvalidMessage("IPv4 address too short".into()));
            }
            let ip = format!("{}.{}.{}.{}", payload[1], payload[2], payload[3], payload[4]);
            let port = u16::from_be_bytes([payload[5], payload[6]]);
            Ok((ip, port))
        }
        // Domain name
        0x03 => {
            if payload.len() < 2 {
                return Err(Error::InvalidMessage("domain address too short".into()));
            }
            let domain_len = payload[1] as usize;
            if payload.len() < 2 + domain_len + 2 {
                return Err(Error::InvalidMessage("domain address truncated".into()));
            }
            let domain = String::from_utf8_lossy(&payload[2..2 + domain_len]).to_string();
            let port = u16::from_be_bytes([
                payload[2 + domain_len],
                payload[2 + domain_len + 1],
            ]);
            Ok((domain, port))
        }
        // IPv6
        0x04 => {
            if payload.len() < 19 {
                return Err(Error::InvalidMessage("IPv6 address too short".into()));
            }
            let mut segments = [0u16; 8];
            for i in 0..8 {
                segments[i] = u16::from_be_bytes([payload[1 + i * 2], payload[2 + i * 2]]);
            }
            let ip = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7]
            );
            let port = u16::from_be_bytes([payload[17], payload[18]]);
            Ok((ip, port))
        }
        _ => Err(Error::InvalidMessage(format!("unknown address type: 0x{:02x}", addr_type))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let frame = Frame::stream_data(42, b"hello world");
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded.frame_type, FrameType::StreamData);
        assert_eq!(decoded.stream_id, 42);
        assert_eq!(decoded.payload, b"hello world");
    }

    #[test]
    fn test_frame_open_ack() {
        let frame = Frame::stream_open_ack(1, 0x00);
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded.frame_type, FrameType::StreamOpenAck);
        assert_eq!(decoded.stream_id, 1);
        assert_eq!(decoded.payload, vec![0x00]);
    }

    #[test]
    fn test_parse_ipv4_addr() {
        let payload = vec![0x01, 93, 184, 216, 34, 0x01, 0xBB]; // 93.184.216.34:443
        let (host, port) = parse_target_addr(&payload).unwrap();
        assert_eq!(host, "93.184.216.34");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_domain_addr() {
        let mut payload = vec![0x03, 11]; // domain type, length 11
        payload.extend_from_slice(b"example.com");
        payload.extend_from_slice(&443u16.to_be_bytes());
        let (host, port) = parse_target_addr(&payload).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }
}
