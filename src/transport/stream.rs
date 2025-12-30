//! Stream multiplexing over a single connection.
//!
//! Provides multiple independent bidirectional streams over one transport
//! connection, similar to QUIC streams.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use parking_lot::RwLock;
use tokio::sync::mpsc;

/// Stream identifier.
pub type StreamId = u32;

/// Stream state.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamState {
    /// Stream is open for sending and receiving
    Open,
    /// Local side has sent FIN
    HalfClosedLocal,
    /// Remote side has sent FIN
    HalfClosedRemote,
    /// Both sides have sent FIN
    Closed,
    /// Stream was reset
    Reset,
}

/// A bidirectional stream.
pub struct Stream {
    /// Stream identifier
    id: StreamId,
    /// Current state
    state: StreamState,
    /// Outbound sequence number
    send_seq: u64,
    /// Inbound data receiver
    recv_rx: mpsc::Receiver<Bytes>,
    /// Send buffer
    send_buffer: Vec<Bytes>,
    /// Flow control: receive window
    recv_window: u32,
    /// Flow control: send window
    send_window: u32,
}

impl Stream {
    /// Get the stream ID.
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get current state.
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Check if stream is writable.
    pub fn is_writable(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedRemote)
            && self.send_window > 0
    }

    /// Check if stream is readable.
    pub fn is_readable(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Queue data for sending.
    pub fn send(&mut self, data: Bytes) -> Result<(), StreamError> {
        if !self.is_writable() {
            return Err(StreamError::NotWritable);
        }

        self.send_buffer.push(data);
        Ok(())
    }

    /// Receive data (non-blocking).
    pub fn try_recv(&mut self) -> Option<Bytes> {
        self.recv_rx.try_recv().ok()
    }

    /// Receive data (async).
    pub async fn recv(&mut self) -> Option<Bytes> {
        if !self.is_readable() {
            return None;
        }
        self.recv_rx.recv().await
    }

    /// Close the sending side.
    pub fn close_send(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => self.state = StreamState::Closed,
            _ => {}
        }
    }

    /// Take queued send data.
    pub fn take_send_data(&mut self) -> Vec<Bytes> {
        std::mem::take(&mut self.send_buffer)
    }

    /// Update send window from ACK.
    pub fn update_send_window(&mut self, window: u32) {
        self.send_window = window;
    }

    /// Get next send sequence number and increment.
    pub fn next_send_seq(&mut self) -> u64 {
        let seq = self.send_seq;
        self.send_seq += 1;
        seq
    }
}

/// Stream error types.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamError {
    /// Stream is not writable
    NotWritable,
    /// Stream is not readable
    NotReadable,
    /// Stream was reset
    Reset,
    /// Maximum streams exceeded
    MaxStreamsExceeded,
    /// Stream not found
    NotFound,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::NotWritable => write!(f, "stream is not writable"),
            StreamError::NotReadable => write!(f, "stream is not readable"),
            StreamError::Reset => write!(f, "stream was reset"),
            StreamError::MaxStreamsExceeded => write!(f, "maximum streams exceeded"),
            StreamError::NotFound => write!(f, "stream not found"),
        }
    }
}

impl std::error::Error for StreamError {}

/// Manages multiple streams over a connection.
pub struct StreamManager {
    /// Active streams
    streams: RwLock<HashMap<StreamId, StreamHandle>>,
    /// Next stream ID for client-initiated streams
    next_client_id: AtomicU64,
    /// Next stream ID for server-initiated streams
    next_server_id: AtomicU64,
    /// Maximum concurrent streams
    max_streams: usize,
    /// Is this the client side?
    is_client: bool,
    /// Default receive window
    default_recv_window: u32,
}

/// Handle to send data to a stream.
struct StreamHandle {
    send_tx: mpsc::Sender<Bytes>,
    state: StreamState,
}

impl StreamManager {
    /// Create a new stream manager.
    pub fn new(is_client: bool, max_streams: usize, default_recv_window: u32) -> Self {
        Self {
            streams: RwLock::new(HashMap::new()),
            // Client uses even IDs, server uses odd IDs
            next_client_id: AtomicU64::new(0),
            next_server_id: AtomicU64::new(1),
            max_streams,
            is_client,
            default_recv_window,
        }
    }

    /// Open a new stream.
    pub fn open(&self) -> Result<Stream, StreamError> {
        let streams = self.streams.read();
        if streams.len() >= self.max_streams {
            return Err(StreamError::MaxStreamsExceeded);
        }
        drop(streams);

        // Generate stream ID
        let id = if self.is_client {
            self.next_client_id.fetch_add(2, Ordering::SeqCst) as StreamId
        } else {
            self.next_server_id.fetch_add(2, Ordering::SeqCst) as StreamId
        };

        self.create_stream(id)
    }

    /// Accept an incoming stream.
    pub fn accept(&self, id: StreamId) -> Result<Stream, StreamError> {
        let streams = self.streams.read();
        if streams.len() >= self.max_streams {
            return Err(StreamError::MaxStreamsExceeded);
        }
        if streams.contains_key(&id) {
            return Err(StreamError::NotFound);
        }
        drop(streams);

        self.create_stream(id)
    }

    fn create_stream(&self, id: StreamId) -> Result<Stream, StreamError> {
        let (send_tx, recv_rx) = mpsc::channel(256);

        let stream = Stream {
            id,
            state: StreamState::Open,
            send_seq: 0,
            recv_rx,
            send_buffer: Vec::new(),
            recv_window: self.default_recv_window,
            send_window: self.default_recv_window,
        };

        let handle = StreamHandle {
            send_tx,
            state: StreamState::Open,
        };

        self.streams.write().insert(id, handle);

        Ok(stream)
    }

    /// Deliver data to a stream.
    pub async fn deliver(&self, id: StreamId, data: Bytes) -> Result<(), StreamError> {
        let streams = self.streams.read();
        let handle = streams.get(&id).ok_or(StreamError::NotFound)?;

        if handle.state == StreamState::Reset {
            return Err(StreamError::Reset);
        }

        handle.send_tx.send(data).await.map_err(|_| StreamError::Reset)
    }

    /// Mark stream as remotely closed.
    pub fn remote_close(&self, id: StreamId) {
        let mut streams = self.streams.write();
        if let Some(handle) = streams.get_mut(&id) {
            match handle.state {
                StreamState::Open => handle.state = StreamState::HalfClosedRemote,
                StreamState::HalfClosedLocal => handle.state = StreamState::Closed,
                _ => {}
            }
        }
    }

    /// Reset a stream.
    pub fn reset(&self, id: StreamId) {
        let mut streams = self.streams.write();
        if let Some(handle) = streams.get_mut(&id) {
            handle.state = StreamState::Reset;
        }
    }

    /// Remove a closed stream.
    pub fn remove(&self, id: StreamId) {
        self.streams.write().remove(&id);
    }

    /// Get count of active streams.
    pub fn active_count(&self) -> usize {
        self.streams.read().len()
    }

    /// Check if a stream exists.
    pub fn exists(&self, id: StreamId) -> bool {
        self.streams.read().contains_key(&id)
    }

    /// Get all stream IDs.
    pub fn stream_ids(&self) -> Vec<StreamId> {
        self.streams.read().keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_creation() {
        let manager = StreamManager::new(true, 100, 65536);
        let stream = manager.open().unwrap();

        assert!(stream.is_writable());
        assert!(stream.is_readable());
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn test_stream_id_generation() {
        let client_manager = StreamManager::new(true, 100, 65536);
        let server_manager = StreamManager::new(false, 100, 65536);

        let stream1 = client_manager.open().unwrap();
        let stream2 = client_manager.open().unwrap();
        let stream3 = server_manager.open().unwrap();
        let stream4 = server_manager.open().unwrap();

        // Client uses even IDs
        assert_eq!(stream1.id() % 2, 0);
        assert_eq!(stream2.id() % 2, 0);

        // Server uses odd IDs
        assert_eq!(stream3.id() % 2, 1);
        assert_eq!(stream4.id() % 2, 1);

        // IDs should be different
        assert_ne!(stream1.id(), stream2.id());
        assert_ne!(stream3.id(), stream4.id());
    }

    #[test]
    fn test_max_streams() {
        let manager = StreamManager::new(true, 2, 65536);

        let _s1 = manager.open().unwrap();
        let _s2 = manager.open().unwrap();
        let result = manager.open();

        assert!(matches!(result, Err(StreamError::MaxStreamsExceeded)));
    }

    #[test]
    fn test_stream_send() {
        let manager = StreamManager::new(true, 100, 65536);
        let mut stream = manager.open().unwrap();

        let result = stream.send(Bytes::from("hello"));
        assert!(result.is_ok());

        let data = stream.take_send_data();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0], Bytes::from("hello"));
    }

    #[test]
    fn test_stream_close() {
        let manager = StreamManager::new(true, 100, 65536);
        let mut stream = manager.open().unwrap();

        stream.close_send();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
        assert!(!stream.is_writable());
        assert!(stream.is_readable());
    }

    #[tokio::test]
    async fn test_stream_deliver() {
        let manager = Arc::new(StreamManager::new(true, 100, 65536));
        let mut stream = manager.open().unwrap();
        let stream_id = stream.id();

        // Deliver data
        manager
            .deliver(stream_id, Bytes::from("test data"))
            .await
            .unwrap();

        // Should be receivable
        let data = stream.try_recv();
        assert!(data.is_some());
        assert_eq!(data.unwrap(), Bytes::from("test data"));
    }

    #[test]
    fn test_stream_reset() {
        let manager = StreamManager::new(true, 100, 65536);
        let stream = manager.open().unwrap();
        let id = stream.id();

        manager.reset(id);

        // Try to deliver to reset stream
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(manager.deliver(id, Bytes::from("data")));

        assert!(matches!(result, Err(StreamError::Reset)));
    }

    #[test]
    fn test_sequence_numbers() {
        let manager = StreamManager::new(true, 100, 65536);
        let mut stream = manager.open().unwrap();

        assert_eq!(stream.next_send_seq(), 0);
        assert_eq!(stream.next_send_seq(), 1);
        assert_eq!(stream.next_send_seq(), 2);
    }
}
