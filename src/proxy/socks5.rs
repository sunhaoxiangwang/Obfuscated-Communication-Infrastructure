//! Client-side SOCKS5 proxy.
//!
//! Listens on a local port, accepts SOCKS5 CONNECT requests, and tunnels
//! them through the encrypted SCF connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::proxy::mux::{Frame, FrameType, StreamId, MAX_FRAME_PAYLOAD};
use crate::reality::client::{RealityReader, RealityWriter};

/// Run the SOCKS5 proxy, tunneling all connections through the SCF tunnel.
pub async fn run_socks5_proxy(
    listen_addr: &str,
    reader: RealityReader,
    writer: RealityWriter,
) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    tracing::info!("SOCKS5 proxy listening on {}", listen_addr);

    let next_stream_id = Arc::new(AtomicU32::new(1));

    // Channel for sending mux frames into the tunnel
    let (frame_tx, frame_rx) = mpsc::channel::<Frame>(256);

    // Per-stream channels: stream_id → sender for frames coming back from tunnel
    let stream_senders: Arc<Mutex<HashMap<StreamId, mpsc::Sender<Frame>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Writer task: sends mux frames over the encrypted tunnel
    let writer_handle = tokio::spawn(tunnel_writer(writer, frame_rx));

    // Reader task: reads mux frames from the tunnel, dispatches to streams
    let stream_senders2 = Arc::clone(&stream_senders);
    let reader_handle = tokio::spawn(tunnel_reader(reader, stream_senders2));

    // Accept SOCKS5 connections until the tunnel dies
    let frame_tx_accept = frame_tx.clone();
    let accept_loop = async {
        loop {
            match listener.accept().await {
                Ok((client, peer)) => {
                    tracing::debug!("SOCKS5 connection from {}", peer);

                    let stream_id = next_stream_id.fetch_add(1, Ordering::SeqCst);
                    let frame_tx = frame_tx_accept.clone();
                    let stream_senders = Arc::clone(&stream_senders);

                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_socks5_client(client, stream_id, frame_tx, stream_senders).await
                        {
                            tracing::debug!("SOCKS5 stream {} error: {}", stream_id, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("Accept error: {}", e);
                }
            }
        }
    };

    // If the tunnel reader or writer exits, we're done
    tokio::select! {
        _ = accept_loop => {}
        _ = reader_handle => {
            tracing::info!("Tunnel closed");
        }
        _ = writer_handle => {
            tracing::info!("Tunnel closed");
        }
    }

    Ok(())
}

/// Send mux frames over the encrypted tunnel.
async fn tunnel_writer(mut writer: RealityWriter, mut rx: mpsc::Receiver<Frame>) {
    while let Some(frame) = rx.recv().await {
        let data = frame.encode();
        if writer.send(&data).await.is_err() {
            break;
        }
    }
}

/// Read mux frames from the tunnel and dispatch to per-stream channels.
async fn tunnel_reader(
    mut reader: RealityReader,
    stream_senders: Arc<Mutex<HashMap<StreamId, mpsc::Sender<Frame>>>>,
) {
    loop {
        match reader.recv().await {
            Ok(data) => {
                if let Ok(frame) = Frame::decode(&data) {
                    let senders = stream_senders.lock();
                    if let Some(tx) = senders.get(&frame.stream_id) {
                        let _ = tx.try_send(frame);
                    }
                }
            }
            Err(_) => break,
        }
    }
}

/// Handle a single SOCKS5 client connection.
async fn handle_socks5_client(
    mut client: TcpStream,
    stream_id: StreamId,
    frame_tx: mpsc::Sender<Frame>,
    stream_senders: Arc<Mutex<HashMap<StreamId, mpsc::Sender<Frame>>>>,
) -> Result<()> {
    // === SOCKS5 Greeting ===
    let mut buf = [0u8; 258];
    let n = client.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err(Error::InvalidMessage("Not SOCKS5".into()));
    }

    // Reply: no authentication required
    client.write_all(&[0x05, 0x00]).await?;

    // === SOCKS5 CONNECT Request ===
    let mut req = [0u8; 4];
    client.read_exact(&mut req).await?;

    if req[0] != 0x05 || req[1] != 0x01 {
        // Only CONNECT (0x01) supported
        client
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(Error::InvalidMessage("Only CONNECT supported".into()));
    }

    // Read target address (SOCKS5 format → mux payload)
    let atyp = req[3];
    let addr_payload = match atyp {
        0x01 => {
            // IPv4: 4 bytes + 2 port bytes
            let mut addr = vec![0x01];
            let mut ip_port = [0u8; 6];
            client.read_exact(&mut ip_port).await?;
            addr.extend_from_slice(&ip_port);
            addr
        }
        0x03 => {
            // Domain: 1 byte len + domain + 2 port bytes
            let mut len_buf = [0u8; 1];
            client.read_exact(&mut len_buf).await?;
            let domain_len = len_buf[0] as usize;
            let mut domain_port = vec![0u8; domain_len + 2];
            client.read_exact(&mut domain_port).await?;
            let mut addr = vec![0x03, len_buf[0]];
            addr.extend_from_slice(&domain_port);
            addr
        }
        0x04 => {
            // IPv6: 16 bytes + 2 port bytes
            let mut addr = vec![0x04];
            let mut ip_port = [0u8; 18];
            client.read_exact(&mut ip_port).await?;
            addr.extend_from_slice(&ip_port);
            addr
        }
        _ => {
            client
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(Error::InvalidMessage("Unsupported address type".into()));
        }
    };

    // Register stream channel before sending StreamOpen
    let (reply_tx, mut reply_rx) = mpsc::channel::<Frame>(64);
    stream_senders.lock().insert(stream_id, reply_tx);

    // Send StreamOpen through the tunnel
    frame_tx
        .send(Frame::stream_open(stream_id, addr_payload))
        .await
        .map_err(|_| Error::InvalidMessage("Tunnel closed".into()))?;

    // Wait for StreamOpenAck
    let ack = match tokio::time::timeout(std::time::Duration::from_secs(10), reply_rx.recv()).await
    {
        Ok(Some(frame)) if frame.frame_type == FrameType::StreamOpenAck => frame,
        _ => {
            stream_senders.lock().remove(&stream_id);
            client
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(Error::InvalidMessage("Tunnel open failed".into()));
        }
    };

    if ack.payload.first() != Some(&0x00) {
        stream_senders.lock().remove(&stream_id);
        client
            .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(Error::InvalidMessage("Remote connection refused".into()));
    }

    // Send SOCKS5 success reply
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    // === Bidirectional relay: SOCKS5 client ↔ tunnel stream ===
    let (mut client_reader, mut client_writer) = tokio::io::split(client);

    // Client → tunnel
    let frame_tx2 = frame_tx.clone();
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_FRAME_PAYLOAD];
        loop {
            match client_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if frame_tx2
                        .send(Frame::stream_data(stream_id, &buf[..n]))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = frame_tx2.send(Frame::stream_close(stream_id)).await;
    });

    // Tunnel → client
    let write_task = tokio::spawn(async move {
        while let Some(frame) = reply_rx.recv().await {
            match frame.frame_type {
                FrameType::StreamData => {
                    if client_writer.write_all(&frame.payload).await.is_err() {
                        break;
                    }
                }
                FrameType::StreamClose | FrameType::StreamReset => break,
                _ => {}
            }
        }
    });

    let _ = tokio::join!(read_task, write_task);
    stream_senders.lock().remove(&stream_id);

    Ok(())
}
