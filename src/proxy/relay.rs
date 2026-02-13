//! Server-side TCP relay.
//!
//! Receives multiplexed frames from the client, opens TCP connections to
//! target hosts, and relays data bidirectionally.

use std::collections::HashMap;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::crypto::{Aead, Nonce};
use crate::error::{Error, Result};
use crate::proxy::mux::{parse_target_addr, Frame, FrameType, StreamId, MAX_FRAME_PAYLOAD};

/// Run the server-side relay loop.
///
/// Reads encrypted mux frames from the client, dispatches StreamOpen to target
/// connections, and relays data bidirectionally.
pub async fn run_relay(stream: TcpStream, client_aead: Aead, server_aead: Aead) -> Result<()> {
    let (read_half, write_half) = tokio::io::split(stream);

    // Channel for frames going back to the client
    let (tx, rx) = mpsc::channel::<Frame>(256);

    // Writer task: encrypts outbound frames and writes TLS records
    let writer_handle = tokio::spawn(relay_writer(write_half, server_aead, rx));

    // Reader loop: reads TLS records, decrypts, dispatches mux frames
    let reader_result = relay_reader(read_half, client_aead, tx).await;

    // Writer exits when all tx senders are dropped
    let _ = writer_handle.await;

    reader_result
}

async fn relay_writer(
    mut writer: tokio::io::WriteHalf<TcpStream>,
    server_aead: Aead,
    mut rx: mpsc::Receiver<Frame>,
) -> Result<()> {
    let mut send_nonce = Nonce::new(0);

    while let Some(frame) = rx.recv().await {
        let data = frame.encode();
        let ciphertext = server_aead.encrypt(&send_nonce, &data, b"")?;
        send_nonce.increment();

        let mut record = Vec::with_capacity(5 + ciphertext.len());
        record.push(0x17); // Application data
        record.push(0x03);
        record.push(0x03); // TLS 1.2 record version
        record.push((ciphertext.len() >> 8) as u8);
        record.push((ciphertext.len() & 0xff) as u8);
        record.extend_from_slice(&ciphertext);

        writer.write_all(&record).await.map_err(Error::Network)?;
    }

    Ok(())
}

async fn relay_reader(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    client_aead: Aead,
    reply_tx: mpsc::Sender<Frame>,
) -> Result<()> {
    let mut recv_nonce = Nonce::new(0);
    let mut streams: HashMap<StreamId, mpsc::Sender<Vec<u8>>> = HashMap::new();

    loop {
        // Read TLS record header
        let mut header = [0u8; 5];
        match reader.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(Error::Network(e)),
        }

        let record_type = header[0];
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;

        // TLS alert → close
        if record_type == 0x15 {
            return Ok(());
        }

        if length > 16384 + 256 {
            return Err(Error::InvalidMessage("Record too large".into()));
        }

        let mut record_body = vec![0u8; length];
        reader.read_exact(&mut record_body).await?;

        // Only process application data records
        if record_type != 0x17 {
            continue;
        }

        // Decrypt
        let plaintext = client_aead.decrypt(&recv_nonce, &record_body, b"")?;
        recv_nonce.increment();

        // Parse mux frame
        let frame = Frame::decode(&plaintext)?;

        match frame.frame_type {
            FrameType::StreamOpen => {
                let stream_id = frame.stream_id;
                let (host, port) = match parse_target_addr(&frame.payload) {
                    Ok(v) => v,
                    Err(_) => {
                        let _ = reply_tx
                            .send(Frame::stream_open_ack(stream_id, 0x01))
                            .await;
                        continue;
                    }
                };

                let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
                streams.insert(stream_id, data_tx);

                let reply_tx = reply_tx.clone();
                tokio::spawn(async move {
                    match TcpStream::connect(format!("{}:{}", host, port)).await {
                        Ok(target_stream) => {
                            let _ = reply_tx
                                .send(Frame::stream_open_ack(stream_id, 0x00))
                                .await;
                            let _ =
                                relay_target(stream_id, target_stream, data_rx, reply_tx).await;
                        }
                        Err(_) => {
                            let _ = reply_tx
                                .send(Frame::stream_open_ack(stream_id, 0x01))
                                .await;
                        }
                    }
                });
            }
            FrameType::StreamData => {
                if let Some(tx) = streams.get(&frame.stream_id) {
                    if tx.send(frame.payload).await.is_err() {
                        streams.remove(&frame.stream_id);
                    }
                }
            }
            FrameType::StreamClose | FrameType::StreamReset => {
                streams.remove(&frame.stream_id);
            }
            _ => {}
        }
    }
}

/// Relay data between a mux stream and a target TCP connection.
async fn relay_target(
    stream_id: StreamId,
    target: TcpStream,
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    reply_tx: mpsc::Sender<Frame>,
) -> Result<()> {
    let (mut target_reader, mut target_writer) = tokio::io::split(target);

    // Target → client
    let reply_tx2 = reply_tx.clone();
    let read_task = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_FRAME_PAYLOAD];
        loop {
            match target_reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if reply_tx2
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
        let _ = reply_tx2.send(Frame::stream_close(stream_id)).await;
    });

    // Client → target
    let write_task = tokio::spawn(async move {
        while let Some(data) = data_rx.recv().await {
            if target_writer.write_all(&data).await.is_err() {
                break;
            }
        }
    });

    let _ = tokio::join!(read_task, write_task);
    Ok(())
}
