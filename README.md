# Steganographic Communication Framework (SCF)

A privacy-preserving transport layer that makes your traffic look like normal HTTPS. Route all your internet traffic through a VPS so it appears to originate from there.

## How It Works

```
You (macOS/iOS)                         Your VPS                    Internet
┌──────────────┐    Encrypted Tunnel    ┌──────────┐               ┌────────┐
│ SOCKS5 Proxy ├───────────────────────►│ SCF      ├──────────────►│ Target │
│ 127.0.0.1    │   Looks like normal    │ Server   │  Connects on  │ Site   │
│              │◄───────────────────────┤          │◄──────────────┤        │
└──────────────┘   TLS 1.3 traffic      └──────────┘  your behalf  └────────┘
```

Your traffic is indistinguishable from normal TLS 1.3 HTTPS — it uses real certificates from a cover server (e.g. `www.microsoft.com`). Multiple TCP connections are multiplexed over a single encrypted tunnel.

## Quick Install (VPS)

One command to deploy on Ubuntu 22.04/24.04:

```bash
curl -sSf https://raw.githubusercontent.com/sunhaoxiangwang/Obfuscated-Communication-Infrastructure/main/scripts/remote-install.sh | sudo bash
```

This downloads the latest release binary, sets up systemd, generates keys, and starts the server.

After install, add a client:

```bash
sudo scf-server --add-client /etc/scf/server.toml
# Outputs a client.json — give this to whoever needs access
sudo systemctl restart scf-server
```

## Client Setup

### macOS (Desktop)

1. Download the latest release (or build from source)
2. Save your `client.json` in the same directory
3. Double-click `start-proxy.command` — it enables the system SOCKS5 proxy and routes all traffic through the VPS
4. Close the window to stop

Or manually:

```bash
scf-client --config client.json
# SOCKS5 proxy starts on 127.0.0.1:1080
# Set your browser/system SOCKS5 proxy to 127.0.0.1:1080
```

Verify it works:

```bash
curl --socks5 127.0.0.1:1080 https://ifconfig.me
# Should print your VPS IP
```

### iOS

A native Swift iOS app is available in a separate repo: [SCF-iOS-app](https://github.com/sunhaoxiangwang/SCF-iOS-app)

Uses a Network Extension (NEPacketTunnelProvider) with a local SOCKS5 proxy — tap Connect and all HTTP/HTTPS traffic routes through the VPS.

## Building from Source

```bash
# Server (for VPS deployment)
cargo build --release --bin scf-server --features server

# Client (for your machine)
cargo build --release --bin scf-client --features client

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Server Management

### Add/Remove Clients

```bash
# Add a new client (generates short_id, outputs client.json)
sudo scf-server --add-client /etc/scf/server.toml
sudo systemctl restart scf-server

# Show server public key and all allowed clients
sudo scf-server --show-pubkey /etc/scf/server.toml
```

### Service Commands

| Action | Command |
|--------|---------|
| Start | `sudo systemctl start scf-server` |
| Stop | `sudo systemctl stop scf-server` |
| Status | `sudo systemctl status scf-server` |
| Logs | `journalctl -u scf-server -f` |
| Restart | `sudo systemctl restart scf-server` |

### File Locations

| Path | Purpose |
|------|---------|
| `/usr/local/bin/scf-server` | Server binary |
| `/etc/scf/server.toml` | Server config (contains keys — not in git) |
| `/etc/scf/scf.env` | Environment overrides (log level, etc.) |

### Uninstall

```bash
sudo systemctl stop scf-server scf-maintenance.timer
sudo systemctl disable scf-server scf-maintenance.timer
sudo rm /etc/systemd/system/scf-server.service \
        /etc/systemd/system/scf-maintenance.service \
        /etc/systemd/system/scf-maintenance.timer
sudo systemctl daemon-reload
sudo rm /usr/local/bin/scf-server
sudo rm -rf /opt/scf /etc/scf
sudo userdel scf
```

## Architecture

### Protocol Stack

| Layer | Component | Purpose |
|-------|-----------|---------|
| **Proxy** | SOCKS5 + Mux | Local proxy, stream multiplexing over single tunnel |
| **REALITY** | TLS 1.3 Mimicry | Real cover server certs, HMAC auth in ClientHello |
| **Crypto** | X25519, ChaCha20-Poly1305, HKDF | Key exchange, encryption, key derivation |
| **Transport** | TCP + TLS record framing | Reliable delivery with standard record format |

### Multiplexing Protocol

Multiple connections share one encrypted tunnel via a lightweight frame header:

| Field | Size | Description |
|-------|------|-------------|
| Type | 1 byte | StreamOpen / OpenAck / Data / Close / Reset |
| StreamID | 4 bytes | Client-allocated stream identifier |
| DataLen | 2 bytes | Payload length (max 15,000 bytes) |

### Security Properties

| Property | Implementation |
|----------|----------------|
| **Unobservability** | Traffic indistinguishable from Nginx TLS 1.3 patterns |
| **Forward Secrecy** | Per-session X25519 ephemeral keys |
| **Authentication** | HMAC-based auth tag embedded in ClientHello `client_random` |
| **Confidentiality** | ChaCha20-Poly1305 AEAD with independent send/recv keys |
| **Zero-Log** | RAM-only sessions, zeroized on drop |

## Project Structure

```
src/
├── lib.rs                # Library entry point
├── error.rs              # Error types
├── crypto/               # Cryptographic primitives
│   ├── keys.rs           # X25519 key types
│   ├── aead.rs           # ChaCha20-Poly1305
│   ├── kdf.rs            # HKDF key derivation
│   └── random.rs         # Secure RNG
├── reality/              # REALITY protocol
│   ├── config.rs         # Configuration
│   ├── handshake.rs      # TLS 1.3 ClientHello/ServerHello
│   ├── client.rs         # Client (connect + split)
│   └── server.rs         # Server (accept + verify)
├── proxy/                # Proxy layer
│   ├── mux.rs            # Stream multiplexing frames
│   ├── socks5.rs         # Client-side SOCKS5 proxy
│   └── relay.rs          # Server-side TCP relay
├── server/               # Server infrastructure
│   ├── config.rs         # Server config + client management
│   ├── session.rs        # RAM-only sessions
│   ├── rate_limit.rs     # Rate limiting
│   └── metrics.rs        # Metrics collection
├── obfuscation/          # Traffic obfuscation
│   ├── padding.rs        # Packet padding
│   ├── timing.rs         # Timing obfuscation
│   └── traffic_model.rs  # Traffic pattern matching
├── transport/            # Transport layer
│   ├── congestion.rs     # BBR-like congestion control
│   ├── fec.rs            # Forward error correction
│   └── reliability.rs    # SACK retransmission
└── bin/                  # CLI binaries
    ├── server.rs         # scf-server
    └── client.rs         # scf-client
```

## Cross-Platform

| Platform | Method |
|----------|--------|
| Linux x86_64 | Pre-built release binary or `cargo build` |
| macOS (Intel/Apple Silicon) | `cargo build` + `start-proxy.command` |
| iOS | Native Swift app ([separate repo](https://github.com/sunhaoxiangwang/virtual-p2p-connection-iOS-app)) |

## License

Copyright (c) 2025 [SUM INNOVATION INC](https://suminnovation.xyz). All rights reserved.

MIT OR Apache-2.0

## Disclaimer

This software is intended for academic research and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction.
