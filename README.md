# Steganographic Communication Framework (SCF)

A privacy-preserving transport layer achieving statistical unobservability through TLS 1.3 traffic mimicry.

## Overview

SCF is a Rust implementation of an obfuscated communication protocol designed for academic research in network privacy. It provides:

- **REALITY Protocol**: Perfect TLS 1.3 mimicry using real certificates from cover servers
- **Traffic Obfuscation**: Padding and timing countermeasures for traffic analysis resistance
- **Resilient Transport**: Custom congestion control and FEC for high-loss environments
- **Zero-Log Architecture**: RAM-only session storage with forward secrecy

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
├─────────────────────────────────────────────────────────┤
│  Obfuscation Engine (padding, timing, traffic shaping)  │
├─────────────────────────────────────────────────────────┤
│  REALITY Protocol (TLS 1.3 mimicry + authentication)    │
├─────────────────────────────────────────────────────────┤
│  Transport Stack (QUIC-like, custom congestion control) │
├─────────────────────────────────────────────────────────┤
│  Crypto Layer (X25519, ChaCha20-Poly1305, HKDF)        │
└─────────────────────────────────────────────────────────┘
```

## Building

```bash
# Build library
cargo build --release

# Build with all features
cargo build --release --all-features

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Usage

### Server Setup

```bash
# Generate configuration
./target/release/scf-server --generate > server.toml

# Edit server.toml with your settings

# Run server
./target/release/scf-server --config server.toml
```

### Client Connection

```bash
# Create client.json with connection parameters
./target/release/scf-client --test client.json
```

### Library Usage

```rust
use scf::reality::{RealityClient, RealityConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = RealityConfig {
        server_public_key: [/* 32 bytes */],
        short_id: [/* 8 bytes */],
        cover_sni: "www.example.com".to_string(),
        server_addr: "your-server.com".to_string(),
        server_port: 443,
        ..Default::default()
    };

    let client = RealityClient::new(config)?;
    let mut conn = client.connect().await?;

    conn.send(b"Hello, World!").await?;
    let response = conn.recv().await?;

    conn.close().await?;
    Ok(())
}
```

## Deployment (VPS)

### Prerequisites

- Ubuntu 22.04 / 24.04
- Rust toolchain (or pre-built binary copied via `scp`)

### Quick Start

```bash
# On VPS — clone, build, install
git clone <repo-url> /opt/scf-src && cd /opt/scf-src
cargo build --release --features server
sudo ./scripts/install.sh

# Edit config (contains generated keys)
sudo nano /etc/scf/server.toml

# Start
sudo systemctl start scf-server
sudo systemctl start scf-maintenance.timer
```

### Service Management

| Action | Command |
|--------|---------|
| Start | `sudo systemctl start scf-server` |
| Stop | `sudo systemctl stop scf-server` |
| Status | `sudo systemctl status scf-server` |
| Logs | `journalctl -u scf-server -f` |
| Restart | `sudo systemctl restart scf-server` |
| Maintenance logs | `journalctl -u scf-maintenance -e` |

### File Locations

| Path | Purpose |
|------|---------|
| `/usr/local/bin/scf-server` | Server binary |
| `/etc/scf/server.toml` | Server config (secret — not in git) |
| `/etc/scf/scf.env` | Environment overrides |
| `/etc/scf/maintenance.conf` | Maintenance tunables |
| `/opt/scf/scripts/maintenance.sh` | Maintenance script |

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

## Security Properties

| Property | Implementation |
|----------|----------------|
| **Unobservability** | Traffic indistinguishable from Nginx TLS patterns |
| **Forward Secrecy** | Per-session X25519 ephemeral keys |
| **Authentication** | HMAC-based auth tag embedded in ClientHello |
| **Confidentiality** | ChaCha20-Poly1305 AEAD encryption |
| **Integrity** | Poly1305 authentication tags |

## Evaluation

See [docs/EVALUATION.md](docs/EVALUATION.md) for detailed testing methodology including:

- KL divergence analysis for traffic distribution matching
- ML classifier resistance testing
- Packet loss resilience benchmarks
- Latency overhead measurements

## Project Structure

```
src/
├── lib.rs              # Library entry point
├── error.rs            # Error types
├── crypto/             # Cryptographic primitives
│   ├── keys.rs         # X25519 key types
│   ├── aead.rs         # ChaCha20-Poly1305
│   ├── kdf.rs          # HKDF key derivation
│   └── random.rs       # Secure RNG
├── reality/            # REALITY protocol
│   ├── config.rs       # Configuration
│   ├── handshake.rs    # TLS message building
│   ├── client.rs       # Client implementation
│   └── server.rs       # Server implementation
├── obfuscation/        # Traffic obfuscation
│   ├── padding.rs      # Packet padding
│   ├── timing.rs       # Timing obfuscation
│   └── traffic_model.rs # Traffic patterns
├── transport/          # Transport layer
│   ├── packet.rs       # Packet framing
│   ├── congestion.rs   # BBR-like CC
│   ├── fec.rs          # Forward error correction
│   ├── reliability.rs  # SACK retransmission
│   └── stream.rs       # Stream multiplexing
├── server/             # Server infrastructure
│   ├── config.rs       # Server config
│   ├── session.rs      # RAM-only sessions
│   ├── rate_limit.rs   # Rate limiting
│   └── metrics.rs      # Metrics collection
├── ffi/                # C FFI bindings
└── bin/                # CLI binaries
    ├── server.rs
    └── client.rs
```

## Cross-Platform Support

The core library supports:
- Linux (x86_64, ARM64)
- macOS (x86_64, ARM64)
- Windows (x86_64)
- Android (via JNI)
- iOS (via C FFI)

## License

MIT OR Apache-2.0

## Disclaimer

This software is intended for academic research and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations in their jurisdiction.
