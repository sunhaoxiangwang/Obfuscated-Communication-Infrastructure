//! SOCKS5 proxy over the encrypted SCF tunnel.
//!
//! Client side: local SOCKS5 listener that tunnels traffic through REALITY.
//! Server side: TCP relay connecting to targets on behalf of proxied clients.

pub mod mux;
pub mod relay;
pub mod socks5;
