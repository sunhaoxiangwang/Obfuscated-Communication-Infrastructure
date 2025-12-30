//! Cryptographic primitives for SCF.
//!
//! This module provides:
//! - X25519 Elliptic Curve Diffie-Hellman key exchange
//! - ChaCha20-Poly1305 AEAD encryption
//! - HKDF key derivation
//! - Secure random number generation
//!
//! All secret material is zeroized on drop to prevent memory leakage.

mod aead;
mod kdf;
mod keys;
mod random;

pub use aead::{Aead, AeadKey, Nonce};
pub use kdf::{Hkdf, SessionKeys};
pub use keys::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
pub use random::SecureRandom;

/// Size of symmetric keys in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Size of AEAD nonce in bytes (96 bits for ChaCha20-Poly1305)
pub const NONCE_SIZE: usize = 12;

/// Size of AEAD authentication tag in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// Size of X25519 public keys in bytes
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of HMAC-SHA256 output used for auth tags
pub const AUTH_TAG_SIZE: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_key_exchange_and_encryption() {
        // Server generates static keypair (done once)
        let server_static = StaticSecret::random();
        let server_public = PublicKey::from(&server_static);

        // Client generates ephemeral keypair (per session)
        let client_ephemeral = EphemeralSecret::random();
        let client_public = PublicKey::from(&client_ephemeral);

        // Both sides compute shared secret
        let client_shared = client_ephemeral.diffie_hellman(&server_public);
        let server_shared = server_static.diffie_hellman(&client_public);

        // Shared secrets should match
        assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());

        // Derive session keys
        let client_keys = SessionKeys::derive(&client_shared, b"test_context");
        let server_keys = SessionKeys::derive(&server_shared, b"test_context");

        // Session keys should match
        assert_eq!(client_keys.client_key(), server_keys.client_key());
        assert_eq!(client_keys.server_key(), server_keys.server_key());

        // Test encryption/decryption
        let plaintext = b"Hello, secure world!";
        let aad = b"additional authenticated data";
        let nonce = Nonce::new(1);

        let client_aead = Aead::new(client_keys.client_key());
        let ciphertext = client_aead.encrypt(&nonce, plaintext, aad).unwrap();

        let server_aead = Aead::new(server_keys.client_key());
        let decrypted = server_aead.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
