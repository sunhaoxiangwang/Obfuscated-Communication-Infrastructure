//! Authenticated Encryption with Associated Data (AEAD).
//!
//! Uses ChaCha20-Poly1305 for symmetric encryption with authentication.
//! This cipher is:
//! - Fast in software (no hardware AES required)
//! - Constant-time (resistant to timing attacks)
//! - Widely deployed (TLS 1.3, WireGuard, etc.)

use chacha20poly1305::{
    aead::{Aead as AeadTrait, KeyInit, Payload},
    ChaCha20Poly1305,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use crate::error::{Error, Result};

/// A symmetric key for AEAD operations.
///
/// Automatically zeroized when dropped.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; KEY_SIZE]);

impl AeadKey {
    /// Create a new AEAD key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw key bytes.
    ///
    /// # Security
    ///
    /// Handle with care - this is secret key material.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl AsRef<[u8]> for AeadKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A nonce (number used once) for AEAD operations.
///
/// Must be unique for each encryption with the same key.
/// We use a counter-based nonce to ensure uniqueness.
#[derive(Clone, Copy, Debug)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Create a nonce from a 64-bit counter value.
    ///
    /// The counter is placed in the last 8 bytes (little-endian).
    /// First 4 bytes are zero (can be used for additional context).
    pub fn new(counter: u64) -> Self {
        let mut nonce = [0u8; NONCE_SIZE];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        Self(nonce)
    }

    /// Create a nonce from raw bytes.
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }

    /// Get the current counter value (for diagnostics).
    pub fn counter(&self) -> u64 {
        u64::from_le_bytes(self.0[4..12].try_into().unwrap())
    }

    /// Increment the counter portion of the nonce.
    pub fn increment(&mut self) {
        let counter = u64::from_le_bytes(self.0[4..12].try_into().unwrap());
        self.0[4..12].copy_from_slice(&counter.wrapping_add(1).to_le_bytes());
    }
}

impl From<u64> for Nonce {
    fn from(counter: u64) -> Self {
        Self::new(counter)
    }
}

/// ChaCha20-Poly1305 AEAD cipher.
pub struct Aead {
    cipher: ChaCha20Poly1305,
}

impl Aead {
    /// Create a new AEAD instance with the given key.
    pub fn new(key: &AeadKey) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.as_bytes().into()),
        }
    }

    /// Encrypt plaintext with associated authenticated data.
    ///
    /// Returns ciphertext || tag (16 bytes appended).
    ///
    /// # Arguments
    ///
    /// * `nonce` - Must be unique for this key
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Additional data to authenticate (but not encrypt)
    pub fn encrypt(&self, nonce: &Nonce, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        self.cipher
            .encrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| Error::crypto("encryption failed"))
    }

    /// Decrypt ciphertext with associated authenticated data.
    ///
    /// # Arguments
    ///
    /// * `nonce` - Must match the nonce used for encryption
    /// * `ciphertext` - Encrypted data with appended tag
    /// * `aad` - Must match the AAD used for encryption
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails (wrong key, tampered data, etc.)
    pub fn decrypt(&self, nonce: &Nonce, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < TAG_SIZE {
            return Err(Error::Buffer {
                expected: TAG_SIZE,
                actual: ciphertext.len(),
            });
        }

        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce.as_bytes().into(), payload)
            .map_err(|_| Error::crypto("decryption/authentication failed"))
    }

    /// Encrypt in-place to avoid allocation.
    ///
    /// The buffer must have TAG_SIZE bytes of extra capacity.
    pub fn encrypt_in_place(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        use chacha20poly1305::aead::AeadInPlace;

        self.cipher
            .encrypt_in_place(nonce.as_bytes().into(), aad, buffer)
            .map_err(|_| Error::crypto("in-place encryption failed"))
    }

    /// Decrypt in-place to avoid allocation.
    pub fn decrypt_in_place(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<()> {
        use chacha20poly1305::aead::AeadInPlace;

        if buffer.len() < TAG_SIZE {
            return Err(Error::Buffer {
                expected: TAG_SIZE,
                actual: buffer.len(),
            });
        }

        self.cipher
            .decrypt_in_place(nonce.as_bytes().into(), aad, buffer)
            .map_err(|_| Error::crypto("in-place decryption/authentication failed"))
    }
}

/// Calculate the ciphertext length for a given plaintext length.
pub const fn ciphertext_len(plaintext_len: usize) -> usize {
    plaintext_len + TAG_SIZE
}

/// Calculate the maximum plaintext length for a given ciphertext length.
pub const fn plaintext_len(ciphertext_len: usize) -> usize {
    ciphertext_len.saturating_sub(TAG_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> AeadKey {
        AeadKey::from_bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ])
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = test_key();
        let aead = Aead::new(&key);
        let nonce = Nonce::new(1);

        let plaintext = b"Hello, World!";
        let aad = b"context";

        let ciphertext = aead.encrypt(&nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = aead.decrypt(&nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let key2 = AeadKey::from_bytes([0x42u8; KEY_SIZE]);

        let aead1 = Aead::new(&key1);
        let aead2 = Aead::new(&key2);
        let nonce = Nonce::new(1);

        let plaintext = b"secret data";
        let aad = b"";

        let ciphertext = aead1.encrypt(&nonce, plaintext, aad).unwrap();
        let result = aead2.decrypt(&nonce, &ciphertext, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = test_key();
        let aead = Aead::new(&key);
        let nonce = Nonce::new(1);

        let plaintext = b"secret data";
        let aad1 = b"context1";
        let aad2 = b"context2";

        let ciphertext = aead.encrypt(&nonce, plaintext, aad1).unwrap();
        let result = aead.decrypt(&nonce, &ciphertext, aad2);

        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let aead = Aead::new(&key);
        let nonce = Nonce::new(1);

        let plaintext = b"secret data";
        let aad = b"";

        let mut ciphertext = aead.encrypt(&nonce, plaintext, aad).unwrap();
        ciphertext[0] ^= 0x01; // Flip one bit

        let result = aead.decrypt(&nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = Nonce::new(0);
        assert_eq!(nonce.as_bytes()[4..12], [0u8; 8]);

        nonce.increment();
        let counter = u64::from_le_bytes(nonce.as_bytes()[4..12].try_into().unwrap());
        assert_eq!(counter, 1);

        nonce.increment();
        let counter = u64::from_le_bytes(nonce.as_bytes()[4..12].try_into().unwrap());
        assert_eq!(counter, 2);
    }

    #[test]
    fn test_encrypt_decrypt_in_place() {
        let key = test_key();
        let aead = Aead::new(&key);
        let nonce = Nonce::new(1);

        let plaintext = b"Hello, World!";
        let aad = b"context";

        let mut buffer = plaintext.to_vec();
        aead.encrypt_in_place(&nonce, aad, &mut buffer).unwrap();
        assert_eq!(buffer.len(), plaintext.len() + TAG_SIZE);

        aead.decrypt_in_place(&nonce, aad, &mut buffer).unwrap();
        assert_eq!(buffer, plaintext);
    }

    #[test]
    fn test_ciphertext_length() {
        assert_eq!(ciphertext_len(0), TAG_SIZE);
        assert_eq!(ciphertext_len(100), 100 + TAG_SIZE);
        assert_eq!(plaintext_len(TAG_SIZE), 0);
        assert_eq!(plaintext_len(100 + TAG_SIZE), 100);
    }
}
