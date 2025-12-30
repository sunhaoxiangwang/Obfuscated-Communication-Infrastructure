//! X25519 key exchange primitives.
//!
//! Provides type-safe wrappers around X25519 operations with automatic
//! zeroization of secret material on drop.

use x25519_dalek::{
    EphemeralSecret as DalekEphemeral, PublicKey as DalekPublic,
    SharedSecret as DalekShared, StaticSecret as DalekStatic,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::PUBLIC_KEY_SIZE;

/// An ephemeral (single-use) X25519 secret key.
///
/// This key is generated fresh for each session and provides forward secrecy.
/// It is automatically zeroized when dropped.
pub struct EphemeralSecret(DalekEphemeral);

impl EphemeralSecret {
    /// Generate a new random ephemeral secret.
    pub fn random() -> Self {
        Self(DalekEphemeral::random_from_rng(rand::thread_rng()))
    }

    /// Perform X25519 Diffie-Hellman key agreement.
    pub fn diffie_hellman(self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(self.0.diffie_hellman(&their_public.0))
    }
}

impl From<&EphemeralSecret> for PublicKey {
    fn from(secret: &EphemeralSecret) -> Self {
        PublicKey(DalekPublic::from(&secret.0))
    }
}

/// A static (long-term) X25519 secret key.
///
/// Used by servers for persistent identity. Should be stored securely.
/// Automatically zeroized when dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct StaticSecret(DalekStatic);

impl StaticSecret {
    /// Generate a new random static secret.
    pub fn random() -> Self {
        Self(DalekStatic::random_from_rng(rand::thread_rng()))
    }

    /// Create from raw bytes.
    ///
    /// # Security
    ///
    /// The input bytes should come from a cryptographically secure source.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(DalekStatic::from(bytes))
    }

    /// Perform X25519 Diffie-Hellman key agreement.
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        SharedSecret(self.0.diffie_hellman(&their_public.0))
    }

    /// Export the secret key bytes.
    ///
    /// # Security
    ///
    /// Handle the returned bytes with care and zeroize when done.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<&StaticSecret> for PublicKey {
    fn from(secret: &StaticSecret) -> Self {
        PublicKey(DalekPublic::from(&secret.0))
    }
}

/// An X25519 public key.
///
/// Safe to share publicly. Used for key exchange.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(DalekPublic);

impl PublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_SIZE]) -> Self {
        Self(DalekPublic::from(bytes))
    }

    /// Get the raw bytes of this public key.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Convert to raw bytes.
    pub fn to_bytes(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0.to_bytes()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The result of an X25519 Diffie-Hellman key exchange.
///
/// Contains the shared secret that both parties computed.
/// Automatically zeroized when dropped.
pub struct SharedSecret(DalekShared);

impl SharedSecret {
    /// Get the raw shared secret bytes.
    ///
    /// # Security
    ///
    /// This should be fed into a KDF (like HKDF) before use as a key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        // DalekShared handles its own zeroization, but we ensure it here
        // by forcing the compiler to not optimize away the drop
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_key_exchange() {
        let alice_secret = EphemeralSecret::random();
        let alice_public = PublicKey::from(&alice_secret);

        let bob_secret = EphemeralSecret::random();
        let bob_public = PublicKey::from(&bob_secret);

        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_static_key_exchange() {
        let server_static = StaticSecret::random();
        let server_public = PublicKey::from(&server_static);

        let client_ephemeral = EphemeralSecret::random();
        let client_public = PublicKey::from(&client_ephemeral);

        let client_shared = client_ephemeral.diffie_hellman(&server_public);
        let server_shared = server_static.diffie_hellman(&client_public);

        assert_eq!(client_shared.as_bytes(), server_shared.as_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let secret = StaticSecret::random();
        let public = PublicKey::from(&secret);

        let bytes = public.to_bytes();
        let restored = PublicKey::from_bytes(bytes);

        assert_eq!(public, restored);
    }

    #[test]
    fn test_static_secret_serialization() {
        let secret1 = StaticSecret::random();
        let bytes = secret1.to_bytes();
        let secret2 = StaticSecret::from_bytes(bytes);

        let public1 = PublicKey::from(&secret1);
        let public2 = PublicKey::from(&secret2);

        assert_eq!(public1, public2);
    }
}
