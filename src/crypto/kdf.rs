//! Key Derivation Functions.
//!
//! Uses HKDF (HMAC-based Key Derivation Function) with SHA-256
//! to derive multiple keys from a shared secret.

use hkdf::Hkdf as HkdfImpl;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{AeadKey, AUTH_TAG_SIZE, KEY_SIZE};
use crate::error::{Error, Result};

/// HKDF key derivation using SHA-256.
pub struct Hkdf {
    prk: HkdfImpl<Sha256>,
}

impl Hkdf {
    /// Create a new HKDF instance from input keying material.
    ///
    /// # Arguments
    ///
    /// * `salt` - Optional salt (recommended for better security)
    /// * `ikm` - Input keying material (e.g., shared secret from DH)
    pub fn new(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        Self {
            prk: HkdfImpl::new(salt, ikm),
        }
    }

    /// Expand the PRK to produce output keying material.
    ///
    /// # Arguments
    ///
    /// * `info` - Context and application-specific information
    /// * `len` - Desired output length
    pub fn expand(&self, info: &[u8], len: usize) -> Result<Vec<u8>> {
        let mut okm = vec![0u8; len];
        self.prk
            .expand(info, &mut okm)
            .map_err(|_| Error::crypto("HKDF expansion failed"))?;
        Ok(okm)
    }

    /// Expand to a fixed-size array.
    pub fn expand_fixed<const N: usize>(&self, info: &[u8]) -> Result<[u8; N]> {
        let mut okm = [0u8; N];
        self.prk
            .expand(info, &mut okm)
            .map_err(|_| Error::crypto("HKDF expansion failed"))?;
        Ok(okm)
    }

    /// Derive an AEAD key.
    pub fn derive_aead_key(&self, info: &[u8]) -> Result<AeadKey> {
        let key_bytes = self.expand_fixed::<KEY_SIZE>(info)?;
        Ok(AeadKey::from_bytes(key_bytes))
    }
}

/// Session keys derived from shared secret.
///
/// Contains separate keys for client-to-server and server-to-client directions.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    client_key: [u8; KEY_SIZE],
    server_key: [u8; KEY_SIZE],
    client_iv: [u8; 12],
    server_iv: [u8; 12],
}

impl SessionKeys {
    /// Derive session keys from a shared secret.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - The result of DH key exchange
    /// * `context` - Additional context (e.g., transcript hash)
    pub fn derive(
        shared_secret: &crate::crypto::SharedSecret,
        context: &[u8],
    ) -> Self {
        let hkdf = Hkdf::new(Some(b"SCF_v1"), shared_secret.as_bytes());

        // Derive keys for both directions
        let mut client_key = [0u8; KEY_SIZE];
        let mut server_key = [0u8; KEY_SIZE];
        let mut client_iv = [0u8; 12];
        let mut server_iv = [0u8; 12];

        // Build info strings with context
        let client_key_info = [b"client_key".as_slice(), context].concat();
        let server_key_info = [b"server_key".as_slice(), context].concat();
        let client_iv_info = [b"client_iv".as_slice(), context].concat();
        let server_iv_info = [b"server_iv".as_slice(), context].concat();

        // Expand each key (unwrap is safe because output lengths are valid)
        hkdf.prk.expand(&client_key_info, &mut client_key).unwrap();
        hkdf.prk.expand(&server_key_info, &mut server_key).unwrap();
        hkdf.prk.expand(&client_iv_info, &mut client_iv).unwrap();
        hkdf.prk.expand(&server_iv_info, &mut server_iv).unwrap();

        Self {
            client_key,
            server_key,
            client_iv,
            server_iv,
        }
    }

    /// Get the client-to-server encryption key.
    pub fn client_key(&self) -> AeadKey {
        AeadKey::from_bytes(self.client_key)
    }

    /// Get the server-to-client encryption key.
    pub fn server_key(&self) -> AeadKey {
        AeadKey::from_bytes(self.server_key)
    }

    /// Get the client-to-server IV (nonce prefix).
    pub fn client_iv(&self) -> &[u8; 12] {
        &self.client_iv
    }

    /// Get the server-to-client IV (nonce prefix).
    pub fn server_iv(&self) -> &[u8; 12] {
        &self.server_iv
    }
}

/// Compute HMAC-SHA256 authentication tag for REALITY protocol.
///
/// Returns the first 8 bytes of HMAC output.
pub fn compute_auth_tag(shared_secret: &[u8], client_random: &[u8]) -> [u8; AUTH_TAG_SIZE] {
    let mut mac = Hmac::<Sha256>::new_from_slice(shared_secret)
        .expect("HMAC can take key of any size");
    mac.update(client_random);
    let result = mac.finalize().into_bytes();

    let mut tag = [0u8; AUTH_TAG_SIZE];
    tag.copy_from_slice(&result[..AUTH_TAG_SIZE]);
    tag
}

/// Verify REALITY authentication tag.
pub fn verify_auth_tag(
    shared_secret: &[u8],
    client_random: &[u8],
    expected_tag: &[u8; AUTH_TAG_SIZE],
) -> bool {
    let computed = compute_auth_tag(shared_secret, client_random);
    // Constant-time comparison
    computed.iter().zip(expected_tag.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// XOR two byte arrays of equal length.
pub fn xor_bytes<const N: usize>(a: &[u8; N], b: &[u8; N]) -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = a[i] ^ b[i];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{EphemeralSecret, PublicKey, StaticSecret};

    #[test]
    fn test_hkdf_expand() {
        let ikm = [0x0bu8; 22];
        let salt = [0x00u8; 13];
        let info = [0xf0u8; 10];

        let hkdf = Hkdf::new(Some(&salt), &ikm);
        let okm = hkdf.expand(&info, 42).unwrap();

        assert_eq!(okm.len(), 42);
        // Output should be deterministic
        let okm2 = hkdf.expand(&info, 42).unwrap();
        assert_eq!(okm, okm2);
    }

    #[test]
    fn test_session_keys_derivation() {
        let server_static = StaticSecret::random();
        let server_public = PublicKey::from(&server_static);

        let client_ephemeral = EphemeralSecret::random();
        let client_public = PublicKey::from(&client_ephemeral);

        let client_shared = client_ephemeral.diffie_hellman(&server_public);
        let server_shared = server_static.diffie_hellman(&client_public);

        let client_keys = SessionKeys::derive(&client_shared, b"test_context");
        let server_keys = SessionKeys::derive(&server_shared, b"test_context");

        // Both sides should derive identical keys
        assert_eq!(client_keys.client_key, server_keys.client_key);
        assert_eq!(client_keys.server_key, server_keys.server_key);
        assert_eq!(client_keys.client_iv, server_keys.client_iv);
        assert_eq!(client_keys.server_iv, server_keys.server_iv);

        // Client and server keys should be different
        assert_ne!(client_keys.client_key, client_keys.server_key);
    }

    #[test]
    fn test_auth_tag() {
        let shared_secret = [0x42u8; 32];
        let client_random = [0x01u8; 32];

        let tag = compute_auth_tag(&shared_secret, &client_random);
        assert_eq!(tag.len(), AUTH_TAG_SIZE);

        assert!(verify_auth_tag(&shared_secret, &client_random, &tag));

        // Wrong secret should fail
        let wrong_secret = [0x43u8; 32];
        assert!(!verify_auth_tag(&wrong_secret, &client_random, &tag));

        // Wrong random should fail
        let wrong_random = [0x02u8; 32];
        assert!(!verify_auth_tag(&shared_secret, &wrong_random, &tag));
    }

    #[test]
    fn test_xor_bytes() {
        let a = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let b = [0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8];

        let result = xor_bytes(&a, &b);

        // XOR twice should give back original
        let restored = xor_bytes(&result, &b);
        assert_eq!(restored, a);
    }
}
