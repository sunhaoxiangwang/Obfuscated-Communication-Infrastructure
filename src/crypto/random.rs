//! Secure random number generation.
//!
//! Provides cryptographically secure random bytes using the operating
//! system's entropy source.

use rand::{CryptoRng, RngCore};
use rand_core::OsRng;

/// Cryptographically secure random number generator.
///
/// Wraps the OS-provided entropy source (e.g., /dev/urandom on Unix,
/// BCryptGenRandom on Windows).
pub struct SecureRandom;

impl SecureRandom {
    /// Fill a buffer with cryptographically secure random bytes.
    pub fn fill(dest: &mut [u8]) {
        OsRng.fill_bytes(dest);
    }

    /// Generate a fixed-size array of random bytes.
    pub fn bytes<const N: usize>() -> [u8; N] {
        let mut buf = [0u8; N];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    /// Generate a random u64.
    pub fn u64() -> u64 {
        OsRng.next_u64()
    }

    /// Generate a random u32.
    pub fn u32() -> u32 {
        OsRng.next_u32()
    }

    /// Get an RNG instance that implements CryptoRng.
    pub fn rng() -> impl RngCore + CryptoRng {
        OsRng
    }
}

/// Generate random padding of the specified length.
///
/// The padding is filled with random bytes to make traffic analysis harder.
pub fn random_padding(len: usize) -> Vec<u8> {
    let mut padding = vec![0u8; len];
    SecureRandom::fill(&mut padding);
    padding
}

/// Generate a random delay in microseconds within a range.
///
/// Useful for timing obfuscation.
pub fn random_delay_us(min_us: u64, max_us: u64) -> u64 {
    if min_us >= max_us {
        return min_us;
    }
    let range = max_us - min_us;
    min_us + (SecureRandom::u64() % range)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_secure_random_fill() {
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];

        SecureRandom::fill(&mut buf1);
        SecureRandom::fill(&mut buf2);

        // Should not produce all zeros
        assert!(!buf1.iter().all(|&b| b == 0));
        assert!(!buf2.iter().all(|&b| b == 0));

        // Should produce different values each time
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_secure_random_bytes() {
        let bytes1: [u8; 16] = SecureRandom::bytes();
        let bytes2: [u8; 16] = SecureRandom::bytes();

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_random_padding() {
        let padding = random_padding(100);
        assert_eq!(padding.len(), 100);

        // Should not be all zeros (extremely unlikely with real randomness)
        assert!(!padding.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_random_delay() {
        let min = 100;
        let max = 1000;

        // Generate multiple delays and check distribution
        let mut delays: HashSet<u64> = HashSet::new();
        for _ in 0..100 {
            let delay = random_delay_us(min, max);
            assert!(delay >= min && delay < max);
            delays.insert(delay);
        }

        // Should have some variety (not all same value)
        assert!(delays.len() > 1);
    }

    #[test]
    fn test_random_delay_edge_case() {
        // When min >= max, should return min
        let delay = random_delay_us(100, 100);
        assert_eq!(delay, 100);

        let delay = random_delay_us(200, 100);
        assert_eq!(delay, 200);
    }
}
