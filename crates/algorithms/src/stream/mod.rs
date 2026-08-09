//! Stream cipher implementations
//!
//! This module provides implementations of stream ciphers, which are symmetric
//! key ciphers that encrypt plaintext digits one at a time with a pseudorandom
//! keystream.
//!
//! # Available Stream Ciphers
//!
//! - ChaCha20: A high-speed stream cipher designed by Daniel J. Bernstein
//!
//! # Security Considerations
//!
//! Stream ciphers require unique nonces for each encryption operation with the
//! same key. Reusing a nonce with the same key completely breaks the security
//! of the cipher.

/// ChaCha family of stream cipher implementations
pub mod chacha;

// Re-export commonly used types
pub use chacha::chacha20::{ChaCha20, CHACHA20_BLOCK_SIZE, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE};

use crate::error::{Error, Result};

/// Common trait for stream cipher implementations
pub trait StreamCipher {
    /// The key size in bytes
    const KEY_SIZE: usize;

    /// The nonce size in bytes
    const NONCE_SIZE: usize;

    /// The internal block size in bytes (if applicable)
    const BLOCK_SIZE: usize;

    /// Process data in place (encrypts for encryption, decrypts for decryption)
    fn process(&mut self, data: &mut [u8]) -> Result<()>;

    /// Encrypt data in place
    fn encrypt(&mut self, data: &mut [u8]) -> Result<()> {
        self.process(data)
    }

    /// Decrypt data in place
    fn decrypt(&mut self, data: &mut [u8]) -> Result<()> {
        self.process(data)
    }

    /// Generate keystream directly into an output buffer
    fn keystream(&mut self, output: &mut [u8]) -> Result<()>;

    /// Reset the cipher to its initial state
    fn reset(&mut self) -> Result<()>;

    /// Seek to a specific position in the keystream (if supported)
    fn seek(&mut self, position: u64) -> Result<()>;
}

// Implement StreamCipher for ChaCha20
impl StreamCipher for ChaCha20 {
    const KEY_SIZE: usize = CHACHA20_KEY_SIZE;
    const NONCE_SIZE: usize = CHACHA20_NONCE_SIZE;
    const BLOCK_SIZE: usize = CHACHA20_BLOCK_SIZE;

    fn process(&mut self, data: &mut [u8]) -> Result<()> {
        ChaCha20::process(self, data)
    }

    fn keystream(&mut self, output: &mut [u8]) -> Result<()> {
        ChaCha20::keystream(self, output)
    }

    fn reset(&mut self) -> Result<()> {
        self.reset();
        Ok(())
    }

    fn seek(&mut self, position: u64) -> Result<()> {
        if position > u32::MAX as u64 {
            // Use the new Error::param helper
            return Err(Error::param(
                "position",
                "ChaCha20 seek position must fit in u32",
            ));
        }
        ChaCha20::seek(self, position as u32)
    }
}
