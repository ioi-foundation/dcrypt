//! SHA-1 hash function
//!
//! This module implements the SHA-1 hash function as specified in FIPS 180-4.
//! Note: SHA-1 is considered cryptographically broken and should only be used
//! for compatibility with existing systems.

use crate::error::{Error, Result};
use crate::hash::{Hash, HashAlgorithm, HashFunction};
use crate::types::Digest;
use dcrypt_internal::zeroing::Zeroize;

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

const SHA1_BLOCK_SIZE: usize = 64;
const SHA1_OUTPUT_SIZE: usize = 20;

/// Initial hash values for SHA-1
const H0: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// SHA-1 algorithm marker type
pub enum Sha1Algorithm {}

impl HashAlgorithm for Sha1Algorithm {
    const OUTPUT_SIZE: usize = SHA1_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA1_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "SHA-1";
}

/// SHA-1 hash function
#[derive(Clone)]
pub struct Sha1 {
    /// Current hash state
    h: [u32; 5],
    /// Message buffer
    buffer: [u8; SHA1_BLOCK_SIZE],
    /// Bytes in buffer
    buffer_len: usize,
    /// Total message length in bits
    total_len: u64,
}

impl Zeroize for Sha1 {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.buffer.zeroize();
        self.buffer_len.zeroize();
        self.total_len.zeroize();
    }
}

impl Sha1 {
    /// Creates a new SHA-1 hasher
    pub fn new() -> Self {
        Self {
            h: H0,
            buffer: [0u8; SHA1_BLOCK_SIZE],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Process a single block
    fn process_block(&mut self, block: &[u8; SHA1_BLOCK_SIZE]) {
        let mut w = [0u32; 80];
        // Prepare the message schedule
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().expect("four bytes"));
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        // Main loop
        for (i, &word) in w.iter().enumerate().take(80) {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A827999)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        // Update state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    /// Internal update implementation
    fn update_internal(&mut self, data: &[u8]) -> Result<()> {
        let mut data_idx = 0;

        // Check for overflow in total_len calculation
        let new_bits = (data.len() as u64).wrapping_mul(8);
        self.total_len = self
            .total_len
            .checked_add(new_bits)
            .ok_or(Error::Processing {
                operation: "SHA-1",
                details: "Message length overflow",
            })?;

        if self.buffer_len > 0 {
            let copy_len = core::cmp::min(SHA1_BLOCK_SIZE - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + copy_len]
                .copy_from_slice(&data[..copy_len]);
            self.buffer_len += copy_len;
            data_idx += copy_len;

            if self.buffer_len == SHA1_BLOCK_SIZE {
                let mut block = [0u8; SHA1_BLOCK_SIZE];
                block.copy_from_slice(&self.buffer);
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        while data_idx + SHA1_BLOCK_SIZE <= data.len() {
            let mut block = [0u8; SHA1_BLOCK_SIZE];
            block.copy_from_slice(&data[data_idx..data_idx + SHA1_BLOCK_SIZE]);
            self.process_block(&block);
            data_idx += SHA1_BLOCK_SIZE;
        }

        if data_idx < data.len() {
            let remaining = data.len() - data_idx;
            self.buffer[..remaining].copy_from_slice(&data[data_idx..]);
            self.buffer_len = remaining;
        }

        Ok(())
    }

    /// Internal finalize implementation
    fn finalize_internal(&mut self) -> Result<Hash> {
        // Padding
        let mut buffer = [0u8; SHA1_BLOCK_SIZE];
        let mut buffer_idx = self.buffer_len;

        buffer[..self.buffer_len].copy_from_slice(&self.buffer[..self.buffer_len]);
        buffer[buffer_idx] = 0x80;
        buffer_idx += 1;

        if buffer_idx > SHA1_BLOCK_SIZE - 8 {
            for byte in &mut buffer[buffer_idx..] {
                *byte = 0;
            }
            self.process_block(&buffer);
            buffer_idx = 0;
        }

        for byte in &mut buffer[buffer_idx..SHA1_BLOCK_SIZE - 8] {
            *byte = 0;
        }

        buffer[SHA1_BLOCK_SIZE - 8..].copy_from_slice(&self.total_len.to_be_bytes());
        self.process_block(&buffer);

        let mut result = Vec::with_capacity(SHA1_OUTPUT_SIZE);
        for &word in &self.h {
            result.extend_from_slice(&word.to_be_bytes());
        }
        Ok(result)
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl HashFunction for Sha1 {
    type Algorithm = Sha1Algorithm;
    type Output = Digest<SHA1_OUTPUT_SIZE>;

    fn new() -> Self {
        Sha1::new()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; SHA1_OUTPUT_SIZE];
        digest.copy_from_slice(&hash);
        Ok(Digest::new(digest))
    }

    fn output_size() -> usize {
        Self::Algorithm::OUTPUT_SIZE
    }

    fn block_size() -> usize {
        Self::Algorithm::BLOCK_SIZE
    }

    fn name() -> String {
        Self::Algorithm::ALGORITHM_ID.to_string()
    }
}

#[cfg(test)]
mod tests;
