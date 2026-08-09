//! SHAKE hash functions with fixed output length
//!
//! This module implements the SHAKE family as standard fixed-output hash functions
//! as specified in FIPS PUB 202.
//!
//! For variable-length output, use the XOF implementations in the xof module.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop};

use crate::error::Result;
use crate::hash::{HashAlgorithm, HashFunction};
use crate::types::Digest;

/// Default output size for SHAKE128 (256 bits / 32 bytes)
pub const SHAKE128_OUTPUT_SIZE: usize = 32; // 256 bits

/// Default output size for SHAKE256 (512 bits / 64 bytes)
pub const SHAKE256_OUTPUT_SIZE: usize = 64; // 512 bits

// SHAKE rates (in bytes): r = 1600 - 2*security_level
const SHAKE128_RATE: usize = 168; // 1600 - 2*128 = 1344 bits = 168 bytes
const SHAKE256_RATE: usize = 136; // 1600 - 2*256 = 1088 bits = 136 bytes

// Keccak constants
const KECCAK_ROUNDS: usize = 24;
const KECCAK_STATE_SIZE: usize = 25; // 5x5 of 64-bit words

// Round constants for Keccak
const RC: [u64; KECCAK_ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// Rotation offsets
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

// Mapping from index positions to x,y coordinates in the state array
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// Marker type for SHAKE128 algorithm
pub enum Shake128Algorithm {}

/// Marker type for SHAKE256 algorithm
pub enum Shake256Algorithm {}

// Implement HashAlgorithm for each marker type
impl HashAlgorithm for Shake128Algorithm {
    const OUTPUT_SIZE: usize = SHAKE128_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHAKE128_RATE;
    const ALGORITHM_ID: &'static str = "SHAKE-128";
}

impl HashAlgorithm for Shake256Algorithm {
    const OUTPUT_SIZE: usize = SHAKE256_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHAKE256_RATE;
    const ALGORITHM_ID: &'static str = "SHAKE-256";
}

/// SHAKE-128 hash function with fixed output size (32 bytes)
#[derive(Clone)]
pub struct Shake128 {
    state: [u64; KECCAK_STATE_SIZE],
    buffer: [u8; SHAKE128_RATE],
    buffer_idx: usize,
}

/// SHAKE-256 hash function with fixed output size (64 bytes)
#[derive(Clone)]
pub struct Shake256 {
    state: [u64; KECCAK_STATE_SIZE],
    buffer: [u8; SHAKE256_RATE],
    buffer_idx: usize,
}

macro_rules! impl_shake_zeroize {
    ($name:ident) => {
        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.state.zeroize();
                self.buffer.zeroize();
                self.buffer_idx.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl ZeroizeOnDrop for $name {}
    };
}

impl_shake_zeroize!(Shake128);
impl_shake_zeroize!(Shake256);

// Helper function for the Keccak-f[1600] permutation
fn keccak_f1600(state: &mut [u64; KECCAK_STATE_SIZE]) {
    for &rc in RC.iter().take(KECCAK_ROUNDS) {
        // Theta step
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // Rho and Pi steps
        let mut b = [0u64; KECCAK_STATE_SIZE];
        let mut x = 1;
        let mut y = 0;
        b[0] = state[0];
        for i in 0..24 {
            let idx = x + 5 * y;
            b[PI[i]] = state[idx].rotate_left(RHO[i]);
            let temp = y;
            y = (2 * x + 3 * y) % 5;
            x = temp;
        }

        // Chi step
        for y in 0..5 {
            for x in 0..5 {
                let idx = x + 5 * y;
                state[idx] = b[idx] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // Iota step
        state[0] ^= rc;
    }
}

impl Shake128 {
    fn init() -> Self {
        Shake128 {
            state: [0u64; KECCAK_STATE_SIZE],
            buffer: [0u8; SHAKE128_RATE],
            buffer_idx: 0,
        }
    }

    fn update_internal(&mut self, data: &[u8]) -> Result<()> {
        let mut idx = 0;

        // Fill existing partial block
        if self.buffer_idx > 0 {
            let to_copy = (SHAKE128_RATE - self.buffer_idx).min(data.len());
            self.buffer[self.buffer_idx..self.buffer_idx + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx += to_copy;

            if self.buffer_idx == SHAKE128_RATE {
                // Absorb full block
                for (i, chunk) in self.buffer.chunks_exact(8).enumerate() {
                    let mut lane = 0u64;
                    for (j, &b) in chunk.iter().enumerate() {
                        lane |= (b as u64) << (8 * j);
                    }
                    self.state[i] ^= lane;
                }
                keccak_f1600(&mut self.state);
                self.buffer_idx = 0;
            }
        }

        // Process full blocks
        while idx + SHAKE128_RATE <= data.len() {
            let block = &data[idx..idx + SHAKE128_RATE];
            for (i, chunk) in block.chunks_exact(8).enumerate() {
                let mut lane = 0u64;
                for (j, &b) in chunk.iter().enumerate() {
                    lane |= (b as u64) << (8 * j);
                }
                self.state[i] ^= lane;
            }
            keccak_f1600(&mut self.state);
            idx += SHAKE128_RATE;
        }

        // Store remainder
        if idx < data.len() {
            let rem = data.len() - idx;
            self.buffer[..rem].copy_from_slice(&data[idx..]);
            self.buffer_idx = rem;
        }

        Ok(())
    }

    fn finalize_internal(&mut self) -> Result<Vec<u8>> {
        // Padding: SHAKE domain separator 0x1F, then pad with zeros and final 0x80
        let mut pad_block = [0u8; SHAKE128_RATE];
        pad_block[..self.buffer_idx].copy_from_slice(&self.buffer[..self.buffer_idx]);
        pad_block[self.buffer_idx] = 0x1F;
        pad_block[SHAKE128_RATE - 1] |= 0x80;

        // Absorb final block
        for (i, chunk) in pad_block.chunks_exact(8).enumerate() {
            let mut lane = 0u64;
            for (j, &b) in chunk.iter().enumerate() {
                lane |= (b as u64) << (8 * j);
            }
            self.state[i] ^= lane;
        }
        keccak_f1600(&mut self.state);

        // Squeeze output
        let mut result = vec![0u8; SHAKE128_OUTPUT_SIZE];
        let mut offset = 0;

        while offset < SHAKE128_OUTPUT_SIZE {
            let to_copy = (SHAKE128_OUTPUT_SIZE - offset).min(SHAKE128_RATE);

            // Extract bytes from state
            for i in 0..to_copy {
                let lane_idx = i / 8;
                let byte_idx = i % 8;
                result[offset + i] = ((self.state[lane_idx] >> (8 * byte_idx)) & 0xFF) as u8;
            }

            offset += to_copy;

            // Apply Keccak-f[1600] permutation if more output is needed
            if offset < SHAKE128_OUTPUT_SIZE {
                keccak_f1600(&mut self.state);
            }
        }

        Ok(result)
    }
}

impl Shake256 {
    fn init() -> Self {
        Shake256 {
            state: [0u64; KECCAK_STATE_SIZE],
            buffer: [0u8; SHAKE256_RATE],
            buffer_idx: 0,
        }
    }

    fn update_internal(&mut self, data: &[u8]) -> Result<()> {
        let mut idx = 0;

        // Fill existing partial block
        if self.buffer_idx > 0 {
            let to_copy = (SHAKE256_RATE - self.buffer_idx).min(data.len());
            self.buffer[self.buffer_idx..self.buffer_idx + to_copy]
                .copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx += to_copy;

            if self.buffer_idx == SHAKE256_RATE {
                // Absorb full block
                for (i, chunk) in self.buffer.chunks_exact(8).enumerate() {
                    let mut lane = 0u64;
                    for (j, &b) in chunk.iter().enumerate() {
                        lane |= (b as u64) << (8 * j);
                    }
                    self.state[i] ^= lane;
                }
                keccak_f1600(&mut self.state);
                self.buffer_idx = 0;
            }
        }

        // Process full blocks
        while idx + SHAKE256_RATE <= data.len() {
            let block = &data[idx..idx + SHAKE256_RATE];
            for (i, chunk) in block.chunks_exact(8).enumerate() {
                let mut lane = 0u64;
                for (j, &b) in chunk.iter().enumerate() {
                    lane |= (b as u64) << (8 * j);
                }
                self.state[i] ^= lane;
            }
            keccak_f1600(&mut self.state);
            idx += SHAKE256_RATE;
        }

        // Store remainder
        if idx < data.len() {
            let rem = data.len() - idx;
            self.buffer[..rem].copy_from_slice(&data[idx..]);
            self.buffer_idx = rem;
        }

        Ok(())
    }

    fn finalize_internal(&mut self) -> Result<Vec<u8>> {
        // Padding: SHAKE domain separator 0x1F, then pad with zeros and final 0x80
        let mut pad_block = [0u8; SHAKE256_RATE];
        pad_block[..self.buffer_idx].copy_from_slice(&self.buffer[..self.buffer_idx]);
        pad_block[self.buffer_idx] = 0x1F;
        pad_block[SHAKE256_RATE - 1] |= 0x80;

        // Absorb final block
        for (i, chunk) in pad_block.chunks_exact(8).enumerate() {
            let mut lane = 0u64;
            for (j, &b) in chunk.iter().enumerate() {
                lane |= (b as u64) << (8 * j);
            }
            self.state[i] ^= lane;
        }
        keccak_f1600(&mut self.state);

        // Squeeze output
        let mut result = vec![0u8; SHAKE256_OUTPUT_SIZE];
        let mut offset = 0;

        while offset < SHAKE256_OUTPUT_SIZE {
            let to_copy = (SHAKE256_OUTPUT_SIZE - offset).min(SHAKE256_RATE);

            // Extract bytes from state
            for i in 0..to_copy {
                let lane_idx = i / 8;
                let byte_idx = i % 8;
                result[offset + i] = ((self.state[lane_idx] >> (8 * byte_idx)) & 0xFF) as u8;
            }

            offset += to_copy;

            // Apply Keccak-f[1600] permutation if more output is needed
            if offset < SHAKE256_OUTPUT_SIZE {
                keccak_f1600(&mut self.state);
            }
        }

        Ok(result)
    }
}

// Implement HashFunction for SHAKE128
impl HashFunction for Shake128 {
    type Algorithm = Shake128Algorithm;
    type Output = Digest<SHAKE128_OUTPUT_SIZE>;

    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; SHAKE128_OUTPUT_SIZE];
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

// Implement HashFunction for SHAKE256
impl HashFunction for Shake256 {
    type Algorithm = Shake256Algorithm;
    type Output = Digest<SHAKE256_OUTPUT_SIZE>;

    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; SHAKE256_OUTPUT_SIZE];
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
