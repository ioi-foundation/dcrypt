//! SHAKE extendable output functions
//!
//! This module implements the SHAKE family of extendable output functions (XOFs)
//! as specified in FIPS PUB 202.
//!
//! These are distinct from the SHAKE implementations in the hash module,
//! which provide fixed-output hash function interfaces. This module provides
//! the proper XOF interface for variable-length output generation.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop};

use super::ExtendableOutputFunction;
use crate::error::{validate, Error, Result};

// Import security types from dcrypt-core
use dcrypt_common::security::{barrier, EphemeralSecret, SecretBuffer, SecureZeroingType};

// SHAKE constants
const KECCAK_ROUNDS: usize = 24;
const KECCAK_STATE_SIZE: usize = 25; // 5x5 of 64-bit words

// SHAKE rates (in bytes): r = 1600 - 2*security_level
const SHAKE128_RATE: usize = 168; // 1600 - 2*128 = 1600 - 256 = 1344 bits = 168 bytes
const SHAKE256_RATE: usize = 136; // 1600 - 2*256 = 1600 - 512 = 1088 bits = 136 bytes

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

// Helper struct for secure Keccak state operations
#[derive(Clone)]
struct SecureKeccakState {
    state: SecretBuffer<200>, // 25 * 8 bytes
}

impl Zeroize for SecureKeccakState {
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

impl SecureKeccakState {
    fn new() -> Self {
        Self {
            state: SecretBuffer::zeroed(),
        }
    }

    fn from_u64_array(array: [u64; KECCAK_STATE_SIZE]) -> Self {
        let mut bytes = [0u8; 200];
        for (i, &word) in array.iter().enumerate() {
            let word_bytes = word.to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&word_bytes);
        }
        Self {
            state: SecretBuffer::new(bytes),
        }
    }

    fn to_u64_array(&self) -> [u64; KECCAK_STATE_SIZE] {
        let mut array = [0u64; KECCAK_STATE_SIZE];
        let bytes = self.state.as_ref();
        for (i, word) in array.iter_mut().enumerate() {
            let start = i * 8;
            *word = u64::from_le_bytes([
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
                bytes[start + 4],
                bytes[start + 5],
                bytes[start + 6],
                bytes[start + 7],
            ]);
        }
        array
    }

    fn apply_permutation(&mut self) {
        let mut state_array = self.to_u64_array();
        keccak_f1600(&mut state_array);
        *self = Self::from_u64_array(state_array);
    }
}

impl SecureZeroingType for SecureKeccakState {
    fn zeroed() -> Self {
        Self::new()
    }

    fn secure_clone(&self) -> Self {
        Self {
            state: self.state.secure_clone(),
        }
    }
}

/// SHAKE-128 extendable output function with secure memory handling
#[derive(Clone)]
pub struct ShakeXof128 {
    state: SecureKeccakState,
    buffer: SecretBuffer<SHAKE128_RATE>,
    buffer_idx: usize,
    is_finalized: bool,
    squeezing: bool,
}

impl Zeroize for ShakeXof128 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_idx.zeroize();
        self.is_finalized = false;
        self.squeezing = false;
    }
}

impl Drop for ShakeXof128 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ShakeXof128 {}

/// SHAKE-256 extendable output function with secure memory handling
#[derive(Clone)]
pub struct ShakeXof256 {
    state: SecureKeccakState,
    buffer: SecretBuffer<SHAKE256_RATE>,
    buffer_idx: usize,
    is_finalized: bool,
    squeezing: bool,
}

impl Zeroize for ShakeXof256 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.buffer.zeroize();
        self.buffer_idx.zeroize();
        self.is_finalized = false;
        self.squeezing = false;
    }
}

impl Drop for ShakeXof256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ShakeXof256 {}

// Helper functions for Keccak permutation

/// Performs a full Keccak-f[1600] permutation on the state
fn keccak_f1600(state: &mut [u64; KECCAK_STATE_SIZE]) {
    // Use EphemeralSecret for temporary arrays
    for (_round, &rc) in RC.iter().enumerate().take(KECCAK_ROUNDS) {
        // Theta step with secure temporary storage
        let mut c = EphemeralSecret::new([0u64; 5]);
        for x in 0..5 {
            c.as_mut()[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }

        let mut d = EphemeralSecret::new([0u64; 5]);
        for x in 0..5 {
            d.as_mut()[x] = c.as_ref()[(x + 4) % 5] ^ c.as_ref()[(x + 1) % 5].rotate_left(1);
        }

        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d.as_ref()[x];
            }
        }

        // Rho and Pi steps with secure temporary storage
        let mut b = EphemeralSecret::new([0u64; KECCAK_STATE_SIZE]);
        let mut x = 1;
        let mut y = 0;
        b.as_mut()[0] = state[0];

        for i in 0..24 {
            let idx = x + 5 * y;
            b.as_mut()[PI[i]] = state[idx].rotate_left(RHO[i]);
            let temp = y;
            y = (2 * x + 3 * y) % 5;
            x = temp;
        }

        // Chi step
        for y in 0..5 {
            for x in 0..5 {
                let idx = x + 5 * y;
                state[idx] = b.as_ref()[idx]
                    ^ ((!b.as_ref()[(x + 1) % 5 + 5 * y]) & b.as_ref()[(x + 2) % 5 + 5 * y]);
            }
        }

        // Iota step
        state[0] ^= rc;
    }

    // Insert memory barrier after permutation
    barrier::compiler_fence_seq_cst();
}

/// Absorbs data into the sponge state with secure handling
fn keccak_absorb(state: &mut SecureKeccakState, data: &[u8], rate: usize) {
    // Get state as u64 array for processing
    let mut state_array = state.to_u64_array();

    for (i, &byte) in data.iter().enumerate() {
        let pos = i % rate;
        let byte_idx = pos % 8;
        let word_idx = pos / 8;
        state_array[word_idx] ^= (byte as u64) << (8 * byte_idx);
    }

    if !data.is_empty() && data.len() % rate == 0 {
        keccak_f1600(&mut state_array);
    }

    // Update secure state
    *state = SecureKeccakState::from_u64_array(state_array);
}

impl ShakeXof128 {
    fn init() -> Self {
        ShakeXof128 {
            state: SecureKeccakState::new(),
            buffer: SecretBuffer::zeroed(),
            buffer_idx: 0,
            is_finalized: false,
            squeezing: false,
        }
    }
}

impl ExtendableOutputFunction for ShakeXof128 {
    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_finalized {
            return Err(Error::xof_finalized());
        }
        if self.squeezing {
            return Err(Error::xof_squeezing());
        }

        let mut idx = 0;
        if self.buffer_idx > 0 {
            let to_copy = (SHAKE128_RATE - self.buffer_idx).min(data.len());
            let buffer_slice =
                &mut self.buffer.as_mut()[self.buffer_idx..self.buffer_idx + to_copy];
            buffer_slice.copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx = to_copy;

            if self.buffer_idx == SHAKE128_RATE {
                keccak_absorb(&mut self.state, self.buffer.as_ref(), SHAKE128_RATE);
                self.buffer_idx = 0;
            }
        }

        let remaining = data.len() - idx;
        let full_blocks = remaining / SHAKE128_RATE;
        for i in 0..full_blocks {
            let start = idx + i * SHAKE128_RATE;
            let block = &data[start..start + SHAKE128_RATE];

            // Process directly without copying to buffer
            keccak_absorb(&mut self.state, block, SHAKE128_RATE);
        }
        idx += full_blocks * SHAKE128_RATE;

        if idx < data.len() {
            let rem = data.len() - idx;
            self.buffer.as_mut()[..rem].copy_from_slice(&data[idx..]);
            self.buffer_idx = rem;
        }

        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        if self.is_finalized {
            return Ok(());
        }

        // Use SecretBuffer for pad block
        let mut pad_block = SecretBuffer::<SHAKE128_RATE>::zeroed();
        pad_block.as_mut()[..self.buffer_idx]
            .copy_from_slice(&self.buffer.as_ref()[..self.buffer_idx]);
        pad_block.as_mut()[self.buffer_idx] ^= 0x1F;
        pad_block.as_mut()[SHAKE128_RATE - 1] ^= 0x80;

        keccak_absorb(&mut self.state, pad_block.as_ref(), SHAKE128_RATE);

        self.is_finalized = true;
        self.buffer_idx = 0;
        Ok(())
    }

    fn squeeze(&mut self, output: &mut [u8]) -> Result<()> {
        validate::parameter(
            !output.is_empty(),
            "output_length",
            "Output buffer must not be empty",
        )?;

        if !self.is_finalized {
            self.finalize()?;
        }
        self.squeezing = true;

        let mut offset = 0;
        let rate = SHAKE128_RATE;

        while offset < output.len() {
            if self.buffer_idx >= rate {
                self.state.apply_permutation();
                self.buffer_idx = 0;
            }

            if self.buffer_idx == 0 {
                // Extract state into buffer
                let state_array = self.state.to_u64_array();
                let buffer_mut = self.buffer.as_mut();

                for i in 0..(rate / 8) {
                    let lane = state_array[i];
                    for j in 0..8 {
                        if i * 8 + j < rate {
                            buffer_mut[i * 8 + j] = ((lane >> (8 * j)) & 0xFF) as u8;
                        }
                    }
                }
            }

            let available = rate - self.buffer_idx;
            let needed = output.len() - offset;
            let to_copy = available.min(needed);

            output[offset..offset + to_copy]
                .copy_from_slice(&self.buffer.as_ref()[self.buffer_idx..self.buffer_idx + to_copy]);

            offset += to_copy;
            self.buffer_idx += to_copy;
        }

        // Memory barrier after squeeze operation
        barrier::compiler_fence_seq_cst();
        Ok(())
    }

    fn squeeze_into_vec(&mut self, len: usize) -> Result<Vec<u8>> {
        validate::parameter(
            len > 0,
            "output_length",
            "Output length must be greater than 0",
        )?;

        let mut v = vec![0u8; len];
        self.squeeze(&mut v)?;
        Ok(v)
    }

    fn reset(&mut self) -> Result<()> {
        *self = Self::new();
        Ok(())
    }

    fn security_level() -> usize {
        128
    }
}

impl ShakeXof256 {
    fn init() -> Self {
        ShakeXof256 {
            state: SecureKeccakState::new(),
            buffer: SecretBuffer::zeroed(),
            buffer_idx: 0,
            is_finalized: false,
            squeezing: false,
        }
    }
}

impl ExtendableOutputFunction for ShakeXof256 {
    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_finalized {
            return Err(Error::xof_finalized());
        }
        if self.squeezing {
            return Err(Error::xof_squeezing());
        }

        let mut idx = 0;
        if self.buffer_idx > 0 {
            let to_copy = (SHAKE256_RATE - self.buffer_idx).min(data.len());
            let buffer_slice =
                &mut self.buffer.as_mut()[self.buffer_idx..self.buffer_idx + to_copy];
            buffer_slice.copy_from_slice(&data[..to_copy]);
            self.buffer_idx += to_copy;
            idx = to_copy;

            if self.buffer_idx == SHAKE256_RATE {
                keccak_absorb(&mut self.state, self.buffer.as_ref(), SHAKE256_RATE);
                self.buffer_idx = 0;
            }
        }

        let remaining = data.len() - idx;
        let full_blocks = remaining / SHAKE256_RATE;
        for i in 0..full_blocks {
            let start = idx + i * SHAKE256_RATE;
            let block = &data[start..start + SHAKE256_RATE];

            // Process directly without copying to buffer
            keccak_absorb(&mut self.state, block, SHAKE256_RATE);
        }
        idx += full_blocks * SHAKE256_RATE;

        if idx < data.len() {
            let rem = data.len() - idx;
            self.buffer.as_mut()[..rem].copy_from_slice(&data[idx..]);
            self.buffer_idx = rem;
        }

        Ok(())
    }

    fn finalize(&mut self) -> Result<()> {
        if self.is_finalized {
            return Ok(());
        }

        // Use SecretBuffer for pad block
        let mut pad_block = SecretBuffer::<SHAKE256_RATE>::zeroed();
        pad_block.as_mut()[..self.buffer_idx]
            .copy_from_slice(&self.buffer.as_ref()[..self.buffer_idx]);
        pad_block.as_mut()[self.buffer_idx] ^= 0x1F;
        pad_block.as_mut()[SHAKE256_RATE - 1] ^= 0x80;

        keccak_absorb(&mut self.state, pad_block.as_ref(), SHAKE256_RATE);

        self.is_finalized = true;
        self.buffer_idx = 0;
        Ok(())
    }

    fn squeeze(&mut self, output: &mut [u8]) -> Result<()> {
        validate::parameter(
            !output.is_empty(),
            "output_length",
            "Output buffer must not be empty",
        )?;

        if !self.is_finalized {
            self.finalize()?;
        }
        self.squeezing = true;

        let mut offset = 0;
        let rate = SHAKE256_RATE;

        while offset < output.len() {
            if self.buffer_idx >= rate {
                self.state.apply_permutation();
                self.buffer_idx = 0;
            }

            if self.buffer_idx == 0 {
                // Extract state into buffer
                let state_array = self.state.to_u64_array();
                let buffer_mut = self.buffer.as_mut();

                for i in 0..(rate / 8) {
                    let lane = state_array[i];
                    for j in 0..8 {
                        if i * 8 + j < rate {
                            buffer_mut[i * 8 + j] = ((lane >> (8 * j)) & 0xFF) as u8;
                        }
                    }
                }
            }

            let available = rate - self.buffer_idx;
            let needed = output.len() - offset;
            let to_copy = available.min(needed);

            output[offset..offset + to_copy]
                .copy_from_slice(&self.buffer.as_ref()[self.buffer_idx..self.buffer_idx + to_copy]);

            offset += to_copy;
            self.buffer_idx += to_copy;
        }

        // Memory barrier after squeeze operation
        barrier::compiler_fence_seq_cst();
        Ok(())
    }

    fn squeeze_into_vec(&mut self, len: usize) -> Result<Vec<u8>> {
        validate::parameter(
            len > 0,
            "output_length",
            "Output length must be greater than 0",
        )?;

        let mut v = vec![0u8; len];
        self.squeeze(&mut v)?;
        Ok(v)
    }

    fn reset(&mut self) -> Result<()> {
        *self = Self::new();
        Ok(())
    }

    fn security_level() -> usize {
        256
    }
}

#[cfg(test)]
mod tests;
