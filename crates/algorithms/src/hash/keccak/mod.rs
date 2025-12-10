//! Keccak-256 hash function implementation (Ethereum compatible)
//!
//! This module implements the Keccak-256 hash function as used by Ethereum.
//! It differs from NIST SHA3-256 only in the padding rule (domain separator).
//!
//! - **SHA3-256**: `0x06` domain separator.
//! - **Keccak-256**: `0x01` domain separator.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use zeroize::Zeroize;

use crate::error::{validate, Result};
use crate::hash::{Hash, HashAlgorithm, HashFunction};
use crate::types::Digest;

use core::sync::atomic::{compiler_fence, Ordering};

use dcrypt_params::utils::hash::{KECCAK256_OUTPUT_SIZE, KECCAK256_BLOCK_SIZE};

const KECCAK_ROUNDS: usize = 24;
const KECCAK_STATE_SIZE: usize = 25; // 5 × 5 u64
const KECCAK256_RATE: usize = KECCAK256_BLOCK_SIZE;

/// Keccak round constants.
const RC: [u64; KECCAK_ROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for the ρ step.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// π-mapping indexes.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

// ────────────────────────── constant-time helpers ─────────────────────────

#[inline(always)]
fn get_byte_from_state(state: &[u64; KECCAK_STATE_SIZE], pos: usize) -> u8 {
    let word = pos / 8;
    let shift = (pos % 8) * 8;
    ((state[word] >> shift) & 0xFF) as u8
}

#[inline(always)]
fn xor_byte_in_state(state: &mut [u64; KECCAK_STATE_SIZE], pos: usize, val: u8) {
    let word = pos / 8;
    let shift = (pos % 8) * 8;
    let mask = (val as u64) << shift;

    let before = state[word];
    state[word] = before ^ mask;

    compiler_fence(Ordering::SeqCst);
}

// ──────────────────────── marker algorithm types ──────────────────────────

/// Marker type for **Keccak-256** (Ethereum compatible).
pub enum Keccak256Algorithm {}

impl HashAlgorithm for Keccak256Algorithm {
    const OUTPUT_SIZE: usize = KECCAK256_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = KECCAK256_RATE;
    const ALGORITHM_ID: &'static str = "Keccak-256";
}

// ───────────────────── engine structs (state + pointer) ───────────────────

/// Streaming **Keccak-256** engine.
#[derive(Clone, Zeroize)]
pub struct Keccak256 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
}

impl Keccak256 {
    #[inline(always)]
    fn init() -> Self {
        Self {
            state: [0u64; KECCAK_STATE_SIZE],
            pt: 0,
        }
    }
    #[inline(always)]
    fn rate() -> usize {
        KECCAK256_RATE
    }

    fn update_internal(&mut self, data: &[u8]) -> Result<()> {
        validate::parameter(
            self.pt.checked_add(data.len()).is_some(),
            "data_length",
            "Integer overflow",
        )?;
        let r = Self::rate();
        for &b in data {
            xor_byte_in_state(&mut self.state, self.pt, b);
            self.pt += 1;
            if self.pt == r {
                keccak_f1600(&mut self.state);
                self.pt = 0;
            }
        }
        Ok(())
    }

    fn finalize_internal(&mut self) -> Result<Hash> {
        let r = Self::rate();
        // Keccak padding: domain separator is 0x01
        xor_byte_in_state(&mut self.state, self.pt, 0x01);
        xor_byte_in_state(&mut self.state, r - 1, 0x80);
        keccak_f1600(&mut self.state);

        let mut out = vec![0u8; KECCAK256_OUTPUT_SIZE];
        for i in 0..KECCAK256_OUTPUT_SIZE {
            out[i] = get_byte_from_state(&self.state, i);
        }

        self.state = [0u64; KECCAK_STATE_SIZE];
        self.pt = 0;
        Ok(out)
    }
}

impl HashFunction for Keccak256 {
    type Algorithm = Keccak256Algorithm;
    type Output = Digest<KECCAK256_OUTPUT_SIZE>;

    fn new() -> Self {
        Self::init()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let h = self.finalize_internal()?;
        let mut d = [0u8; KECCAK256_OUTPUT_SIZE];
        d.copy_from_slice(&h);
        Ok(Digest::new(d))
    }

    #[inline(always)]
    fn output_size() -> usize {
        <Keccak256Algorithm as HashAlgorithm>::OUTPUT_SIZE
    }
    #[inline(always)]
    fn block_size() -> usize {
        <Keccak256Algorithm as HashAlgorithm>::BLOCK_SIZE
    }
    #[inline(always)]
    fn name() -> String {
        <Keccak256Algorithm as HashAlgorithm>::ALGORITHM_ID.to_string()
    }
}

// ───────────────────────────── permutation ────────────────────────────────

fn keccak_f1600(state: &mut [u64; KECCAK_STATE_SIZE]) {
    for &rc in RC.iter().take(KECCAK_ROUNDS) {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        // ρ + π
        let mut t = state[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = state[j];
            state[j] = t.rotate_left(RHO[i]);
            t = tmp;
        }
        // χ
        for y in 0..5 {
            let mut row = [0u64; 5];
            for x in 0..5 {
                row[x] = state[x + 5 * y];
            }
            for x in 0..5 {
                state[x + 5 * y] ^= (!row[(x + 1) % 5]) & row[(x + 2) % 5];
            }
        }
        // ι
        state[0] ^= rc;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        // Empty string hash
        let digest = Keccak256::digest(b"").unwrap();
        // Known vector for Keccak-256("")
        let expected = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
        assert_eq!(digest.to_hex(), expected);
    }

    #[test]
    fn test_keccak256_string() {
        // "Hello, world!"
        let digest = Keccak256::digest(b"Hello, world!").unwrap();
        // Note: Different from SHA3-256("Hello, world!")
        let expected = "b6e16d27ac5ab427a7f68900ac5559ce272dc6c37c82b3e052246c82244c50e4";
        assert_eq!(digest.to_hex(), expected);
    }
}