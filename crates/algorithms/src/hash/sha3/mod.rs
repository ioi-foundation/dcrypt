//! SHA-3 hash function implementations
//!
//! Constant-time & side-channel-hardened Keccak sponge (FIPS 202).

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{validate, Result};
use crate::hash::{HashAlgorithm, HashFunction};
use crate::types::Digest;

use core::sync::atomic::{compiler_fence, Ordering};

// ──────────────────────────────── constants ────────────────────────────────

use dcrypt_params::utils::hash::{
    SHA3_224_OUTPUT_SIZE, SHA3_256_OUTPUT_SIZE, SHA3_384_OUTPUT_SIZE, SHA3_512_OUTPUT_SIZE,
};

const KECCAK_ROUNDS: usize = 24;
const KECCAK_STATE_SIZE: usize = 25; // 5 × 5 u64
const SHA3_224_RATE: usize = 144; // 1152 bits
const SHA3_256_RATE: usize = 136; // 1088 bits
const SHA3_384_RATE: usize = 104; // 832 bits
const SHA3_512_RATE: usize = 72; // 576 bits

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
    // Perform an unconditionally-executed, explicit read-modify-write so
    // hashing an all-zero block still incurs the same memory traffic as
    // hashing random data (mitigates store-elimination optimisations).
    let word = pos / 8;
    let shift = (pos % 8) * 8;
    let mask = (val as u64) << shift;

    let before = state[word];
    state[word] = before ^ mask;

    // Prevent the compiler from hoisting or eliminating the store.
    compiler_fence(Ordering::SeqCst);
}

// ──────────────────────── marker algorithm types ──────────────────────────

/// Marker type for **SHA3-224**.
pub enum Sha3_224Algorithm {}
/// Marker type for **SHA3-256**.
pub enum Sha3_256Algorithm {}
/// Marker type for **SHA3-384**.
pub enum Sha3_384Algorithm {}
/// Marker type for **SHA3-512**.
pub enum Sha3_512Algorithm {}

impl HashAlgorithm for Sha3_224Algorithm {
    const OUTPUT_SIZE: usize = SHA3_224_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA3_224_RATE;
    const ALGORITHM_ID: &'static str = "SHA3-224";
}
impl HashAlgorithm for Sha3_256Algorithm {
    const OUTPUT_SIZE: usize = SHA3_256_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA3_256_RATE;
    const ALGORITHM_ID: &'static str = "SHA3-256";
}
impl HashAlgorithm for Sha3_384Algorithm {
    const OUTPUT_SIZE: usize = SHA3_384_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA3_384_RATE;
    const ALGORITHM_ID: &'static str = "SHA3-384";
}
impl HashAlgorithm for Sha3_512Algorithm {
    const OUTPUT_SIZE: usize = SHA3_512_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA3_512_RATE;
    const ALGORITHM_ID: &'static str = "SHA3-512";
}

// ───────────────────── engine structs (state + pointer) ───────────────────

/// Streaming **SHA3-224** engine.
#[derive(Clone)]
pub struct Sha3_224 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
}

/// Streaming **SHA3-256** engine.
#[derive(Clone)]
pub struct Sha3_256 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
}

/// Streaming **SHA3-384** engine.
#[derive(Clone)]
pub struct Sha3_384 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
}

/// Streaming **SHA3-512** engine.
#[derive(Clone)]
pub struct Sha3_512 {
    state: [u64; KECCAK_STATE_SIZE],
    pt: usize,
}

macro_rules! impl_sha3_zeroize {
    ($name:ident) => {
        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.state.zeroize();
                self.pt.zeroize();
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

impl_sha3_zeroize!(Sha3_224);
impl_sha3_zeroize!(Sha3_256);
impl_sha3_zeroize!(Sha3_384);
impl_sha3_zeroize!(Sha3_512);

// ─────────────────────── shared engine-helper macro ───────────────────────

macro_rules! impl_sha3_variant {
    ($name:ident, $rate:expr, $out:expr, $alg:ty) => {
        impl $name {
            #[inline(always)]
            fn init() -> Self {
                Self {
                    state: [0u64; KECCAK_STATE_SIZE],
                    pt: 0,
                }
            }
            #[inline(always)]
            fn rate() -> usize {
                $rate
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

            fn finalize_internal(&mut self) -> Result<Zeroizing<[u8; $out]>> {
                let r = Self::rate();
                xor_byte_in_state(&mut self.state, self.pt, 0x06);
                xor_byte_in_state(&mut self.state, r - 1, 0x80);
                keccak_f1600(&mut self.state);

                let mut out = Zeroizing::new([0u8; $out]);
                for i in 0..$out {
                    out[i] = get_byte_from_state(&self.state, i);
                }

                self.zeroize();
                Ok(out)
            }
        }

        impl HashFunction for $name {
            type Algorithm = $alg;
            type Output = Digest<$out>;

            fn new() -> Self {
                Self::init()
            }

            fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
                self.update_internal(data)?;
                Ok(self)
            }

            fn finalize(&mut self) -> Result<Self::Output> {
                let h = self.finalize_internal()?;
                let mut digest = Digest::<$out>::zeroed();
                digest.as_mut().copy_from_slice(&h[..]);
                Ok(digest)
            }

            #[inline(always)]
            fn output_size() -> usize {
                <$alg as HashAlgorithm>::OUTPUT_SIZE
            }
            #[inline(always)]
            fn block_size() -> usize {
                <$alg as HashAlgorithm>::BLOCK_SIZE
            }
            #[inline(always)]
            fn name() -> String {
                <$alg as HashAlgorithm>::ALGORITHM_ID.to_string()
            }
        }
    };
}

impl_sha3_variant!(
    Sha3_224,
    SHA3_224_RATE,
    SHA3_224_OUTPUT_SIZE,
    Sha3_224Algorithm
);
impl_sha3_variant!(
    Sha3_256,
    SHA3_256_RATE,
    SHA3_256_OUTPUT_SIZE,
    Sha3_256Algorithm
);
impl_sha3_variant!(
    Sha3_384,
    SHA3_384_RATE,
    SHA3_384_OUTPUT_SIZE,
    Sha3_384Algorithm
);
impl_sha3_variant!(
    Sha3_512,
    SHA3_512_RATE,
    SHA3_512_OUTPUT_SIZE,
    Sha3_512Algorithm
);

// ───────────────────────────── permutation ────────────────────────────────

fn keccak_f1600(state: &mut [u64; KECCAK_STATE_SIZE]) {
    for &rc in RC.iter().take(KECCAK_ROUNDS) {
        // θ
        let mut c = Zeroizing::new([0u64; 5]);
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let mut d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
            d.zeroize();
        }
        // ρ + π
        let mut t = state[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = state[j];
            state[j] = t.rotate_left(RHO[i]);
            t = tmp;
        }
        t.zeroize();
        // χ
        for y in 0..5 {
            let mut row = Zeroizing::new([0u64; 5]);
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
mod tests;
