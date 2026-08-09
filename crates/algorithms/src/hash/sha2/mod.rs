//! SHA-2 hash function implementations with enhanced memory safety
//!
//! This module implements the SHA-2 family of hash functions as specified in
//! FIPS PUB 180-4 with additional security measures for memory handling.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use crate::error::{validate, Result};
use crate::hash::{HashAlgorithm, HashFunction};
use crate::types::Digest;
use dcrypt_internal::zeroing::{Zeroize, Zeroizing};

// Import security types from dcrypt-core
use core::sync::atomic::{compiler_fence, Ordering};
use dcrypt_common::security::{EphemeralSecret, SecureZeroingType, ZeroizeGuard};

use dcrypt_params::utils::hash::{
    SHA224_OUTPUT_SIZE, SHA256_BLOCK_SIZE, SHA256_OUTPUT_SIZE, SHA384_OUTPUT_SIZE,
    SHA512_BLOCK_SIZE, SHA512_OUTPUT_SIZE,
};

// SHA-256 round constants
const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// SHA-512 round constants
const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

// Define algorithm marker types for each hash function
/// Marker type for SHA-256 algorithm
pub enum Sha256Algorithm {}

impl HashAlgorithm for Sha256Algorithm {
    const OUTPUT_SIZE: usize = SHA256_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA256_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "SHA-256";
}

/// Marker type for SHA-224 algorithm
pub enum Sha224Algorithm {}

impl HashAlgorithm for Sha224Algorithm {
    const OUTPUT_SIZE: usize = SHA224_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA256_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "SHA-224";
}

/// Marker type for SHA-384 algorithm
pub enum Sha384Algorithm {}

impl HashAlgorithm for Sha384Algorithm {
    const OUTPUT_SIZE: usize = SHA384_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA512_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "SHA-384";
}

/// Marker type for SHA-512 algorithm
pub enum Sha512Algorithm {}

impl HashAlgorithm for Sha512Algorithm {
    const OUTPUT_SIZE: usize = SHA512_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA512_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "SHA-512";
}

/// Marker type for SHA-512/224 algorithm
pub enum Sha512_224Algorithm {}

impl HashAlgorithm for Sha512_224Algorithm {
    const OUTPUT_SIZE: usize = SHA224_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA512_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "SHA-512/224";
}

/// Marker type for SHA-512/256 algorithm
pub enum Sha512_256Algorithm {}

impl HashAlgorithm for Sha512_256Algorithm {
    const OUTPUT_SIZE: usize = SHA256_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = SHA512_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "SHA-512/256";
}

/// SHA-224 hash function state with enhanced memory safety
#[derive(Clone)]
pub struct Sha224 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u64,
}

impl Drop for Sha224 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// SHA-256 hash function state with enhanced memory safety
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; SHA256_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u64,
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// SHA-384 hash function state with enhanced memory safety
#[derive(Clone)]
pub struct Sha384 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u128, // bits counter
}

impl Drop for Sha384 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// SHA-512 hash function state with enhanced memory safety
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u128,
}

impl Drop for Sha512 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// SHA-512/224 hash function state with enhanced memory safety
#[derive(Clone)]
pub struct Sha512_224 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u128,
}

impl Drop for Sha512_224 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// SHA-512/256 hash function state with enhanced memory safety
#[derive(Clone)]
pub struct Sha512_256 {
    state: [u64; 8],
    buffer: [u8; SHA512_BLOCK_SIZE],
    buffer_idx: usize,
    total_bytes: u128,
}

macro_rules! impl_sha2_zeroize {
    ($name:ident) => {
        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.state.zeroize();
                self.buffer.zeroize();
                self.buffer_idx.zeroize();
                self.total_bytes.zeroize();
            }
        }
    };
}

impl_sha2_zeroize!(Sha224);
impl_sha2_zeroize!(Sha256);
impl_sha2_zeroize!(Sha384);
impl_sha2_zeroize!(Sha512);
impl_sha2_zeroize!(Sha512_224);
impl_sha2_zeroize!(Sha512_256);

impl Drop for Sha512_256 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// --- SHA-256 internal methods with enhanced security ---
impl Sha256 {
    fn init_state() -> [u32; 8] {
        [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ]
    }

    fn new() -> Self {
        Sha256 {
            state: Self::init_state(),
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }

    fn compress(state: &mut [u32; 8], block: &[u8; SHA256_BLOCK_SIZE]) -> Result<()> {
        // Use EphemeralSecret for message schedule
        let mut w = EphemeralSecret::new([0u32; 64]);

        // Memory barrier before processing
        compiler_fence(Ordering::SeqCst);

        for i in 0..16 {
            let start = i * 4;
            validate::max_length("SHA-256 block read", start + 4, SHA256_BLOCK_SIZE)?;
            w[i] = (u32::from(block[start]) << 24)
                | (u32::from(block[start + 1]) << 16)
                | (u32::from(block[start + 2]) << 8)
                | u32::from(block[start + 3]);
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Use ZeroizeGuard for working variables
        let mut working_vars = [
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        ];
        let mut guard = ZeroizeGuard::new(&mut working_vars);

        // Use temporary variables instead of multiple mutable references
        let mut a = guard[0];
        let mut b = guard[1];
        let mut c = guard[2];
        let mut d = guard[3];
        let mut e = guard[4];
        let mut f = guard[5];
        let mut g = guard[6];
        let mut h = guard[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Write back the results
        guard[0] = a;
        guard[1] = b;
        guard[2] = c;
        guard[3] = d;
        guard[4] = e;
        guard[5] = f;
        guard[6] = g;
        guard[7] = h;

        // Update state
        state[0] = state[0].wrapping_add(guard[0]);
        state[1] = state[1].wrapping_add(guard[1]);
        state[2] = state[2].wrapping_add(guard[2]);
        state[3] = state[3].wrapping_add(guard[3]);
        state[4] = state[4].wrapping_add(guard[4]);
        state[5] = state[5].wrapping_add(guard[5]);
        state[6] = state[6].wrapping_add(guard[6]);
        state[7] = state[7].wrapping_add(guard[7]);

        a.zeroize();
        b.zeroize();
        c.zeroize();
        d.zeroize();
        e.zeroize();
        f.zeroize();
        g.zeroize();
        h.zeroize();

        // Memory barrier after processing
        compiler_fence(Ordering::SeqCst);

        Ok(())
    }

    fn update_internal(&mut self, mut input: &[u8]) -> Result<()> {
        while !input.is_empty() {
            let fill = core::cmp::min(input.len(), SHA256_BLOCK_SIZE - self.buffer_idx);
            self.buffer[self.buffer_idx..self.buffer_idx + fill].copy_from_slice(&input[..fill]);
            self.buffer_idx += fill;
            input = &input[fill..];
            if self.buffer_idx == SHA256_BLOCK_SIZE {
                let mut block = Zeroizing::new([0u8; SHA256_BLOCK_SIZE]);
                block.copy_from_slice(&self.buffer);
                Self::compress(&mut self.state, &block)?;
                self.total_bytes += SHA256_BLOCK_SIZE as u64;
                self.buffer.zeroize();
                self.buffer_idx = 0;
            }
        }
        Ok(())
    }

    fn finalize_internal(&mut self) -> Result<Zeroizing<[u8; SHA256_OUTPUT_SIZE]>> {
        self.total_bytes += self.buffer_idx as u64;
        let bit_len = self.total_bytes * 8;

        // Use ZeroizeGuard for sensitive padding operations
        let pad_buffer = EphemeralSecret::new([0u8; SHA256_BLOCK_SIZE]);

        // padding
        self.buffer[self.buffer_idx] = 0x80;
        if self.buffer_idx >= 56 {
            for b in &mut self.buffer[self.buffer_idx + 1..] {
                *b = 0;
            }
            let mut block = Zeroizing::new([0u8; SHA256_BLOCK_SIZE]);
            block.copy_from_slice(&self.buffer);
            Self::compress(&mut self.state, &block)?;
            self.buffer = *pad_buffer;
        } else {
            for b in &mut self.buffer[self.buffer_idx + 1..56] {
                *b = 0;
            }
        }

        for (index, byte) in self.buffer[56..].iter_mut().enumerate() {
            *byte = (bit_len >> (56 - 8 * index)) as u8;
        }
        let mut block = Zeroizing::new([0u8; SHA256_BLOCK_SIZE]);
        block.copy_from_slice(&self.buffer);
        Self::compress(&mut self.state, &block)?;

        let mut out = Zeroizing::new([0u8; SHA256_OUTPUT_SIZE]);
        for (word_index, &word) in self.state.iter().enumerate() {
            for byte in 0..4 {
                out[word_index * 4 + byte] = (word >> (24 - byte * 8)) as u8;
            }
        }
        self.zeroize();
        Ok(out)
    }
}

// SHA-224 implementation with enhanced security
impl Sha224 {
    fn init_state() -> [u32; 8] {
        [
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
            0xbefa4fa4,
        ]
    }

    fn new() -> Self {
        Sha224 {
            state: Self::init_state(),
            buffer: [0u8; SHA256_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }
}

// --- SHA-512 internal methods with enhanced security ---
impl Sha512 {
    fn init_state() -> [u64; 8] {
        [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ]
    }

    fn new() -> Self {
        Sha512 {
            state: Self::init_state(),
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }

    fn compress(state: &mut [u64; 8], block: &[u8; SHA512_BLOCK_SIZE]) -> Result<()> {
        // Use EphemeralSecret for message schedule
        let mut w = EphemeralSecret::new([0u64; 80]);

        // Memory barrier before processing
        compiler_fence(Ordering::SeqCst);

        for i in 0..16 {
            let start = i * 8;
            validate::max_length("SHA-512 block read", start + 8, SHA512_BLOCK_SIZE)?;
            let mut word = 0u64;
            for byte in 0..8 {
                word |= u64::from(block[start + byte]) << (56 - byte * 8);
            }
            w[i] = word;
            word.zeroize();
        }

        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Use ZeroizeGuard for working variables
        let mut working_vars = [
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        ];
        let mut guard = ZeroizeGuard::new(&mut working_vars);

        // Use temporary variables instead of multiple mutable references
        let mut a = guard[0];
        let mut b = guard[1];
        let mut c = guard[2];
        let mut d = guard[3];
        let mut e = guard[4];
        let mut f = guard[5];
        let mut g = guard[6];
        let mut h = guard[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Write back the results
        guard[0] = a;
        guard[1] = b;
        guard[2] = c;
        guard[3] = d;
        guard[4] = e;
        guard[5] = f;
        guard[6] = g;
        guard[7] = h;

        // Update state
        state[0] = state[0].wrapping_add(guard[0]);
        state[1] = state[1].wrapping_add(guard[1]);
        state[2] = state[2].wrapping_add(guard[2]);
        state[3] = state[3].wrapping_add(guard[3]);
        state[4] = state[4].wrapping_add(guard[4]);
        state[5] = state[5].wrapping_add(guard[5]);
        state[6] = state[6].wrapping_add(guard[6]);
        state[7] = state[7].wrapping_add(guard[7]);

        a.zeroize();
        b.zeroize();
        c.zeroize();
        d.zeroize();
        e.zeroize();
        f.zeroize();
        g.zeroize();
        h.zeroize();

        // Memory barrier after processing
        compiler_fence(Ordering::SeqCst);

        Ok(())
    }

    fn update_internal_u128(&mut self, mut input: &[u8]) -> Result<()> {
        while !input.is_empty() {
            let fill = core::cmp::min(input.len(), SHA512_BLOCK_SIZE - self.buffer_idx);
            self.buffer[self.buffer_idx..self.buffer_idx + fill].copy_from_slice(&input[..fill]);
            self.buffer_idx += fill;
            input = &input[fill..];
            if self.buffer_idx == SHA512_BLOCK_SIZE {
                let mut block = Zeroizing::new([0u8; SHA512_BLOCK_SIZE]);
                block.copy_from_slice(&self.buffer);
                Self::compress(&mut self.state, &block)?;
                self.total_bytes = self.total_bytes.wrapping_add(SHA512_BLOCK_SIZE as u128);
                self.buffer.zeroize();
                self.buffer_idx = 0;
            }
        }
        Ok(())
    }

    fn finalize_internal_u128(&mut self) -> Result<Zeroizing<[u8; SHA512_OUTPUT_SIZE]>> {
        self.total_bytes = self.total_bytes.wrapping_add(self.buffer_idx as u128);
        let bit_len = self.total_bytes.wrapping_mul(8);

        // Use EphemeralSecret for sensitive padding operations
        let pad_buffer = EphemeralSecret::new([0u8; SHA512_BLOCK_SIZE]);

        self.buffer[self.buffer_idx] = 0x80;
        if self.buffer_idx >= SHA512_BLOCK_SIZE - 16 {
            for b in &mut self.buffer[self.buffer_idx + 1..] {
                *b = 0;
            }
            let mut block = Zeroizing::new([0u8; SHA512_BLOCK_SIZE]);
            block.copy_from_slice(&self.buffer);
            Self::compress(&mut self.state, &block)?;
            self.buffer = *pad_buffer;
        } else {
            for b in &mut self.buffer[self.buffer_idx + 1..SHA512_BLOCK_SIZE - 16] {
                *b = 0;
            }
        }

        for (index, byte) in self.buffer[SHA512_BLOCK_SIZE - 16..].iter_mut().enumerate() {
            *byte = (bit_len >> (120 - index * 8)) as u8;
        }
        let mut block = Zeroizing::new([0u8; SHA512_BLOCK_SIZE]);
        block.copy_from_slice(&self.buffer);
        Self::compress(&mut self.state, &block)?;

        let mut out = Zeroizing::new([0u8; SHA512_OUTPUT_SIZE]);
        for (word_index, &word) in self.state.iter().enumerate() {
            for byte in 0..8 {
                out[word_index * 8 + byte] = (word >> (56 - byte * 8)) as u8;
            }
        }
        self.zeroize();
        Ok(out)
    }
}

// SHA-512/224 implementation
impl Sha512_224 {
    fn init_state() -> [u64; 8] {
        [
            0x8c3d37c819544da2,
            0x73e1996689dcd4d6,
            0x1dfab7ae32ff9c82,
            0x679dd514582f9fcf,
            0x0f6d2b697bd44da8,
            0x77e36f7304c48942,
            0x3f9d85a86a1d36c8,
            0x1112e6ad91d692a1,
        ]
    }

    fn new() -> Self {
        Sha512_224 {
            state: Self::init_state(),
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }
}

// SHA-512/256 implementation
impl Sha512_256 {
    fn init_state() -> [u64; 8] {
        [
            0x22312194fc2bf72c,
            0x9f555fa3c84c64c2,
            0x2393b86b6f53b151,
            0x963877195940eabd,
            0x96283ee2a88effe3,
            0xbe5e1e2553863992,
            0x2b0199fc2c85b8aa,
            0x0eb72ddc81c52ca2,
        ]
    }

    fn new() -> Self {
        Sha512_256 {
            state: Self::init_state(),
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }
}

// --- HashFunction impls with SecureZeroingType ---
impl SecureZeroingType for Sha256 {
    fn zeroed() -> Self {
        Self::new()
    }
}

impl HashFunction for Sha256 {
    type Algorithm = Sha256Algorithm;
    type Output = Digest<SHA256_OUTPUT_SIZE>;

    fn new() -> Self {
        Sha256::new()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = Digest::<SHA256_OUTPUT_SIZE>::zeroed();
        digest.as_mut().copy_from_slice(&hash[..]);
        Ok(digest)
    }

    fn output_size() -> usize {
        SHA256_OUTPUT_SIZE
    }

    fn block_size() -> usize {
        SHA256_BLOCK_SIZE
    }

    fn name() -> String {
        "SHA-256".to_string()
    }
}

impl SecureZeroingType for Sha224 {
    fn zeroed() -> Self {
        Self::new()
    }
}

impl HashFunction for Sha224 {
    type Algorithm = Sha224Algorithm;
    type Output = Digest<SHA224_OUTPUT_SIZE>;

    fn new() -> Self {
        Sha224::new()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        let mut tmp = Sha256::new();
        tmp.state = self.state;
        tmp.buffer = self.buffer;
        tmp.buffer_idx = self.buffer_idx;
        tmp.total_bytes = self.total_bytes;
        tmp.update_internal(data)?;
        self.state = tmp.state;
        self.buffer = tmp.buffer;
        self.buffer_idx = tmp.buffer_idx;
        self.total_bytes = tmp.total_bytes;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let mut tmp = Sha256::new();
        tmp.state = self.state;
        tmp.buffer = self.buffer;
        tmp.buffer_idx = self.buffer_idx;
        tmp.total_bytes = self.total_bytes;
        let full = tmp.finalize_internal()?;
        let mut digest = Digest::<SHA224_OUTPUT_SIZE>::zeroed();
        digest.as_mut().copy_from_slice(&full[..SHA224_OUTPUT_SIZE]);
        Ok(digest)
    }

    fn output_size() -> usize {
        SHA224_OUTPUT_SIZE
    }

    fn block_size() -> usize {
        SHA256_BLOCK_SIZE
    }

    fn name() -> String {
        "SHA-224".to_string()
    }
}

impl SecureZeroingType for Sha384 {
    fn zeroed() -> Self {
        Sha384 {
            state: [
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4,
            ],
            buffer: [0u8; SHA512_BLOCK_SIZE],
            buffer_idx: 0,
            total_bytes: 0,
        }
    }
}

impl HashFunction for Sha384 {
    type Algorithm = Sha384Algorithm;
    type Output = Digest<SHA384_OUTPUT_SIZE>;

    fn new() -> Self {
        SecureZeroingType::zeroed()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        let mut tmp = Sha512::new();
        tmp.state = self.state;
        tmp.buffer = self.buffer;
        tmp.buffer_idx = self.buffer_idx;
        tmp.total_bytes = self.total_bytes;
        tmp.update_internal_u128(data)?;
        self.state = tmp.state;
        self.buffer = tmp.buffer;
        self.buffer_idx = tmp.buffer_idx;
        self.total_bytes = tmp.total_bytes;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let mut tmp = Sha512::new();
        tmp.state = self.state;
        tmp.buffer = self.buffer;
        tmp.buffer_idx = self.buffer_idx;
        tmp.total_bytes = self.total_bytes;
        let full = tmp.finalize_internal_u128()?;
        let mut digest = Digest::<SHA384_OUTPUT_SIZE>::zeroed();
        digest.as_mut().copy_from_slice(&full[..SHA384_OUTPUT_SIZE]);
        Ok(digest)
    }

    fn output_size() -> usize {
        SHA384_OUTPUT_SIZE
    }

    fn block_size() -> usize {
        SHA512_BLOCK_SIZE
    }

    fn name() -> String {
        "SHA-384".to_string()
    }
}

impl SecureZeroingType for Sha512 {
    fn zeroed() -> Self {
        Self::new()
    }
}

impl HashFunction for Sha512 {
    type Algorithm = Sha512Algorithm;
    type Output = Digest<SHA512_OUTPUT_SIZE>;

    fn new() -> Self {
        Sha512::new()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        self.update_internal_u128(data)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal_u128()?;
        let mut digest = Digest::<SHA512_OUTPUT_SIZE>::zeroed();
        digest.as_mut().copy_from_slice(&hash[..]);
        Ok(digest)
    }

    fn output_size() -> usize {
        SHA512_OUTPUT_SIZE
    }

    fn block_size() -> usize {
        SHA512_BLOCK_SIZE
    }

    fn name() -> String {
        "SHA-512".to_string()
    }
}

impl SecureZeroingType for Sha512_224 {
    fn zeroed() -> Self {
        Self::new()
    }
}

impl HashFunction for Sha512_224 {
    type Algorithm = Sha512_224Algorithm;
    type Output = Digest<SHA224_OUTPUT_SIZE>;

    fn new() -> Self {
        Sha512_224::new()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        let mut tmp = Sha512::new();
        tmp.state = self.state;
        tmp.buffer = self.buffer;
        tmp.buffer_idx = self.buffer_idx;
        tmp.total_bytes = self.total_bytes;
        tmp.update_internal_u128(data)?;
        self.state = tmp.state;
        self.buffer = tmp.buffer;
        self.buffer_idx = tmp.buffer_idx;
        self.total_bytes = tmp.total_bytes;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let mut tmp = Sha512::new();
        tmp.state = self.state;
        tmp.buffer = self.buffer;
        tmp.buffer_idx = self.buffer_idx;
        tmp.total_bytes = self.total_bytes;
        let full = tmp.finalize_internal_u128()?;
        let mut digest = Digest::<SHA224_OUTPUT_SIZE>::zeroed();
        digest.as_mut().copy_from_slice(&full[..SHA224_OUTPUT_SIZE]);
        Ok(digest)
    }

    fn output_size() -> usize {
        SHA224_OUTPUT_SIZE
    }

    fn block_size() -> usize {
        SHA512_BLOCK_SIZE
    }

    fn name() -> String {
        "SHA-512/224".to_string()
    }
}

impl SecureZeroingType for Sha512_256 {
    fn zeroed() -> Self {
        Self::new()
    }
}

impl HashFunction for Sha512_256 {
    type Algorithm = Sha512_256Algorithm;
    type Output = Digest<SHA256_OUTPUT_SIZE>;

    fn new() -> Self {
        Sha512_256::new()
    }

    fn update(&mut self, data: &[u8]) -> Result<&mut Self> {
        let mut tmp = Sha512::new();
        tmp.state = self.state;
        tmp.buffer = self.buffer;
        tmp.buffer_idx = self.buffer_idx;
        tmp.total_bytes = self.total_bytes;
        tmp.update_internal_u128(data)?;
        self.state = tmp.state;
        self.buffer = tmp.buffer;
        self.buffer_idx = tmp.buffer_idx;
        self.total_bytes = tmp.total_bytes;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let mut tmp = Sha512::new();
        tmp.state = self.state;
        tmp.buffer = self.buffer;
        tmp.buffer_idx = self.buffer_idx;
        tmp.total_bytes = self.total_bytes;
        let full = tmp.finalize_internal_u128()?;
        let mut digest = Digest::<SHA256_OUTPUT_SIZE>::zeroed();
        digest.as_mut().copy_from_slice(&full[..SHA256_OUTPUT_SIZE]);
        Ok(digest)
    }

    fn output_size() -> usize {
        SHA256_OUTPUT_SIZE
    }

    fn block_size() -> usize {
        SHA512_BLOCK_SIZE
    }

    fn name() -> String {
        "SHA-512/256".to_string()
    }
}

#[cfg(test)]
mod tests;
