//! BLAKE2 hash function implementations
//!
//! This module implements the BLAKE2 family of hash functions as specified in
//! RFC 7693 (<https://www.rfc-editor.org/rfc/rfc7693.html>). BLAKE2 is optimized
//! for speed on 64-bit platforms while maintaining high security levels.
//!
//! Supported variants:
//! - **BLAKE2b** – 64‑bit optimized, digest up to 64 bytes.
//! - **BLAKE2s** – 32‑bit optimized, digest up to 32 bytes.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

#[cfg(not(feature = "std"))]
use core::{cmp::min, convert::TryInto};
#[cfg(feature = "std")]
use core::{cmp::min, convert::TryInto};

use dcrypt_internal::zeroing::Zeroize;

use crate::error::{validate, Error, Result};
use crate::hash::{HashAlgorithm, HashFunction};
use crate::types::Digest;
use dcrypt_common::security::{EphemeralSecret, SecretBuffer, SecureZeroingType};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────
const BLAKE2B_BLOCK_SIZE: usize = 128;
const BLAKE2B_MAX_OUTPUT_SIZE: usize = 64;
const BLAKE2B_ROUNDS: usize = 12;
const BLAKE2B_KEY_SIZE: usize = 64; // Maximum key size for keyed mode

// Export constants for Argon2 module to use
pub(crate) const BLAKE2B_IV: [u64; 8] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1,
    0x9B05_688C_2B3E_6C1F,
    0x1F83_D9AB_FB41_BD6B,
    0x5BE0_CD19_137E_2179,
];

/// Message‑word permutation schedule (σ) for each of the 12 rounds
const BLAKE2B_SIGMA: [[usize; 16]; BLAKE2B_ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

// ─────────────────────────────────────────────────────────────────────────────
// Marker type implementing the HashAlgorithm trait
// ─────────────────────────────────────────────────────────────────────────────
#[allow(missing_docs)]
pub enum Blake2bAlgorithm {}
impl HashAlgorithm for Blake2bAlgorithm {
    const OUTPUT_SIZE: usize = BLAKE2B_MAX_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = BLAKE2B_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "BLAKE2b";
}

// ─────────────────────────────────────────────────────────────────────────────
// State structure
// ─────────────────────────────────────────────────────────────────────────────
#[allow(missing_docs)]
#[derive(Clone)]
pub struct Blake2b {
    pub(crate) h: [u64; 8],
    pub(crate) t: [u64; 2],
    pub(crate) f: [u64; 2],
    pub(crate) buf: [u8; BLAKE2B_BLOCK_SIZE],
    pub(crate) buf_len: usize,
    pub(crate) out_len: usize,
    pub(crate) key: Option<SecretBuffer<BLAKE2B_KEY_SIZE>>, // present only in keyed mode
    pub(crate) is_keyed: bool,
}
impl Zeroize for Blake2b {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.t.zeroize();
        self.f.zeroize();
        self.buf.zeroize();
        self.buf_len.zeroize();
        self.out_len.zeroize();
        self.key.zeroize();
        self.is_keyed.zeroize();
    }
}
impl Drop for Blake2b {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Constructors
// ─────────────────────────────────────────────────────────────────────────────
impl Blake2b {
    /// Generic constructor (non‑keyed) with configurable output length.
    pub fn with_output_size(out_len: usize) -> Self {
        if !(1..=BLAKE2B_MAX_OUTPUT_SIZE).contains(&out_len) {
            panic!("Blake2b output size must be between 1 and 64 bytes");
        }
        let mut h = BLAKE2B_IV;
        h[0] ^= 0x0101_0000u64 | out_len as u64; // digest_len | fanout=1 | depth=1
        Self {
            h,
            t: [0; 2],
            f: [0; 2],
            buf: [0; BLAKE2B_BLOCK_SIZE],
            buf_len: 0,
            out_len,
            key: None,
            is_keyed: false,
        }
    }

    /// Generic constructor with a fully specified parameter block.
    ///
    /// The parameter block is a 64-byte array that controls the Blake2b configuration.
    /// This is primarily used for specialized hash constructions.
    ///
    /// # Arguments
    /// * `param` - The 64-byte parameter block
    /// * `out_len` - The desired output length in bytes
    pub fn with_parameter_block(param: [u8; 64], out_len: usize) -> Self {
        if !(1..=BLAKE2B_MAX_OUTPUT_SIZE).contains(&out_len) {
            panic!("Blake2b output size must be between 1 and 64 bytes");
        }

        let mut h = BLAKE2B_IV;
        for (i, chunk) in param.chunks_exact(8).enumerate() {
            h[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }

        Self {
            h,
            t: [0; 2],
            f: [0; 2],
            buf: [0; BLAKE2B_BLOCK_SIZE],
            buf_len: 0,
            out_len,
            key: None,
            is_keyed: false,
        }
    }

    /// Creates a new Blake2b instance with a key (keyed mode).
    ///
    /// # Arguments
    ///
    /// * `key` - The key bytes (must be between 1 and 64 bytes)
    /// * `out_len` - The desired output size in bytes (must be between 1 and 64)
    pub fn with_key(key: &[u8], out_len: usize) -> Result<Self> {
        if key.is_empty() || key.len() > BLAKE2B_KEY_SIZE {
            return Err(Error::param(
                "key",
                "Key length must be between 1 and 64 bytes",
            ));
        }

        // Store the original key in SecretBuffer
        let mut key_secret_buf_content = [0u8; BLAKE2B_KEY_SIZE];
        key_secret_buf_content[..key.len()].copy_from_slice(key);

        let mut h = BLAKE2B_IV;
        let param0 = (out_len as u64)               // digest_length (byte 0)
                   | ((key.len() as u64) << 8)      // key_length (byte 1)
                   | (1u64 << 16)                   // fanout = 1 (byte 2)
                   | (1u64 << 24); // depth = 1 (byte 3)
        h[0] ^= param0;

        let mut blake2b = Blake2b {
            h,
            t: [0; 2],
            f: [0; 2],
            buf: [0; BLAKE2B_BLOCK_SIZE],
            buf_len: 0,
            out_len,
            key: Some(SecretBuffer::new(key_secret_buf_content)),
            is_keyed: true,
        };

        // If keyed, process the key block first.
        let mut key_block_padded = [0u8; BLAKE2B_BLOCK_SIZE];
        key_block_padded[..key.len()].copy_from_slice(key);
        blake2b.update_internal(&key_block_padded)?;

        Ok(blake2b)
    }

    // --- internal functions ---
    // -------------------------------------------------------------------------
    //  Standard BLAKE2b quarter-round (RFC-7693, §3.2, Figure 3)
    // -------------------------------------------------------------------------
    #[inline(always)]
    fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }

    fn compress(&mut self, last: bool) -> Result<()> {
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&BLAKE2B_IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        if last {
            v[14] ^= 0xFFFF_FFFF_FFFF_FFFF;
        } // RFC 7693 §3.2, step 3

        let mut m = [0u64; 16];
        for (i, elem) in m.iter_mut().enumerate().take(16) {
            let idx = i * 8;
            validate::max_length("BLAKE2b buffer slice", idx + 8, self.buf.len())?;
            *elem = u64::from_le_bytes(self.buf[idx..idx + 8].try_into().map_err(|_| {
                Error::Processing {
                    operation: "BLAKE2b compression",
                    details: "Failed to convert bytes to u64",
                }
            })?);
        }
        let m_ephemeral = EphemeralSecret::new(m);
        for s in BLAKE2B_SIGMA.iter().take(BLAKE2B_ROUNDS) {
            Self::blake2b_g(&mut v, 0, 4, 8, 12, m_ephemeral[s[0]], m_ephemeral[s[1]]);
            Self::blake2b_g(&mut v, 1, 5, 9, 13, m_ephemeral[s[2]], m_ephemeral[s[3]]);
            Self::blake2b_g(&mut v, 2, 6, 10, 14, m_ephemeral[s[4]], m_ephemeral[s[5]]);
            Self::blake2b_g(&mut v, 3, 7, 11, 15, m_ephemeral[s[6]], m_ephemeral[s[7]]);
            Self::blake2b_g(&mut v, 0, 5, 10, 15, m_ephemeral[s[8]], m_ephemeral[s[9]]);
            Self::blake2b_g(&mut v, 1, 6, 11, 12, m_ephemeral[s[10]], m_ephemeral[s[11]]);
            Self::blake2b_g(&mut v, 2, 7, 8, 13, m_ephemeral[s[12]], m_ephemeral[s[13]]);
            Self::blake2b_g(&mut v, 3, 4, 9, 14, m_ephemeral[s[14]], m_ephemeral[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
        Ok(())
    }

    fn update_internal(&mut self, mut input: &[u8]) -> Result<()> {
        while !input.is_empty() {
            let fill = min(input.len(), BLAKE2B_BLOCK_SIZE - self.buf_len);
            self.buf[self.buf_len..self.buf_len + fill].copy_from_slice(&input[..fill]);
            self.buf_len += fill;
            input = &input[fill..];

            if self.buf_len == BLAKE2B_BLOCK_SIZE {
                if input.is_empty() {
                    // Don't compress yet - keep the full block for finalization
                    break;
                }
                // Not the last block -> normal, non-final compression
                let inc = BLAKE2B_BLOCK_SIZE as u64;
                self.t[0] = self.t[0].wrapping_add(inc);
                if self.t[0] < inc {
                    self.t[1] = self.t[1].wrapping_add(1);
                }
                self.compress(false)?;
                self.buf_len = 0;
            }
        }
        Ok(())
    }

    fn finalize_internal(&mut self) -> Result<Vec<u8>> {
        // At this point, buffer always contains data (either partial or full block)
        let inc = self.buf_len as u64;
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }

        // Pad any remainder with zeros (does nothing if buf_len == BLAKE2B_BLOCK_SIZE)
        for b in &mut self.buf[self.buf_len..] {
            *b = 0;
        }
        self.compress(true)?;

        // Produce the digest
        let mut out = Vec::with_capacity(self.out_len);
        for &w in &self.h {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(self.out_len);
        Ok(out)
    }
}

impl HashFunction for Blake2b {
    type Algorithm = Blake2bAlgorithm;
    type Output = Digest<BLAKE2B_MAX_OUTPUT_SIZE>;

    fn new() -> Self {
        Blake2b::with_output_size(BLAKE2B_MAX_OUTPUT_SIZE)
    }

    fn update(&mut self, input: &[u8]) -> Result<&mut Self> {
        self.update_internal(input)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; BLAKE2B_MAX_OUTPUT_SIZE];
        digest[..hash.len()].copy_from_slice(&hash);
        Ok(Digest::with_len(digest, self.out_len))
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

/// BLAKE2s constants
const BLAKE2S_BLOCK_SIZE: usize = 64;
const BLAKE2S_MAX_OUTPUT_SIZE: usize = 32;
const BLAKE2S_ROUNDS: usize = 10;
const BLAKE2S_KEY_SIZE: usize = 32; // Maximum key size for keyed mode
const BLAKE2S_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];
const BLAKE2S_SIGMA: [[usize; 16]; BLAKE2S_ROUNDS] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Define Blake2s algorithm marker type
pub enum Blake2sAlgorithm {}

/// Implement HashAlgorithm for Blake2s
impl HashAlgorithm for Blake2sAlgorithm {
    const OUTPUT_SIZE: usize = BLAKE2S_MAX_OUTPUT_SIZE;
    const BLOCK_SIZE: usize = BLAKE2S_BLOCK_SIZE;
    const ALGORITHM_ID: &'static str = "BLAKE2s";
}

/// BLAKE2s state
#[derive(Clone)]
pub struct Blake2s {
    h: [u32; 8],
    t: [u32; 2],
    f: [u32; 2],
    buf: [u8; BLAKE2S_BLOCK_SIZE],
    buf_len: usize,
    out_len: usize,
    key: Option<SecretBuffer<BLAKE2S_KEY_SIZE>>, // Optional key for keyed mode
    is_keyed: bool,
}

impl Zeroize for Blake2s {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.t.zeroize();
        self.f.zeroize();
        self.buf.zeroize();
        self.buf_len.zeroize();
        self.out_len.zeroize();
        self.key.zeroize();
        self.is_keyed.zeroize();
    }
}

// Manually implement zeroize on drop for additional security
impl Drop for Blake2s {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Blake2s {
    /// Creates a new Blake2s instance with a custom output size.
    ///
    /// # Arguments
    ///
    /// * `out_len` - The desired output size in bytes (must be between 1 and 32)
    ///
    /// # Panics
    ///
    /// This function may panic if `out_len` is 0 or greater than 32.
    pub fn with_output_size(out_len: usize) -> Self {
        if out_len == 0 || out_len > BLAKE2S_MAX_OUTPUT_SIZE {
            panic!("Blake2s output size must be between 1 and 32 bytes");
        }
        let mut h = BLAKE2S_IV;
        // Use | for parameter construction instead of ^ to ensure correct parameter block
        let param0 = (out_len as u32) | (1u32 << 16) | (1u32 << 24); // 0x01010000 | out_len
        h[0] ^= param0;
        Blake2s {
            h,
            t: [0; 2],
            f: [0; 2],
            buf: [0; BLAKE2S_BLOCK_SIZE],
            buf_len: 0,
            out_len,
            key: None,
            is_keyed: false,
        }
    }

    /// Creates a new Blake2s instance with a key (keyed mode).
    ///
    /// # Arguments
    ///
    /// * `key` - The key bytes (must be between 1 and 32 bytes)
    /// * `out_len` - The desired output size in bytes (must be between 1 and 32)
    pub fn with_key(key: &[u8], out_len: usize) -> Result<Self> {
        if key.is_empty() || key.len() > BLAKE2S_KEY_SIZE {
            return Err(Error::param(
                "key",
                "Key length must be between 1 and 32 bytes",
            ));
        }

        // Store the original key in SecretBuffer
        let mut key_secret_buf_content = [0u8; BLAKE2S_KEY_SIZE];
        key_secret_buf_content[..key.len()].copy_from_slice(key);

        let mut h = BLAKE2S_IV;
        // Use | for parameter construction instead of ^ to ensure correct parameter block
        let param0 = (out_len as u32)             // digest_length (byte 0)
                   | ((key.len() as u32) << 8)    // key_length (byte 1)
                   | (1u32 << 16)                 // fanout = 1 (byte 2)
                   | (1u32 << 24); // depth = 1 (byte 3)
        h[0] ^= param0;

        let mut blake2s = Blake2s {
            h,
            t: [0; 2],
            f: [0; 2],
            buf: [0; BLAKE2S_BLOCK_SIZE],
            buf_len: 0,
            out_len,
            key: Some(SecretBuffer::new(key_secret_buf_content)),
            is_keyed: true,
        };

        // If keyed, process the key block first.
        // The key K is padded with zero bytes to fill a full block (64 bytes for Blake2s).
        let mut key_block_padded = [0u8; BLAKE2S_BLOCK_SIZE];
        key_block_padded[..key.len()].copy_from_slice(key);

        blake2s.update_internal(&key_block_padded)?;

        Ok(blake2s)
    }

    fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(12);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(8);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(7);
    }

    fn compress(&mut self, last: bool) -> Result<()> {
        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&BLAKE2S_IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        if last {
            v[14] = !v[14];
        }

        let mut m = [0u32; 16];
        for (i, elem) in m.iter_mut().enumerate().take(16) {
            let idx = i * 4;
            // Validate buffer bounds
            validate::max_length("BLAKE2s buffer slice", idx + 4, self.buf.len())?;

            // Convert bytes to u32 with proper error handling
            *elem = u32::from_le_bytes(self.buf[idx..idx + 4].try_into().map_err(|_| {
                Error::Processing {
                    operation: "BLAKE2s compression",
                    details: "Failed to convert bytes to u32",
                }
            })?);
        }

        // Use EphemeralSecret to ensure intermediate values are zeroized
        let m_ephemeral = EphemeralSecret::new(m);

        for s in BLAKE2S_SIGMA.iter().take(BLAKE2S_ROUNDS) {
            Self::g(&mut v, 0, 4, 8, 12, m_ephemeral[s[0]], m_ephemeral[s[1]]);
            Self::g(&mut v, 1, 5, 9, 13, m_ephemeral[s[2]], m_ephemeral[s[3]]);
            Self::g(&mut v, 2, 6, 10, 14, m_ephemeral[s[4]], m_ephemeral[s[5]]);
            Self::g(&mut v, 3, 7, 11, 15, m_ephemeral[s[6]], m_ephemeral[s[7]]);
            Self::g(&mut v, 0, 5, 10, 15, m_ephemeral[s[8]], m_ephemeral[s[9]]);
            Self::g(&mut v, 1, 6, 11, 12, m_ephemeral[s[10]], m_ephemeral[s[11]]);
            Self::g(&mut v, 2, 7, 8, 13, m_ephemeral[s[12]], m_ephemeral[s[13]]);
            Self::g(&mut v, 3, 4, 9, 14, m_ephemeral[s[14]], m_ephemeral[s[15]]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }

        Ok(())
    }

    fn update_internal(&mut self, mut input: &[u8]) -> Result<()> {
        while !input.is_empty() {
            let fill = min(input.len(), BLAKE2S_BLOCK_SIZE - self.buf_len);
            self.buf[self.buf_len..self.buf_len + fill].copy_from_slice(&input[..fill]);
            self.buf_len += fill;
            input = &input[fill..];

            if self.buf_len == BLAKE2S_BLOCK_SIZE {
                if input.is_empty() {
                    // Don't compress yet - keep the full block for finalization
                    break;
                }
                // Not the last block -> normal, non-final compression
                let inc = BLAKE2S_BLOCK_SIZE as u32;
                self.t[0] = self.t[0].wrapping_add(inc);
                if self.t[0] < inc {
                    self.t[1] = self.t[1].wrapping_add(1);
                }
                self.compress(false)?;
                self.buf_len = 0;
            }
        }
        Ok(())
    }

    fn finalize_internal(&mut self) -> Result<Vec<u8>> {
        // At this point, buffer always contains data (either partial or full block)
        let inc = self.buf_len as u32;
        self.t[0] = self.t[0].wrapping_add(inc);
        if self.t[0] < inc {
            self.t[1] = self.t[1].wrapping_add(1);
        }

        // Pad any remainder with zeros (does nothing if buf_len == BLAKE2S_BLOCK_SIZE)
        for b in &mut self.buf[self.buf_len..] {
            *b = 0;
        }
        self.compress(true)?;

        // Produce the digest
        let mut out = Vec::with_capacity(self.out_len);
        for &w in &self.h {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(self.out_len);
        Ok(out)
    }
}

impl HashFunction for Blake2s {
    type Algorithm = Blake2sAlgorithm;
    type Output = Digest<BLAKE2S_MAX_OUTPUT_SIZE>;

    fn new() -> Self {
        Blake2s::with_output_size(BLAKE2S_MAX_OUTPUT_SIZE)
    }

    fn update(&mut self, input: &[u8]) -> Result<&mut Self> {
        self.update_internal(input)?;
        Ok(self)
    }

    fn finalize(&mut self) -> Result<Self::Output> {
        let hash = self.finalize_internal()?;
        let mut digest = [0u8; BLAKE2S_MAX_OUTPUT_SIZE];
        digest[..hash.len()].copy_from_slice(&hash);
        // Create digest with the actual output length
        Ok(Digest::with_len(digest, self.out_len))
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

// Implement SecureZeroingType for Blake2b and Blake2s
impl SecureZeroingType for Blake2b {
    fn zeroed() -> Self {
        Blake2b::with_output_size(BLAKE2B_MAX_OUTPUT_SIZE)
    }

    fn secure_clone(&self) -> Self {
        self.clone()
    }
}

impl SecureZeroingType for Blake2s {
    fn zeroed() -> Self {
        Blake2s::with_output_size(BLAKE2S_MAX_OUTPUT_SIZE)
    }

    fn secure_clone(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests;
