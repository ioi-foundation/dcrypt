//! Poly1305 message authentication code
//! Pure-Rust branch-free limb arithmetic implementation.
//!
//! Implements the algorithm described in RFC 8439.
//! Branch-free source is not a blanket side-channel proof for every compiler
//! and target.

use crate::error::{validate, Result};
use crate::mac::MacAlgorithm;
use crate::types::Tag;
use dcrypt_common::security::{SecretBuffer, SecretVec};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Size of the Poly1305 key in bytes (32 B)
pub const POLY1305_KEY_SIZE: usize = 32;
/// Size of the Poly1305 authentication tag in bytes (16 B)
pub const POLY1305_TAG_SIZE: usize = 16;

/// Marker for the Poly1305 algorithm (type-level)
pub enum Poly1305Algorithm {}

impl MacAlgorithm for Poly1305Algorithm {
    const KEY_SIZE: usize = POLY1305_KEY_SIZE;
    const TAG_SIZE: usize = POLY1305_TAG_SIZE;
    const BLOCK_SIZE: usize = 16;

    fn name() -> &'static str {
        "Poly1305"
    }
}

/// Poly1305 MAC (branch-free limb arithmetic)
pub struct Poly1305 {
    r: SecretBuffer<24>, // 130-bit key r stored as 3 u64s (24 bytes)
    s: SecretBuffer<16>, // 128-bit key s stored as 2 u64s (16 bytes)
    data: SecretVec,     // exact-size buffered input
}

impl Zeroize for Poly1305 {
    fn zeroize(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.data.zeroize();
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Poly1305 {}

impl Poly1305 {
    /* ------------------------------------------------------------------ */
    /*                           INITIALISATION                           */
    /* ------------------------------------------------------------------ */

    /// Construct a new `Poly1305` context from a 32-byte key.
    ///
    /// The key is split into the clamped `r` portion (first 16 bytes) and the
    /// `s` portion (last 16 bytes) exactly as specified in RFC 8439 §2.5.2.
    pub fn new(key: &[u8]) -> Result<Self> {
        validate::length("Poly1305 key", key.len(), POLY1305_KEY_SIZE)?;

        // ---- split & clamp r -------------------------------------------
        let mut r_bytes = Zeroizing::new([0u8; 16]);
        r_bytes.copy_from_slice(&key[..16]);
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        // Keep key-derived temporaries inside zeroizing containers.
        let mut r = SecretBuffer::<24>::zeroed();
        r.as_mut()[..16].copy_from_slice(r_bytes.as_ref());

        // ---- split s ---------------------------------------------------
        let mut s = SecretBuffer::<16>::zeroed();
        s.as_mut().copy_from_slice(&key[16..32]);

        Ok(Self {
            r,
            s,
            data: SecretVec::empty(),
        })
    }

    /* ------------------------------------------------------------------ */
    /*                           HELPER METHODS                           */
    /* ------------------------------------------------------------------ */

    /// Extract r values from the secure buffer
    fn get_r(&self) -> Zeroizing<[u64; 3]> {
        let bytes = self.r.as_ref();
        let mut words = Zeroizing::new([0u64; 3]);
        for (word_index, word) in words.iter_mut().enumerate() {
            for byte_index in 0..8 {
                *word |= u64::from(bytes[word_index * 8 + byte_index]) << (byte_index * 8);
            }
        }
        words
    }

    /// Extract s values from the secure buffer
    fn get_s(&self) -> Zeroizing<[u64; 2]> {
        let bytes = self.s.as_ref();
        let mut words = Zeroizing::new([0u64; 2]);
        for (word_index, word) in words.iter_mut().enumerate() {
            for byte_index in 0..8 {
                *word |= u64::from(bytes[word_index * 8 + byte_index]) << (byte_index * 8);
            }
        }
        words
    }

    /* ------------------------------------------------------------------ */
    /*                                UPDATE                               */
    /* ------------------------------------------------------------------ */

    /// Absorb additional message data into the MAC state.
    ///
    /// This can be called zero or more times before [`Self::finalize`].  
    /// Data is internally buffered in 16-byte blocks.  
    /// Always returns `Ok(())` (provided for API symmetry).
    pub fn update(&mut self, chunk: &[u8]) -> Result<()> {
        if !chunk.is_empty() {
            self.data.extend_from_slice(chunk);
        }
        Ok(())
    }

    /* ------------------------------------------------------------------ */
    /*                               FINALISE                              */
    /* ------------------------------------------------------------------ */

    /// Consume the context and return the 16-byte authentication tag.
    ///
    /// After this call the `Poly1305` instance must be discarded because its
    /// internal key material has been moved.
    pub fn finalize(self) -> Tag<POLY1305_TAG_SIZE> {
        // 1) polynomial evaluation h = Σ (block · r^i)
        let mut h = Zeroizing::new([0u64; 3]);
        let r = self.get_r();

        for block in self.data.chunks(16) {
            let mut buf = Zeroizing::new([0u8; 16]);
            buf[..block.len()].copy_from_slice(block);
            let n2 = if block.len() == 16 {
                1
            } else {
                buf[block.len()] = 1;
                0
            };
            let mut n = Zeroizing::new([0u64; 2]);
            for (word_index, word) in n.iter_mut().enumerate() {
                for byte_index in 0..8 {
                    *word |= u64::from(buf[word_index * 8 + byte_index]) << (byte_index * 8);
                }
            }

            // h += n (carry-prop)
            let mut sum = Zeroizing::new(u128::from(h[0]) + u128::from(n[0]));
            h[0] = *sum as u64;
            *sum = u128::from(h[1]) + u128::from(n[1]) + (*sum >> 64);
            h[1] = *sum as u64;
            h[2] = h[2].wrapping_add(n2).wrapping_add((*sum >> 64) as u64);

            let reduced = mul_reduce(&h, &r);
            h.copy_from_slice(&*reduced);
        }

        // 2) final reduction mod p = 2^130 − 5 (branch-free)
        const P0: u64 = 0xffff_ffff_ffff_fffb;
        const P1: u64 = 0xffff_ffff_ffff_ffff;
        const P2: u64 = 3;

        let mut g = Zeroizing::new([0u64; 3]);
        let mut borrow = Zeroizing::new(0u64);
        let mut wide = Zeroizing::new((1u128 << 64) + u128::from(h[0]) - u128::from(P0));
        g[0] = *wide as u64;
        *borrow = 1 - (*wide >> 64) as u64;
        *wide = (1u128 << 64) + u128::from(h[1]) - u128::from(P1) - u128::from(*borrow);
        g[1] = *wide as u64;
        *borrow = 1 - (*wide >> 64) as u64;
        *wide = (1u128 << 64) + u128::from(h[2]) - u128::from(P2) - u128::from(*borrow);
        g[2] = *wide as u64;
        *borrow = 1 - (*wide >> 64) as u64;

        // mask = 0xFFFF… when borrow2 == 0, else 0x0
        let mask = Zeroizing::new(borrow.wrapping_sub(1));
        h[0] = (h[0] & !*mask) | (g[0] & *mask);
        h[1] = (h[1] & !*mask) | (g[1] & *mask);
        h[2] = (h[2] & !*mask) | (g[2] & *mask);

        // 3) add s (mod 2^128)
        let s = self.get_s();
        *wide = u128::from(h[0]) + u128::from(s[0]);
        let mut tag_words = Zeroizing::new([0u64; 2]);
        tag_words[0] = *wide as u64;
        *wide = u128::from(h[1]) + u128::from(s[1]) + (*wide >> 64);
        tag_words[1] = *wide as u64;

        let mut out = [0u8; POLY1305_TAG_SIZE];
        for (word_index, word) in tag_words.iter().enumerate() {
            for byte_index in 0..8 {
                out[word_index * 8 + byte_index] = (word >> (byte_index * 8)) as u8;
            }
        }
        Tag::new(out)
    }
}

/* ---------------------------------------------------------------------- */
/*                SCHOOLBOOK MUL & REDUCE (2^130 − 5)                     */
/* ---------------------------------------------------------------------- */
fn mul_reduce(h: &[u64; 3], r: &[u64; 3]) -> Zeroizing<[u64; 3]> {
    let operands = Zeroizing::new([
        u128::from(h[0]),
        u128::from(h[1]),
        u128::from(h[2]),
        u128::from(r[0]),
        u128::from(r[1]),
        u128::from(r[2]),
    ]);

    // schoolbook multiply
    let mut products = Zeroizing::new([0u128; 5]);
    products[0] = operands[0] * operands[3];
    products[1] = operands[0] * operands[4] + operands[1] * operands[3];
    products[2] = operands[0] * operands[5] + operands[1] * operands[4] + operands[2] * operands[3];
    products[3] = operands[1] * operands[5] + operands[2] * operands[4];
    products[4] = operands[2] * operands[5];

    // propagate carries
    for limb in 0..4 {
        products[limb + 1] += products[limb] >> 64;
        products[limb] &= u128::from(u64::MAX);
    }
    products[4] &= u128::from(u64::MAX);

    // fold bits ≥2^130 back in via 2^130 ≡ 5 (mod p)
    let high = Zeroizing::new((products[2] >> 2) + (products[3] << 62) + (products[4] << 126));

    // combine low limbs with folded carry
    let mut reduced = Zeroizing::new([0u128; 3]);
    reduced[0] = products[0] + *high * 5;
    reduced[1] = products[1];
    reduced[2] = products[2] & 0x3;

    // final carry
    reduced[1] += reduced[0] >> 64;
    reduced[0] &= u128::from(u64::MAX);
    reduced[2] += reduced[1] >> 64;
    reduced[1] &= u128::from(u64::MAX);
    reduced[2] &= 0x3fff_ffff_ffff_ffff;

    let mut result = Zeroizing::new([0u64; 3]);
    for (output, value) in result.iter_mut().zip(reduced.iter()) {
        *output = *value as u64;
    }
    result
}

#[cfg(test)]
mod tests;
