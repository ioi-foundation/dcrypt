//! Poly1305 message authentication code
//! Pure-Rust branch-free limb arithmetic implementation.
//!
//! Implements the algorithm described in RFC 8439.
//! Branch-free source is not a blanket side-channel proof for every compiler
//! and target.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::error::{validate, Result};
use crate::mac::MacAlgorithm;
use crate::types::Tag;
use dcrypt_common::security::SecretBuffer;
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
    r: SecretBuffer<24>,      // 130-bit key r stored as 3 u64s (24 bytes)
    s: SecretBuffer<16>,      // 128-bit key s stored as 2 u64s (16 bytes)
    data: Zeroizing<Vec<u8>>, // buffered input
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
            data: Zeroizing::new(Vec::new()),
        })
    }

    /* ------------------------------------------------------------------ */
    /*                           HELPER METHODS                           */
    /* ------------------------------------------------------------------ */

    /// Extract r values from the secure buffer
    fn get_r(&self) -> [u64; 3] {
        let bytes = self.r.as_ref();
        [
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        ]
    }

    /// Extract s values from the secure buffer
    fn get_s(&self) -> [u64; 2] {
        let bytes = self.s.as_ref();
        [
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        ]
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
        let mut h = [0u64; 3];
        let r = Zeroizing::new(self.get_r());

        for block in self.data.chunks(16) {
            let mut buf = Zeroizing::new([0u8; 16]);
            buf[..block.len()].copy_from_slice(block);
            let n2 = if block.len() == 16 {
                1
            } else {
                buf[block.len()] = 1;
                0
            };
            let n0 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            let n1 = u64::from_le_bytes(buf[8..16].try_into().unwrap());

            // h += n (carry-prop)
            let (h0, c0) = h[0].overflowing_add(n0);
            let (h1a, c1a) = h[1].overflowing_add(n1);
            let (h1, c1b) = h1a.overflowing_add(c0 as u64);
            let c1 = (c1a || c1b) as u64;
            let (h2a, _) = h[2].overflowing_add(n2);
            let (h2, _) = h2a.overflowing_add(c1);

            h = mul_reduce([h0, h1, h2], &r);
        }

        // 2) final reduction mod p = 2^130 − 5 (branch-free)
        const P0: u64 = 0xffff_ffff_ffff_fffb;
        const P1: u64 = 0xffff_ffff_ffff_ffff;
        const P2: u64 = 3;

        let (g0, b0) = h[0].overflowing_sub(P0);
        let (g1a, b1a) = h[1].overflowing_sub(P1);
        let (g1, b1b) = g1a.overflowing_sub(b0 as u64);
        let borrow1 = (b1a || b1b) as u64;
        let (g2, borrow2_bool) = h[2].overflowing_sub(P2 + borrow1);

        // mask = 0xFFFF… when borrow2 == 0, else 0x0
        let mask = (borrow2_bool as u64).wrapping_sub(1);
        h[0] = (h[0] & !mask) | (g0 & mask);
        h[1] = (h[1] & !mask) | (g1 & mask);
        h[2] = (h[2] & !mask) | (g2 & mask);

        // 3) add s (mod 2^128)
        let s = Zeroizing::new(self.get_s());
        let (t0, carry0) = h[0].overflowing_add(s[0]);
        let (t1a, _) = h[1].overflowing_add(s[1]);
        let (t1, _) = t1a.overflowing_add(carry0 as u64);

        let mut out = [0u8; POLY1305_TAG_SIZE];
        out[..8].copy_from_slice(&t0.to_le_bytes());
        out[8..16].copy_from_slice(&t1.to_le_bytes());
        Tag::new(out)
    }
}

/* ---------------------------------------------------------------------- */
/*                SCHOOLBOOK MUL & REDUCE (2^130 − 5)                     */
/* ---------------------------------------------------------------------- */
fn mul_reduce(h: [u64; 3], r: &[u64; 3]) -> [u64; 3] {
    let (h0, h1, h2) = (h[0] as u128, h[1] as u128, h[2] as u128);
    let (r0, r1, r2) = (r[0] as u128, r[1] as u128, r[2] as u128);

    // schoolbook multiply
    let mut t0 = h0 * r0;
    let mut t1 = h0 * r1 + h1 * r0;
    let mut t2 = h0 * r2 + h1 * r1 + h2 * r0;
    let mut t3 = h1 * r2 + h2 * r1;
    let mut t4 = h2 * r2;

    // propagate carries
    let c1 = (t0 >> 64) as u64;
    t0 &= u128::from(u64::MAX);
    t1 += c1 as u128;
    let c2 = (t1 >> 64) as u64;
    t1 &= u128::from(u64::MAX);
    t2 += c2 as u128;
    let c3 = (t2 >> 64) as u64;
    t2 &= u128::from(u64::MAX);
    t3 += c3 as u128;
    let c4 = (t3 >> 64) as u64;
    t3 &= u128::from(u64::MAX);
    t4 += c4 as u128;
    let _c5 = (t4 >> 64) as u64;
    t4 &= u128::from(u64::MAX);

    // fold bits ≥2^130 back in via 2^130 ≡ 5 (mod p)
    let high = (t2 >> 2) + (t3 << 62) + (t4 << 126);
    let low2 = t2 & 0x3;

    // combine low limbs with folded carry
    let mut m0 = t0 + high * 5;
    let mut m1 = t1;
    let mut m2 = low2;

    // final carry
    let f1 = (m0 >> 64) as u64;
    m0 &= u128::from(u64::MAX);
    m1 += f1 as u128;
    let f2 = (m1 >> 64) as u64;
    m1 &= u128::from(u64::MAX);
    m2 += f2 as u128;

    m2 &= 0x3fff_ffff_ffff_ffff;
    [m0 as u64, m1 as u64, m2 as u64]
}

#[cfg(test)]
mod tests;
