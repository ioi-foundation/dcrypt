//! HMAC (Hash-based Message Authentication Code)
//!
//! • RFC 2104 / FIPS 198-1 compliant
//! • Key-derived padding and hash state are zeroized on drop
//! • Tag bytes are compared in constant time after an exact-length check

use crate::error::{Error, Result};
use crate::hash::HashFunction;
use dcrypt_common::security::{SecretBuffer, SecureZeroingType};
use dcrypt_internal::constant_time::ConstantTimeEq;
use dcrypt_internal::zeroing::{
    zeroizing_bytes_from_slice, Zeroize, ZeroizeOnDrop, ZeroizingBytes,
};

const MAX_BLOCK: usize = 144; // SHA3-224 block size (largest among SHA-2 and SHA-3)

/// HMAC implementation with constant-time tag-byte comparison.
#[derive(Clone)]
pub struct Hmac<H: HashFunction + Clone + Zeroize> {
    // The inner hash has absorbed the key-derived ipad and is secret state.
    hash: H,
    ipad: SecretBuffer<MAX_BLOCK>,
    opad: SecretBuffer<MAX_BLOCK>,
    block_size: usize,
    is_finalized: bool,
}

impl<H: HashFunction + Clone + Zeroize> Zeroize for Hmac<H> {
    fn zeroize(&mut self) {
        self.hash.zeroize();
        self.ipad.zeroize();
        self.opad.zeroize();
        self.block_size.zeroize();
        self.is_finalized.zeroize();
    }
}

impl<H: HashFunction + Clone + Zeroize> Drop for Hmac<H> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<H: HashFunction + Clone + Zeroize> ZeroizeOnDrop for Hmac<H> {}

impl<H> Hmac<H>
where
    H: HashFunction + Clone + Zeroize,
    H::Output: AsRef<[u8]> + Clone + Zeroize,
{
    const IPAD_BYTE: u8 = 0x36;
    const OPAD_BYTE: u8 = 0x5c;

    /* ------------------------------------------------------------------ */
    /*                         Construction helpers                       */
    /* ------------------------------------------------------------------ */

    /// Create a new HMAC instance from `key`.
    pub fn new(key: &[u8]) -> Result<Self> {
        let bs = H::block_size();
        debug_assert!(bs <= MAX_BLOCK);

        /* --- Derive K′ in constant-time --- */
        // Hash the key unconditionally so the running time
        // depends only on the public key length.
        let mut hk = H::new();
        if let Err(error) = hk.update(key) {
            hk.zeroize();
            return Err(error);
        }
        let mut hashed = match hk.finalize() {
            Ok(output) => output,
            Err(error) => {
                hk.zeroize();
                return Err(error);
            }
        }; // ≤ bs bytes
        hk.zeroize();

        // Select either `key` or `hashed` per byte with a mask.
        let mut k_prime = SecretBuffer::<MAX_BLOCK>::zeroed();
        let long = (key.len() > bs) as u8; // 1 if key > bs
        let mask = long.wrapping_neg(); // 0xFF when long else 0x00
        #[allow(clippy::needless_range_loop)] // We need the index for multiple arrays
        for i in 0..bs {
            let k = *key.get(i).unwrap_or(&0);
            let hk = hashed.as_ref().get(i).copied().unwrap_or(0);
            k_prime.as_mut()[i] = (hk & mask) | (k & !mask);
        }
        hashed.zeroize();

        /* --- Build inner / outer paddings --- */
        let mut ipad = SecretBuffer::<MAX_BLOCK>::zeroed();
        let mut opad = SecretBuffer::<MAX_BLOCK>::zeroed();
        #[allow(clippy::needless_range_loop)] // We need to index multiple arrays
        for i in 0..bs {
            ipad.as_mut()[i] = k_prime.as_ref()[i] ^ Self::IPAD_BYTE;
            opad.as_mut()[i] = k_prime.as_ref()[i] ^ Self::OPAD_BYTE;
        }

        // Zero K′ before any fallible hash operation.
        k_prime.zeroize();

        /* --- Initialise inner hash --- */
        let mut hash = H::new();
        if let Err(error) = hash.update(&ipad.as_ref()[..bs]) {
            hash.zeroize();
            return Err(error);
        }

        Ok(Self {
            hash,
            ipad,
            opad,
            block_size: bs,
            is_finalized: false,
        })
    }

    /* ------------------------------------------------------------------ */
    /*                            Streaming API                           */
    /* ------------------------------------------------------------------ */

    /// Feed additional `data` into the MAC.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        if self.is_finalized {
            return Err(Error::param(
                "hmac_state",
                "Cannot update after finalization",
            ));
        }

        self.hash.update(data).map(|_| ())
    }

    /// Finalise and return the tag.
    pub fn finalize(&mut self) -> Result<ZeroizingBytes> {
        if self.is_finalized {
            return Err(Error::param("hmac_state", "HMAC already finalized"));
        }

        self.is_finalized = true;

        let mut inner_hash = match self.hash.finalize() {
            Ok(output) => {
                self.hash.zeroize();
                output
            }
            Err(error) => {
                self.hash.zeroize();
                return Err(error);
            }
        };

        let mut outer = H::new();
        if let Err(error) = outer.update(&self.opad.as_ref()[..self.block_size]) {
            inner_hash.zeroize();
            outer.zeroize();
            return Err(error);
        }
        if let Err(error) = outer.update(inner_hash.as_ref()) {
            inner_hash.zeroize();
            outer.zeroize();
            return Err(error);
        }
        inner_hash.zeroize();

        let mut output = match outer.finalize() {
            Ok(output) => output,
            Err(error) => {
                outer.zeroize();
                return Err(error);
            }
        };
        outer.zeroize();
        let tag = zeroizing_bytes_from_slice(output.as_ref());
        output.zeroize();
        Ok(tag)
    }

    /* ------------------------------------------------------------------ */
    /*                        Convenience wrappers                         */
    /* ------------------------------------------------------------------ */

    /// One-shot MAC helper.
    pub fn mac(key: &[u8], data: &[u8]) -> Result<ZeroizingBytes> {
        let mut h = Self::new(key)?;
        h.update(data)?;
        h.finalize()
    }

    /// Fixed-width verification of `tag` against `key` / `data`.
    ///
    /// Tag bytes are accumulated without an early exit. Public lengths, hash
    /// errors, allocation, and the returned boolean still have ordinary control
    /// flow, so this is not a whole-operation constant-time guarantee.
    pub fn verify(key: &[u8], data: &[u8], tag: &[u8]) -> Result<bool> {
        let expected = Self::mac(key, data)?;

        // Always iterate over the fixed, public digest length to avoid
        // timing variation when the caller supplies a shorter tag.
        let mut diff = 0u8;
        #[allow(clippy::needless_range_loop)] // Accessing both arrays with same index
        for i in 0..H::output_size() {
            let a = expected.get(i).copied().unwrap_or(0);
            let b = tag.get(i).copied().unwrap_or(0);
            diff |= a ^ b;
        }
        // Lengths are public, but compare them without narrowing `usize`: a
        // difference of 256 bytes must never disappear in an `as u8` cast.
        diff |= tag.len().ct_eq(&H::output_size()).unwrap_u8() ^ 1;

        Ok(diff.ct_eq(&0u8).unwrap_u8() == 1)
    }
}

impl<H> SecureZeroingType for Hmac<H>
where
    H: HashFunction + Default + Clone + Zeroize,
{
    fn zeroed() -> Self {
        Self {
            hash: H::default(),
            ipad: SecretBuffer::zeroed(),
            opad: SecretBuffer::zeroed(),
            block_size: 0,
            is_finalized: false,
        }
    }

    fn secure_clone(&self) -> Self {
        Self {
            hash: self.hash.clone(),
            ipad: self.ipad.secure_clone(),
            opad: self.opad.secure_clone(),
            block_size: self.block_size,
            is_finalized: self.is_finalized,
        }
    }
}

#[cfg(test)]
mod tests;
