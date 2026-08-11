//! GHASH implementation for Galois/Counter Mode (GCM)
//!
//! This module provides an implementation of the GHASH function as specified in
//! NIST SP 800-38D for use with GCM mode.
//!
//! ## Implementation Note
//!
//! NIST SP 800-38D allows for multiple valid implementations of the Galois field
//! arithmetic that underpins GHASH. This implementation has been tested against
//! the repository's byte-bound GCM known-answer corpus, checking correctness of
//! the overall authenticated encryption. Upstream acquisition provenance for
//! the local fixtures is unverified.
//!
//! The Galois field multiplication in particular may produce intermediate values
//! that differ from other implementations (like OpenSSL, Bouncy Castle, etc.)
//! while still producing correct final results for the full GCM operation.
//!
//! This is due to differences in:
//! 1. Bit ordering conventions
//! 2. Polynomial reduction implementation
//! 3. Internal state representation
//!
//! The tests include repository CAVP/ACVP-format data for GCM mode. Passing
//! those locally bound fixtures is a correctness gate, not authenticated
//! upstream provenance, formal module validation, or certification.
//!
//! ## Timing-sensitive implementation properties
//!
//! GF(2^128) multiplication uses fixed-iteration, mask-based arithmetic with
//! respect to the hash key and input blocks. Processing time still depends on
//! the public input lengths, as permitted by the GCM interface.
//! Release tooling checks the optimized loop and arithmetic-mask shape on every
//! supported target for the selected release compiler. This is not a blanket
//! constant-time proof for every compiler or target.

use crate::error::{validate, Error, Result};
use dcrypt_internal::zeroing::{Zeroize, Zeroizing};

const GCM_BLOCK_SIZE: usize = 16;

/// `GHash` struct for computing the GHASH function in GCM mode.
#[derive(Clone)]
pub struct GHash {
    /// The hash key H, a 16-byte array.
    h: [u8; GCM_BLOCK_SIZE],
    /// The current hash value Y, a 16-byte array.
    y: [u8; GCM_BLOCK_SIZE],
}

impl Zeroize for GHash {
    fn zeroize(&mut self) {
        self.h.zeroize();
        self.y.zeroize();
    }
}

impl Drop for GHash {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl GHash {
    /// Creates a new `GHash` instance with the given hash key `h`.
    ///
    /// # Arguments
    /// * `h` - A 16-byte array representing the hash key.
    ///
    /// # Returns
    /// A new `GHash` instance with `y` initialized to zero.
    pub fn new(h: &[u8; GCM_BLOCK_SIZE]) -> Self {
        let mut h_copy = Zeroizing::new([0u8; GCM_BLOCK_SIZE]);
        h_copy.copy_from_slice(h);
        let y = [0u8; GCM_BLOCK_SIZE];
        Self {
            h: h_copy.into_inner(),
            y,
        }
    }

    /// Updates the hash with input data, processing it in 16-byte blocks.
    ///
    /// # Arguments
    /// * `data` - The input data to process.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if processing fails.
    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0;

        // Process full 16-byte blocks
        while offset + GCM_BLOCK_SIZE <= data.len() {
            self.update_block(&data[offset..offset + GCM_BLOCK_SIZE], GCM_BLOCK_SIZE)?;
            offset += GCM_BLOCK_SIZE;
        }

        // Handle any remaining partial block
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.update_block(&data[offset..], remaining)?;
        }

        Ok(())
    }

    /// Updates the hash with a single block, padding with zeros if necessary.
    /// Processing depends on the public block length and uses fixed-width field
    /// arithmetic for the selected block.
    ///
    /// # Arguments
    /// * `block` - The input block data.
    /// * `block_len` - The length of the block (up to 16 bytes).
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the block length is invalid.
    pub fn update_block(&mut self, block: &[u8], block_len: usize) -> Result<()> {
        validate::max_length("GHASH block", block_len, GCM_BLOCK_SIZE)?;
        validate::min_length("GHASH block input", block.len(), block_len)?;

        // Create a temporary block with zeros
        let mut temp_block = [0u8; GCM_BLOCK_SIZE];

        // Copy only the valid, public-length portion of the input.
        for i in 0..GCM_BLOCK_SIZE {
            // Only copy if within valid range (constant-time selection)
            // For each position i, we compute a mask that's 0xFF if i < block_len, and 0x00 otherwise
            // This avoids branches and ensures constant-time operation
            let in_range = i.wrapping_sub(block_len) >> (usize::BITS - 1);
            let mask = 0u8.wrapping_sub(in_range as u8);

            // Only read from input if in range (avoid out-of-bounds access).
            let source_byte = if i < block_len { block[i] } else { 0 };

            // Masked assignment (constant-time selection)
            temp_block[i] = source_byte & mask;
        }

        // XOR with current state
        for (y_byte, temp_byte) in self.y.iter_mut().zip(temp_block.iter()) {
            *y_byte ^= temp_byte;
        }

        // Multiply by H in GF(2^128)
        let product = Self::gf_multiply(&self.y, &self.h);
        self.y.copy_from_slice(&*product);

        Ok(())
    }

    /// Updates the hash with the lengths of AAD and ciphertext.
    ///
    /// # Arguments
    /// * `aad_len` - Length of the Additional Authenticated Data in bytes.
    /// * `cipher_len` - Length of the ciphertext in bytes.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if processing fails.
    pub fn update_lengths(&mut self, aad_len: u64, cipher_len: u64) -> Result<()> {
        let mut length_block = [0u8; GCM_BLOCK_SIZE];
        let aad_bits = aad_len.checked_mul(8).ok_or(Error::Processing {
            operation: "GHASH length encoding",
            details: "AAD length exceeds the GCM bit-length field",
        })?;
        let cipher_bits = cipher_len.checked_mul(8).ok_or(Error::Processing {
            operation: "GHASH length encoding",
            details: "ciphertext length exceeds the GCM bit-length field",
        })?;
        // AAD length in bits (big-endian)
        length_block[0..8].copy_from_slice(&aad_bits.to_be_bytes());
        // Ciphertext length in bits (big-endian)
        length_block[8..16].copy_from_slice(&cipher_bits.to_be_bytes());
        self.update_block(&length_block, GCM_BLOCK_SIZE)
    }

    /// Returns the final hash value.
    ///
    /// # Returns
    /// A 16-byte array containing the GHASH result.
    pub fn finalize(&self) -> [u8; GCM_BLOCK_SIZE] {
        self.y
    }

    /// Returns the final hash value in wiping storage for internal keyed use.
    pub(crate) fn finalize_protected(&self) -> Zeroizing<[u8; GCM_BLOCK_SIZE]> {
        Zeroizing::new(self.y)
    }

    /// Performs multiplication in GF(2^128) according to the NIST SP 800-38D specification.
    ///
    /// This implements GHASH's specific bit ordering convention where:
    /// - The least significant bit of each byte represents the highest-degree coefficient
    /// - The most significant bit represents the lowest-degree coefficient
    ///
    /// At source level this uses a fixed 128 steps and arithmetic masks rather
    /// than data-dependent selection. Release tooling checks the optimized
    /// compiler shape on each supported target; this does not claim a universal
    /// constant-time guarantee for every compiler and target.
    ///
    /// # Arguments
    /// * `x` - First 16-byte operand.
    /// * `y` - Second 16-byte operand.
    ///
    /// # Returns
    /// A 16-byte array representing the product in GF(2^128).
    #[inline(never)]
    fn gf_multiply(x: &[u8; 16], y: &[u8; 16]) -> Zeroizing<[u8; 16]> {
        // Keep each field element in one logical integer. LLVM turned the old
        // byte-at-a-time masked XOR into a branch that skipped sixteen XORs
        // when an accumulator bit was zero. After the first GHASH block those
        // bits depend on the secret hash subkey H. The whole-width masks below
        // retain one fixed 128-iteration loop in optimized supported-target
        // builds; the release compiler-shape gate enforces that property.
        const REDUCTION: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

        let mut x_value = Zeroizing::new(u128::from_be_bytes(*x));
        let mut v = Zeroizing::new(u128::from_be_bytes(*y));
        let mut z = Zeroizing::new(0u128);
        let mut x_mask = Zeroizing::new(0u128);
        let mut reduction_mask = Zeroizing::new(0u128);

        for _ in 0..128 {
            *x_mask = 0u128.wrapping_sub(*x_value >> 127);
            *z ^= *v & *x_mask;

            *reduction_mask = 0u128.wrapping_sub(*v & 1);
            *v = (*v >> 1) ^ (REDUCTION & *reduction_mask);
            *x_value <<= 1;
        }

        Zeroizing::new(z.to_be_bytes())
    }
}

/// Process a message with GHASH
///
/// This is a helper function that creates a GHASH instance, processes the AAD
/// and ciphertext, and returns the final GHASH tag.
///
/// # Returns
/// The GHASH tag as a 16-byte array, or an error if processing fails.
pub fn process_ghash(
    h: &[u8; GCM_BLOCK_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; GCM_BLOCK_SIZE]> {
    let mut ghash_instance = GHash::new(h);

    // Process AAD with timing balancing
    ghash_instance.update(aad)?;

    // Process ciphertext with timing balancing
    ghash_instance.update(ciphertext)?;

    // Add length block
    ghash_instance.update_lengths(aad.len() as u64, ciphertext.len() as u64)?;

    // Return final GHASH value
    Ok(ghash_instance.finalize())
}

#[cfg(test)]
mod tests;
