//! GHASH implementation for Galois/Counter Mode (GCM)
//!
//! This module provides an implementation of the GHASH function as specified in
//! NIST SP 800-38D for use with GCM mode.
//!
//! ## Implementation Note
//!
//! NIST SP 800-38D allows for multiple valid implementations of the Galois field
//! arithmetic that underpins GHASH. This implementation has been tested against
//! official NIST vectors for the complete GCM algorithm, checking
//! interoperability and correctness of the overall authenticated encryption.
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
//! The tests include NIST CAVP/ACVP data for GCM mode. Passing those vectors is
//! a correctness gate, not formal module validation or certification.
//!
//! ## Constant-Time Guarantees
//!
//! GF(2^128) multiplication uses fixed-iteration, mask-based arithmetic with
//! respect to the hash key and input blocks. Processing time still depends on
//! the public input lengths, as permitted by the GCM interface.

use crate::error::{validate, Error, Result};
use dcrypt_internal::zeroing::Zeroize;

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
        let mut h_copy = [0u8; GCM_BLOCK_SIZE];
        h_copy.copy_from_slice(h);
        let y = [0u8; GCM_BLOCK_SIZE];
        let instance = Self { h: h_copy, y };
        h_copy.zeroize();
        instance
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

        // Create a temporary block with zeros
        let mut temp_block = [0u8; GCM_BLOCK_SIZE];

        // Copy only the valid, public-length portion of the input.
        for i in 0..GCM_BLOCK_SIZE {
            // Only copy if within valid range (constant-time selection)
            // For each position i, we compute a mask that's 0xFF if i < block_len, and 0x00 otherwise
            // This avoids branches and ensures constant-time operation
            let in_range = ((block_len as isize - 1 - i as isize) >> 63) as u8;
            let mask = !in_range; // 0xFF if i < block_len, 0x00 otherwise

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
        self.y = Self::gf_multiply(&self.y, &self.h);

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

    /// Performs multiplication in GF(2^128) according to the NIST SP 800-38D specification.
    ///
    /// This implements GHASH's specific bit ordering convention where:
    /// - The least significant bit of each byte represents the highest-degree coefficient
    /// - The most significant bit represents the lowest-degree coefficient
    ///
    /// This implementation is constant-time with respect to the input data.
    ///
    /// # Arguments
    /// * `x` - First 16-byte operand.
    /// * `y` - Second 16-byte operand.
    ///
    /// # Returns
    /// A 16-byte array representing the product in GF(2^128).
    fn gf_multiply(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
        let mut z = [0u8; 16];
        let mut v = *y;

        // Process each byte of x
        for x_byte in x.iter() {
            // Process each bit in the byte (MSB first in byte representation)
            for j in 0..8 {
                // Extract the bit value (0 or 1) in constant time
                let bit_val = (x_byte >> (7 - j)) & 1;

                // Create a mask from the bit: 0xFF if bit=1, 0x00 if bit=0
                let mask = 0u8.wrapping_sub(bit_val);

                // XOR the value of V into Z if the bit is set (in constant time)
                for (z_byte, v_byte) in z.iter_mut().zip(v.iter()) {
                    *z_byte ^= v_byte & mask;
                }

                // Check if LSB of V is set (in constant time)
                let lsb = v[15] & 1;

                // Create mask for the reduction step: 0xFF if lsb=1, 0x00 if lsb=0
                let lsb_mask = 0u8.wrapping_sub(lsb);

                // Right shift V by 1 bit (in big-endian representation)
                let mut carry = 0;
                for v_byte in &mut v {
                    let next_carry = *v_byte & 1;
                    *v_byte = (*v_byte >> 1) | (carry << 7);
                    carry = next_carry;
                }

                // If LSB was 1, XOR with the reduction polynomial in constant time
                // The polynomial is x^128 + x^7 + x^2 + x + 1
                // In GCM bit ordering, this is 0xE1 in the MSB
                v[0] ^= 0xE1 & lsb_mask;
            }
        }

        z
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
