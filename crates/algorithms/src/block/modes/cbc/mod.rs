//! Cipher Block Chaining (CBC) mode implementation
//!
//! CBC mode is a block cipher mode of operation that provides confidentiality
//! by XORing each plaintext block with the previous ciphertext block before
//! encryption. The first block is XORed with an initialization vector (IV).
//!
//! This implementation follows NIST SP 800-38A specifications and provides
//! secure memory handling with automatic zeroization of sensitive data.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use dcrypt_internal::zeroing::{boxed_bytes_zeroed, Zeroize, ZeroizeOnDrop, Zeroizing};

use super::super::{BlockCipher, CipherAlgorithm};
use crate::error::{validate, Error, Result};
use crate::types::Nonce;

/// Marker trait for nonces that are compatible with CBC mode
pub trait CbcCompatible: crate::types::sealed::Sealed {}

// Implement CbcCompatible trait for Nonce types that match block sizes
impl<const N: usize> CbcCompatible for Nonce<N> {}

/// CBC mode implementation
#[derive(Clone)]
pub struct Cbc<B: BlockCipher + Zeroize + ZeroizeOnDrop> {
    cipher: B,
    iv: Vec<u8>,
}

impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> Zeroize for Cbc<B> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.iv.zeroize();
    }
}

impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> Drop for Cbc<B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> ZeroizeOnDrop for Cbc<B> {}

impl<B: BlockCipher + CipherAlgorithm + Zeroize + ZeroizeOnDrop> Cbc<B> {
    /// Creates a new CBC mode instance with the given cipher and IV
    ///
    /// The IV (nonce) must be the same size as the block size of the cipher.
    pub fn new<const N: usize>(cipher: B, iv: &Nonce<N>) -> Result<Self>
    where
        Nonce<N>: CbcCompatible,
    {
        // Validate that the nonce size matches the block size at runtime
        validate::length("CBC initialization vector", N, B::block_size())?;

        Ok(Self {
            cipher,
            iv: iv.as_ref().to_vec(),
        })
    }

    /// Encrypts a message using CBC mode
    ///
    /// The plaintext must be a multiple of the block size.
    /// For plaintext that is not a multiple of the block size,
    /// padding must be applied before calling this function.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Validate plaintext length is a multiple of block size
        let block_size = B::block_size();
        if plaintext.len() % block_size != 0 {
            let expected_len = ((plaintext.len() / block_size) + 1) * block_size;
            return Err(Error::Length {
                context: "CBC plaintext",
                expected: expected_len,
                actual: plaintext.len(),
            });
        }

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut prev_block = self.iv.clone();

        // Process the plaintext in blocks
        for chunk in plaintext.chunks(block_size) {
            let mut block = Zeroizing::new([0u8; 16]); // AES block size is 16 bytes
            block[..chunk.len()].copy_from_slice(chunk);

            // XOR with previous ciphertext block (or IV for the first block)
            for i in 0..block_size {
                block[i] ^= prev_block[i];
            }

            // Encrypt the XORed block
            self.cipher.encrypt_block(&mut block[..])?;

            // Append to ciphertext and update previous block
            ciphertext.extend_from_slice(&block[..]);
            prev_block = block.to_vec();
        }

        Ok(ciphertext)
    }

    /// Decrypts a message using CBC mode
    ///
    /// The ciphertext must be a multiple of the block size.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Validate ciphertext length is a multiple of block size
        let block_size = B::block_size();
        if ciphertext.len() % block_size != 0 {
            let expected_len = ((ciphertext.len() / block_size) + 1) * block_size;
            return Err(Error::Length {
                context: "CBC ciphertext",
                expected: expected_len,
                actual: ciphertext.len(),
            });
        }

        let mut plaintext = Zeroizing::new(boxed_bytes_zeroed(ciphertext.len()));
        let mut prev_block = self.iv.clone();
        let mut plaintext_offset = 0usize;

        // Process the ciphertext in blocks
        for chunk in ciphertext.chunks(block_size) {
            let mut block = Zeroizing::new([0u8; 16]); // AES block size is 16 bytes
            block[..chunk.len()].copy_from_slice(chunk);

            // Save current ciphertext block
            let current_block = *block;

            // Decrypt the block
            self.cipher.decrypt_block(&mut block[..])?;

            // XOR with previous ciphertext block (or IV for the first block)
            for i in 0..block_size {
                block[i] ^= prev_block[i];
            }

            // Append to plaintext and update previous block
            plaintext[plaintext_offset..plaintext_offset + block_size]
                .copy_from_slice(&block[..block_size]);
            plaintext_offset += block_size;
            prev_block = current_block.to_vec();
        }

        Ok(plaintext.into_inner().into_vec())
    }
}

#[cfg(test)]
mod tests;
