//! Counter (CTR) mode with proper error propagation and secure memory handling
//!
//! Counter mode turns a block cipher into a stream cipher by encrypting
//! successive values of a counter and XORing the result with the plaintext.
//!
//! This implementation follows NIST SP 800-38A recommendations for CTR mode,
//! using a flexible nonce-counter format with secure memory handling.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::super::BlockCipher;
use crate::error::{validate, Result};
use crate::types::nonce::AesCtrCompatible;
use crate::types::Nonce;

// Import security types for memory safety
use dcrypt_common::security::barrier;

/// Counter position within the counter block
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CounterPosition {
    /// Counter is placed at the beginning of the block (bytes 0 to counter_size-1)
    /// This is common in some implementations, especially with 8-byte counters
    Prefix,

    /// Counter is placed at the end of the block (last counter_size bytes)
    /// This is the most common arrangement for AES-CTR
    Postfix,

    /// Counter is placed at a specific offset within the block
    /// Allows for custom layouts
    Custom(usize),
}

/// Counter mode implementation with secure memory handling
#[derive(Clone)]
pub struct Ctr<B: BlockCipher + Zeroize> {
    cipher: B,
    counter_block: Zeroizing<Vec<u8>>,
    counter_position: usize,
    counter_size: usize,
    keystream: Zeroizing<Vec<u8>>,
    keystream_pos: usize,
}

impl<B: BlockCipher + Zeroize> Zeroize for Ctr<B> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.counter_block.zeroize();
        self.counter_position.zeroize();
        self.counter_size.zeroize();
        self.keystream.zeroize();
        self.keystream_pos.zeroize();
    }
}

impl<B: BlockCipher + Zeroize> Drop for Ctr<B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<B: BlockCipher + Zeroize> ZeroizeOnDrop for Ctr<B> {}

impl<B: BlockCipher + Zeroize> Ctr<B> {
    /// Creates a new CTR mode instance with the default configuration
    ///
    /// * `cipher` - The block cipher to use
    /// * `nonce` - The nonce (must be compatible with CTR mode)
    ///
    /// This creates a standard CTR mode with the counter in the last 4 bytes
    /// and the nonce filling the beginning of the counter block.
    pub fn new<const N: usize>(cipher: B, nonce: &Nonce<N>) -> Result<Self>
    where
        Nonce<N>: AesCtrCompatible,
    {
        // Standard CTR mode with 4-byte counter at the end
        Self::with_counter_params(cipher, nonce, CounterPosition::Postfix, 4)
    }

    /// Creates a new CTR mode instance with custom counter parameters
    ///
    /// * `cipher` - The block cipher to use
    /// * `nonce` - The nonce (must be compatible with CTR mode)
    /// * `counter_pos` - Position of the counter within the counter block
    /// * `counter_size` - Size of the counter in bytes (1-8)
    ///
    /// This allows for flexible counter block layouts to match different standards
    /// and implementations.
    pub fn with_counter_params<const N: usize>(
        cipher: B,
        nonce: &Nonce<N>,
        counter_pos: CounterPosition,
        counter_size: usize,
    ) -> Result<Self>
    where
        Nonce<N>: AesCtrCompatible,
    {
        let block_size = B::block_size();

        // Validate counter size (1-8 bytes for u64 counter)
        validate::parameter(
            counter_size > 0 && counter_size <= 8,
            "counter_size",
            "Counter size must be between 1 and 8 bytes",
        )?;

        // Determine the counter position
        let position = match counter_pos {
            CounterPosition::Prefix => 0,
            CounterPosition::Postfix => block_size - counter_size,
            CounterPosition::Custom(offset) => {
                validate::parameter(
                    offset + counter_size <= block_size,
                    "counter_position",
                    "Counter with specified size doesn't fit at offset in block",
                )?;
                offset
            }
        };

        // Create and initialize the counter block with Zeroizing
        let mut counter_block = Zeroizing::new(vec![0u8; block_size]);

        // Handle nonce according to its size
        let max_nonce_size = block_size - counter_size;

        // If nonce is too large, truncate it
        let effective_nonce = if N > max_nonce_size {
            &nonce.as_ref()[0..max_nonce_size]
        } else {
            nonce.as_ref()
        };

        // Fill in the nonce
        if position == 0 {
            // Counter is at the beginning, place nonce after it
            counter_block[counter_size..counter_size + effective_nonce.len()]
                .copy_from_slice(effective_nonce);
        } else {
            // Counter is elsewhere, place nonce at the beginning by default
            counter_block[0..effective_nonce.len()].copy_from_slice(effective_nonce);
        }

        Ok(Self {
            cipher,
            counter_block,
            counter_position: position,
            counter_size,
            keystream: Zeroizing::new(Vec::new()),
            keystream_pos: 0,
        })
    }

    /// Generate keystream for CTR mode with secure memory handling
    fn generate_keystream(&mut self) -> Result<()> {
        let block_size = B::block_size();

        // Create a new zeroizing keystream buffer
        self.keystream = Zeroizing::new(vec![0u8; block_size]);

        // Use memory barrier to prevent optimization
        barrier::compiler_fence_seq_cst();

        // Copy current counter block to keystream
        self.keystream.copy_from_slice(&self.counter_block);

        // Encrypt the counter value
        self.cipher.encrypt_block(&mut self.keystream)?;

        // Increment the counter based on its size
        self.increment_counter();

        self.keystream_pos = 0;

        // Use memory barrier after operation
        barrier::compiler_fence_seq_cst();

        Ok(())
    }

    /// Increment the counter in the counter block
    fn increment_counter(&mut self) {
        match self.counter_size {
            8 => {
                let mut counter = [0u8; 8];
                counter.copy_from_slice(
                    &self.counter_block[self.counter_position..self.counter_position + 8],
                );
                let value = u64::from_be_bytes(counter);
                counter.copy_from_slice(&value.wrapping_add(1).to_be_bytes());
                self.counter_block[self.counter_position..self.counter_position + 8]
                    .copy_from_slice(&counter);

                // Zeroize the temporary counter array
                counter.zeroize();
            }
            4 => {
                let mut counter = [0u8; 4];
                counter.copy_from_slice(
                    &self.counter_block[self.counter_position..self.counter_position + 4],
                );
                let value = u32::from_be_bytes(counter);
                counter.copy_from_slice(&value.wrapping_add(1).to_be_bytes());
                self.counter_block[self.counter_position..self.counter_position + 4]
                    .copy_from_slice(&counter);

                // Zeroize the temporary counter array
                counter.zeroize();
            }
            // For other counter sizes, we'll read/write the appropriate number of bytes
            size => {
                let mut value: u64 = 0;

                // Read counter value (big-endian)
                for i in 0..size {
                    value = (value << 8) | (self.counter_block[self.counter_position + i] as u64);
                }

                // Increment counter
                value = value.wrapping_add(1);

                // Write counter value back (big-endian)
                for i in 0..size {
                    self.counter_block[self.counter_position + size - 1 - i] = (value & 0xff) as u8;
                    value >>= 8;
                }
            }
        }
    }

    /// Encrypts a message using CTR mode
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());

        // Use memory barrier before sensitive operations
        barrier::compiler_fence_seq_cst();

        for &byte in plaintext {
            if self.keystream_pos >= self.keystream.len() {
                self.generate_keystream()?;
            }

            ciphertext.push(byte ^ self.keystream[self.keystream_pos]);
            self.keystream_pos += 1;
        }

        // Use memory barrier after sensitive operations
        barrier::compiler_fence_seq_cst();

        Ok(ciphertext)
    }

    /// Decrypts a message using CTR mode
    /// In CTR mode, encryption and decryption are the same operation
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(ciphertext)
    }

    /// Process data in place (encrypt or decrypt)
    pub fn process(&mut self, data: &mut [u8]) -> Result<()> {
        // Use memory barrier before sensitive operations
        barrier::compiler_fence_seq_cst();

        for byte in data.iter_mut() {
            // Generate new keystream block if needed
            if self.keystream_pos >= self.keystream.len() {
                self.generate_keystream()?;
            }

            // XOR data with keystream
            *byte ^= self.keystream[self.keystream_pos];
            self.keystream_pos += 1;
        }

        // Use memory barrier after sensitive operations
        barrier::compiler_fence_seq_cst();

        Ok(())
    }

    /// Generate keystream directly into an output buffer
    pub fn keystream(&mut self, output: &mut [u8]) -> Result<()> {
        // Zero the output buffer
        for byte in output.iter_mut() {
            *byte = 0;
        }

        // Force generation from a block boundary (ignore any leftover position)
        self.keystream_pos = self.keystream.len();

        // Then run the encryption pass to copy the keystream
        self.process(output)
    }

    /// Seek to a specific block position
    ///
    /// `block_offset` is the number of full blocks that have been consumed;
    /// after seeking, the next generated block will be at `block_offset + 1`.
    pub fn seek(&mut self, block_offset: u32) {
        // Calculate the counter value based on the offset
        let mut counter_value = [0u8; 8];
        counter_value[4..].copy_from_slice(&block_offset.wrapping_add(1).to_be_bytes());

        // Update counter in the counter block
        for i in 0..self.counter_size {
            let idx = self.counter_position + self.counter_size - 1 - i;
            self.counter_block[idx] = counter_value[7 - i];
        }

        // Force regeneration on next use
        self.keystream_pos = self.keystream.len();

        // Clear any old keystream with Zeroizing
        self.keystream = Zeroizing::new(Vec::new());

        // Zeroize the temporary counter value
        counter_value.zeroize();
    }

    /// Set the counter value directly
    ///
    /// This allows for manual control of the counter, which can be useful for
    /// seeking to specific positions in the stream.
    ///
    /// # Arguments
    /// * `counter` - The new counter value
    pub fn set_counter(&mut self, counter: u32) {
        // Update counter in the counter block
        let counter_pos = self.counter_position;

        // Write the counter value in big-endian format
        // This handles various counter sizes (1-8 bytes)
        let counter_bytes = counter.to_be_bytes();
        let start_idx = 4 - self.counter_size;

        for i in 0..self.counter_size {
            if start_idx + i < 4 {
                // Only copy if within counter_bytes bounds
                self.counter_block[counter_pos + i] = counter_bytes[start_idx + i];
            }
        }

        // Force regeneration of keystream on next use
        self.keystream_pos = self.keystream.len();
    }

    /// Reset to initial state with the same key and nonce
    ///
    /// This resets the counter to 0 and clears any buffered keystream.
    ///
    /// # Arguments
    /// * `nonce` - Optional new nonce to use (if not provided, keeps the current nonce)
    /// * `counter` - Optional initial counter value (defaults to 0)
    pub fn reset<const N: usize>(&mut self, nonce: Option<&Nonce<N>>, counter: u32) -> Result<()>
    where
        Nonce<N>: AesCtrCompatible,
    {
        // Use memory barrier before sensitive operations
        barrier::compiler_fence_seq_cst();

        // Update nonce if provided
        if let Some(new_nonce) = nonce {
            let block_size = B::block_size();
            let max_nonce_size = block_size - self.counter_size;

            // If nonce is too large, truncate it
            let effective_nonce = if N > max_nonce_size {
                &new_nonce.as_ref()[0..max_nonce_size]
            } else {
                new_nonce.as_ref()
            };

            // Clear the counter block
            for b in &mut *self.counter_block {
                *b = 0;
            }

            // Fill in the nonce
            let counter_pos = match self.counter_position {
                0 => self.counter_size, // Counter is at beginning, nonce follows
                _ => 0,                 // Otherwise nonce is at beginning
            };

            // Copy the new nonce
            self.counter_block[counter_pos..counter_pos + effective_nonce.len()]
                .copy_from_slice(effective_nonce);
        }

        // Set the counter value
        self.set_counter(counter);

        // Clear keystream
        self.keystream = Zeroizing::new(Vec::new());
        self.keystream_pos = 0;

        // Use memory barrier after sensitive operations
        barrier::compiler_fence_seq_cst();

        Ok(())
    }
}

#[cfg(test)]
mod tests;
