//! Galois/Counter Mode (GCM) for authenticated encryption
//!
//! GCM is an authenticated encryption with associated data (AEAD) mode
//! that provides both confidentiality and authenticity. It combines the
//! Counter (CTR) mode with the GHASH authentication function.
//!
//! ## Implementation Note
//!
//! This implementation has been validated against official NIST Cryptographic Algorithm
//! Validation Program (CAVP) test vectors. It follows the Galois/Counter Mode (GCM)
//! specification as defined in NIST Special Publication 800-38D.
//!
//! ## Constant-Time Guarantees
//!
//! This implementation is designed to be timing-attack resistant:
//! - All cryptographic operations are performed before authentication validation
//! - Authentication tag verification uses the `subtle` crate's constant-time comparison
//! - Timing-safe conditional operations are performed without data-dependent branches
//! - Memory barriers prevent compiler optimizations that could introduce timing variation

#![cfg_attr(not(feature = "std"), no_std)]

// Conditionally import Vec based on available features
#[cfg(not(feature = "std"))]
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use byteorder::{BigEndian, ByteOrder};
#[cfg(not(feature = "std"))]
use portable_atomic::{compiler_fence, Ordering};
#[cfg(feature = "std")]
use std::sync::atomic::{compiler_fence, Ordering};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Import security types from dcrypt-core - FIXED PATH
use dcrypt_common::security::{SecretBuffer, SecureZeroingType};

// Fix import paths by using crate:: for internal modules
use crate::block::BlockCipher;
use dcrypt_api::traits::symmetric::{DecryptOperation, EncryptOperation, Operation};
use dcrypt_api::traits::AuthenticatedCipher;
use dcrypt_api::traits::SymmetricCipher;

use crate::error::{validate, Error, Result};
use crate::types::nonce::AesGcmCompatible; // Import the AesGcmCompatible trait
use crate::types::Nonce; // Using generic Nonce type
use crate::types::SecretBytes;
use dcrypt_api::error::Error as CoreError;
use dcrypt_api::types::Ciphertext;

// Import the GHASH module
mod ghash;
use ghash::{process_ghash, GHash};

// GCM constants
const GCM_BLOCK_SIZE: usize = 16;
const GCM_TAG_SIZE: usize = 16;

/// GCM mode implementation
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Gcm<B: BlockCipher + Zeroize + ZeroizeOnDrop> {
    cipher: B,
    h: SecretBuffer<GCM_BLOCK_SIZE>, // GHASH key (encrypted all-zero block) - now secured
    nonce: Zeroizing<Vec<u8>>,
    tag_len: usize, // desired tag length in bytes
}

/// Operation for GCM encryption operations
pub struct GcmEncryptOperation<'a, B: BlockCipher + Zeroize + ZeroizeOnDrop> {
    cipher: &'a Gcm<B>,
    nonce: Option<&'a Nonce<12>>, // Using generic Nonce<12> instead of Nonce12
    aad: Option<&'a [u8]>,
}

/// Operation for GCM decryption operations
pub struct GcmDecryptOperation<'a, B: BlockCipher + Zeroize + ZeroizeOnDrop> {
    cipher: &'a Gcm<B>,
    nonce: Option<&'a Nonce<12>>, // Using generic Nonce<12> instead of Nonce12
    aad: Option<&'a [u8]>,
}

impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> Gcm<B> {
    /// Creates a new GCM mode instance with default (16-byte) tag.
    pub fn new<const N: usize>(cipher: B, nonce: &Nonce<N>) -> Result<Self>
    where
        Nonce<N>: AesGcmCompatible,
    {
        Self::new_with_tag_len(cipher, nonce, GCM_TAG_SIZE)
    }

    /// Creates a new GCM mode instance with specified tag length (in bytes).
    ///
    /// tag_len must be between 1 and 16 (inclusive).
    pub fn new_with_tag_len<const N: usize>(
        cipher: B,
        nonce: &Nonce<N>,
        tag_len: usize,
    ) -> Result<Self>
    where
        Nonce<N>: AesGcmCompatible,
    {
        // Ensure block size
        validate::parameter(
            B::block_size() == GCM_BLOCK_SIZE,
            "block_size",
            "GCM only works with 128-bit block ciphers",
        )?;

        validate::parameter(
            !nonce.is_empty() && nonce.len() <= 16,
            "nonce_length",
            "GCM nonce must be between 1 and 16 bytes",
        )?;

        validate::parameter(
            (1..=GCM_TAG_SIZE).contains(&tag_len),
            "tag_length",
            "GCM tag length must be between 1 and 16 bytes",
        )?;

        // Generate GHASH key H (encrypt all-zero block)
        let mut h_bytes = [0u8; GCM_BLOCK_SIZE];
        cipher.encrypt_block(&mut h_bytes)?;

        // Wrap the GHASH key in SecretBuffer for secure storage
        let h = SecretBuffer::new(h_bytes);

        Ok(Self {
            cipher,
            h,
            nonce: Zeroizing::new(nonce.as_ref().to_vec()),
            tag_len,
        })
    }

    /// Generate initial counter value J0
    fn generate_j0(&self) -> Result<[u8; GCM_BLOCK_SIZE]> {
        let mut j0 = [0u8; GCM_BLOCK_SIZE];
        if self.nonce.len() == 12 {
            j0[..12].copy_from_slice(&self.nonce);
            j0[15] = 1;
        } else {
            // Convert SecretBuffer reference to array reference
            let h_array: &[u8; GCM_BLOCK_SIZE] = self
                .h
                .as_ref()
                .try_into()
                .expect("SecretBuffer has correct size");

            let mut g = GHash::new(h_array);
            g.update(&self.nonce)?;
            let rem = self.nonce.len() % GCM_BLOCK_SIZE;
            if rem != 0 {
                g.update(&vec![0u8; GCM_BLOCK_SIZE - rem])?;
            }
            g.update_lengths(0, self.nonce.len() as u64)?;
            j0 = g.finalize();
        }
        Ok(j0)
    }

    /// Generate encryption keystream for CTR mode
    fn generate_keystream(
        &self,
        j0: &[u8; GCM_BLOCK_SIZE],
        data_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let num_blocks = data_len.div_ceil(GCM_BLOCK_SIZE);
        let mut keystream = Zeroizing::new(Vec::with_capacity(num_blocks * GCM_BLOCK_SIZE));

        let mut counter = *j0;
        let mut ctr_val = BigEndian::read_u32(&counter[12..16]).wrapping_add(1);
        BigEndian::write_u32(&mut counter[12..16], ctr_val);

        for _ in 0..num_blocks {
            let mut block = counter;
            self.cipher.encrypt_block(&mut block)?;
            keystream.extend_from_slice(&block);
            ctr_val = ctr_val.wrapping_add(1);
            BigEndian::write_u32(&mut counter[12..16], ctr_val);
        }

        Ok(keystream)
    }

    /// Generate authentication tag (full 16 bytes)
    fn generate_tag(
        &self,
        j0: &[u8; GCM_BLOCK_SIZE],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<[u8; GCM_TAG_SIZE]> {
        // Convert SecretBuffer reference to array reference
        let h_array: &[u8; GCM_BLOCK_SIZE] = self
            .h
            .as_ref()
            .try_into()
            .expect("SecretBuffer has correct size");

        // Process the AAD and ciphertext with GHASH
        let mut tag = process_ghash(h_array, aad, ciphertext)?;

        // Encrypt the initial counter block
        let mut j0_copy = *j0;
        self.cipher.encrypt_block(&mut j0_copy)?;

        // XOR the encrypted counter with the GHASH result
        for i in 0..GCM_TAG_SIZE {
            tag[i] ^= j0_copy[i];
        }

        Ok(tag)
    }

    /// Internal encrypt method - exposed for testing
    pub fn internal_encrypt(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let aad = associated_data.unwrap_or(&[]);
        let j0 = self.generate_j0()?;

        let mut ciphertext = Vec::with_capacity(plaintext.len() + self.tag_len);
        if !plaintext.is_empty() {
            let keystream = self.generate_keystream(&j0, plaintext.len())?;
            for i in 0..plaintext.len() {
                ciphertext.push(plaintext[i] ^ keystream[i]);
            }
        }

        let full_tag = self.generate_tag(&j0, aad, &ciphertext)?;
        ciphertext.extend_from_slice(&full_tag[..self.tag_len]);
        Ok(ciphertext)
    }

    /// Internal decrypt method with improved constant-time implementation - exposed for testing
    pub fn internal_decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        // Length check is not a secret-dependent branch
        validate::min_length("GCM ciphertext", ciphertext.len(), self.tag_len)?;

        let aad = associated_data.unwrap_or(&[]);
        let ciphertext_len = ciphertext.len() - self.tag_len;
        let (ciphertext_data, received_tag) = ciphertext.split_at(ciphertext_len);

        // Generate initial counter and expected tag
        let j0 = self.generate_j0()?;
        let full_expected = self.generate_tag(&j0, aad, ciphertext_data)?;
        let expected_tag = &full_expected[..self.tag_len];

        // Generate keystream and decrypt data
        let keystream = self.generate_keystream(&j0, ciphertext_len)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext_len));
        for i in 0..ciphertext_len {
            plaintext.push(ciphertext_data[i] ^ keystream[i]);
        }

        // Memory barrier to ensure all decryption operations complete before comparison
        compiler_fence(Ordering::SeqCst);

        // Constant-time tag comparison that doesn't leak timing information
        let tag_matches = expected_tag.ct_eq(received_tag);

        // Memory barrier to ensure comparison is done before selecting result
        compiler_fence(Ordering::SeqCst);

        // Convert the constant-time comparison result to an error if needed
        if tag_matches.unwrap_u8() == 0 {
            // Zeroize the plaintext securely before returning to avoid leaking data
            // This runs on the error path, but doesn't leak timing information about the tag
            // since all cryptographic work is already done by this point
            Err(Error::Authentication { algorithm: "GCM" })
        } else {
            Ok(plaintext.to_vec())
        }
    }
}

// Implement SecureZeroingType for Gcm
impl<B: BlockCipher + Clone + Zeroize + ZeroizeOnDrop> SecureZeroingType for Gcm<B> {
    fn zeroed() -> Self {
        // This is a bit tricky since we need a cipher instance
        // For now, we'll panic if called, as this shouldn't be used directly
        panic!("Cannot create a zeroed GCM instance without a cipher")
    }

    fn secure_clone(&self) -> Self {
        self.clone()
    }
}

// Implement the marker trait AuthenticatedCipher
impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> AuthenticatedCipher for Gcm<B> {
    const TAG_SIZE: usize = GCM_TAG_SIZE;
    const ALGORITHM_ID: &'static str = "GCM";
}

// Implement SymmetricCipher trait
impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> SymmetricCipher for Gcm<B> {
    // We can't use B::KEY_SIZE in const generic expressions, so we'll use a different approach
    type Key = SecretBytes<32>; // Using a fixed size for demonstration - adjust based on your needs
    type Nonce = Nonce<12>; // Using generic Nonce<12> instead of Nonce12
    type Ciphertext = Ciphertext;
    type EncryptOperation<'a>
        = GcmEncryptOperation<'a, B>
    where
        Self: 'a;
    type DecryptOperation<'a>
        = GcmDecryptOperation<'a, B>
    where
        Self: 'a;

    fn name() -> &'static str {
        "GCM"
    }

    fn encrypt(&self) -> <Self as SymmetricCipher>::EncryptOperation<'_> {
        GcmEncryptOperation {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }

    fn decrypt(&self) -> <Self as SymmetricCipher>::DecryptOperation<'_> {
        GcmDecryptOperation {
            cipher: self,
            nonce: None,
            aad: None,
        }
    }

    fn generate_key<R: rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
    ) -> std::result::Result<<Self as SymmetricCipher>::Key, CoreError> {
        let mut key_data = [0u8; 32]; // Using same fixed size as type Key
        rng.fill_bytes(&mut key_data);
        Ok(SecretBytes::new(key_data))
    }

    fn generate_nonce<R: rand::RngCore + rand::CryptoRng>(
        rng: &mut R,
    ) -> std::result::Result<<Self as SymmetricCipher>::Nonce, CoreError> {
        let mut nonce_data = [0u8; 12];
        rng.fill_bytes(&mut nonce_data);
        Ok(Nonce::<12>::new(nonce_data)) // Using generic Nonce::<12> instead of Nonce12
    }

    fn derive_key_from_bytes(
        bytes: &[u8],
    ) -> std::result::Result<<Self as SymmetricCipher>::Key, CoreError> {
        if bytes.len() < 32 {
            // Using same fixed size as type Key
            return Err(CoreError::InvalidLength {
                context: "GCM key derivation",
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut key_data = [0u8; 32]; // Using same fixed size as type Key
        key_data.copy_from_slice(&bytes[..32]);
        Ok(SecretBytes::new(key_data))
    }
}

// Implement Operation for GcmEncryptOperation
impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> Operation<Ciphertext>
    for GcmEncryptOperation<'_, B>
{
    fn execute(self) -> std::result::Result<Ciphertext, CoreError> {
        if self.nonce.is_none() {
            return Err(CoreError::InvalidParameter {
                context: "GCM encryption",
                #[cfg(feature = "std")]
                message: "Nonce is required for GCM encryption".to_string(),
            });
        }
        let plaintext = b""; // Default empty plaintext

        let ciphertext = self
            .cipher
            .internal_encrypt(plaintext, self.aad)
            .map_err(CoreError::from)?;

        Ok(Ciphertext::new(ciphertext))
    }
}

// Implement EncryptOperation for GcmEncryptOperation
impl<'a, B: BlockCipher + Zeroize + ZeroizeOnDrop> EncryptOperation<'a, Gcm<B>>
    for GcmEncryptOperation<'a, B>
{
    fn with_nonce(mut self, nonce: &'a <Gcm<B> as SymmetricCipher>::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }

    fn encrypt(self, plaintext: &'a [u8]) -> std::result::Result<Ciphertext, CoreError> {
        if self.nonce.is_none() {
            return Err(CoreError::InvalidParameter {
                context: "GCM encryption",
                #[cfg(feature = "std")]
                message: "Nonce is required for GCM encryption".to_string(),
            });
        }

        let ciphertext = self
            .cipher
            .internal_encrypt(plaintext, self.aad)
            .map_err(CoreError::from)?;

        Ok(Ciphertext::new(ciphertext))
    }
}

// Implement Operation for GcmDecryptOperation
impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> Operation<Vec<u8>> for GcmDecryptOperation<'_, B> {
    fn execute(self) -> std::result::Result<Vec<u8>, CoreError> {
        Err(CoreError::InvalidParameter {
            context: "GCM decryption",
            #[cfg(feature = "std")]
            message: "Use decrypt method instead".to_string(),
        })
    }
}

// Implement DecryptOperation for GcmDecryptOperation
impl<'a, B: BlockCipher + Zeroize + ZeroizeOnDrop> DecryptOperation<'a, Gcm<B>>
    for GcmDecryptOperation<'a, B>
{
    fn with_nonce(mut self, nonce: &'a <Gcm<B> as SymmetricCipher>::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }

    fn decrypt(
        self,
        ciphertext: &'a <Gcm<B> as SymmetricCipher>::Ciphertext,
    ) -> std::result::Result<Vec<u8>, CoreError> {
        if self.nonce.is_none() {
            return Err(CoreError::InvalidParameter {
                context: "GCM decryption",
                #[cfg(feature = "std")]
                message: "Nonce is required for GCM decryption".to_string(),
            });
        }

        self.cipher
            .internal_decrypt(ciphertext.as_ref(), self.aad)
            .map_err(CoreError::from)
    }
}

#[cfg(test)]
mod tests;
