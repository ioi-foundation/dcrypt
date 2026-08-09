//! Galois/Counter Mode (GCM) for authenticated encryption
//!
//! GCM is an authenticated encryption with associated data (AEAD) mode
//! that provides both confidentiality and authenticity. It combines the
//! Counter (CTR) mode with the GHASH authentication function.
//!
//! ## Implementation Note
//!
//! This implementation is tested against official NIST Cryptographic Algorithm
//! Validation Program (CAVP/ACVP) known-answer data. Vector tests are not a FIPS
//! validation or certification claim.
//!
//! ## Timing behavior
//!
//! Authentication tag bytes are compared with dcrypt's owned constant-time trait after
//! checking the public length. Input lengths, state errors, and authentication
//! results use ordinary branching. No blanket side-channel guarantee is made
//! for every backend, compiler, or target.

// Conditionally import Vec based on available features
#[cfg(not(feature = "std"))]
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

use dcrypt_internal::constant_time::ConstantTimeEq;
use dcrypt_internal::random::{try_fill_bytes_zeroing_on_error, CryptoRng, RngCore};
use dcrypt_internal::zeroing::{
    boxed_bytes_zeroed, Zeroize, ZeroizeOnDrop, Zeroizing, ZeroizingBytes,
};

// Import security types from dcrypt-core - FIXED PATH
use dcrypt_common::security::SecretBuffer;

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
#[derive(Clone)]
pub struct Gcm<B: BlockCipher + Zeroize + ZeroizeOnDrop> {
    cipher: B,
    h: SecretBuffer<GCM_BLOCK_SIZE>, // GHASH key (encrypted all-zero block) - now secured
    tag_len: usize,                  // desired tag length in bytes
}

impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> Zeroize for Gcm<B> {
    fn zeroize(&mut self) {
        self.cipher.zeroize();
        self.h.zeroize();
        self.tag_len.zeroize();
    }
}

impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> Drop for Gcm<B> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> ZeroizeOnDrop for Gcm<B> {}

/// Key construction needed by the generic [`SymmetricCipher`] adapter.
pub trait GcmKey: AsRef<[u8]> + AsMut<[u8]> + Clone + Zeroize {
    /// Construct an exactly-sized block-cipher key from caller-provided bytes.
    fn from_key_bytes(bytes: &[u8]) -> core::result::Result<Self, CoreError>;
}

impl<const N: usize> GcmKey for SecretBytes<N> {
    fn from_key_bytes(bytes: &[u8]) -> core::result::Result<Self, CoreError> {
        SecretBytes::<N>::from_slice(bytes)
    }
}

fn gcm_block_count(data_len: usize) -> Result<usize> {
    let num_blocks = data_len.div_ceil(GCM_BLOCK_SIZE);
    validate::parameter(
        (num_blocks as u128) <= u128::from(u32::MAX - 1),
        "message_length",
        "GCM message exceeds the 2^32-2 block construction limit",
    )?;
    Ok(num_blocks)
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
    /// Creates a key-only GCM instance with a fixed 16-byte tag.
    ///
    /// The nonce is deliberately supplied to each encrypt/decrypt operation;
    /// retaining it in this reusable object made accidental nonce reuse easy.
    pub fn new(cipher: B) -> Result<Self> {
        Self::new_with_tag_len(cipher, GCM_TAG_SIZE)
    }

    /// Creates a new GCM mode instance with specified tag length (in bytes).
    ///
    /// Truncated tags are supported only from 12 through 16 bytes.
    pub fn new_with_tag_len(cipher: B, tag_len: usize) -> Result<Self> {
        // Ensure block size
        validate::parameter(
            B::block_size() == GCM_BLOCK_SIZE,
            "block_size",
            "GCM only works with 128-bit block ciphers",
        )?;

        validate::parameter(
            (12..=GCM_TAG_SIZE).contains(&tag_len),
            "tag_length",
            "GCM tag length must be between 12 and 16 bytes",
        )?;

        // Generate GHASH key H (encrypt all-zero block)
        let mut h_bytes = Zeroizing::new([0u8; GCM_BLOCK_SIZE]);
        cipher.encrypt_block(h_bytes.as_mut())?;

        // Wrap the GHASH key in SecretBuffer for secure storage
        let h = SecretBuffer::new(*h_bytes);

        Ok(Self { cipher, h, tag_len })
    }

    /// Generate initial counter value J0
    fn generate_j0<const N: usize>(&self, nonce: &Nonce<N>) -> Result<[u8; GCM_BLOCK_SIZE]>
    where
        Nonce<N>: AesGcmCompatible,
    {
        validate::parameter(
            !nonce.is_empty() && nonce.len() <= 16,
            "nonce_length",
            "GCM nonce must be between 1 and 16 bytes",
        )?;
        let mut j0 = [0u8; GCM_BLOCK_SIZE];
        if nonce.len() == 12 {
            j0[..12].copy_from_slice(nonce.as_ref());
            j0[15] = 1;
        } else {
            // Convert SecretBuffer reference to array reference
            let h_array: &[u8; GCM_BLOCK_SIZE] = self
                .h
                .as_ref()
                .try_into()
                .expect("SecretBuffer has correct size");

            let mut g = GHash::new(h_array);
            // GHash::update already pads its final partial block. Adding a
            // second explicit padding update here produced a non-standard J0.
            g.update(nonce.as_ref())?;
            g.update_lengths(0, nonce.len() as u64)?;
            j0 = g.finalize();
        }
        Ok(j0)
    }

    /// Generate encryption keystream for CTR mode
    fn generate_keystream(
        &self,
        j0: &[u8; GCM_BLOCK_SIZE],
        data_len: usize,
    ) -> Result<ZeroizingBytes> {
        // Validate the construction limit before allocating output. This also
        // makes the limit directly testable without constructing a huge slice.
        let num_blocks = gcm_block_count(data_len)?;
        let mut keystream = Zeroizing::new(boxed_bytes_zeroed(num_blocks * GCM_BLOCK_SIZE));
        let mut keystream_offset = 0usize;

        let mut counter = *j0;
        let mut ctr_val =
            u32::from_be_bytes(counter[12..16].try_into().expect("four bytes")).wrapping_add(1);
        counter[12..16].copy_from_slice(&ctr_val.to_be_bytes());

        for _ in 0..num_blocks {
            let mut block = Zeroizing::new(counter);
            self.cipher.encrypt_block(block.as_mut())?;
            keystream[keystream_offset..keystream_offset + GCM_BLOCK_SIZE]
                .copy_from_slice(block.as_ref());
            keystream_offset += GCM_BLOCK_SIZE;
            ctr_val = ctr_val.wrapping_add(1);
            counter[12..16].copy_from_slice(&ctr_val.to_be_bytes());
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
        let mut j0_copy = Zeroizing::new(*j0);
        self.cipher.encrypt_block(j0_copy.as_mut())?;

        // XOR the encrypted counter with the GHASH result
        for i in 0..GCM_TAG_SIZE {
            tag[i] ^= j0_copy[i];
        }

        Ok(tag)
    }

    /// Internal encrypt method - exposed for testing
    pub fn internal_encrypt<const N: usize>(
        &self,
        nonce: &Nonce<N>,
        plaintext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>
    where
        Nonce<N>: AesGcmCompatible,
    {
        let aad = associated_data.unwrap_or(&[]);
        let j0 = self.generate_j0(nonce)?;

        let keystream = if plaintext.is_empty() {
            None
        } else {
            Some(self.generate_keystream(&j0, plaintext.len())?)
        };
        let output_len = plaintext
            .len()
            .checked_add(self.tag_len)
            .ok_or(Error::Processing {
                operation: "GCM encryption",
                details: "ciphertext length overflow",
            })?;
        let mut ciphertext = Vec::with_capacity(output_len);
        if let Some(keystream) = keystream {
            for i in 0..plaintext.len() {
                ciphertext.push(plaintext[i] ^ keystream[i]);
            }
        }

        let full_tag = self.generate_tag(&j0, aad, &ciphertext)?;
        ciphertext.extend_from_slice(&full_tag[..self.tag_len]);
        Ok(ciphertext)
    }

    /// Internal decrypt method; exposed for testing.
    pub fn internal_decrypt<const N: usize>(
        &self,
        nonce: &Nonce<N>,
        ciphertext: &[u8],
        associated_data: Option<&[u8]>,
    ) -> Result<Vec<u8>>
    where
        Nonce<N>: AesGcmCompatible,
    {
        // Length check is not a secret-dependent branch
        validate::min_length("GCM ciphertext", ciphertext.len(), self.tag_len)?;

        let aad = associated_data.unwrap_or(&[]);
        let ciphertext_len = ciphertext.len() - self.tag_len;
        let (ciphertext_data, received_tag) = ciphertext.split_at(ciphertext_len);

        // Generate initial counter and expected tag
        let j0 = self.generate_j0(nonce)?;
        let full_expected = self.generate_tag(&j0, aad, ciphertext_data)?;
        let expected_tag = &full_expected[..self.tag_len];

        // Generate keystream and decrypt data
        let keystream = self.generate_keystream(&j0, ciphertext_len)?;
        let mut plaintext = Zeroizing::new(boxed_bytes_zeroed(ciphertext_len));
        for i in 0..ciphertext_len {
            plaintext[i] = ciphertext_data[i] ^ keystream[i];
        }

        // Compare all tag bytes without a value-dependent early exit.
        let tag_matches = expected_tag.ct_eq(received_tag);

        // The tag bytes are compared without a value-dependent early exit. The
        // public result/error branch is not a blanket constant-time claim for
        // the complete decrypt operation.
        if tag_matches.unwrap_u8() == 0 {
            Err(Error::Authentication { algorithm: "GCM" })
        } else {
            Ok(plaintext.into_inner().into_vec())
        }
    }
}

// Implement the marker trait AuthenticatedCipher
impl<B: BlockCipher + Zeroize + ZeroizeOnDrop> AuthenticatedCipher for Gcm<B> {
    const TAG_SIZE: usize = GCM_TAG_SIZE;
    const ALGORITHM_ID: &'static str = "GCM";
}

// Implement SymmetricCipher trait
impl<B> SymmetricCipher for Gcm<B>
where
    B: BlockCipher + Zeroize + ZeroizeOnDrop,
    B::Key: GcmKey,
{
    type Key = B::Key;
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

    fn generate_key<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> core::result::Result<<Self as SymmetricCipher>::Key, CoreError> {
        B::generate_key(rng).map_err(CoreError::from)
    }

    fn generate_nonce<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> core::result::Result<<Self as SymmetricCipher>::Nonce, CoreError> {
        let mut nonce_data = [0u8; 12];
        try_fill_bytes_zeroing_on_error(rng, &mut nonce_data).map_err(|_| CoreError::Other {
            context: "randomness",
            #[cfg(feature = "std")]
            message: "caller-provided randomness source failed".to_string(),
        })?;
        Ok(Nonce::<12>::new(nonce_data)) // Using generic Nonce::<12> instead of Nonce12
    }

    fn derive_key_from_bytes(
        bytes: &[u8],
    ) -> core::result::Result<<Self as SymmetricCipher>::Key, CoreError> {
        if bytes.len() != B::key_size() {
            return Err(CoreError::InvalidLength {
                context: "GCM key derivation",
                expected: B::key_size(),
                actual: bytes.len(),
            });
        }
        B::Key::from_key_bytes(bytes)
    }
}

// Implement Operation for GcmEncryptOperation
impl<B> Operation<Ciphertext> for GcmEncryptOperation<'_, B>
where
    B: BlockCipher + Zeroize + ZeroizeOnDrop,
    B::Key: GcmKey,
{
    fn execute(self) -> core::result::Result<Ciphertext, CoreError> {
        let nonce = self.nonce.ok_or_else(|| CoreError::InvalidParameter {
            context: "GCM encryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for GCM encryption".to_string(),
        })?;
        let plaintext = b""; // Default empty plaintext

        let ciphertext = self
            .cipher
            .internal_encrypt(nonce, plaintext, self.aad)
            .map_err(CoreError::from)?;

        Ok(Ciphertext::new(ciphertext))
    }
}

// Implement EncryptOperation for GcmEncryptOperation
impl<'a, B> EncryptOperation<'a, Gcm<B>> for GcmEncryptOperation<'a, B>
where
    B: BlockCipher + Zeroize + ZeroizeOnDrop,
    B::Key: GcmKey,
{
    fn with_nonce(mut self, nonce: &'a <Gcm<B> as SymmetricCipher>::Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    fn with_aad(mut self, aad: &'a [u8]) -> Self {
        self.aad = Some(aad);
        self
    }

    fn encrypt(self, plaintext: &'a [u8]) -> core::result::Result<Ciphertext, CoreError> {
        let nonce = self.nonce.ok_or_else(|| CoreError::InvalidParameter {
            context: "GCM encryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for GCM encryption".to_string(),
        })?;

        let ciphertext = self
            .cipher
            .internal_encrypt(nonce, plaintext, self.aad)
            .map_err(CoreError::from)?;

        Ok(Ciphertext::new(ciphertext))
    }
}

// Implement Operation for GcmDecryptOperation
impl<B> Operation<Vec<u8>> for GcmDecryptOperation<'_, B>
where
    B: BlockCipher + Zeroize + ZeroizeOnDrop,
    B::Key: GcmKey,
{
    fn execute(self) -> core::result::Result<Vec<u8>, CoreError> {
        Err(CoreError::InvalidParameter {
            context: "GCM decryption",
            #[cfg(feature = "std")]
            message: "Use decrypt method instead".to_string(),
        })
    }
}

// Implement DecryptOperation for GcmDecryptOperation
impl<'a, B> DecryptOperation<'a, Gcm<B>> for GcmDecryptOperation<'a, B>
where
    B: BlockCipher + Zeroize + ZeroizeOnDrop,
    B::Key: GcmKey,
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
    ) -> core::result::Result<Vec<u8>, CoreError> {
        let nonce = self.nonce.ok_or_else(|| CoreError::InvalidParameter {
            context: "GCM decryption",
            #[cfg(feature = "std")]
            message: "Nonce is required for GCM decryption".to_string(),
        })?;

        self.cipher
            .internal_decrypt(nonce, ciphertext.as_ref(), self.aad)
            .map_err(CoreError::from)
    }
}

#[cfg(test)]
mod tests;
