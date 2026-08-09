//! Trait definition for Public Key Encryption (PKE) schemes.

use crate::error::Result; // from api::error
use dcrypt_internal::random::{CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroize;

// Ensure Vec is available for no_std + alloc, and other necessary imports
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Trait for Public Key Encryption schemes.
pub trait Pke {
    /// Public key type for the PKE scheme.
    /// Expected to be a byte representation that can be deserialized.
    type PublicKey: AsRef<[u8]> + Clone;

    /// Secret key type for the PKE scheme.
    /// Expected to be a byte representation that can be deserialized.
    type SecretKey: Zeroize + AsRef<[u8]> + Clone;

    /// Ciphertext type produced by the PKE scheme.
    /// This is typically a `Vec<u8>` containing the serialized ciphertext components.
    type Ciphertext: AsRef<[u8]> + Clone;

    /// Returns the PKE algorithm name.
    fn name() -> &'static str;

    /// Generates a new key pair for the PKE scheme.
    fn keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey)>;

    /// Encrypts a plaintext message using the recipient's public key.
    ///
    /// # Arguments
    /// * `pk_recipient` - The recipient's public key.
    /// * `plaintext` - The message to encrypt.
    /// * `aad` - Optional Associated Additional Data to be authenticated.
    /// * `rng` - A cryptographically secure random number generator.
    ///
    /// # Returns
    /// The resulting ciphertext as a `Vec<u8>`.
    fn encrypt<R: RngCore + CryptoRng>(
        pk_recipient: &Self::PublicKey,
        plaintext: &[u8],
        aad: Option<&[u8]>,
        rng: &mut R,
    ) -> Result<Self::Ciphertext>;

    /// Decrypts a ciphertext using the recipient's secret key.
    ///
    /// # Arguments
    /// * `sk_recipient` - The recipient's secret key.
    /// * `ciphertext` - The ciphertext to decrypt.
    /// * `aad` - Optional Associated Additional Data that was authenticated.
    ///
    /// # Returns
    /// The original plaintext as a `Vec<u8>` if decryption and authentication (if applicable) succeed.
    fn decrypt(
        sk_recipient: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>>;
}
