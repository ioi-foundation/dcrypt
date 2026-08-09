// File: crates/hybrid/src/kem/traits.rs

//! Defines traits for extending KEM functionality within the hybrid crate.

use dcrypt_api::Kem;
use dcrypt_kem::{ecdh, ml_kem};

/// Extends the `dcrypt_api::Kem` trait with compile-time length constants.
/// This is essential for generic serialization of hybrid data structures.
pub trait KemDimensions: Kem {
    /// Stable suite identifier for transcript and combiner domain separation.
    const SUITE_ID: &'static [u8];
    /// The byte length of the public key.
    const PUBLIC_KEY_LEN: usize;
    /// The byte length of the secret key.
    const SECRET_KEY_LEN: usize;
    /// The byte length of the ciphertext.
    const CIPHERTEXT_LEN: usize;
    /// The byte length of the shared secret emitted by the KEM.
    const SHARED_SECRET_LEN: usize;
}

// --- ECDH Implementations ---
impl KemDimensions for ecdh::EcdhP224 {
    const SUITE_ID: &'static [u8] = b"ECDH-P224";
    const PUBLIC_KEY_LEN: usize = 29;
    const SECRET_KEY_LEN: usize = 28;
    const CIPHERTEXT_LEN: usize = 45; // Authenticated ciphertext (29-byte key + 16-byte tag)
    const SHARED_SECRET_LEN: usize = 32;
}
impl KemDimensions for ecdh::EcdhP256 {
    const SUITE_ID: &'static [u8] = b"ECDH-P256";
    const PUBLIC_KEY_LEN: usize = 33;
    const SECRET_KEY_LEN: usize = 32;
    const CIPHERTEXT_LEN: usize = 33;
    const SHARED_SECRET_LEN: usize = 32;
}
impl KemDimensions for ecdh::EcdhP384 {
    const SUITE_ID: &'static [u8] = b"ECDH-P384";
    const PUBLIC_KEY_LEN: usize = 49;
    const SECRET_KEY_LEN: usize = 48;
    const CIPHERTEXT_LEN: usize = 49;
    const SHARED_SECRET_LEN: usize = 48;
}
impl KemDimensions for ecdh::EcdhP521 {
    const SUITE_ID: &'static [u8] = b"ECDH-P521";
    const PUBLIC_KEY_LEN: usize = 67;
    const SECRET_KEY_LEN: usize = 66;
    const CIPHERTEXT_LEN: usize = 67;
    const SHARED_SECRET_LEN: usize = 64;
}
impl KemDimensions for ecdh::EcdhK256 {
    const SUITE_ID: &'static [u8] = b"ECDH-K256";
    const PUBLIC_KEY_LEN: usize = 33;
    const SECRET_KEY_LEN: usize = 32;
    const CIPHERTEXT_LEN: usize = 33;
    const SHARED_SECRET_LEN: usize = 32;
}
// --- ML-KEM implementations ---
impl KemDimensions for ml_kem::MlKem512 {
    const SUITE_ID: &'static [u8] = b"ML-KEM-512";
    const PUBLIC_KEY_LEN: usize = 800;
    const SECRET_KEY_LEN: usize = 1632;
    const CIPHERTEXT_LEN: usize = 768;
    const SHARED_SECRET_LEN: usize = 32;
}
impl KemDimensions for ml_kem::MlKem768 {
    const SUITE_ID: &'static [u8] = b"ML-KEM-768";
    const PUBLIC_KEY_LEN: usize = 1184;
    const SECRET_KEY_LEN: usize = 2400;
    const CIPHERTEXT_LEN: usize = 1088;
    const SHARED_SECRET_LEN: usize = 32;
}
impl KemDimensions for ml_kem::MlKem1024 {
    const SUITE_ID: &'static [u8] = b"ML-KEM-1024";
    const PUBLIC_KEY_LEN: usize = 1568;
    const SECRET_KEY_LEN: usize = 3168;
    const CIPHERTEXT_LEN: usize = 1568;
    const SHARED_SECRET_LEN: usize = 32;
}
