//! Algorithm definitions for type-safe cryptography
//!
//! This module defines concrete algorithm types that can be used
//! with the type-safe wrappers in this crate.

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use crate::types::key::{AsymmetricAlgorithm, SymmetricAlgorithm};

// =============================================================================
// Symmetric Algorithms
// =============================================================================

/// AES-128 algorithm
pub enum Aes128 {}

impl SymmetricAlgorithm for Aes128 {
    const KEY_SIZE: usize = 16;
    const BLOCK_SIZE: usize = 16;
    const ALGORITHM_ID: &'static str = "AES-128";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// AES-256 algorithm
pub enum Aes256 {}

impl SymmetricAlgorithm for Aes256 {
    const KEY_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 16;
    const ALGORITHM_ID: &'static str = "AES-256";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// ChaCha20 algorithm
pub enum ChaCha20 {}

impl SymmetricAlgorithm for ChaCha20 {
    const KEY_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64;
    const ALGORITHM_ID: &'static str = "ChaCha20";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// ChaCha20Poly1305 algorithm
pub enum ChaCha20Poly1305 {}

impl SymmetricAlgorithm for ChaCha20Poly1305 {
    const KEY_SIZE: usize = 32;
    const BLOCK_SIZE: usize = 64; // ChaCha20 block size
    const ALGORITHM_ID: &'static str = "ChaCha20Poly1305";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

// =============================================================================
// Asymmetric Algorithms
// =============================================================================

/// Ed25519 signature algorithm
pub enum Ed25519 {}

impl AsymmetricAlgorithm for Ed25519 {
    const PUBLIC_KEY_SIZE: usize = 32;
    const SECRET_KEY_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "Ed25519";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// X25519 key exchange algorithm
pub enum X25519 {}

impl AsymmetricAlgorithm for X25519 {
    const PUBLIC_KEY_SIZE: usize = 32;
    const SECRET_KEY_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "X25519";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// NIST P-256 elliptic curve algorithm
pub enum P256 {}

impl AsymmetricAlgorithm for P256 {
    // Using uncompressed point size for PK as a general default
    const PUBLIC_KEY_SIZE: usize = 65;
    const SECRET_KEY_SIZE: usize = 32;
    const ALGORITHM_ID: &'static str = "P-256";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// NIST P-384 elliptic curve algorithm
pub enum P384 {}

impl AsymmetricAlgorithm for P384 {
    // Using uncompressed point size for PK as a general default
    const PUBLIC_KEY_SIZE: usize = 97;
    const SECRET_KEY_SIZE: usize = 48;
    const ALGORITHM_ID: &'static str = "P-384";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// NIST P-521 elliptic curve algorithm
pub enum P521 {}

impl AsymmetricAlgorithm for P521 {
    // Using uncompressed point size for PK as a general default
    const PUBLIC_KEY_SIZE: usize = 133;
    const SECRET_KEY_SIZE: usize = 66;
    const ALGORITHM_ID: &'static str = "P-521";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

/// BLS12-381 pairing-friendly curve
pub enum Bls12_381 {}

impl AsymmetricAlgorithm for Bls12_381 {
    const PUBLIC_KEY_SIZE: usize = 48; // G1 compressed
    const SECRET_KEY_SIZE: usize = 32; // Scalar field element
    const ALGORITHM_ID: &'static str = "BLS12-381";

    fn name() -> String {
        Self::ALGORITHM_ID.to_string()
    }
}

// =============================================================================
// Type Aliases
// =============================================================================

// Re-export type aliases for common key types
use crate::types::key::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey};

// Symmetric key aliases
/// AES-128 symmetric key (128-bit/16-byte key size).
pub type Aes128Key = SymmetricKey<Aes128, 16>;

/// AES-256 symmetric key (256-bit/32-byte key size).
pub type Aes256Key = SymmetricKey<Aes256, 32>;

/// ChaCha20 symmetric key (256-bit/32-byte key size).
pub type ChaCha20Key = SymmetricKey<ChaCha20, 32>;

/// ChaCha20-Poly1305 AEAD symmetric key (256-bit/32-byte key size).
pub type ChaCha20Poly1305Key = SymmetricKey<ChaCha20Poly1305, 32>;

// Asymmetric key aliases
/// Ed25519 secret key for digital signatures (256-bit/32-byte key size).
pub type Ed25519SecretKey = AsymmetricSecretKey<Ed25519, 32>;

/// Ed25519 public key for digital signatures (256-bit/32-byte key size).
pub type Ed25519PublicKey = AsymmetricPublicKey<Ed25519, 32>;

/// X25519 secret key for key exchange (256-bit/32-byte key size).
pub type X25519SecretKey = AsymmetricSecretKey<X25519, 32>;

/// X25519 public key for key exchange (256-bit/32-byte key size).
pub type X25519PublicKey = AsymmetricPublicKey<X25519, 32>;

/// P-256 secret key (256-bit/32-byte key size).
pub type P256SecretKey = AsymmetricSecretKey<P256, 32>;

/// P-256 public key (uncompressed 512-bit/65-byte key size).
pub type P256PublicKeyUncompressed = AsymmetricPublicKey<P256, 65>;

/// P-256 public key (compressed 264-bit/33-byte key size).
pub type P256PublicKeyCompressed = AsymmetricPublicKey<P256, 33>;

/// P-384 secret key (384-bit/48-byte key size).
pub type P384SecretKey = AsymmetricSecretKey<P384, 48>;

/// P-384 public key (uncompressed 768-bit/97-byte key size).
pub type P384PublicKeyUncompressed = AsymmetricPublicKey<P384, 97>;

/// P-384 public key (compressed 392-bit/49-byte key size).
pub type P384PublicKeyCompressed = AsymmetricPublicKey<P384, 49>;

/// P-521 secret key (521-bit/66-byte key size).
pub type P521SecretKey = AsymmetricSecretKey<P521, 66>;

/// P-521 public key (uncompressed 1056-bit/133-byte key size).
pub type P521PublicKeyUncompressed = AsymmetricPublicKey<P521, 133>;

/// P-521 public key (compressed 528-bit/67-byte key size).
pub type P521PublicKeyCompressed = AsymmetricPublicKey<P521, 67>;

/// BLS12-381 secret key (a scalar field element).
pub type Bls12_381SecretKey = AsymmetricSecretKey<Bls12_381, 32>;

/// BLS12-381 public key (a compressed G1 point).
pub type Bls12_381PublicKey = AsymmetricPublicKey<Bls12_381, 48>;

/* Note on compressed vs uncompressed public keys:
 *
 * For NIST curves, we provide both compressed and uncompressed type aliases:
 * - Uncompressed format: 0x04 || x || y (1 + 2*coordinate_size bytes)
 * - Compressed format: 0x02/0x03 || x (1 + coordinate_size bytes)
 *
 * The AsymmetricAlgorithm trait uses the uncompressed size as the default
 * PUBLIC_KEY_SIZE, but applications can choose which format to use based
 * on their requirements for space efficiency vs. computational overhead.
 */
