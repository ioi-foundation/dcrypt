//! Cryptographic primitive implementations and adapters.
//!
//! This crate provides implementations of various cryptographic primitives
//! with explicit validation and zeroization boundaries. Constant-time behavior
//! and `no_std` support are primitive- and feature-specific; the crate does not
//! make blanket guarantees for either property.
//!
//! # Security Features
//!
//! Relevant defensive patterns include:
//!
//! - Secure memory handling with automatic zeroization
//! - Constant-time comparison operations
//! - Memory barrier utilities
//! - Secure operation patterns

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "alloc")]
mod alloc_prelude {
    pub(crate) use alloc::{
        string::{String, ToString},
        vec::Vec,
    };
}

// Error module and re-exports
pub mod error;
pub use error::{validate, Error, Result, ResultExt, SecureErrorHandling};

// Block cipher implementations
pub mod block;
pub use block::{Aes128, Aes192, Aes256, Cbc, Ctr};

// Hash function implementations
pub mod hash;
pub use hash::{
    Blake2b, Blake2s, Keccak256, Sha1, Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384,
    Sha3_512, Sha512, Shake128, Shake256,
};

// AEAD cipher implementations
#[cfg(feature = "alloc")]
pub mod aead;
#[cfg(feature = "alloc")]
pub use aead::{AeadCipher, ChaCha20Poly1305, ChaCha20Poly1305Cipher, Gcm, XChaCha20Poly1305};

// MAC implementations
pub mod mac;
pub use mac::{Hmac, Poly1305};

// Stream cipher implementations
pub mod stream;
pub use stream::chacha::chacha20::ChaCha20;

// KDF implementations
#[cfg(feature = "alloc")]
pub mod kdf;
#[cfg(feature = "alloc")]
pub use kdf::{Argon2, Hkdf, KeyDerivationFunction, PasswordHashFunction, Pbkdf2};

// Elliptic Curve primitives
pub mod ec;
pub use ec::{
    // Re-export curve-specific modules
    p256,
    p384,
    p521,
    // Re-export common EC types
    P256Point,
    P256Scalar,
    P384Point,
    P384Scalar,
    P521Point,
    P521Scalar,
};

// Type system
pub mod types;
pub use types::{
    ByteSerializable, ConstantTimeEq, Digest, FixedSize, Nonce, RandomGeneration, Salt,
    SecretBytes, SecureZeroingType, Tag,
};

// Re-export security types from dcrypt-core
pub use dcrypt_common::security::{
    barrier, EphemeralSecret, SecretBuffer, SecretVec, SecureCompare, SecureOperation,
    SecureOperationBuilder, SecureOperationExt, ZeroizeGuard,
};

// Algorithm types and compatibility traits
pub use types::{
    // Algorithm marker types
    algorithms::{
        Aes128 as Aes128Algorithm, Aes256 as Aes256Algorithm, ChaCha20 as ChaCha20Algorithm,
        ChaCha20Poly1305 as ChaCha20Poly1305Algorithm, Ed25519 as Ed25519Algorithm,
        P521 as P521Algorithm, X25519 as X25519Algorithm,
    },

    digest::{Blake2bCompatible, Keccak256Compatible, Sha256Compatible, Sha512Compatible},
    // Key types
    key::{AsymmetricPublicKey, AsymmetricSecretKey, SymmetricKey},

    // Compatibility traits for specific algorithms
    nonce::{AesCtrCompatible, AesGcmCompatible, ChaCha20Compatible, XChaCha20Compatible},
    salt::{Argon2Compatible, HkdfCompatible, Pbkdf2Compatible},
    tag::{ChaCha20Poly1305Compatible, GcmCompatible, HmacCompatible, Poly1305Compatible},
};

// XOF implementations (if enabled)
#[cfg(feature = "xof")]
pub mod xof;
#[cfg(feature = "xof")]
pub use xof::{Blake3Xof, ExtendableOutputFunction, ShakeXof128, ShakeXof256};

// **NEW** PQC Math Primitive Modules
#[cfg(feature = "alloc")] // Polynomial arithmetic often benefits from dynamic allocation
pub mod poly;

// Re-export polynomial types for easier access
#[cfg(feature = "alloc")]
pub use poly::{
    ntt::{montgomery_reduce, CooleyTukeyNtt, InverseNttOperator, NttOperator},
    params::{DilithiumParams, Kyber256Params, Modulus, NttModulus},
    polynomial::Polynomial,
    prelude,
    sampling::{CbdSampler, DefaultSamplers, UniformSampler},
    serialize::{CoefficientPacker, CoefficientUnpacker, DefaultCoefficientSerde},
};
