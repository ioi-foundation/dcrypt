//! # dcrypt
//!
//! A modular cryptographic library providing both traditional and post-quantum algorithms.
//!
//! ## Security status
//!
//! Releases through `v1.2.3` contain serious memory-safety,
//! authentication, nonce-handling, and format vulnerabilities and must not be
//! used for production cryptography. `v2.0.0` contains important remediations
//! but is withdrawn for violating the project's implementation policy. No
//! published dcrypt release is currently supported. Consult the workspace
//! `SECURITY.md` before use.
//!
//! ## Features
//!
//! - `traditional` (default): symmetric primitives plus ECDH, ECIES, ECDSA,
//!   and Ed25519
//! - `post-quantum`: final FIPS 203 ML-KEM and FIPS 204 ML-DSA
//! - `hybrid`: Hybrid constructions combining traditional and post-quantum
//!   primitives (and therefore enables both categories)
//! - `alloc`: allocation-backed APIs without the standard library
//! - `full`: All features enabled
//!
//! ## Crate Structure
//!
//! This is a facade crate that re-exports functionality from several sub-crates:
//!
//! - [`dcrypt-algorithms`]: Core algorithms (AES, SHA, etc.)
//! - [`dcrypt-symmetric`]: Symmetric encryption
//! - [`dcrypt-kem`]: Key Encapsulation Mechanisms
//! - [`dcrypt-sign`]: Digital signatures
//! - [`dcrypt-pke`]: Public Key Encryption
//! - [`dcrypt-hybrid`]: Hybrid constructions
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! # #[cfg(feature = "post-quantum")]
//! # {
//! // The category feature activates and re-exports the required crates.
//! use dcrypt::api::Signature;
//! use dcrypt::sign::mldsa::MlDsa44;
//! # }
//!
//! // Or using the prelude (always available)
//! use dcrypt::prelude::*;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

// Core re-exports (always available)
pub use dcrypt_api as api;
pub use dcrypt_common as common;
pub use dcrypt_internal as internal;
pub use dcrypt_params as params;

// Re-export commonly used items from api at the crate root for convenience
pub use api::{Error, Result};

// Feature-gated re-exports
#[cfg(feature = "algorithms")]
pub use dcrypt_algorithms as algorithms;

#[cfg(feature = "symmetric")]
pub use dcrypt_symmetric as symmetric;

#[cfg(feature = "kem")]
pub use dcrypt_kem as kem;

#[cfg(feature = "sign")]
pub use dcrypt_sign as sign;

#[cfg(feature = "pke")]
pub use dcrypt_pke as pke;

#[cfg(feature = "hybrid")]
pub use dcrypt_hybrid as hybrid;

// Re-export commonly used traits at the crate root for easier access
#[cfg(feature = "sign")]
pub use api::Signature;

// Also re-export the traits module for direct trait access
pub use api::traits;

/// Common imports for dcrypt users
pub mod prelude {
    // Re-export error types
    pub use crate::api::{Error, Result};

    // Re-export core traits from api
    pub use crate::api::{
        AuthenticatedCipher, BlockCipher, HashAlgorithm, Kem, KeyDerivationFunction, Serialize,
        Signature, StreamCipher, SymmetricCipher,
    };

    // Re-export all traits from api::traits if they exist
    pub use crate::api::traits::*;

    // Re-export security types
    pub use crate::common::{EphemeralSecret, SecretBuffer, SecureZeroingType, ZeroizeGuard};

    // Re-export memory safety utilities
    pub use crate::common::{SecureCompare, SecureOperation, SecureOperationExt};

    // Conditional re-exports based on features
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub use crate::common::SecureOperationBuilder;

    #[cfg(feature = "alloc")]
    pub use crate::common::SecretVec;

    #[cfg(any(feature = "std", feature = "alloc"))]
    pub use crate::common::{CurveParams, ECPoint};

    // Note: Specific algorithm implementations should be imported directly from their modules
    // For example:
    // - use dcrypt::kem::ecdh::p256::{EcdhP256PublicKey, EcdhP256SecretKey};
    // - use dcrypt::sign::mldsa::MlDsa44;
    // - use dcrypt::pke::ecies::p256::{EciesP256PublicKey, EciesP256Ciphertext};
}

// Test that imports work correctly
#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(feature = "sign", feature = "traditional"))]
    fn test_sign_imports() {
        // This should compile if the imports are working
        use crate::api::Signature as SignatureTrait;
        use crate::sign;

        fn assert_signature<T: SignatureTrait>() {}
        assert_signature::<sign::eddsa::Ed25519>();
    }

    #[test]
    #[cfg(feature = "full")]
    fn test_full_imports() {
        // Test that all modules are accessible with full features
        #[allow(unused_imports)]
        use crate::{algorithms, api, common, hybrid, internal, kem, params, pke, sign, symmetric};

        // The imports above check module resolution; this checks the core API
        // re-export as a concrete type rather than treating an enum as a value.
        let _ = core::mem::size_of::<api::Error>();
    }

    #[test]
    #[cfg(feature = "traditional")]
    fn traditional_category_exposes_promised_modules() {
        use crate::{algorithms, kem, pke, sign, symmetric};

        let _ = core::mem::size_of::<algorithms::Sha256>();
        let _ = core::mem::size_of::<kem::EcdhP256>();
        let _ = core::mem::size_of::<pke::EciesP256>();
        let _ = core::mem::size_of::<sign::EcdsaP256>();
        let _ = core::mem::size_of::<symmetric::Aes256Gcm>();
    }

    #[test]
    #[cfg(feature = "post-quantum")]
    fn post_quantum_category_exposes_promised_modules() {
        use crate::{kem, sign};

        let _ = core::mem::size_of::<kem::MlKem768>();
        let _ = core::mem::size_of::<sign::MlDsa65>();
    }

    #[test]
    #[cfg(feature = "hybrid")]
    fn hybrid_category_exposes_promised_modules() {
        use crate::hybrid::{kem::EcdhP256MlKem768, sign::EcdsaMlDsa65Hybrid};

        let _ = core::mem::size_of::<EcdhP256MlKem768>();
        let _ = core::mem::size_of::<EcdsaMlDsa65Hybrid>();
    }
}
