//! BLS12-381 pairing-friendly elliptic curve implementation.
//!
//! This module exposes low-level group, scalar, RFC 9380 hash-to-curve, and
//! pairing primitives. It does not implement a complete BLS signature
//! ciphersuite (including key generation, proof of possession, aggregation,
//! or protocol-specific input validation).
//!
//! The following demonstrates the core equation used by an Eth2-style
//! minimum-public-key-size construction. Production code must derive a
//! nonzero secret scalar with the selected ciphersuite's key-generation
//! procedure, keep its encoded form in zeroizing storage, and enforce that
//! ciphersuite's validation rules. `Bls12_381Scalar` is a generic `Copy` field
//! element, not a protected long-lived secret-key container; explicitly clear
//! an arithmetic scalar after use.
//! External public keys and signatures should be decoded with
//! `G1Projective::from_bytes_validated` or
//! `G2Projective::from_bytes_validated`, which also reject the identity.
//!
//! ```
//! use dcrypt_algorithms::ec::bls12_381::{
//!     pairing, Bls12_381Scalar, G1Affine, G1Projective, G2Affine, G2Projective,
//! };
//! use dcrypt_api::types::SecretBytes;
//! use dcrypt_internal::zeroing::Zeroize;
//!
//! // Demonstration only: KeyGen normally derives 48 pseudorandom OKM bytes
//! // using HKDF. SecretBytes zeroizes this exact-size OKM owner.
//! let mut okm = [0u8; 48];
//! okm[47] = 42; // OS2IP-style big-endian integer.
//! let secret_bytes = SecretBytes::new(okm);
//! let mut secret_scalar = Bls12_381Scalar::from_be_bytes_mod_order(secret_bytes.as_ref())?;
//! if bool::from(secret_scalar.is_zero()) {
//!     return Err(dcrypt_algorithms::Error::param("secret_key", "zero scalar"));
//! }
//!
//! let public_key = G1Affine::from(G1Projective::generator() * secret_scalar);
//! let message_point = G2Projective::hash_to_curve(
//!     b"message",
//!     b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
//! )?;
//! let signature = G2Affine::from(message_point * secret_scalar);
//! let message_point = G2Affine::from(message_point);
//!
//! assert_eq!(
//!     pairing(&public_key, &message_point),
//!     pairing(&G1Affine::generator(), &signature),
//! );
//! secret_scalar.zeroize();
//! drop(secret_bytes);
//! # Ok::<(), dcrypt_algorithms::Error>(())
//! ```

// External crates
#[cfg(feature = "alloc")]
extern crate alloc;

// Module declarations
mod field;
mod g1;
mod g2;
mod hash_to_curve;
mod hash_to_curve_g1;
mod hash_to_curve_g2;
mod pairings;
mod scalar;

#[cfg(test)]
mod tests;

// Internal use for submodules
use crate::error::Result;
use scalar::Scalar;

// Public API exports (following dcrypt conventions)
pub use self::scalar::Scalar as Bls12_381Scalar;
pub use g1::{G1Affine, G1Projective};
pub use g2::{G2Affine, G2Projective};
pub use hash_to_curve::{hash_to_curve_g1, hash_to_curve_g2};
pub use pairings::{pairing, Bls12, Gt, MillerLoopResult};

#[cfg(feature = "alloc")]
pub use pairings::{multi_miller_loop, G2Prepared};

// BLS curve parameters
/// BLS parameter x = -0xd201000000010000
const BLS_X: u64 = 0xd201_0000_0001_0000;
/// Sign of BLS parameter x
const BLS_X_IS_NEGATIVE: bool = true;

impl G1Projective {
    /// Hash a message to a point on G1 using the hash-to-curve protocol.
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<Self> {
        hash_to_curve_g1(msg, dst)
    }
}

impl G2Projective {
    /// Hash a message to a point on G2 using the hash-to-curve protocol.
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<Self> {
        hash_to_curve_g2(msg, dst)
    }
}
