//! FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM).
//!
//! This module implements the final FIPS 203 algorithms and parameter sets. It
//! uses caller-supplied fallible randomness only, validates canonical
//! encapsulation keys and the required decapsulation-key hash, and performs
//! implicit rejection for every exactly-sized modified ciphertext.

mod kem;
mod params;
mod pke;
mod poly;

pub use kem::{
    MlKem, MlKemCiphertext, MlKemDecapsulationKey, MlKemEncapsulationKey, MlKemKeyPair,
    MlKemSharedSecret,
};
pub use params::{MlKem1024Params, MlKem512Params, MlKem768Params, MlKemParameterSet};

/// FIPS 203 ML-KEM-512.
pub type MlKem512 = MlKem<MlKem512Params>;
/// FIPS 203 ML-KEM-768.
pub type MlKem768 = MlKem<MlKem768Params>;
/// FIPS 203 ML-KEM-1024.
pub type MlKem1024 = MlKem<MlKem1024Params>;

/// Validated ML-KEM-512 encapsulation key.
pub type MlKem512EncapsulationKey = MlKemEncapsulationKey<MlKem512Params>;
/// Validated ML-KEM-768 encapsulation key.
pub type MlKem768EncapsulationKey = MlKemEncapsulationKey<MlKem768Params>;
/// Validated ML-KEM-1024 encapsulation key.
pub type MlKem1024EncapsulationKey = MlKemEncapsulationKey<MlKem1024Params>;

/// Validated ML-KEM-512 decapsulation key.
pub type MlKem512DecapsulationKey = MlKemDecapsulationKey<MlKem512Params>;
/// Validated ML-KEM-768 decapsulation key.
pub type MlKem768DecapsulationKey = MlKemDecapsulationKey<MlKem768Params>;
/// Validated ML-KEM-1024 decapsulation key.
pub type MlKem1024DecapsulationKey = MlKemDecapsulationKey<MlKem1024Params>;

/// ML-KEM-512 ciphertext.
pub type MlKem512Ciphertext = MlKemCiphertext<MlKem512Params>;
/// ML-KEM-768 ciphertext.
pub type MlKem768Ciphertext = MlKemCiphertext<MlKem768Params>;
/// ML-KEM-1024 ciphertext.
pub type MlKem1024Ciphertext = MlKemCiphertext<MlKem1024Params>;

/// Coherent ML-KEM-512 keypair.
pub type MlKem512KeyPair = MlKemKeyPair<MlKem512Params>;
/// Coherent ML-KEM-768 keypair.
pub type MlKem768KeyPair = MlKemKeyPair<MlKem768Params>;
/// Coherent ML-KEM-1024 keypair.
pub type MlKem1024KeyPair = MlKemKeyPair<MlKem1024Params>;

/// Shared-secret size for every FIPS 203 ML-KEM parameter set.
pub const ML_KEM_SHARED_SECRET_BYTES: usize = 32;

#[cfg(test)]
mod tests;
