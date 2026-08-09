//! FIPS 203 ML-KEM parameter sets.

mod sealed {
    pub trait Sealed {}
}

/// Parameters fixed by FIPS 203 for an ML-KEM parameter set.
///
/// This trait is sealed: applications select one of the three standard marker
/// types rather than defining non-standard parameter combinations.
pub trait MlKemParameterSet: sealed::Sealed + Send + Sync + 'static {
    /// Module rank.
    const K: usize;
    /// Secret and key-generation error distribution parameter.
    const ETA1: usize;
    /// Encryption error distribution parameter.
    const ETA2: usize = 2;
    /// Compression width for the polynomial vector in a ciphertext.
    const DU: usize;
    /// Compression width for the final polynomial in a ciphertext.
    const DV: usize;
    /// FIPS 203 algorithm name.
    const NAME: &'static str;
    /// Encapsulation-key length in bytes.
    const ENCAPSULATION_KEY_BYTES: usize;
    /// Decapsulation-key length in bytes.
    const DECAPSULATION_KEY_BYTES: usize;
    /// Ciphertext length in bytes.
    const CIPHERTEXT_BYTES: usize;
}

/// Parameters for ML-KEM-512.
pub enum MlKem512Params {}

/// Parameters for ML-KEM-768.
pub enum MlKem768Params {}

/// Parameters for ML-KEM-1024.
pub enum MlKem1024Params {}

impl sealed::Sealed for MlKem512Params {}
impl sealed::Sealed for MlKem768Params {}
impl sealed::Sealed for MlKem1024Params {}

impl MlKemParameterSet for MlKem512Params {
    const K: usize = 2;
    const ETA1: usize = 3;
    const DU: usize = 10;
    const DV: usize = 4;
    const NAME: &'static str = "ML-KEM-512";
    const ENCAPSULATION_KEY_BYTES: usize = 800;
    const DECAPSULATION_KEY_BYTES: usize = 1_632;
    const CIPHERTEXT_BYTES: usize = 768;
}

impl MlKemParameterSet for MlKem768Params {
    const K: usize = 3;
    const ETA1: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const NAME: &'static str = "ML-KEM-768";
    const ENCAPSULATION_KEY_BYTES: usize = 1_184;
    const DECAPSULATION_KEY_BYTES: usize = 2_400;
    const CIPHERTEXT_BYTES: usize = 1_088;
}

impl MlKemParameterSet for MlKem1024Params {
    const K: usize = 4;
    const ETA1: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
    const NAME: &'static str = "ML-KEM-1024";
    const ENCAPSULATION_KEY_BYTES: usize = 1_568;
    const DECAPSULATION_KEY_BYTES: usize = 3_168;
    const CIPHERTEXT_BYTES: usize = 1_568;
}

pub(crate) const N: usize = 256;
pub(crate) const Q: i16 = 3_329;
pub(crate) const SYM_BYTES: usize = 32;
pub(crate) const POLY_BYTES: usize = 384;

#[inline]
pub(crate) const fn pke_secret_key_bytes<P: MlKemParameterSet>() -> usize {
    P::K * POLY_BYTES
}

#[inline]
pub(crate) const fn compressed_polyvec_bytes<P: MlKemParameterSet>() -> usize {
    P::K * N * P::DU / 8
}
