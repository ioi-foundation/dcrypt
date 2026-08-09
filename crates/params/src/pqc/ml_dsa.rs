//! Final FIPS 204 ML-DSA parameter constants.
//!
//! This module implements the parameter sets defined in FIPS 204 (August 2024)
//! "Module-Lattice-Based Digital Signature Standard"
//! <https://doi.org/10.6028/NIST.FIPS.204>
//!
//! All constants in this file are taken directly from the final FIPS 204 standard,
//! NOT from earlier CRYSTALS-ML-DSA submissions or draft specifications.

/// ML-DSA polynomial degree (n = 256)
/// FIPS 204, Table 1: Common to all ML-DSA parameter sets
pub const ML_DSA_N: usize = 256;

/// ML-DSA modulus (q = 8380417 = 2²³ - 2¹³ + 1)
/// FIPS 204, Table 1: Common to all ML-DSA parameter sets
pub const ML_DSA_Q: u32 = 8380417;

/// FIPS 204 Appendix C, Table 3 minimum allowable loop limit for `ML-DSA.Sign_internal`.
///
/// NIST states that implementations which cap the signing rejection loop "shall not use
/// a limit lower than" this value, and that this limit yields an approximately `2^-256`
/// or smaller probability of being reached under the standard output-distribution
/// assumptions for the XOF and hash functions.
pub const FIPS204_SIGN_INTERNAL_MIN_LOOP_LIMIT: u16 = 814;

/// Common trait for ML-DSA parameter sets as defined in FIPS 204
pub trait MlDsaSchemeParams: Send + Sync + 'static {
    /// Algorithm name (ML-DSA-44, ML-DSA-65, ML-DSA-87)
    const NAME: &'static str;

    // Ring parameters (FIPS 204, Section 3)
    /// Polynomial degree n = 256 (FIPS 204, Table 1)
    const N: usize = ML_DSA_N;
    /// Prime modulus q = 2²³ - 2¹³ + 1 (FIPS 204, Table 1)
    const Q: u32 = ML_DSA_Q;
    /// Dropped bits parameter d (FIPS 204, Table 1)
    const D_PARAM: u32;

    // Matrix dimensions (FIPS 204, Table 1)
    /// Number of polynomials in s₂ and t (rows in matrix A)
    const K_DIM: usize;
    /// Number of polynomials in s₁ and y (columns in matrix A)
    const L_DIM: usize;

    // Security parameters (FIPS 204, Table 1)
    /// Classical security parameter λ in bits
    /// ML-DSA-44: λ = 128, ML-DSA-65: λ = 192, ML-DSA-87: λ = 256
    const LAMBDA: usize;

    /// Challenge hash size in bytes (λ/4)
    /// ML-DSA-44: 32 bytes, ML-DSA-65: 48 bytes, ML-DSA-87: 64 bytes
    const CHALLENGE_BYTES: usize;

    // Norm bounds (FIPS 204, Table 1)
    /// Bound η for secret polynomials s₁, s₂
    const ETA_S1S2: u32;
    /// Range parameter γ₁ for masking vector y
    const GAMMA1_PARAM: u32;
    /// Number of bits to represent z coefficients
    /// Computed as ceil(log₂(2·γ₁))
    /// DEPRECATED: Use Z_BITS for packing z coefficients
    const GAMMA1_BITS: usize;
    /// Decomposition parameter γ₂
    const GAMMA2_PARAM: u32;
    /// Rejection bound β = τ·η (FIPS 204, Table 1)
    const BETA_PARAM: u32;
    /// Maximum number of hint bits ω (FIPS 204, Table 1)
    const OMEGA_PARAM: u32;
    /// Number of ±1 coefficients in challenge polynomial c
    const TAU_PARAM: usize;

    // Byte sizes (FIPS 204, Table 1)
    /// Public key size in bytes
    const PUBLIC_KEY_BYTES: usize;
    /// Secret key size in bytes (includes 32-byte K seed)
    const SECRET_KEY_BYTES: usize;
    /// Signature size in bytes
    const SIGNATURE_SIZE: usize;

    // Seed sizes (FIPS 204, Section 5.1)
    /// Seed size for matrix A generation (ρ)
    const SEED_RHO_BYTES: usize = 32;
    /// Seed size for secret/error sampling (ρ')
    const SEED_KEY_BYTES: usize = 64;
    /// Master seed size for key generation (ζ)
    const SEED_ZETA_BYTES: usize = 32;
    /// Hash output size for tr = H(pk)
    const HASH_TR_BYTES: usize = 64;

    // Additional parameters
    /// Maximum signing attempts before failure
    const MAX_SIGN_ABORTS: u16 = 1000;
    /// Fixed public signing window used by the constant-time signer.
    ///
    /// For a formally justified rejection cap, implementations must not go below the
    /// Appendix C, Table 3 bound from FIPS 204.
    const FIXED_SIGNING_WINDOW: u16 = FIPS204_SIGN_INTERNAL_MIN_LOOP_LIMIT;
    /// Bits for packing w₁ coefficients
    /// FIPS 204, Algorithm 28: b = bitlen((q-1)/(2·γ₂) − 1)
    const W1_BITS: usize;

    /// Number of bits used when packing each z-coefficient in signatures
    /// This is determined by the range [-γ₁+β, γ₁-β] which requires:
    /// - ML-DSA-44: 18 bits (since 2·(γ₁-β) < 2¹⁸)
    /// - ML-DSA-65/87: 20 bits (since 2·(γ₁-β) < 2²⁰)
    const Z_BITS: usize;
}

/// Structure containing ML-DSA-44 parameters
/// FIPS 204, Table 1: ML-DSA-44 (NIST security category 2)
pub struct MlDsa44Params {
    /// Polynomial degree n = 256
    pub n: usize,

    /// Modulus q = 8380417
    pub q: u32,

    /// Dropped bits d = 13
    pub d: u32,

    /// Matrix dimension k = 4 (rows)
    pub k: usize,

    /// Matrix dimension ℓ = 4 (columns)
    pub l: usize,

    /// Infinity norm bound η = 2
    pub eta: u32,

    /// Challenge weight τ = 39
    pub tau: usize,

    /// Public key size = 1312 bytes
    pub public_key_size: usize,

    /// Secret key size = 2560 bytes (includes 32-byte K seed)
    pub secret_key_size: usize,

    /// Signature size = 2420 bytes
    pub signature_size: usize,
}

/// ML-DSA-44 parameter set (FIPS 204, Table 1)
/// Targets NIST security category 2 (collision resistance of SHA-256)
pub const ML_DSA_44: MlDsa44Params = MlDsa44Params {
    n: ML_DSA_N,
    q: ML_DSA_Q,
    d: 13,
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    public_key_size: 1312,
    secret_key_size: 2560, // FIPS 204 final: includes 32-byte K seed
    signature_size: 2420,  // Updated: 32 + 2304 + 80 + 4 = 2420 bytes
};

impl MlDsaSchemeParams for MlDsa44Params {
    const NAME: &'static str = "ML-DSA-44";
    const D_PARAM: u32 = 13;
    const K_DIM: usize = 4;
    const L_DIM: usize = 4;
    const LAMBDA: usize = 128; // Classical security parameter
    const CHALLENGE_BYTES: usize = 32; // λ/4 = 128/4 = 32
    const ETA_S1S2: u32 = 2;
    const GAMMA1_PARAM: u32 = 1 << 17; // 2¹⁷ = 131072
    const GAMMA1_BITS: usize = 18; // ceil(log₂(2·2¹⁷)) = 18
                                   // γ₂ = (q − 1)/88 = 95232 (FIPS 204, Table 1, ML-DSA-44)
    const GAMMA2_PARAM: u32 = (ML_DSA_Q - 1) / 88; // = 95232
    const BETA_PARAM: u32 = 78; // β = τ·η = 39·2 = 78
                                // FIXED: OMEGA must be 80 for ML-DSA-44 per FIPS 204 Table 1
    const OMEGA_PARAM: u32 = 80;
    const TAU_PARAM: usize = 39;
    const PUBLIC_KEY_BYTES: usize = 1312;
    const SECRET_KEY_BYTES: usize = 2560;
    // SIGNATURE_SIZE updated: 32 (challenge) + 2304 (z) + 80 (hints) + 4 (counters) = 2420
    const SIGNATURE_SIZE: usize = 2420;
    // w₁ encoding: (q-1)/(2·γ₂) = 8380416/(2·95232) = 44
    // Decompose returns r₁ ∈ [0, 43], which still requires 6 bits.
    const W1_BITS: usize = 6;
    // Number of bits for packing z coefficients
    // Range [-γ₁+β, γ₁-β] = [-131072+78, 131072-78] = [-130994, 130994]
    // Maximum absolute value: 130994 < 2¹⁷, so 2·130994 < 2¹⁸
    // Therefore 18 bits are sufficient
    const Z_BITS: usize = 18;
}

/// Structure containing ML-DSA-65 parameters
/// FIPS 204, Table 1: ML-DSA-65 (NIST security category 3)
pub struct MlDsa65Params {
    /// Polynomial degree n = 256
    pub n: usize,

    /// Modulus q = 8380417
    pub q: u32,

    /// Dropped bits d = 13
    pub d: u32,

    /// Matrix dimension k = 6 (rows)
    pub k: usize,

    /// Matrix dimension ℓ = 5 (columns)
    pub l: usize,

    /// Infinity norm bound η = 4
    pub eta: u32,

    /// Challenge weight τ = 49
    pub tau: usize,

    /// Public key size = 1952 bytes
    pub public_key_size: usize,

    /// Secret key size = 4032 bytes (includes 32-byte K seed)
    pub secret_key_size: usize,

    /// Signature size = 3309 bytes
    pub signature_size: usize,
}

/// ML-DSA-65 parameter set (FIPS 204, Table 1)
/// Targets NIST security category 3 (collision resistance of SHA-384)
pub const ML_DSA_65: MlDsa65Params = MlDsa65Params {
    n: ML_DSA_N,
    q: ML_DSA_Q,
    d: 13,
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    public_key_size: 1952,
    secret_key_size: 4032, // FIPS 204 final: includes 32-byte K seed
    signature_size: 3309,  // FIPS 204 final value
};

impl MlDsaSchemeParams for MlDsa65Params {
    const NAME: &'static str = "ML-DSA-65";
    const D_PARAM: u32 = 13;
    const K_DIM: usize = 6;
    const L_DIM: usize = 5;
    const LAMBDA: usize = 192; // Classical security parameter
    const CHALLENGE_BYTES: usize = 48; // λ/4 = 192/4 = 48
    const ETA_S1S2: u32 = 4;
    const GAMMA1_PARAM: u32 = 1 << 19; // 2¹⁹ = 524288
    const GAMMA1_BITS: usize = 20; // ceil(log₂(2·2¹⁹)) = 20
                                   // CORRECTED: γ₂ = (q − 1)/32 = 261888 (FIPS 204, Table 1, ML-DSA-65)
    const GAMMA2_PARAM: u32 = (ML_DSA_Q - 1) / 32; // = 261888
    const BETA_PARAM: u32 = 196; // β = τ·η = 49·4 = 196
                                 // CORRECTED: OMEGA must be 55 for ML-DSA-65 per FIPS 204 Table 1
    const OMEGA_PARAM: u32 = 55;
    const TAU_PARAM: usize = 49;
    const PUBLIC_KEY_BYTES: usize = 1952;
    const SECRET_KEY_BYTES: usize = 4032;
    const SIGNATURE_SIZE: usize = 3309;
    // w₁ encoding for γ₂ = 261888
    // (q-1)/(2·γ₂) = 8380416/(2·261888) = 16
    // Decompose returns r₁ ∈ [0, 15], which requires 4 bits.
    const W1_BITS: usize = 4;
    // Number of bits for packing z coefficients
    // Range [-γ₁+β, γ₁-β] = [-524288+196, 524288-196] = [-524092, 524092]
    // Maximum absolute value: 524092 < 2¹⁹, so 2·524092 < 2²⁰
    // Therefore 20 bits are sufficient
    const Z_BITS: usize = 20;
}

/// Structure containing ML-DSA-87 parameters
/// FIPS 204, Table 1: ML-DSA-87 (NIST security category 5)
pub struct MlDsa87Params {
    /// Polynomial degree n = 256
    pub n: usize,

    /// Modulus q = 8380417
    pub q: u32,

    /// Dropped bits d = 13
    pub d: u32,

    /// Matrix dimension k = 8 (rows)
    pub k: usize,

    /// Matrix dimension ℓ = 7 (columns)
    pub l: usize,

    /// Infinity norm bound η = 2
    pub eta: u32,

    /// Challenge weight τ = 60
    pub tau: usize,

    /// Public key size = 2592 bytes
    pub public_key_size: usize,

    /// Secret key size = 4896 bytes (includes 32-byte K seed)
    pub secret_key_size: usize,

    /// Signature size = 4627 bytes
    pub signature_size: usize,
}

/// ML-DSA-87 parameter set (FIPS 204, Table 1)
/// Targets NIST security category 5 (collision resistance of SHA-512)
pub const ML_DSA_87: MlDsa87Params = MlDsa87Params {
    n: ML_DSA_N,
    q: ML_DSA_Q,
    d: 13,
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    public_key_size: 2592,
    secret_key_size: 4896, // FIPS 204 final: includes 32-byte K seed
    signature_size: 4627,  // FIPS 204 final value
};

impl MlDsaSchemeParams for MlDsa87Params {
    const NAME: &'static str = "ML-DSA-87";
    const D_PARAM: u32 = 13;
    const K_DIM: usize = 8;
    const L_DIM: usize = 7;
    const LAMBDA: usize = 256; // Classical security parameter
    const CHALLENGE_BYTES: usize = 64; // λ/4 = 256/4 = 64
    const ETA_S1S2: u32 = 2;
    const GAMMA1_PARAM: u32 = 1 << 19; // 2¹⁹ = 524288
    const GAMMA1_BITS: usize = 20; // ceil(log₂(2·2¹⁹)) = 20
                                   // γ₂ = (q − 1)/32 = 261888 (FIPS 204, Table 1, ML-DSA-87)
    const GAMMA2_PARAM: u32 = (ML_DSA_Q - 1) / 32; // = 261888
                                                   // β = τ·η = 60·2 = 120 (FIPS 204, Table 1, ML-DSA-87)
    const BETA_PARAM: u32 = 120; // Corrected from earlier drafts
                                 // FIPS 204, Table 1 specifies Ω = 75 for ML-DSA-87.
    const OMEGA_PARAM: u32 = 75;
    const TAU_PARAM: usize = 60;
    const PUBLIC_KEY_BYTES: usize = 2592;
    const SECRET_KEY_BYTES: usize = 4896;
    const SIGNATURE_SIZE: usize = 4627;
    // w₁ encoding: (q-1)/(2·γ₂) = 8380416/(2·261888) = 16
    // Decompose returns r₁ ∈ [0, 15], which requires 4 bits.
    const W1_BITS: usize = 4;
    // Number of bits for packing z coefficients
    // Range [-γ₁+β, γ₁-β] = [-524288+120, 524288-120] = [-524168, 524168]
    // Maximum absolute value: 524168 < 2¹⁹, so 2·524168 < 2²⁰
    // Therefore 20 bits are sufficient
    const Z_BITS: usize = 20;
}
