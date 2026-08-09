//! Final FIPS 203 ML-KEM parameter constants.

/// ML-KEM polynomial degree
pub const ML_KEM_N: usize = 256;

/// ML-KEM modulus
pub const ML_KEM_Q: u16 = 3329;

/// Structure containing ML-KEM-512 parameters
pub struct MlKem512Params {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Number of polynomials (dimension)
    pub k: usize,

    /// Error distribution parameter
    pub eta1: u8,

    /// Error distribution parameter
    pub eta2: u8,

    /// Number of bits dropped for compression of public key
    pub du: usize,

    /// Number of bits dropped for compression of ciphertext
    pub dv: usize,

    /// Size of public key in bytes
    pub public_key_size: usize,

    /// Size of secret key in bytes
    pub secret_key_size: usize,

    /// Size of ciphertext in bytes
    pub ciphertext_size: usize,

    /// Size of shared secret in bytes
    pub shared_secret_size: usize,
}

/// ML-KEM-512 parameters
pub const ML_KEM_512: MlKem512Params = MlKem512Params {
    n: ML_KEM_N,
    q: ML_KEM_Q,
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
    public_key_size: 800,
    secret_key_size: 1632,
    ciphertext_size: 768,
    shared_secret_size: 32,
};

/// Structure containing ML-KEM-768 parameters
pub struct MlKem768Params {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Number of polynomials (dimension)
    pub k: usize,

    /// Error distribution parameter
    pub eta1: u8,

    /// Error distribution parameter
    pub eta2: u8,

    /// Number of bits dropped for compression of public key
    pub du: usize,

    /// Number of bits dropped for compression of ciphertext
    pub dv: usize,

    /// Size of public key in bytes
    pub public_key_size: usize,

    /// Size of secret key in bytes
    pub secret_key_size: usize,

    /// Size of ciphertext in bytes
    pub ciphertext_size: usize,

    /// Size of shared secret in bytes
    pub shared_secret_size: usize,
}

/// ML-KEM-768 parameters
pub const ML_KEM_768: MlKem768Params = MlKem768Params {
    n: ML_KEM_N,
    q: ML_KEM_Q,
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
    public_key_size: 1184,
    secret_key_size: 2400,
    ciphertext_size: 1088,
    shared_secret_size: 32,
};

/// Structure containing ML-KEM-1024 parameters
pub struct MlKem1024Params {
    /// Polynomial degree
    pub n: usize,

    /// Modulus
    pub q: u16,

    /// Number of polynomials (dimension)
    pub k: usize,

    /// Error distribution parameter
    pub eta1: u8,

    /// Error distribution parameter
    pub eta2: u8,

    /// Number of bits dropped for compression of public key
    pub du: usize,

    /// Number of bits dropped for compression of ciphertext
    pub dv: usize,

    /// Size of public key in bytes
    pub public_key_size: usize,

    /// Size of secret key in bytes
    pub secret_key_size: usize,

    /// Size of ciphertext in bytes
    pub ciphertext_size: usize,

    /// Size of shared secret in bytes
    pub shared_secret_size: usize,
}

/// ML-KEM-1024 parameters
pub const ML_KEM_1024: MlKem1024Params = MlKem1024Params {
    n: ML_KEM_N,
    q: ML_KEM_Q,
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
    public_key_size: 1568,
    secret_key_size: 3168,
    ciphertext_size: 1568,
    shared_secret_size: 32,
};
