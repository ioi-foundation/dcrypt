# Cryptographic Parameters (`params`)

The `params` crate is a `no_std` library dedicated to centralizing constant values and parameter sets for various cryptographic algorithms used within the dcrypt ecosystem. This approach ensures consistency and makes it easier to manage and update parameters across different dcrypt crates.

By being `no_std`, this crate can be used in a wide range of environments, including embedded systems.

## Structure

The `params` crate is organized into sub-modules based on the category of algorithms:

1.  **Traditional Algorithms (`dcrypt_docs/params/traditional/README.md`)**:
    Contains constants for well-established classical cryptographic algorithms.
    *   `rsa.rs`: Modulus sizes (2048, 3072, 4096 bits), common public exponent.
    *   `dsa.rs`: Modulus and subgroup sizes (e.g., 2048/256).
    *   `dh.rs`: Modulus sizes for Diffie-Hellman, standard generator.
    *   `ecdsa.rs`: Parameters for NIST curves (P-256, P-384), including prime, curve coefficients, generator point, order, and cofactor.
    *   `ecdh.rs`: Key and shared secret sizes for ECDH over NIST curves.
    *   `ed25519.rs`: Key sizes, signature size, curve order, base point for Ed25519.

2.  **Post-Quantum Cryptography (PQC) Algorithms (`dcrypt_docs/params/pqc/README.md`)**:
    Contains constants and parameter structures for post-quantum algorithms, often aligned with NIST PQC standardization efforts.
    *   `kyber.rs`: Parameters for Kyber-512, Kyber-768, Kyber-1024 (polynomial degree, modulus, dimensions, key/ciphertext sizes).
    *   `dilithium.rs`: Parameters for Dilithium2, Dilithium3, Dilithium5 (polynomial degree, modulus, dimensions, key/signature sizes).
    *   `ntru.rs`: Parameters for NTRU-HPS and NTRU-HRSS variants (polynomial degree, modulus, key/ciphertext sizes).
    *   `saber.rs`: Parameters for LightSABER, SABER, FireSABER (polynomial degree, modulus, dimensions, key/ciphertext sizes).
    *   `sphincs.rs`: Parameters for SPHINCS+ (SHA256 and SHAKE variants) including hypertree height, layers, Winternitz parameter, FORS tree parameters, key/signature sizes.
    *   `falcon.rs`: Parameters for Falcon-512, Falcon-1024 (polynomial degree, modulus, key/signature sizes).
    *   `mceliece.rs`: Parameters for Classic McEliece variants (code length, dimension, error capability, key/ciphertext sizes).
    *   `rainbow.rs`: Parameters for Rainbow-I, Rainbow-III, Rainbow-V (number of variables, oil/vinegar variables, field size, key/signature sizes).

3.  **Utility Constants (`utils`)**:
    Contains general-purpose constants related to common cryptographic operations.
    *   `hash.rs`: Output and block sizes for various hash functions (SHA-2, SHA-3).
    *   `symmetric.rs`: Key, nonce, and block sizes for symmetric ciphers like AES, ChaCha20, and Poly1305.

## Parameter Structures

For more complex algorithms, especially PQC schemes, this crate often defines `struct`s to hold a complete set of parameters for a specific variant. For example:

```rust
// From params/src/pqc/kyber.rs
pub struct Kyber768Params {
    pub n: usize, // Polynomial degree
    pub q: u16,   // Modulus
    pub k: usize,   // Number of polynomials (dimension)
    // ... other parameters ...
    pub public_key_size: usize,
    pub secret_key_size: usize,
    pub ciphertext_size: usize,
    pub shared_secret_size: usize,
}

pub const KYBER768: Kyber768Params = Kyber768Params {
    n: KYBER_N, // KYBER_N = 256
    q: KYBER_Q, // KYBER_Q = 3329
    k: 3,
    // ...
    public_key_size: 1184,
    secret_key_size: 2400,
    ciphertext_size: 1088,
    shared_secret_size: 32,
};
```

## Purpose

-   **Single Source of Truth**: Provides one location for all cryptographic constants, reducing the risk of inconsistencies or errors if these values were hardcoded in multiple places.
-   **Clarity**: Makes algorithm parameters explicit and easy to find.
-   **Maintainability**: If parameters need to be updated (e.g., due to new security recommendations or standard revisions), changes can be made in one place.
-   **`no_std` Compatibility**: Ensures that these essential constants are available even in resource-constrained environments.
-   **Facilitates Generic Programming**: Algorithm implementations in other dcrypt crates can refer to these constants generically or through specific parameter structs.

This crate is a crucial dependency for `algorithms`, `kem`, `sign`, and other dcrypt components that implement specific cryptographic schemes, as it provides them with the necessary operational parameters.