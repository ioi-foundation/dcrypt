# API Traits (`api/traits`)

This module defines the core public traits that cryptographic components in the dcrypt ecosystem must implement. These traits establish a consistent and type-safe interface for various cryptographic operations, abstracting the underlying algorithm details.

## Key Traits

1.  **`Kem` (`kem.rs`)**:
    *   **Purpose**: Defines the interface for Key Encapsulation Mechanisms.
    *   **Associated Types**: `PublicKey`, `SecretKey`, `SharedSecret`, `Ciphertext`, `KeyPair`.
    *   **Key Methods**:
        *   `name() -> &'static str`: Returns the KEM algorithm name.
        *   `keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair>`: Generates a new key pair.
        *   `public_key(keypair: &Self::KeyPair) -> Self::PublicKey`: Extracts the public key from a keypair.
        *   `secret_key(keypair: &Self::KeyPair) -> Self::SecretKey`: Extracts the secret key from a keypair.
        *   `encapsulate<R: CryptoRng + RngCore>(rng: &mut R, public_key: &Self::PublicKey) -> Result<(Self::Ciphertext, Self::SharedSecret)>`: Encapsulates a shared secret for the given public key.
        *   `decapsulate(secret_key: &Self::SecretKey, ciphertext: &Self::Ciphertext) -> Result<Self::SharedSecret>`: Decapsulates a shared secret using the private key.

2.  **`Signature` (`signature.rs`)**:
    *   **Purpose**: Defines the interface for digital signature schemes.
    *   **Associated Types**: `PublicKey`, `SecretKey`, `SignatureData`, `KeyPair`.
    *   **Key Methods**:
        *   `name() -> &'static str`: Returns the signature algorithm name.
        *   `keypair<R: CryptoRng + RngCore>(rng: &mut R) -> Result<Self::KeyPair>`: Generates a new key pair.
        *   `public_key(keypair: &Self::KeyPair) -> Self::PublicKey`: Extracts the public key.
        *   `secret_key(keypair: &Self::KeyPair) -> Self::SecretKey`: Extracts the secret key.
        *   `sign(message: &[u8], secret_key: &Self::SecretKey) -> Result<Self::SignatureData>`: Signs a message.
        *   `verify(message: &[u8], signature: &Self::SignatureData, public_key: &Self::PublicKey) -> Result<()>`: Verifies a signature.
        *   `batch_sign(...)` and `batch_verify(...)` (optional, with default implementations).

3.  **`SymmetricCipher` (`symmetric.rs`)**:
    *   **Purpose**: Defines the interface for symmetric encryption algorithms.
    *   **Associated Types**: `Key`, `Nonce`, `Ciphertext`, `EncryptOperation<'a>`, `DecryptOperation<'a>`.
    *   **Key Methods**:
        *   `name() -> &'static str`: Returns the cipher name.
        *   `encrypt<'a>(&'a self) -> Self::EncryptOperation<'a>`: Begins an encryption operation (builder pattern).
        *   `decrypt<'a>(&'a self) -> Self::DecryptOperation<'a>`: Begins a decryption operation (builder pattern).
        *   `generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key>`: Generates a random key.
        *   `generate_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Nonce>`: Generates a random nonce.
        *   `derive_key_from_bytes(bytes: &[u8]) -> Result<Self::Key>`: Derives a key from raw bytes.
    *   **Operation Traits (`symmetric.rs`)**:
        *   `Operation<T>`: Base for operations, with `execute() -> Result<T>`.
        *   `EncryptOperation<'a, C>`: Extends `Operation`, adds `with_nonce`, `with_aad`, `encrypt(plaintext)`.
        *   `DecryptOperation<'a, C>`: Extends `Operation`, adds `with_nonce`, `with_aad`, `decrypt(ciphertext)`.

4.  **`Serialize` (`serialize.rs`)**:
    *   **Purpose**: For objects that can be serialized to and deserialized from byte arrays.
    *   **Key Methods**:
        *   `to_bytes(&self) -> Result<Vec<u8>>`
        *   `from_bytes(bytes: &[u8]) -> Result<Self>`

## Marker Traits (`mod.rs`)

These traits are primarily used to categorize algorithms and define their fundamental compile-time properties. They typically do not have methods but associate constants with implementing types.

-   **`BlockCipher`**:
    *   Constants: `BLOCK_SIZE`, `ALGORITHM_ID`.
-   **`StreamCipher`**:
    *   Constants: `STATE_SIZE`, `ALGORITHM_ID`.
-   **`AuthenticatedCipher`**:
    *   Constants: `TAG_SIZE`, `ALGORITHM_ID`. (AEAD ciphers implement this along with `SymmetricCipher`).
-   **`KeyDerivationFunction`**:
    *   Constants: `MIN_SALT_SIZE`, `DEFAULT_OUTPUT_SIZE`, `ALGORITHM_ID`.
-   **`HashAlgorithm`**:
    *   Constants: `OUTPUT_SIZE`, `BLOCK_SIZE`, `ALGORITHM_ID`.

## Purpose and Usage

These traits provide a common language for interacting with cryptographic primitives in dcrypt.
-   **Abstraction**: Users can write generic code that works with any KEM, signature scheme, or symmetric cipher that implements these traits.
-   **Type Safety**: Associated types (like `Self::Key`, `Self::Nonce`) ensure that correct types are used with specific algorithms, often enforced further by specific implementations using types from `dcrypt-algorithms/src/types`.
-   **Discoverability**: They define a clear set of operations expected from each category of cryptographic algorithm.
-   **Modularity**: Implementations of these traits reside in other dcrypt crates (e.g., `algorithms`, `symmetric`, `kem`, `sign`), allowing users to depend only on the functionalities they need.

By adhering to these traits, the dcrypt library aims to provide a secure, consistent, and user-friendly cryptographic toolkit.