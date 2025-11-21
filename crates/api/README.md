# dcrypt API (`api`)

The `api` crate defines the public Application Programming Interface for the dcrypt cryptographic ecosystem. It establishes the core traits, error handling mechanisms, and fundamental types that are used consistently across all dcrypt libraries.

The primary goal of this crate is to provide a stable and ergonomic interface for users of dcrypt, abstracting away the specific implementation details of the underlying cryptographic algorithms.

## Core Components

1.  **Traits (`dcrypt_docs/api/traits/README.md`)**:
    Defines the essential traits that cryptographic primitives must implement. These traits ensure a consistent interface for various operations:
    *   `Kem`: For Key Encapsulation Mechanisms.
    *   `Signature`: For Digital Signature schemes.
    *   `SymmetricCipher`: For symmetric encryption algorithms, including builder patterns for `EncryptOperation` and `DecryptOperation`.
    *   `Serialize`: For objects that can be serialized to and from byte arrays.
    *   Marker Traits: `BlockCipher`, `StreamCipher`, `AuthenticatedCipher`, `KeyDerivationFunction`, `HashAlgorithm` to categorize algorithms and define their core properties (like block size, tag size, etc.).

2.  **Error Handling (`dcrypt_docs/api/error/README.md`)**:
    Provides a unified error handling system:
    *   `Error` (enum): The primary error type for all dcrypt operations, with variants for common cryptographic failures (e.g., `InvalidKey`, `InvalidSignature`, `DecryptionFailed`, `InvalidLength`).
    *   `Result<T>`: A type alias for `core::result::Result<T, api::Error>`.
    *   `ResultExt` (trait): Extension methods for `Result` types to easily add context or wrap errors.
    *   `SecureErrorHandling` (trait): For handling errors in constant-time operations, integrating with `ErrorRegistry`.
    *   `ErrorRegistry`: A global (or thread-local) mechanism to record errors occurring within constant-time code paths without immediate branching.
    *   `validate` (module): Utility functions for common input validations (e.g., length checks, parameter conditions).

3.  **Types (`dcrypt_docs/api/types.rs`)**:
    Defines fundamental, security-conscious data types:
    *   `SecretBytes<const N: usize>`: A fixed-size array for sensitive data, guaranteeing zeroization on drop and providing constant-time equality.
    *   `SecretVec`: A variable-length vector for sensitive data, also with zeroization on drop.
    *   `Key`: A wrapper for cryptographic key data, ensuring zeroization.
    *   `PublicKey`: A wrapper for public key data.
    *   `Ciphertext`: A wrapper for ciphertext data.
    *   These types often implement `AsRef<[u8]>`, `AsMut<[u8]>`, `Zeroize`, `Serialize`, and sometimes `PartialEq` (with constant-time comparison for secret types).

## Design Philosophy

-   **Consistency**: Provides a uniform way to interact with different cryptographic algorithms.
-   **Type Safety**: Leverages Rust's type system to prevent common errors, such as using a key with an incompatible algorithm or providing data of incorrect length.
-   **Ergonomics**: Aims for an API that is easy to use correctly and hard to misuse. Builder patterns for operations like encryption and decryption enhance this.
-   **Security by Default**: Secure practices, like zeroization of sensitive data and constant-time comparisons, are built into the core types and traits where appropriate.
-   **`no_std` Compatibility**: Designed to be usable in `no_std` environments, with features like heap allocations (`alloc`) being optional.

## How It Fits in dcrypt

The `api` crate serves as the contract between the users of the dcrypt library and the underlying algorithm implementations (primarily found in `dcrypt-algorithms`). Higher-level crates like `dcrypt-symmetric`, `dcrypt-kem`, and `dcrypt-sign` implement the traits defined in `api` to expose their functionalities.

### Example: Using the `SymmetricCipher` Trait

A typical AEAD cipher in `dcrypt-algorithms` or `dcrypt-symmetric` would implement `api::SymmetricCipher` and `api::AuthenticatedCipher`.

```rust
use dcrypt_api::{SymmetricCipher, AuthenticatedCipher, Result, Key, Ciphertext};
use dcrypt_api::types::SecretBytes; // Assuming Nonce type from api::types or algorithms::types
use dcrypt_algorithms::types::Nonce; // Example, actual Nonce would be defined
use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

// Hypothetical AEAD Cipher struct
struct MyAeadCipher {
    key_material: SecretBytes<32>, // Internal key
}

// Implementing the operation traits (simplified)
pub struct MyEncryptOperation<'a> {
    cipher: &'a MyAeadCipher,
    nonce: Option<&'a Nonce<12>>, // Example nonce type
    aad: Option<&'a [u8]>,
}
// ... (EncryptOperation methods) ...
impl<'a> dcrypt_api::traits::symmetric::Operation<Ciphertext> for MyEncryptOperation<'a> {
    fn execute(self) -> Result<Ciphertext> { /* ... */ Ok(Ciphertext::new(&[])) }
}
impl<'a> dcrypt_api::traits::symmetric::EncryptOperation<'a, MyAeadCipher> for MyEncryptOperation<'a> {
    fn with_nonce(mut self, nonce: &'a Nonce<12>) -> Self { self.nonce = Some(nonce); self }
    fn with_aad(mut self, aad: &'a [u8]) -> Self { self.aad = Some(aad); self }
    fn encrypt(self, _plaintext: &'a [u8]) -> Result<Ciphertext> {
        // Actual encryption logic using self.cipher, self.nonce, self.aad, plaintext
        Ok(Ciphertext::new(b"encrypted_data")) // Placeholder
    }
}

// ... (DecryptOperation similarly) ...
pub struct MyDecryptOperation<'a> { /* ... */ }
impl<'a> dcrypt_api::traits::symmetric::Operation<Vec<u8>> for MyDecryptOperation<'a> {
    fn execute(self) -> Result<Vec<u8>> { /* ... */ Ok(Vec::new()) }
}
impl<'a> dcrypt_api::traits::symmetric::DecryptOperation<'a, MyAeadCipher> for MyDecryptOperation<'a> {
    fn with_nonce(self, _nonce: &'a Nonce<12>) -> Self { self }
    fn with_aad(self, _aad: &'a [u8]) -> Self { self }
    fn decrypt(self, _ciphertext: &'a Ciphertext) -> Result<Vec<u8>> {
        Ok(b"decrypted_data".to_vec()) // Placeholder
    }
}


impl SymmetricCipher for MyAeadCipher {
    type Key = Key; // Using api::Key
    type Nonce = Nonce<12>; // Using a fixed-size Nonce
    type Ciphertext = Ciphertext; // Using api::Ciphertext
    type EncryptOperation<'a> = MyEncryptOperation<'a>;
    type DecryptOperation<'a> = MyDecryptOperation<'a>;

    fn name() -> &'static str { "MyAeadCipher" }

    fn encrypt<'a>(&'a self) -> Self::EncryptOperation<'a> {
        MyEncryptOperation { cipher: self, nonce: None, aad: None }
    }
    fn decrypt<'a>(&'a self) -> Self::DecryptOperation<'a> {
        /* MyDecryptOperation { ... } */
        unimplemented!()
    }

    fn generate_key<R: RngCore + CryptoRng>(_rng: &mut R) -> Result<Self::Key> {
        let mut k = vec![0u8; 32];
        _rng.fill_bytes(&mut k);
        Ok(Key::new(&k))
    }
    fn generate_nonce<R: RngCore + CryptoRng>(_rng: &mut R) -> Result<Self::Nonce> {
        let mut n_bytes = [0u8; 12];
        _rng.fill_bytes(&mut n_bytes);
        Ok(Nonce::new(n_bytes))
    }
    fn derive_key_from_bytes(bytes: &[u8]) -> Result<Self::Key> {
        if bytes.len() < 32 { return Err(crate::Error::InvalidKey{ context: "Key too short", #[cfg(feature="std")] message: "".into()}); }
        Ok(Key::new(&bytes[..32]))
    }
}

impl AuthenticatedCipher for MyAeadCipher {
    const TAG_SIZE: usize = 16;
    const ALGORITHM_ID: &'static str = "MYAEAD";
}

// fn main() {
//     let mut rng = rand::rngs::OsRng;
//     let key = MyAeadCipher::generate_key(&mut rng).unwrap();
//     let cipher = MyAeadCipher { key_material: SecretBytes::from_slice(key.as_ref()).unwrap() };
//     let nonce = MyAeadCipher::generate_nonce(&mut rng).unwrap();
//     let ciphertext = cipher.encrypt()
//         .with_nonce(&nonce)
//         .encrypt(b"hello")
//         .unwrap();
//     // ...
// }
```

This structure allows users to work with a consistent set of traits and types, regardless of the specific cryptographic algorithm being used, promoting safer and more maintainable cryptographic code.