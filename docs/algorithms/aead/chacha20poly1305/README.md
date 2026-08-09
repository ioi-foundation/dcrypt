# AEAD: ChaCha20-Poly1305

## Overview

This module provides dcrypt's safe-Rust implementation of the
ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD)
algorithm specified in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).

ChaCha20-Poly1305 is a widely adopted AEAD construction that combines the ChaCha20 stream cipher with the Poly1305 message authentication code. It is known for its high performance on modern CPUs that lack dedicated AES hardware acceleration, while providing a high level of security.

This implementation is designed to be used through the `SymmetricCipher` trait, providing a consistent and type-safe API.

## Security-relevant implementation properties

The implementation prioritizes resistance against side-channel attacks and correctness.

*   **Tag Verification:** The Poly1305 tag is compared with dcrypt's owned
    constant-time equality primitive. Release gates inspect representative
    target code, but this is not a compiler- or target-wide constant-time proof.
*   **Uniform Post-Authentication Flow:** After tag calculation, the same
    byte-wise selection loop runs for valid and invalid tags before the result
    is returned.
*   **Owned Memory Hygiene:** The key and secret-derived scratch use exact-size
    wrappers that explicitly clear their owned initialized bytes on drop. Safe
    Rust cannot guarantee physical erasure of compiler/register copies, caller
    copies, freed storage, swap, or crash dumps.

## Usage

The primary way to use this module is through the `ChaCha20Poly1305` struct, which implements the `SymmetricCipher` trait. This provides a builder pattern for both encryption and decryption.

### Encryption and Decryption Example

```rust
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::types::{Nonce, SecretBytes};
use dcrypt::api::traits::SymmetricCipher;
use dcrypt::api::traits::symmetric::{EncryptOperation, DecryptOperation};

// 1. Setup a 32-byte key and a 12-byte nonce.
let key_bytes = [42u8; 32];
let nonce = Nonce::<12>::new([1u8; 12]);
let plaintext = b"this is a highly secret message";
let associated_data = b"important authenticated metadata";

// 2. Create the ChaCha20-Poly1305 cipher instance.
let cipher = ChaCha20Poly1305::new(&key_bytes);

// 3. Encrypt the data using the builder pattern.
let ciphertext_obj = cipher.encrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .encrypt(plaintext)
    .unwrap();

// The resulting object contains the ciphertext and the 16-byte authentication tag.
println!("Ciphertext: {}", hex::encode(ciphertext_obj.as_ref()));
assert_eq!(ciphertext_obj.len(), plaintext.len() + 16);

// 4. Decrypt the data.
let decrypted_payload = cipher.decrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .decrypt(&ciphertext_obj)
    .unwrap();

assert_eq!(decrypted_payload, plaintext);
println!("Decryption successful!");

// 5. Verify that tampering results in an error.
let mut tampered_ciphertext = ciphertext_obj.as_ref().to_vec();
tampered_ciphertext[0] ^= 0xff; // Flip a bit in the ciphertext.
let tampered_obj = dcrypt::api::types::Ciphertext::new(tampered_ciphertext);

let decryption_result = cipher.decrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .decrypt(&tampered_obj);

assert!(decryption_result.is_err());
println!("Tampered ciphertext correctly rejected.");
```

## API Structure

*   **`ChaCha20Poly1305`**: The main struct representing the cipher. It is initialized with a 32-byte key.
*   **`SymmetricCipher` Trait**: The primary interface for this cipher.
    *   `encrypt()`: Returns an `EncryptOperation` builder.
    *   `decrypt()`: Returns a `DecryptOperation` builder.
*   **`ChaCha20Poly1305EncryptOperation`**: A builder for encryption that allows setting the `nonce` and `aad` before encrypting the plaintext.
*   **`ChaCha20Poly1305DecryptOperation`**: A builder for decryption that allows setting the `nonce` and `aad` before decrypting the ciphertext.

## Constants

This module exports several important constants:

*   **`CHACHA20POLY1305_KEY_SIZE`**: The required key size in bytes (32).
*   **`CHACHA20POLY1305_NONCE_SIZE`**: The required nonce size in bytes (12).
*   **`CHACHA20POLY1305_TAG_SIZE`**: The size of the authentication tag in bytes (16).

## Relationship to XChaCha20-Poly1305

This module provides the core ChaCha20-Poly1305 AEAD. When a protocol needs a
24-byte nonce to reduce accidental random-collision risk, use
`dcrypt::algorithms::aead::xchacha20poly1305`. XChaCha20-Poly1305 is not
nonce-misuse resistant: nonce reuse under one key remains forbidden.
