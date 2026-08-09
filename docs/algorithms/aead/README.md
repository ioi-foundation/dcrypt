# Authenticated Encryption with Associated Data (AEAD)

## Overview

This module provides implementations of Authenticated Encryption with Associated Data (AEAD) ciphers. AEAD is a mode of operation for symmetric-key ciphers that simultaneously provides confidentiality, integrity, and authenticity for encrypted data.

-   **Confidentiality:** The plaintext is encrypted into ciphertext, which is unintelligible without the key.
-   **Integrity & Authenticity:** A Message Authentication Code (MAC), called a tag, is generated over the plaintext and "associated data". This tag allows the decrypting party to verify that the data has not been tampered with and that it originated from a party holding the secret key.
-   **Associated Data (AD):** This is optional, unencrypted data that is included in the authentication process. It is useful for authenticating metadata, headers, or other contextual information that should not be encrypted but must be protected from modification.

## Implemented Algorithms

This module provides the following AEAD schemes:

*   **AES-GCM:** The Advanced Encryption Standard (AES) in Galois/Counter Mode. The implementation is generic over the underlying AES block cipher, supporting:
    *   `Gcm<Aes128>`
    *   `Gcm<Aes192>`
    *   `Gcm<Aes256>`
*   **ChaCha20-Poly1305:** A high-performance stream cipher-based AEAD construction, as specified in RFC 8439.
*   **XChaCha20-Poly1305:** An extended-nonce variant of ChaCha20-Poly1305, which allows a larger 24-byte nonce to be used safely, making it more robust against nonce misuse.

## Key Security Features

The implementations in this module are designed with a focus on security and side-channel resistance.

*   **Constant-Time Execution:** Tag verification is performed in constant time using the `subtle` crate's `ConstantTimeEq` trait. This prevents timing side-channel attacks where an attacker could learn information about the tag by measuring the time it takes for a comparison to complete.
*   **Secure Memory Management:** All secret key material is handled using `SecretBuffer` and `Zeroizing` types, which ensure that sensitive data is securely wiped from memory when it is no longer needed.
*   **Correctness testing:** Implementations are tested against NIST
    known-answer data (for supported AES-GCM cases) and relevant RFC vectors.
    This is not formal validation or certification.

## Usage

The AEAD ciphers in this module follow a consistent API provided by the `SymmetricCipher` and `AuthenticatedCipher` traits. They use a builder pattern for encryption and decryption operations.

### Example: AES-128-GCM

```rust
use dcrypt::algorithms::aead::gcm::Gcm;
use dcrypt::algorithms::block::Aes128;
use dcrypt::algorithms::types::{Nonce, SecretBytes};
use dcrypt::api::traits::SymmetricCipher;
use dcrypt::api::traits::symmetric::{EncryptOperation, DecryptOperation};

// 1. Setup the key, nonce, and plaintext.
let key = SecretBytes::new([42u8; 16]);
let nonce = Nonce::<12>::new([1u8; 12]);
let plaintext = b"this is a secret message";
let associated_data = b"metadata";

// 2. Create the AES block cipher and the GCM instance.
let aes = Aes128::new(&key);
let gcm = Gcm::new(aes).unwrap();

// 3. Encrypt the data using the builder pattern.
let ciphertext_obj = <Gcm<Aes128> as SymmetricCipher>::encrypt(&gcm)
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .encrypt(plaintext)
    .unwrap();

// The ciphertext object contains the encrypted data and the authentication tag.
println!("AES-GCM Ciphertext: {}", hex::encode(ciphertext_obj.as_ref()));

// 4. Decrypt the data.
let aes_decrypt = Aes128::new(&key);
let gcm_decrypt = Gcm::new(aes_decrypt).unwrap();
let decrypted_payload = <Gcm<Aes128> as SymmetricCipher>::decrypt(&gcm_decrypt)
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .decrypt(&ciphertext_obj)
    .unwrap();

assert_eq!(decrypted_payload, plaintext);
println!("AES-GCM Decryption successful!");
```

### Example: ChaCha20-Poly1305

```rust
use dcrypt::algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt::algorithms::types::Nonce;
use dcrypt::api::traits::SymmetricCipher;
use dcrypt::api::traits::symmetric::{EncryptOperation, DecryptOperation};

// 1. Setup the key, nonce, and plaintext.
let key = [42u8; 32];
let nonce = Nonce::<12>::new([1u8; 12]);
let plaintext = b"another secret message";
let associated_data = b"more metadata";

// 2. Create the ChaCha20-Poly1305 instance.
let cipher = ChaCha20Poly1305::new(&key);

// 3. Encrypt the data.
let ciphertext_obj = cipher.encrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .encrypt(plaintext)
    .unwrap();

println!("ChaCha20-Poly1305 Ciphertext: {}", hex::encode(ciphertext_obj.as_ref()));

// 4. Decrypt the data.
let decrypted_payload = cipher.decrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .decrypt(&ciphertext_obj)
    .unwrap();

assert_eq!(decrypted_payload, plaintext);
println!("ChaCha20-Poly1305 Decryption successful!");
```

**Note on XChaCha20-Poly1305:** The API for `XChaCha20Poly1305` is identical to `ChaCha20Poly1305`, except that it requires a 24-byte nonce (`Nonce<24>`).

## API Design Philosophy

The AEAD API is designed to be both ergonomic and secure:

*   **Builder Pattern:** The `EncryptOperation` and `DecryptOperation` builders guide the user through the process of providing all necessary parameters (nonce, AAD, plaintext/ciphertext) before the final operation is executed. This prevents mistakes like forgetting to specify a nonce.
*   **Trait-Based:** By implementing the `SymmetricCipher` trait from `dcrypt-api`, all AEAD ciphers in this module provide a consistent interface, making them interchangeable where appropriate.
*   **Type Safety:** The use of `Nonce<N>` and `SecretBytes<N>` prevents errors related to incorrect nonce or key lengths at compile time.

## `no_std` Support

The current workspace does not claim a validated standalone `no_std` AEAD
build. The feature surface remains for future repair, but the exact algorithm,
target, and feature combination must compile and be reviewed independently.
