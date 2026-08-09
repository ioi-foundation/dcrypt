# AES-GCM Authenticated Encryption

## Overview

This module provides an implementation of AES-GCM (Advanced Encryption
Standard in Galois/Counter Mode), the authenticated encryption with associated
data (AEAD) mode specified in **NIST Special Publication 800-38D**. It is tested
against known-answer data; this is not a FIPS validation or blanket side-channel
claim.

It combines the AES block cipher operating in Counter (CTR) mode for encryption with the GHASH function for authentication, providing strong guarantees of both **confidentiality** and **authenticity**.

## Features

*   **AEAD Functionality:** Encrypts plaintext and generates an authentication tag that covers both the plaintext and optional associated data (AD).
*   **Generic Implementation:** The `Gcm<B>` struct is generic over the underlying 128-bit block cipher. It is intended for use with the AES variants provided in this crate:
    *   `Gcm<Aes128>`
    *   `Gcm<Aes192>`
    *   `Gcm<Aes256>`
*   **NIST vectors:** Supported tag/IV combinations are tested against NIST CAVP/ACVP known-answer data for correctness and interoperability.
*   **Supported Nonce Sizes:** The public nonce types support 96-, 120-, and 128-bit (12-, 15-, and 16-byte) IVs. The non-96-bit `J0` derivation follows NIST SP 800-38D; arbitrary IV lengths are not exposed by this API.
*   **Safe Tag Lengths:** Uses a 128-bit (16-byte) tag by default. The compatibility constructor permits only 96- through 128-bit tags (12 through 16 bytes).

## Security

Security is the primary design consideration for this implementation.

*   **Tag comparison:** Equal-length tag bytes use `subtle::ConstantTimeEq`; public length and error paths use ordinary branching. Target-specific analysis remains required for broader timing claims.
*   **Memory hygiene:** Owned GHASH and AES key state use zeroization. This does not guarantee erasure of caller, compiler, register, or allocator copies.
*   **Robust API:** The API is designed around the `SymmetricCipher` trait, using a builder pattern that guides the user to provide all necessary components (like the nonce) before an operation can be executed, reducing the risk of misuse.

## Usage

### Encryption and Decryption with AES-128-GCM

The following example demonstrates a complete encrypt-decrypt cycle using `Gcm<Aes128>`.

```rust
use dcrypt::algorithms::aead::gcm::Gcm;
use dcrypt::algorithms::block::Aes128;
use dcrypt::algorithms::types::{Nonce, SecretBytes};
use dcrypt::api::traits::SymmetricCipher;
use dcrypt::api::traits::symmetric::{EncryptOperation, DecryptOperation};

// 1. Setup the key, nonce, plaintext, and associated data.
let key = SecretBytes::new([42u8; 16]);
let nonce = Nonce::<12>::new([1u8; 12]); // A 96-bit (12-byte) nonce is standard.
let plaintext = b"this is a secret message that needs protection";
let associated_data = b"unencrypted but authenticated metadata";

// 2. Create the AES-128 block cipher instance.
let aes_encrypt = Aes128::new(&key);

// 3. Create the GCM instance for encryption.
let gcm_encrypt = Gcm::new(aes_encrypt).unwrap();

// 4. Encrypt the data using the builder pattern.
// The `encrypt()` method on the SymmetricCipher trait returns an EncryptOperation builder.
let ciphertext_obj = gcm_encrypt
    .encrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .encrypt(plaintext)
    .unwrap();

// The resulting object contains the ciphertext with the authentication tag appended.
println!("AES-GCM Ciphertext (hex): {}", hex::encode(ciphertext_obj.as_ref()));

// 5. For decryption, create a new cipher instance.
let aes_decrypt = Aes128::new(&key);
let gcm_decrypt = Gcm::new(aes_decrypt).unwrap();

// 6. Decrypt the data. This will fail if the ciphertext or AAD was tampered with.
let decrypted_payload = gcm_decrypt
    .decrypt()
    .with_nonce(&nonce)
    .with_aad(associated_data)
    .decrypt(&ciphertext_obj)
    .unwrap();

assert_eq!(decrypted_payload, plaintext);
println!("Decryption successful and data verified!");
```

### Security Considerations

#### Nonce (IV) Uniqueness

**CRITICAL:** The security of GCM relies on the uniqueness of the nonce for every encryption operation performed with the same key. **Never reuse a nonce with the same key.** Reusing a nonce can lead to a catastrophic failure of confidentiality and authenticity. It is recommended to generate nonces using a cryptographically secure random number generator or a counter-based scheme.

#### Tag Length

`Gcm::new` always uses a full 16-byte (128-bit) tag. `Gcm::new_with_tag_len` exists for protocol compatibility and accepts only 12 through 16 bytes; shorter tags are rejected. Prefer the default 16-byte tag for new protocols.

## `no_std` Support

The current workspace does not claim a validated standalone `no_std` GCM build.
The feature surface is being retained for future repair; use the tested `std`
configuration unless the exact target/feature combination is independently
made to compile and reviewed.
