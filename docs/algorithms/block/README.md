# Block Ciphers and Modes of Operation

## Overview

This module provides implementations of block ciphers and common modes of operation. The primary focus is on security, correctness, and a type-safe API that leverages Rust's trait system to create a flexible and secure foundation for symmetric encryption.

The components avoid intentional secret-indexed lookup tables and
secret-dependent early exits where documented. Release gates inspect supported
targets, but this is not a blanket constant-time proof.

## Core Concepts & Design

The module is built around a few key abstractions:

*   **`BlockCipher` Trait:** This is the fundamental trait for any block cipher implementation. It defines the core operations of encrypting and decrypting a single block of data. All ciphers, like `Aes128`, implement this trait.
*   **`BlockCipherMode` Traits:** These traits define how a block cipher should be used to securely encrypt messages longer than a single block. Implementations like `Cbc` and `Ctr` are generic over any type that satisfies the `BlockCipher` trait.
*   **Timing-sensitive design:** The AES implementation avoids data-dependent
    lookup tables by using arithmetic S-box operations. Concrete compiler and
    target behavior remains a release-validation concern.
*   **Owned memory hygiene:** Keys and secret-derived scratch use wrappers that
    explicitly clear their initialized storage on drop. This cannot erase
    caller, compiler/register, allocator, swap, or crash-dump copies.

## Available Primitives

### Block Ciphers

*   **AES (Advanced Encryption Standard)**
    *   `Aes128`: AES with a 128-bit key.
    *   `Aes192`: AES with a 192-bit key.
    *   `Aes256`: AES with a 256-bit key.

### Modes of Operation

*   **CBC (Cipher Block Chaining):** A standard mode of operation that chains blocks together. Requires padding for messages that are not a multiple of the block size.
*   **CTR (Counter Mode):** A mode that turns a block cipher into a stream cipher. It does not require padding and is suitable for parallel processing.

> **Note on Authenticated Modes:** Authenticated Encryption with Associated Data (AEAD) modes like AES-GCM are available in the `dcrypt::algorithms::aead` module, as they provide both encryption and authentication.

## Usage Examples

### Example 1: Basic AES Block Encryption

This example demonstrates the direct use of the `BlockCipher` trait to encrypt and decrypt a single 16-byte block.

```rust
use dcrypt::algorithms::block::{Aes128, BlockCipher};
use dcrypt::algorithms::types::SecretBytes;

// AES-128 uses a 16-byte key.
let key_bytes = [0x42; 16];
let key = SecretBytes::new(key_bytes);
let aes = Aes128::new(&key);

let mut block = [0u8; 16]; // A single 16-byte block of data.
let original_block = block;

// Encrypt the block in place.
aes.encrypt_block(&mut block).unwrap();
println!("Encrypted Block: {:?}", block);

// Decrypt the block in place.
aes.decrypt_block(&mut block).unwrap();
println!("Decrypted Block: {:?}", block);

assert_eq!(block, original_block);
```

### Example 2: Using CBC Mode

This example shows how to use AES-128 within the CBC mode of operation to encrypt a longer message.

```rust
use dcrypt::algorithms::block::{Aes128, BlockCipher, Cbc};
use dcrypt::algorithms::types::{Nonce, SecretBytes};

// Setup key and initialization vector (IV).
let key_bytes = [0x42; 16];
let key = SecretBytes::new(key_bytes);
let iv_bytes = [0x24; 16];
let iv = Nonce::<16>::new(iv_bytes); // CBC's IV must match the block size.

// Plaintext must be a multiple of the block size (16 bytes for AES).
// In a real application, you would apply padding (e.g., PKCS#7).
let plaintext = b"This is a sample text for CBC!!"; // 32 bytes
assert_eq!(plaintext.len() % 16, 0);

// Create the cipher and wrap it in CBC mode.
let cipher = Aes128::new(&key);
let cbc_encrypt = Cbc::new(cipher, &iv).unwrap();

// Encrypt the data.
let ciphertext = cbc_encrypt.encrypt(plaintext).unwrap();
println!("CBC Ciphertext: {:?}", ciphertext);

// For decryption, create a new CBC instance.
let cipher_decrypt = Aes128::new(&key);
let cbc_decrypt = Cbc::new(cipher_decrypt, &iv).unwrap();

// Decrypt the data.
let decrypted_text = cbc_decrypt.decrypt(&ciphertext).unwrap();

assert_eq!(decrypted_text, plaintext);
```

### Example 3: Using CTR Mode

This example demonstrates using AES-128 in CTR mode, which acts like a stream cipher.

```rust
use dcrypt::algorithms::block::{Aes128, BlockCipher, Ctr};
use dcrypt::algorithms::types::{Nonce, SecretBytes};

// Setup key and nonce.
let key_bytes = [0x42; 16];
let key = SecretBytes::new(key_bytes);
let nonce_bytes = [0x24; 12];
let nonce = Nonce::<12>::new(nonce_bytes); // CTR nonces are typically shorter than the block size.

// Plaintext does not need to be a multiple of the block size.
let plaintext = b"This is a sample text for CTR mode.";

// Create the cipher and wrap it in CTR mode.
let cipher = Aes128::new(&key);
let mut ctr_encrypt = Ctr::new(cipher, &nonce).unwrap();

// Encrypt the data.
let mut buffer = plaintext.to_vec();
ctr_encrypt.encrypt(&mut buffer).unwrap();
println!("CTR Ciphertext: {:?}", buffer);

// Decryption is the same operation.
let cipher_decrypt = Aes128::new(&key);
let mut ctr_decrypt = Ctr::new(cipher_decrypt, &nonce).unwrap();
ctr_decrypt.decrypt(&mut buffer).unwrap();

assert_eq!(buffer, plaintext);
```

## Security Features

*   **AES source structure:** The implementation avoids common sources of timing side-channels:
    *   **Arithmetic S-Box:** Instead of secret-indexed lookup tables, the S-Box
        transformation uses fixed arithmetic operations.
    *   **Branchless Arithmetic:** Galois Field multiplication (`gf_mul`) and other sensitive operations are implemented to avoid secret-dependent branches.
*   **Owned Memory Hygiene:** Keys, round keys, and block scratch use exact-size
    wrappers that explicitly clear their owned initialized bytes on drop. This
    best-effort safe-Rust behavior cannot guarantee physical erasure of
    compiler/register copies, caller copies, freed storage, swap, or crash
    dumps.
*   **Type Safety:** The generic structure of the modes of operation ensures that they can only be used with a valid `BlockCipher` implementation. The use of the `Nonce` type adds clarity and helps prevent misuse of initialization vectors.

## Module Structure

The `block` module is organized as follows:

*   `src/block/mod.rs`: Defines the core traits (`BlockCipher`, `BlockCipherMode`, etc.) and re-exports the main components.
*   `src/block/aes/`: Contains the implementation of the AES algorithm (AES-128, AES-192, AES-256).
*   `src/block/modes/`: Contains implementations for the different modes of operation.
    *   `cbc/`: Cipher Block Chaining mode.
    *   `ctr/`: Counter mode.
