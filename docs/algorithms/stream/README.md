# Stream Ciphers

## Overview

This module provides implementations of stream ciphers, which are symmetric key ciphers that encrypt plaintext one byte at a time using a pseudorandom keystream. The design prioritizes security, correctness, and a type-safe, ergonomic API.

The core **ChaCha20** implementation uses fixed-round arithmetic and explicit
clearing wrappers for owned secret state. Release checks are not a blanket
compiler/target timing proof or a physical-erasure guarantee.

### Key Features

*   **Owned memory hygiene:** Uses `SecretBuffer` and clearing implementations
    for stateful secret storage, subject to software-zeroization limits.
*   **Type Safety:** Leverages Rust's type system with generic `Nonce<N>` types and compatibility traits (`ChaCha20Compatible`) to prevent API misuse at compile time.
*   **Stateful Operations:** Provides a full suite of stream cipher operations, including `encrypt`, `decrypt`, direct `keystream` generation, `seek` to arbitrary block positions, and `reset`.
*   **RFC Compliance:** The ChaCha20 implementation is validated against official RFC 8439 test vectors.
*   **`no_std` Compatible:** Suitable for use in embedded and resource-constrained environments (requires an allocator).

---

## Available Ciphers

*   **ChaCha20:** A high-speed, secure stream cipher as specified in [RFC 8439](https://tools.ietf.org/html/rfc8439). It is widely used in protocols like TLS 1.3 and WireGuard.

---

## The `StreamCipher` Trait

A common interface is provided through the `StreamCipher` trait, which defines the core functionality for all stream ciphers in this module.

### Methods

*   `process(&mut self, data: &mut [u8])`: Encrypts or decrypts data in place by XORing it with the keystream. In a stream cipher, these two operations are identical.
*   `keystream(&mut self, output: &mut [u8])`: Generates the raw keystream and writes it directly to the output buffer without requiring any plaintext or ciphertext.
*   `seek(&mut self, block_offset: u64)`: Jumps to a specific block position in the keystream. This is useful for randomly accessing encrypted data without processing the entire stream.
*   `reset(&mut self)`: Resets the cursor to the initial counter. This may be
    used only to reproduce the same keystream for an already-defined operation;
    never encrypt distinct plaintext under the same key and nonce.

---

## ⚠️ Critical Security Warning: Nonce Reuse

The security of all stream ciphers, including ChaCha20, depends critically on the uniqueness of the **nonce** for every message encrypted with the same key.

**NEVER REUSE A (KEY, NONCE) PAIR.**

Reusing a nonce allows an attacker to compute the XOR of the two plaintexts, which can lead to a complete loss of confidentiality. It is the responsibility of the user to ensure nonce uniqueness, for example, by using a counter or a random number generator.

---

## Usage Examples

### Basic Encryption and Decryption

```rust
use dcrypt::algorithms::stream::ChaCha20;
use dcrypt::algorithms::types::Nonce;

// A 32-byte (256-bit) key
let key = [0x42; 32];
// A 12-byte (96-bit) nonce, which must be unique for each message
let nonce_data = [0x24; 12];
let nonce = Nonce::<12>::new(nonce_data);

// Create a new cipher instance
let mut cipher = ChaCha20::new(&key, &nonce);

let mut message = *b"this is a secret message";

// Encrypt the message in place
cipher.encrypt(&mut message);

println!("Ciphertext: {:?}", message);
// Ciphertext will be different from the original plaintext

// To decrypt, reset the cipher to its initial state
cipher.reset();

// Decrypt the message in place
cipher.decrypt(&mut message);

println!("Decrypted: {:?}", String::from_utf8_lossy(&message));
assert_eq!(&message, b"this is a secret message");
```

### Direct Keystream Generation

You can also generate the raw keystream for use in other protocols.

```rust
use dcrypt::algorithms::stream::ChaCha20;
use dcrypt::algorithms::types::Nonce;

let key = [0x01; 32];
let nonce = Nonce::<12>::new([0x02; 12]);
let mut cipher = ChaCha20::new(&key, &nonce);

// Generate 128 bytes of keystream
let mut keystream = [0u8; 128];
cipher.keystream(&mut keystream).unwrap();

// The `keystream` buffer is now filled with the pseudorandom output.
// This is equivalent to encrypting a buffer of 128 zero bytes.
```

### Seeking to a Keystream Position

The `seek` method allows you to jump to a specific block in the keystream without generating all preceding blocks. Each block is 64 bytes long.

```rust
use dcrypt::algorithms::stream::ChaCha20;
use dcrypt::algorithms::types::Nonce;

let key = [0x03; 32];
let nonce = Nonce::<12>::new([0x04; 12]);

// Create two identical cipher instances
let mut cipher1 = ChaCha20::new(&key, &nonce);
let mut cipher2 = ChaCha20::new(&key, &nonce);

// 1. Advance the first cipher by processing 64 bytes of data (1 full block)
let mut data = [0u8; 64];
cipher1.process(&mut data);

// 2. Seek the second cipher to the start of the second block (offset 1)
cipher2.seek(1).unwrap();

// 3. The keystream generated by both ciphers should now be identical
let mut keystream1 = [0u8; 32];
let mut keystream2 = [0u8; 32];
cipher1.keystream(&mut keystream1).unwrap();
cipher2.keystream(&mut keystream2).unwrap();

assert_eq!(keystream1, keystream2);
```
