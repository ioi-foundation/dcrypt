# AEAD: XChaCha20-Poly1305

## Overview

This module provides an implementation of the **XChaCha20-Poly1305**
Authenticated Encryption with Associated Data (AEAD) construction. Its 24-byte
nonce reduces accidental collision risk for correctly sampled random nonces;
reuse under one key remains forbidden.

Under the construction's key, nonce, and message-limit requirements, its
intended security properties are confidentiality and authenticity.

> **Migration note:** every published `dcrypt-algorithms` version from
> `0.9.0-beta.1` through `1.2.3` emitted a nonstandard custom construction
> under this name. This implementation follows standard XChaCha20-Poly1305 and
> intentionally does not accept those legacy ciphertexts. Existing data must
> be migrated with the separately isolated decrypt-only tool; it must not be
> relabeled as standard XChaCha20-Poly1305.

## The Nonce Advantage: Why Use XChaCha20?

The primary motivation for XChaCha20 is its use of a large **24-byte (192-bit) nonce**. This is a significant advantage over the 12-byte (96-bit) nonce used by the standard ChaCha20-Poly1305.

### The Problem with 96-bit Nonces

With a 96-bit nonce, generating random nonces for every message carries a non-trivial risk of collision due to the birthday bound. After encrypting 2³² messages, the probability of a nonce collision is about 1 in 2³². While this is a large number, it is not outside the realm of possibility for high-traffic applications. Reusing a nonce with the same key under ChaCha20 (or any stream cipher) is catastrophic and leads to a complete loss of confidentiality. To use a 96-bit nonce safely, it is often recommended to use a counter-based or deterministic generation scheme, which can add complexity.

### The 192-bit Solution

XChaCha20's 192-bit nonce is large enough that generating a unique random nonce for every message is a safe, simple, and highly effective strategy. The probability of a random collision is so astronomically low that it is considered negligible for any practical application.

This makes XChaCha20 an excellent choice for systems where managing a sequential nonce counter is difficult or impractical, such as in distributed or stateless environments.

## Security Considerations

*   **Nonce Safety:** The primary security advantage of this algorithm is its large nonce size, which makes random nonce generation a safe practice. **However, it is still a critical violation to ever reuse a (key, nonce) pair.**
*   **Owned Implementation:** HChaCha20 and the composed ChaCha20-Poly1305
    implementation are dcrypt-owned safe Rust and are checked against published
    vectors and an isolated shared-lineage comparator outside the published
    dependency graph. The comparison is corroborative and does not count as
    independent assurance evidence.
*   **Memory Hygiene:** The adapter explicitly clears its initialized owned key
    bytes on drop. This does not erase caller, compiler, register, or allocator
    copies.
*   **Cryptography:** The cryptographic core of this algorithm is based on the well-vetted ChaCha20 stream cipher and the Poly1305 message authentication code.

## Usage

The low-level API accepts an explicit 24-byte nonce on each encryption and decryption call.

### Example: Encrypting and Decrypting Data

```rust
use dcrypt::algorithms::aead::xchacha20poly1305::XChaCha20Poly1305;
use dcrypt::algorithms::types::Nonce;

// 1. Setup the key, a 24-byte nonce, and plaintext.
let key = [42u8; 32];
let nonce = Nonce::<24>::new([1u8; 24]); // Note the 24-byte size
let plaintext = b"a secret message with an extended nonce";
let associated_data = b"authenticated but not encrypted metadata";

// 2. Create the XChaCha20-Poly1305 instance.
let cipher = XChaCha20Poly1305::new(&key);

// 3. Encrypt with an explicit nonce and AAD.
let ciphertext = cipher
    .encrypt(&nonce, plaintext, Some(associated_data))
    .unwrap();

println!("XChaCha20-Poly1305 Ciphertext: {}", hex::encode(&ciphertext));

// 4. Decrypt the data.
let decrypted_payload = cipher
    .decrypt(&nonce, &ciphertext, Some(associated_data))
    .unwrap();

assert_eq!(decrypted_payload, plaintext);
println!("XChaCha20-Poly1305 Decryption successful!");
```

## API Overview

*   **`XChaCha20Poly1305`**: The main struct representing the XChaCha20-Poly1305 cipher.
    *   `new(key: &[u8; 32]) -> Self`: Creates a new instance with the given 32-byte key.
    *   Provides `.encrypt(&nonce, plaintext, aad)` and `.decrypt(&nonce, ciphertext, aad)` methods and implements `AuthenticatedCipher`.

## Relationship to ChaCha20-Poly1305

The vetted implementation follows the standard construction:

1.  The **HChaCha20** function is used to derive a unique 32-byte subkey from the original key and the first 16 bytes of the 24-byte nonce.
2.  This subkey is then used to initialize a standard `ChaCha20Poly1305` instance.
3.  The remaining 8 bytes of the nonce are padded with 4 zero bytes to form the final 12-byte nonce for the underlying `ChaCha20Poly1305` encryption/decryption operation.

## Performance

Performance is nearly identical to `ChaCha20Poly1305`, with a very small, fixed overhead per message to derive the subkey via HChaCha20. For messages of any significant size, this overhead is negligible. The core encryption and decryption loop is the same as the standard ChaCha20 cipher.

## `no_std` Support

XChaCha20-Poly1305 is included in the release's allocation-backed
`dcrypt-algorithms` AEAD profile compiled for `thumbv7em-none-eabihf` with
default features disabled. Consumers must provide a compatible allocator and
validate their exact target, feature set, nonce management, and platform
behavior.
