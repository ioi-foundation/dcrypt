# Poly1305 Message Authentication Code

## Overview

This module provides a branch-free limb implementation of the **Poly1305**
message authentication code, as specified in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439). Poly1305 is a high-speed polynomial evaluation MAC designed to ensure message integrity and authenticity. Branch-free source is not, by itself, a constant-time proof for every compiler and target.

Its API deliberately does not implement the reusable `Mac` trait because that trait exposes cloning/reset-style patterns that are unsafe for a one-time authenticator.

## ⚠️ Security Warning: One-Time MAC

**Poly1305 is a one-time authenticator.** This is its most critical security property.

Using the same key to authenticate two different messages is catastrophic and will allow an attacker to forge authenticator tags for other messages. The security of the algorithm relies on the uniqueness of the key for each invocation.

For this reason, Poly1305 **should not be used as a general-purpose MAC**. It is almost always used as part of a higher-level AEAD (Authenticated Encryption with Associated Data) construction, such as **ChaCha20-Poly1305**. In such constructions, a stream cipher is used to generate a unique, single-use Poly1305 key for each message, thus satisfying the one-time-key requirement.

## Features

*   **RFC 8439 Compliant:** The implementation strictly follows the official standard, ensuring interoperability.
*   **Branch-Free Arithmetic:** Polynomial evaluation and final reduction avoid secret-dependent source branches; statistical or target-specific analysis is still required before a side-channel claim.
*   **Memory Hygiene:** Owned `r`, `s`, buffered input, and key-derived temporaries use zeroizing containers. This cannot erase caller copies or guarantee the absence of compiler/register copies.
*   **Consume-on-Finalize API:** `Poly1305` cannot be cloned or reset, and `finalize(self)` consumes the one-time context.

## Usage

### Computing a Tag

```rust
use dcrypt::algorithms::mac::{Poly1305, POLY1305_KEY_SIZE};

// A 32-byte key is required for Poly1305.
// IMPORTANT: This key must only be used ONCE for a single message.
let key = [0x42; POLY1305_KEY_SIZE];
let message = b"message to authenticate once";

// A context is tied to this one-time key and one message.
let mut poly = Poly1305::new(&key).unwrap();
poly.update(message).unwrap();
let tag = poly.finalize();
println!("Poly1305 Tag: {}", hex::encode(tag.as_ref()));
```

Applications should normally use Poly1305 only through ChaCha20-Poly1305, which derives a fresh one-time key and performs constant-time tag verification. If a protocol requires standalone Poly1305 verification, compute the expected tag with a fresh context and compare equal-length tags in constant time.

### Incremental (Streaming) API

For messages that are not available all at once, you can use the incremental `update` and `finalize` methods.

```rust
use dcrypt::algorithms::mac::{Poly1305, POLY1305_KEY_SIZE};

let key = [0x85; POLY1305_KEY_SIZE]; // A different one-time key
let part1 = b"Cryptographic Forum ";
let part2 = b"Research Group";

// Create a new Poly1305 instance
let mut poly = Poly1305::new(&key).unwrap();

// Update with message parts
poly.update(part1).unwrap();
poly.update(part2).unwrap();

// Finalize to get the tag
let tag = poly.finalize(); // consumes `poly`; it cannot be reset or reused
```

## Implementation Details

The implementation follows the specification in RFC 8439 closely.

*   **Polynomial Evaluation:** The core of the algorithm is the evaluation of a polynomial over the prime field defined by `p = 2^130 - 5`. Each 16-byte block of the message is interpreted as a little-endian integer and added to an accumulator.
*   **Key Structure:** The 32-byte key is split into two 16-byte components:
    *   `r`: The multiplier for the polynomial evaluation. It is "clamped" by clearing specific bits to ensure it remains within a secure range and to prevent certain cryptographic attacks.
    *   `s`: A one-time pad that is added to the result of the polynomial evaluation to produce the final tag.
*   **Finalization:** After processing all message blocks, the final accumulator value is added to `s` (mod 2^128) to produce the 16-byte authentication tag.

## Module Structure

*   `src/mac/poly1305/mod.rs`: Contains the consume-on-finalize `Poly1305` struct and the core cryptographic logic.
*   `src/mac/poly1305/tests.rs`: Contains unit and integration tests, including vectors from RFC 8439 to ensure correctness and compliance.
