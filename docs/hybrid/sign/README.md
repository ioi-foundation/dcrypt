# Hybrid Digital Signatures 

## Overview

This module combines classical and post-quantum signature components. A hybrid
construction can reduce dependence on one primitive during migration, but its
security also depends on strict framing, domain separation, key validation, the
combiner, both implementations, and the surrounding protocol.

A hybrid signature is created by signing a message with two algorithms. Both
components must verify. That rule alone is not an unconditional proof that the
complete system remains secure whenever either component survives.

This module exports the following hybrid signature schemes:

*   `EcdsaMlDsa65Hybrid`: Combines classical **ECDSA P-384** with final FIPS 204 **ML-DSA-65**. The old `EcdsaDilithiumHybrid` spelling is a source-compatible alias to the remediated implementation.

## Format and compatibility

`EcdsaMlDsa65Hybrid` public keys, secret keys, and signatures use
domain-separated version-2 framing. The decoder deliberately rejects version-1
hybrid objects, whose former dcrypt Dilithium component was not a standard
FIPS 204 encoding. Version-1 bytes are not accepted, upgraded, or relabeled.

`v2.0.0` is the first remediated release; `v1.2.3` is confirmed affected, and
earlier releases have not been cleared. Only the default `std` configuration is
supported in `v2.0.0`; the declared `no_std` feature is not a validated release
configuration because transitive dependencies still enable standard library
defaults.

## How It Works

1.  **Key Generation**: A hybrid key pair contains one key pair for each component. The keys are encoded in the scheme's versioned framing.
2.  **Signing**: Each component signs the message, and the two signatures are encoded in a domain-separated `HybridSignature` frame.
3.  **Verification**: The framing and both component signatures are checked. Verification succeeds only if every check succeeds.

## Example Usage

Here is an example demonstrating a full sign-and-verify roundtrip using the `EcdsaMlDsa65Hybrid` scheme. This assumes you are using the top-level `dcrypt` crate which re-exports the necessary modules.

```rust
use dcrypt::hybrid::sign::EcdsaMlDsa65Hybrid;
use dcrypt::api::Signature; // Use the generic Signature trait
use rand::rngs::OsRng;

// 1. Generate a hybrid key pair.
// This creates both an ECDSA P-384 key pair and an ML-DSA-65 key pair.
let (public_key, secret_key) = EcdsaMlDsa65Hybrid::keypair(&mut OsRng)
    .expect("Hybrid key pair generation failed");

let message = b"This is a message that needs to be securely signed.";

// 2. Sign the message with the hybrid secret key.
// This produces both an ECDSA signature and an ML-DSA-65 signature.
let hybrid_signature = EcdsaMlDsa65Hybrid::sign(message, &secret_key)
    .expect("Signing failed");

// 3. Verify the hybrid signature with the hybrid public key.
// This verifies both signature components. The function will return an
// error if either of the two verifications fails.
let verification_result = EcdsaMlDsa65Hybrid::verify(
    message,
    &hybrid_signature,
    &public_key,
);

assert!(verification_result.is_ok());

println!("Successfully created and verified a hybrid ECDSA + ML-DSA signature!");

// --- Example of a failed verification ---

// Generate a different key pair
let (other_pk, _) = EcdsaMlDsa65Hybrid::keypair(&mut OsRng).unwrap();

// Verification with the wrong public key must fail.
let failed_verification = EcdsaMlDsa65Hybrid::verify(
    message,
    &hybrid_signature,
    &other_pk,
);

assert!(failed_verification.is_err());

println!("Verification correctly failed when using the wrong key.");
```
