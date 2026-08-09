# Ed25519 (`sign::eddsa`)

`dcrypt_sign::eddsa::Ed25519` is a dcrypt-owned safe-Rust implementation of
RFC 8032 Ed25519. It does not depend on an external curve implementation.

The decoder and verifier require canonical encodings, canonical `S < L`, and
non-identity prime-order public-key and commitment points. Verification uses the
strict equation, and secret scalar multiplication follows a fixed iteration
schedule with constant-time point selection. Those properties still require
compiler- and target-specific review before making a concrete side-channel
claim.

Key generation requires a caller-owned cryptographic RNG. Signing is
deterministic as specified by RFC 8032.

```rust,no_run
use dcrypt::api::Signature;
use dcrypt::internal::{CryptoRng, RngCore};
use dcrypt::sign::eddsa::Ed25519;

fn sign_and_verify<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (public_key, secret_key) = Ed25519::keypair(rng)?;
    let message = b"Ed25519 message";
    let signature = Ed25519::sign(message, &secret_key)?;
    Ed25519::verify(message, &signature, &public_key)
}
```

An existing 32-byte RFC 8032 seed can be imported with
`Ed25519SecretKey::from_seed`. Treat seed exports and all copies as secret,
encrypt them at rest, and clear caller-owned buffers after use.
