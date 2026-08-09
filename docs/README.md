# dcrypt documentation

This directory documents only the algorithms and public surfaces implemented by
the v3 codebase. Placeholder documentation for unimplemented schemes has been
removed so a documentation path cannot be mistaken for algorithm support.

The main areas are:

- `algorithms`: owned low-level hashes, ciphers, KDFs, elliptic curves,
  BLS12-381 pairings, and RFC 9380 hash-to-curve.
- `kem`: ECDH KEMs and final FIPS 203 ML-KEM.
- `sign`: ECDSA, dcrypt-owned strict Ed25519, and final FIPS 204 ML-DSA.
- `pke`: versioned dcrypt ECIES constructions.
- `hybrid`: ECDH/ML-KEM combiners and ECDSA-P384/ML-DSA-65 signatures.
- `params`: constants only for implemented algorithms.
- `security`: advisories, withdrawal notices, and legacy migration boundaries.

## Randomness boundary

dcrypt never chooses or accesses an operating-system RNG. Every randomized API
accepts a caller-owned type implementing `CryptoRng + RngCore`.

```rust,no_run
use dcrypt::api::Kem;
use dcrypt::internal::{CryptoRng, RngCore};
use dcrypt::kem::MlKem768;

fn encapsulate<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let keypair = MlKem768::keypair(rng)?;
    let public_key = MlKem768::public_key(&keypair);
    let secret_key = MlKem768::secret_key(&keypair);
    let (ciphertext, sender_secret) = MlKem768::encapsulate(rng, &public_key)?;
    let receiver_secret = MlKem768::decapsulate(&secret_key, &ciphertext)?;
    assert_eq!(
        &sender_secret.to_bytes_zeroizing()[..],
        &receiver_secret.to_bytes_zeroizing()[..],
    );
    Ok(())
}
```

An application may seed `dcrypt::internal::ChaCha20Rng` from its own trusted
entropy boundary, but dcrypt does not obtain that seed. Hard-coded or reused
seeds are not suitable for production.

## Features

The top-level facade provides `traditional`, `post-quantum`, and `hybrid`
category features. Each category activates and re-exports the required crates;
`hybrid` enables both component categories. `std` implies `alloc`, while
allocation-backed `no_std` builds use `default-features = false` plus `alloc`
and the required categories.

No currently published dcrypt release is supported. Review the root README and
`SECURITY.md` before relying on a release.
