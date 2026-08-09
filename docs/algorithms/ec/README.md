# Elliptic-curve primitives

`dcrypt_algorithms::ec` provides owned safe-Rust arithmetic for P-224, P-256,
P-384, P-521, secp256k1, and BLS12-381. P-192 and sect283k1 were removed from
the v3 surface. P-224 remains for interoperability at approximately 112-bit
security; prefer P-256 or stronger for new designs.

The prime-curve modules expose validated scalar and point encodings, keypair
generation with a caller-supplied RNG, scalar multiplication, and the KDF
helpers used by dcrypt's higher-level KEM/PKE suites. For protocol work, prefer
the typed `dcrypt-kem`, `dcrypt-pke`, or `dcrypt-sign` wrappers rather than
assembling a construction from low-level points.

```rust,no_run
use dcrypt::algorithms::ec::p256;
use dcrypt::internal::{CryptoRng, RngCore};

fn exchange<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::algorithms::Result<()> {
    let (alice_secret, alice_public) = p256::generate_keypair(rng)?;
    let (bob_secret, bob_public) = p256::generate_keypair(rng)?;
    let alice_shared = p256::scalar_mult(&alice_secret, &bob_public)?;
    let bob_shared = p256::scalar_mult(&bob_secret, &alice_public)?;
    assert_eq!(alice_shared, bob_shared);
    Ok(())
}
```

The BLS12-381 module additionally provides strict subgroup-checked decoding,
optimal Ate pairings, and RFC 9380 hash-to-curve for G1 and G2. Those primitives
support standard BLS signature ciphersuites, including Eth2-style schemes,
without an external hash-to-curve library; ciphersuite-level KeyGen, DST,
proof-of-possession, aggregation, and validation rules remain the caller's
responsibility.
