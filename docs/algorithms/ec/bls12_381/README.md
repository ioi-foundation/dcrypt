# BLS12-381 primitives

`dcrypt_algorithms::ec::bls12_381` provides safe-Rust BLS12-381 field and group
arithmetic, optimal Ate pairings, strict compressed-point decoding, and RFC
9380 hash-to-curve for both G1 and G2.

These are the complete low-level ingredients needed to implement standard BLS
signature ciphersuites directly on dcrypt, including the Eth2-style
minimum-public-key-size construction (public keys in G1, signatures in G2).
No external hash-to-curve library is required. The module deliberately does not
pretend that a pairing equation alone is a complete ciphersuite: applications
must also implement the selected specification's KeyGen, exact DST, validation,
proof-of-possession or augmentation rules, aggregation policy, and wire framing.

## Eth2-style core equation

The following demonstrates the core sign/verify equation. The scalar is a
fixed demonstration value, not production KeyGen.

```rust
use dcrypt_algorithms::ec::bls12_381::{
    pairing, Bls12_381Scalar, G1Affine, G1Projective, G2Affine, G2Projective,
};
use dcrypt_internal::zeroing::Zeroize;

let mut secret = Bls12_381Scalar::from(42u64);
assert!(!bool::from(secret.is_zero()));

let public_key = G1Affine::from(G1Projective::generator() * secret);
let message_point = G2Projective::hash_to_curve(
    b"message",
    b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
)?;
let signature = G2Affine::from(message_point * secret);

assert_eq!(
    pairing(&public_key, &G2Affine::from(message_point)),
    pairing(&G1Affine::generator(), &signature),
);
secret.zeroize();
# Ok::<(), dcrypt_algorithms::Error>(())
```

Production KeyGen must follow the chosen BLS ciphersuite and reject a zero
scalar. `Bls12_381Scalar` is a general `Copy` field element, not a protected
long-lived secret-key container; keep encoded key material in exact-size
zeroizing storage and clear temporary arithmetic scalars after use.

## Validation and serialization

- Use `G1Projective::from_bytes_validated` and
  `G2Projective::from_bytes_validated` for untrusted public keys and signatures.
  They enforce canonical compression flags, on-curve decoding, subgroup
  membership, and non-identity.
- `G1Projective::hash_to_curve` and `G2Projective::hash_to_curve` implement the
  RFC 9380 random-oracle suites, including the RFC oversize-DST procedure.
- Always use the exact DST required by the selected BLS ciphersuite. A different
  DST defines a different protocol.
- Variable-time MSM is only for public inputs. Secret-dependent operations must
  use the constant-time path and still require target-specific timing review.

The implementation is covered by embedded RFC 9380 G1/G2 vectors,
cross-implementation oracle tests, strict decoding regressions, and positive and
negative pairing equations. Passing those tests is not a claim of formal
verification, independent audit, or protocol-level security.
