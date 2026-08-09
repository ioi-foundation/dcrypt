# BLS12-381 primitives

`dcrypt_algorithms::ec::bls12_381` provides safe-Rust BLS12-381 field and group
arithmetic, optimal Ate pairings, strict compressed-point decoding, and RFC
9380 hash-to-curve for both G1 and G2.

These are the low-level ingredients behind the standard minimum-public-key BLS
profiles in `dcrypt_sign::bls`; no external hash-to-curve library is required.
Applications should use that high-level module for draft-07 Basic,
Augmentation, Proof of Possession, or the separately named Ethereum draft-v4
adapter. A pairing equation alone is not a complete ciphersuite.

## Eth2-style core equation

The following demonstrates the core sign/verify equation. The scalar is a
fixed demonstration value, not production KeyGen.

```rust
use dcrypt_algorithms::ec::bls12_381::{
    pairing, G1Affine, G1Projective, G2Affine, G2Projective,
};
use dcrypt_api::types::SecretBytes;

let mut encoded_secret = [0u8; 32];
encoded_secret[31] = 42;
let secret = SecretBytes::new(encoded_secret);

let public_key = G1Affine::from(
    G1Projective::generator().multiply_secret_be_bytes(&secret)?,
);
let message_point = G2Projective::hash_to_curve(
    b"message",
    b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
)?;
let signature = G2Affine::from(message_point.multiply_secret_be_bytes(&secret)?);

assert_eq!(
    pairing(&public_key, &G2Affine::from(message_point)),
    pairing(&G1Affine::generator(), &signature),
);
drop(secret);
# Ok::<(), dcrypt_algorithms::Error>(())
```

Production code should use `dcrypt_sign::bls::Bls12381SecretKey`, whose KeyGen
implements the selected draft profile and whose exact-size storage is neither
`Copy` nor `Clone`. `Bls12_381Scalar` remains a general `Copy` field element for
public arithmetic, not a protected long-lived secret-key container.

## Validation and serialization

- Use `G1Projective::from_bytes_validated` for untrusted public points when a
  protocol requires a nonidentity value. BLS signature decoding has different
  identity semantics; use the high-level `Bls12381Signature` parser instead of
  applying the low-level nonidentity helper indiscriminately.
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
