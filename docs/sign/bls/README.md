# BLS12-381 signatures

`dcrypt_sign::bls` implements the minimum-public-key BLS12-381 profiles from
[`draft-irtf-cfrg-bls-signature-07`](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-07)
(published 6 July 2026): Basic, Message
Augmentation, and Proof of Possession. Public keys are compressed 48-byte G1
points and signatures/proofs are compressed 96-byte G2 points. Ethereum
consensus compatibility is exposed separately as `Eth2Bls12381G2PopV4` so its
draft-v4 assumptions and empty fast-aggregate rule cannot be selected by
accident.

```rust
use dcrypt_sign::bls::{Bls12381G2Basic, Bls12381SecretKey};

let ikm = [7u8; 32]; // Production IKM must be unpredictable.
let secret = Bls12381SecretKey::key_gen(&ikm, b"application-specific salt")?;
let public = secret.public_key()?;
let signature = Bls12381G2Basic::sign(&secret, b"message")?;
Bls12381G2Basic::verify(&public, b"message", &signature)?;
# Ok::<(), dcrypt_api::Error>(())
```

## Security contracts

- `Bls12381SecretKey` is an exact 32-byte clearing owner and implements neither
  `Copy` nor `Clone`. Protected export returns another clearing owner.
- Draft-07 KeyGen requires at least 32 bytes of unpredictable IKM and an
  explicit caller-selected salt. The Ethereum adapter starts with
  `SHA-256("BLS-SIG-KEYGEN-SALT-")`, as required for draft-v4 compatibility.
- Public-key parsing rejects noncanonical encodings, points outside the prime
  subgroup, and identity. Signature/proof parsing accepts the canonical
  subgroup identity because the draft's decoding contract does; verification
  applies the pairing equation, and only the explicitly named Ethereum empty
  fast-aggregate extension gives identity a special successful meaning.
- Basic aggregate verification rejects duplicate messages. Augmentation signs
  `PK || message`. Proof-of-Possession aggregate methods require and validate a
  proof for every key before using the same-message optimization.
- The Ethereum adapter omits proof arguments only because consensus performs
  proof validation at validator registration. It is not a substitute for the
  draft-07 PoP API in protocols without that precondition.

The implementation uses dcrypt-owned RFC 9380 hash-to-curve and pairing code at
runtime. Published EIP-2333 KeyGen vectors and an independent implementation in
the excluded verification workspace check keys, all four domain separation
tags, signatures, proofs, aggregation, and encodings byte-for-byte. Draft-07
Appendix B still lists G2/minimum-public-key vectors as TBA; no official vector
claim is inferred from their absence.
