# ML-DSA signatures (`sign::mldsa`)

`dcrypt_sign::mldsa` implements final FIPS 204 ML-DSA-44, ML-DSA-65, and
ML-DSA-87. Version 3 exposes only the final-standard `MlDsa44`, `MlDsa65`, and
`MlDsa87` names; it does not alias pre-standard objects into this API.

Key generation and hedged signing require randomness supplied by the caller.
Deterministic signing is also available as the optional deterministic FIPS 204
mode. Contexts may contain at most 255 bytes.

```rust,no_run
use dcrypt_api::Signature;
use dcrypt_internal::{CryptoRng, RngCore};
use dcrypt_sign::mldsa::MlDsa65;

fn sign_and_verify<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt_api::Result<()> {
    let (public_key, secret_key) = MlDsa65::keypair(rng)?;
    let message = b"ML-DSA message";
    let context = b"example protocol";

    let signature = MlDsa65::sign_with_context_rng(message, context, &secret_key, rng)?;
    MlDsa65::verify_with_context(message, context, &signature, &public_key)
}
```

Public keys, expanded private keys, and signatures use the final FIPS 204
encodings. Decoders validate sizes and canonical encodings. Expanded-private-key
imports also recompute the public key and validate the complete key
relationship. Applications migrating historical dcrypt objects must use
explicit versioned framing; legacy objects are not silently relabeled.
