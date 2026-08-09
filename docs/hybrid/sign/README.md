# Hybrid digital signatures

`dcrypt_hybrid::sign::EcdsaMlDsa65Hybrid` combines ECDSA P-384 with final FIPS
204 ML-DSA-65. Version 3 exposes only this standard-oriented name; it does not
provide a pre-standard alias.

Public keys, secret keys, and signatures use domain-separated version-2
framing. The decoder deliberately rejects historical version-1 objects because
their former post-quantum component was not a final FIPS 204 object. That
legacy reference describes a migration boundary, not a supported algorithm or
public alias.

```rust,no_run
use dcrypt::api::Signature;
use dcrypt::hybrid::sign::EcdsaMlDsa65Hybrid;
use dcrypt::internal::{CryptoRng, RngCore};

fn sign_and_verify<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (public_key, secret_key) = EcdsaMlDsa65Hybrid::keypair(rng)?;
    let message = b"hybrid signature message";
    let signature = EcdsaMlDsa65Hybrid::sign(message, &secret_key)?;
    EcdsaMlDsa65Hybrid::verify(message, &signature, &public_key)
}
```

Both component signatures must verify. That rule does not by itself prove the
security of a surrounding protocol; framing, domain separation, downgrade
prevention, key validation, and combiner assumptions still require review.
