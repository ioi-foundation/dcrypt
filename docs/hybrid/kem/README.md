# Hybrid Key Encapsulation Mechanisms

The hybrid KEMs combine an ECDH-based KEM with one of the three final FIPS 203
ML-KEM parameter sets. The public v3 names are:

- `EcdhK256MlKem512`
- `EcdhP256MlKem512`
- `EcdhP256MlKem768`
- `EcdhP384MlKem1024`
- `EcdhP521MlKem1024`

Each component secret, the component suite identifiers, and the serialized
hybrid ciphertext are bound into the domain-separated HKDF-SHA256 combiner.
Applications must supply a fallible `CryptoRng + RngCore`; the library never
selects an operating-system RNG implicitly.

```rust
use dcrypt::api::Kem;
use dcrypt::hybrid::kem::EcdhP256MlKem768;
use dcrypt::internal::{CryptoRng, RngCore};

fn exchange<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (public_key, secret_key) = EcdhP256MlKem768::keypair(rng)?;
    let (ciphertext, sender_secret) = EcdhP256MlKem768::encapsulate(rng, &public_key)?;
    let receiver_secret = EcdhP256MlKem768::decapsulate(&secret_key, &ciphertext)?;
    assert_eq!(
        &sender_secret.to_bytes_zeroizing()[..],
        &receiver_secret.to_bytes_zeroizing()[..],
    );
    Ok(())
}
```

Hybrid composition is not by itself a proof that every surrounding protocol
remains secure if either component fails. Protocol context, combiner assumptions,
key validation, and downgrade prevention still require independent review.
