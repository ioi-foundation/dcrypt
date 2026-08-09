# ECIES-P384

`EciesP384` combines P-384 ECDH, HKDF-SHA-384, and AES-256-GCM in the versioned
dcrypt ECIES frame. It implements `dcrypt_api::traits::Pke` and requires
caller-supplied cryptographic randomness for key generation and every
encryption.

```rust,no_run
use dcrypt::api::traits::Pke;
use dcrypt::internal::{CryptoRng, RngCore};
use dcrypt::pke::EciesP384;

fn roundtrip<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (public_key, secret_key) = EciesP384::keypair(rng)?;
    let ciphertext = EciesP384::encrypt(&public_key, b"message", None, rng)?;
    assert_eq!(EciesP384::decrypt(&secret_key, &ciphertext, None)?, b"message");
    Ok(())
}
```

This construction is not HPKE and does not provide forward secrecy against
later compromise of the recipient's long-term secret key.
