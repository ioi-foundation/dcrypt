# ECIES-P256

`EciesP256` combines P-256 ECDH, HKDF-SHA-256, and ChaCha20-Poly1305 in the
versioned dcrypt ECIES frame. It implements `dcrypt_api::traits::Pke` and
requires caller-supplied cryptographic randomness for key generation and every
encryption.

```rust,no_run
use dcrypt::api::traits::Pke;
use dcrypt::internal::{CryptoRng, RngCore};
use dcrypt::pke::EciesP256;

fn roundtrip<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (public_key, secret_key) = EciesP256::keypair(rng)?;
    let aad = Some(b"context".as_slice());
    let ciphertext = EciesP256::encrypt(&public_key, b"message", aad, rng)?;
    assert_eq!(EciesP256::decrypt(&secret_key, &ciphertext, aad)?, b"message");
    Ok(())
}
```

This construction is not HPKE and does not provide forward secrecy against
later compromise of the recipient's long-term secret key.
