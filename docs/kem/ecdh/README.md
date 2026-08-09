# ECDH-based KEMs

`dcrypt_kem::ecdh` exposes `EcdhP224`, `EcdhP256`, `EcdhP384`, `EcdhP521`, and
`EcdhK256`. Each scheme validates encoded points and derives a fixed-size shared
secret from a versioned, transcript-bound ECDH value with HKDF. These are
dcrypt-specific KEMs, not RFC 9180 HPKE.

P-224 remains for interoperability at approximately 112-bit security; prefer
P-256 or stronger for new designs. P-192 and sect283k1 were removed for v3.

```rust,no_run
use dcrypt::api::Kem;
use dcrypt::internal::{CryptoRng, RngCore};
use dcrypt::kem::EcdhP256;

fn encapsulate<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (public_key, secret_key) = EcdhP256::keypair(rng)?;
    let (ciphertext, sender_secret) = EcdhP256::encapsulate(rng, &public_key)?;
    let receiver_secret = EcdhP256::decapsulate(&secret_key, &ciphertext)?;
    assert_eq!(sender_secret.to_bytes(), receiver_secret.to_bytes());
    Ok(())
}
```

Key generation and encapsulation use only the caller-provided cryptographic
RNG. Invalid keys and ciphertexts return errors; the construction does not
claim HPKE semantics or generic implicit rejection.
