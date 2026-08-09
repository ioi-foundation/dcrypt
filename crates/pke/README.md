# dcrypt-pke

`dcrypt-pke` provides dcrypt-specific ECIES constructions for P-224, P-256,
P-384, and P-521. Each construction generates a fresh ephemeral EC key, derives
an AEAD key from a transcript-bound ECDH value with HKDF, and authenticates the
payload and caller-provided associated data.

| Type | Curve | KDF | AEAD |
| --- | --- | --- | --- |
| `EciesP224` | P-224 | HKDF-SHA-256 | ChaCha20-Poly1305 |
| `EciesP256` | P-256 | HKDF-SHA-256 | ChaCha20-Poly1305 |
| `EciesP384` | P-384 | HKDF-SHA-384 | AES-256-GCM |
| `EciesP521` | P-521 | HKDF-SHA-512 | AES-256-GCM |

P-224 remains available for interoperability at approximately 112-bit
security; prefer P-256 or stronger for new designs. P-192 was removed for v3.

Key generation and encryption require a caller-owned cryptographic RNG. dcrypt
does not select or access an operating-system RNG.

```rust,no_run
use dcrypt::api::traits::Pke;
use dcrypt::internal::{CryptoRng, RngCore};
use dcrypt::pke::EciesP256;

fn roundtrip<R: CryptoRng + RngCore>(rng: &mut R) -> dcrypt::api::Result<()> {
    let (public_key, secret_key) = EciesP256::keypair(rng)?;
    let aad = Some(b"protocol context".as_slice());
    let ciphertext = EciesP256::encrypt(&public_key, b"secret", aad, rng)?;
    let plaintext = EciesP256::decrypt(&secret_key, &ciphertext, aad)?;
    assert_eq!(plaintext, b"secret");
    Ok(())
}
```

This is not HPKE and it does not provide forward secrecy against later
compromise of the recipient's long-term private key. Treat the exact v3 framing,
KDF transcript, and suite labels as protocol identifiers rather than a generic
ECIES interoperability claim.

The default `std` feature implies `alloc`. Allocation-backed `no_std` builds use
`default-features = false, features = ["alloc"]`.
