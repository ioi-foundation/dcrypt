# dcrypt ECIES constructions

The `ecies` module implements four versioned, dcrypt-specific public-key
encryption suites:

| Type | Curve | KDF | AEAD |
| --- | --- | --- | --- |
| `EciesP224` | P-224 | HKDF-SHA-256 | ChaCha20-Poly1305 |
| `EciesP256` | P-256 | HKDF-SHA-256 | ChaCha20-Poly1305 |
| `EciesP384` | P-384 | HKDF-SHA-384 | AES-256-GCM |
| `EciesP521` | P-521 | HKDF-SHA-512 | AES-256-GCM |

Encryption generates a fresh ephemeral keypair, validates the recipient point,
and derives the AEAD key from a transcript containing the shared x-coordinate,
the ephemeral public key, and the recipient public key. A versioned suite label
and fixed v3 extraction salt domain-separate each construction.

The ciphertext frame is `R_len || R || N_len || N || CT_len || (C || T)`, where
lengths are validated and `CT_len` is a four-byte big-endian integer. Associated
data is authenticated by the selected AEAD and must match at decryption.

These suites are not RFC 9180 HPKE and do not provide forward secrecy after
compromise of the recipient's long-term secret key. Their wire format is only
interoperable with an implementation of the same dcrypt v3 construction.

P-224 remains for transition and interoperability; prefer P-256 or stronger for
new deployments. P-192 was removed for v3.
