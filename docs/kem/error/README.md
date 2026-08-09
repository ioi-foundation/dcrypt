# KEM errors

`dcrypt_kem::error` converts implementation failures into the shared
`dcrypt_api::Error` surface. Callers should expect errors for failed randomness,
invalid lengths, malformed encodings, invalid curve points, inconsistent keys,
and other rejected inputs.

Do not build a decryption or validity oracle from detailed diagnostics. Treat
all failures involving untrusted keys or ciphertexts as a rejected operation,
log only non-sensitive context, and never retry with weakened validation.

Randomness failures are propagated from the caller-owned `CryptoRng`; dcrypt
does not silently substitute another entropy source.
