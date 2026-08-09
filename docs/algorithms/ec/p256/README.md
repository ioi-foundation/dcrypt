# P-256 primitives

`dcrypt_algorithms::ec::p256` provides safe-Rust P-256 field, scalar, and point
operations, canonical compressed and uncompressed decoding, caller-supplied
key-generation randomness, and the HKDF-SHA-256 helper used by dcrypt's ECDH
KEM.

Use the typed `EcdhP256`, `EciesP256`, or `EcdsaP256` wrappers for those
constructions. Raw ECDH point output must be bound to a protocol transcript and
processed through an appropriate KDF before use as a key.
