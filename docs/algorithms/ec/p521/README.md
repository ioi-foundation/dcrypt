# P-521 primitives

`dcrypt_algorithms::ec::p521` provides safe-Rust P-521 field, scalar, and point
operations, canonical point decoding, caller-supplied key-generation
randomness, and the HKDF-SHA-512 helper used by dcrypt's ECDH KEM.

Use the typed `EcdhP521`, `EciesP521`, or `EcdsaP521` wrappers for those
constructions. Raw ECDH point output must be bound to a protocol transcript and
processed through an appropriate KDF before use as a key.
