# secp256k1 primitives

`dcrypt_algorithms::ec::k256` provides safe-Rust secp256k1 field, scalar, and
point operations, canonical point decoding, caller-supplied key-generation
randomness, and the HKDF-SHA-256 helper used by `EcdhK256`.

Use the typed `dcrypt_kem::EcdhK256` wrapper for the dcrypt ECDH KEM. Raw ECDH
point output must be bound to a protocol transcript and processed through an
appropriate KDF before use as a key.
