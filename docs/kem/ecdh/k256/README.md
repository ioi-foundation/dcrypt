# ECDH-secp256k1 KEM

`EcdhK256` validates compressed secp256k1 points and derives a 32-byte shared
secret with HKDF-SHA-256 over the versioned dcrypt ECDH transcript. Key
generation and encapsulation require caller-supplied cryptographic randomness.
This scheme is not HPKE.
