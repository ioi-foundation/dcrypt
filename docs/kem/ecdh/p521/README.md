# ECDH-P521 KEM

`EcdhP521` validates compressed P-521 points and derives a 64-byte shared secret
with HKDF-SHA-512 over the versioned dcrypt ECDH transcript. Key generation and
encapsulation require caller-supplied cryptographic randomness. This scheme is
not HPKE.
