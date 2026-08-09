# ECDH-P384 KEM

`EcdhP384` validates compressed P-384 points and derives a 48-byte shared secret
with HKDF-SHA-384 over the versioned dcrypt ECDH transcript. Key generation and
encapsulation require caller-supplied cryptographic randomness. This scheme is
not HPKE.
