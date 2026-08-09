# ECDH-P224 KEM

`EcdhP224` validates compressed P-224 points and applies the versioned dcrypt
ECDH/HKDF transcript. P-224 remains for transition and interoperability at
approximately 112-bit security; prefer P-256 or stronger for new protocols.
Key generation and encapsulation require caller-supplied cryptographic
randomness. This scheme is not HPKE.
