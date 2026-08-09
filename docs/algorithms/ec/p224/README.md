# P-224 primitives

`dcrypt_algorithms::ec::p224` provides safe-Rust P-224 field, scalar, and point
operations with canonical decoding and caller-supplied key-generation
randomness. P-224 is retained for transition and interoperability at
approximately 112-bit security; prefer P-256 or stronger for new protocols.

Use the typed `EcdhP224`, `EciesP224`, or `EcdsaP224` wrappers unless a protocol
specifically requires low-level point arithmetic.
