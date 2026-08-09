# Generic Polynomial Support

The `dcrypt-algorithms::poly` module supplies generic polynomial storage,
packing, sampling, and the arithmetic used by the owned final FIPS 204 ML-DSA
implementation.

ML-KEM does not use the generic cyclic-transform fallback. Final FIPS 203 needs
a distinct seven-layer NTT and base multiplication over pairs; that complete
implementation is local to `dcrypt-kem::ml_kem` so the two transforms cannot be
mistaken for one another.
