# FIPS 203 ML-KEM

`dcrypt-kem::ml_kem` implements the final FIPS 203 ML-KEM-512, ML-KEM-768,
and ML-KEM-1024 parameter sets in owned safe Rust. It includes the standard
seven-layer NTT and base multiplication, canonical key decoding, validated
decapsulation keys, and implicit rejection.

The public types are parameter-set specific: `MlKem512`, `MlKem768`,
`MlKem1024`, and the corresponding validated encapsulation-key,
decapsulation-key, ciphertext, and keypair types. Historical pre-standard names
are intentionally absent.

Randomized key generation and encapsulation require a caller-provided fallible
`CryptoRng + RngCore`. Deterministic `d`, `z`, and `m` entry points exist for
validation replay and callers that explicitly own deterministic inputs.

The repository checks every expected field in its byte-bound ACVP-format
corpus: 75 key-generation, 75 encapsulation, 30 decapsulation, and 60
key-validation cases. The fixtures' upstream URL, revision, acquisition record,
and original download digest have not been independently verified. Passing
them is not FIPS validation, authenticated upstream provenance, or an
independent security audit.
