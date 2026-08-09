# Post-quantum parameters

`dcrypt_params::pqc` exposes parameters only for the final NIST standards that
dcrypt implements:

- `ml_kem`: FIPS 203 ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
- `ml_dsa`: FIPS 204 ML-DSA-44, ML-DSA-65, and ML-DSA-87.

The modules include polynomial dimensions, moduli, sampling and compression
parameters, and exact serialized sizes. They do not contain cryptographic
implementations; those live in `dcrypt-kem` and `dcrypt-sign`.

```rust
use dcrypt_params::pqc::ml_dsa::{ML_DSA_44, ML_DSA_N, ML_DSA_Q};
use dcrypt_params::pqc::ml_kem::{ML_KEM_512, ML_KEM_N, ML_KEM_Q};

assert_eq!((ML_DSA_N, ML_DSA_Q), (256, 8_380_417));
assert_eq!(ML_DSA_44.public_key_size, 1_312);
assert_eq!((ML_KEM_N, ML_KEM_Q), (256, 3_329));
assert_eq!(ML_KEM_512.ciphertext_size, 768);
```
