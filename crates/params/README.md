# dcrypt-params

`dcrypt-params` is a small `no_std` crate containing constants for algorithms
that dcrypt actually implements. It intentionally does not publish speculative
parameter modules for unsupported schemes.

The public modules are:

- `pqc::ml_dsa`: final FIPS 204 parameters for ML-DSA-44, ML-DSA-65, and
  ML-DSA-87.
- `pqc::ml_kem`: final FIPS 203 parameters for ML-KEM-512, ML-KEM-768, and
  ML-KEM-1024.
- `traditional::ecdsa`: curve constants for P-224, P-256, P-384, and P-521.
- `traditional::ecdh`: serialized-key and shared-secret sizes used by the NIST
  ECDH wrappers.
- `traditional::ed25519`: Ed25519 key and signature sizes and curve constants.
- `utils`: hash, MAC, cipher, key, nonce, and tag sizes used across the
  workspace.

These constants are implementation inputs, not standalone algorithm support.
The presence of a parameter set never implies that dcrypt implements a scheme.

```rust
use dcrypt_params::pqc::{ml_dsa::ML_DSA_65, ml_kem::ML_KEM_768};

assert_eq!(ML_DSA_65.signature_size, 3_309);
assert_eq!(ML_KEM_768.shared_secret_size, 32);
```
