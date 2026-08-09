# Traditional algorithm parameters

`dcrypt_params::traditional` contains constants for the classical algorithms
implemented by dcrypt:

- `ecdsa`: P-224, P-256, P-384, and P-521 curve parameters.
- `ecdh`: serialized-key and shared-secret sizes used by the NIST ECDH KEMs.
- `ed25519`: Ed25519 key and signature sizes and curve constants.

P-192 and sect283k1 were removed from the v3 implementation. Their historical
security context remains in `docs/security/V3-TRADITIONAL-EC-REMOVALS.md`; they
are not available through the public parameter API.

```rust
use dcrypt_params::traditional::{
    ecdsa::NIST_P256,
    ed25519::ED25519_SIGNATURE_SIZE,
};

assert_eq!(NIST_P256.h, 1);
assert_eq!(ED25519_SIGNATURE_SIZE, 64);
```
