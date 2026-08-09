# Isolated implementation verification

This workspace is excluded from the publishable dcrypt workspace and every
package in it has `publish = false`. External cryptographic implementations are
allowed here only as test oracles; published dcrypt crates must not depend on
them.

Run the XChaCha20-Poly1305 differential checks with:

```bash
cargo test --manifest-path verification/Cargo.toml --test xchacha20poly1305
```
