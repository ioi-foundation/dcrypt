# Isolated implementation verification

This workspace is excluded from the publishable dcrypt workspace and every
package in it has `publish = false`. External cryptographic implementations are
allowed here only as test oracles; published dcrypt crates must not depend on
them.

Run the XChaCha20-Poly1305 differential checks with:

```bash
cargo test --manifest-path verification/Cargo.toml --test xchacha20poly1305
```

Run the independent traditional-EC scalar multiplication and ECDH checks with:

```bash
cargo test --manifest-path verification/Cargo.toml --test traditional_ec_interop
```

Run the independent BLS12-381 oracle checks and the frozen official Ethereum
consensus adapter vectors with:

```bash
cargo test --manifest-path verification/Cargo.toml --test bls12_381_interop
cargo test --manifest-path verification/Cargo.toml --test ethereum_consensus_bls
```

The Ethereum corpus records its exact upstream commit and per-file Git blob
identifiers in `vectors/ethereum_consensus_spec_tests/PROVENANCE.md`.

Reproduce the removed sect283k1 subgroup/serializer advisory proof with:

```bash
cargo test --manifest-path verification/Cargo.toml --test legacy_b283_advisory
```
