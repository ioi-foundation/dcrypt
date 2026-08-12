# Isolated implementation verification

This workspace is excluded from the publishable dcrypt workspace and every
package in it has `publish = false`. External cryptographic implementations are
allowed here only as candidate comparators; published dcrypt crates must not
depend on them. Isolation alone does not establish implementation independence
or make a comparison assurance evidence.

Run the XChaCha20-Poly1305 differential checks with:

```bash
cargo test --manifest-path verification/Cargo.toml --test xchacha20poly1305
```

Run the corroborative traditional-EC scalar multiplication and ECDH checks with:

```bash
cargo test --manifest-path verification/Cargo.toml --test traditional_ec_interop
```

Run the shared-lineage BLS12-381 comparator checks and the repository Ethereum
consensus adapter corpus with:

```bash
cargo test --manifest-path verification/Cargo.toml --test bls12_381_interop
cargo test --manifest-path verification/Cargo.toml --test ethereum_consensus_bls
```

`vectors/ethereum_consensus_spec_tests/PROVENANCE.md` records a claimed upstream
commit and per-file blob identifiers. No independently verified acquisition
archive or download digest is available, so the corpus is not described as an
officially acquired source.

Package B lineage review currently rejects the BLS, XChaCha, libcrux ML-DSA,
and RustCrypto ML-DSA comparators as independent assurance oracles. The
traditional-EC and `fips204` lineages remain unresolved. Their tests are useful
regressions, but they do not clear interoperability blockers.

Reproduce the removed sect283k1 subgroup/serializer advisory proof with:

```bash
cargo test --manifest-path verification/Cargo.toml --test legacy_b283_advisory
```
