# dcrypt 3.0.0 — corrective security release

`3.0.0` is the supported corrective release for the dcrypt workspace. Upgrade
from every earlier release. `2.0.0` contains important issue-specific fixes but
was withdrawn because its implementation and normal/build dependency closure
violated dcrypt's zero-unsafe, zero-native-code, and zero-FFI policy. `1.2.3`
contains critical defects and is not a safe fallback.

All twelve published workspace crates are released together at `3.0.0` with
exact internal dependency pins.

## Security advisories

This release is the first supported remediation for eleven coordinated findings:

- **Critical — `dcrypt-api`: safe error-registry APIs could cause undefined
  behavior.** Mismatched deallocation, unchecked type confusion, and concurrent
  use-after-free were reachable through safe Rust.
  [GHSA-7hc7-h3f2-r4j6](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-7hc7-h3f2-r4j6)
- **Critical — `dcrypt-sign`: Ed25519 verification permitted universal
  forgery.** Every published pre-2 release allowed forged authorizations,
  through an unconditional placeholder verifier in the first beta and an
  identity-key forgery in later versions.
  [GHSA-7j32-2mpw-c784](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-7j32-2mpw-c784)
- **High — `dcrypt-algorithms`: low-level GCM ignored the operation nonce.**
  Distinct caller-supplied nonces could silently reuse the constructor nonce.
  [GHSA-h9f2-fgp8-vc4h](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-h9f2-fgp8-vc4h)
- **High — `dcrypt-symmetric`: streaming AEAD did not authenticate stream
  structure.** Affected streams permitted truncation, omission, replay or
  reordering within a stream, and attacker-directed oversized allocation.
  [GHSA-8cwp-4826-jg9f](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-8cwp-4826-jg9f)
- **High — `dcrypt-algorithms` / `dcrypt-kem`: sect283k1 validation permitted a
  predictable ECDH-KEM secret.** An accepted order-two point exposed
  secret-scalar parity and made one parity's KDF input predictable.
  [GHSA-w3jf-cj7j-jmc5](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-w3jf-cj7j-jmc5)
- **High — `dcrypt-algorithms`: BLS12-381 G1 decoding bypassed subgroup
  validation.** The affected decoder admitted nonzero torsion points and did
  not meet the validation contract required by standard BLS protocols.
  [GHSA-rcw6-8w42-2cg2](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-rcw6-8w42-2cg2)
- **Moderate — `dcrypt-algorithms`: BLS12-381 hash-to-curve was incompatible
  with RFC 9380.** The former G1/G2 maps disagreed with the standard and every
  tested independent implementation output.
  [GHSA-g6wj-4vqj-4923](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-g6wj-4vqj-4923)
- **Moderate — `dcrypt-kem`: the published Kyber implementation was not final
  FIPS 203 ML-KEM.** It used incompatible arithmetic, derivation, rejection,
  and encoding rules despite later documentation presenting it as FIPS 203.
  [GHSA-xcw2-2p85-wmmp](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-xcw2-2p85-wmmp)
- **High — `dcrypt-algorithms`: zero-nonce XChaCha operations reused a
  one-time nonce.** Reuse exposed overlapping plaintext XORs and invalidated
  Poly1305's one-time-key assumption.
  [GHSA-vwrw-2qvx-3rh9](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-vwrw-2qvx-3rh9)
- **Moderate — `dcrypt-algorithms` / `dcrypt-symmetric`: APIs named
  XChaCha20-Poly1305 used a nonstandard construction.** Explicit-nonce output
  from every affected published version is not standard XChaCha20-Poly1305.
  [GHSA-xj38-xmch-9j4w](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-xj38-xmch-9j4w)
- **Moderate — `dcrypt-algorithms` / `dcrypt-symmetric` / `dcrypt-pke`:
  optimized GHASH contained secret-dependent branches.** Compiler optimization
  turned the intended byte-mask selection into branches derived from the GHASH
  accumulator. No practical key recovery or end-to-end forgery has been
  demonstrated from this behavior.
  [GHSA-86cg-f85f-5ggw](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-86cg-f85f-5ggw)

Updating does not retroactively restore the confidentiality, authenticity, or
provenance of affected ciphertext, signatures, authorizations, keys, or process
memory. Review the incident-response guidance in
[SECURITY.md](https://github.com/ioi-foundation/dcrypt/blob/v3.0.0/SECURITY.md).

## Implementation boundary restored

The published dcrypt implementation and its normal/build dependency closure
contain no unsafe Rust, native code, or FFI. The release also contains no
bundled operating-system RNG: every randomized operation receives a
caller-provided `CryptoRng + RngCore` and propagates entropy failures.

Runtime cryptographic implementations are dcrypt-owned safe Rust. External
implementations are confined to excluded, non-published verification
workspaces and are used only as independent test oracles. The only external
normal/build packages in the published closure are exact `base64 0.22.1` and
`hex 0.4.3` dependencies.

This boundary is an implementation and release-assurance property. It is not
an independent security audit, formal verification, FIPS validation, or a
blanket compiler/target constant-time or physical-memory-erasure claim.

## Cryptographic changes

- Replaced the former Kyber surface with dcrypt-owned final-standard
  `MlKem512`, `MlKem768`, and `MlKem1024` implementations.
- Restored and corrected the dcrypt-owned FIPS 204 implementation as
  `MlDsa44`, `MlDsa65`, and `MlDsa87`; pre-standard Dilithium aliases and
  encodings are not retained.
- Replaced Ed25519 with strict dcrypt-owned field, scalar, and Edwards
  arithmetic, including canonical and prime-order checks and a fixed-step
  secret-scalar path.
- Implemented standard XChaCha20-Poly1305 with owned HChaCha20 and explicit
  nonces. Historical dcrypt-format ciphertext is accepted only by the isolated
  decrypt-only migration tool.
- Added high-level minimum-public-key BLS12-381 Basic, Message Augmentation,
  and Proof of Possession profiles pinned to CFRG BLS draft-07, plus a
  separately named Ethereum PoP-v4 adapter. RFC 9380 G1/G2 hash-to-curve is
  implemented directly by dcrypt; no external hash-to-curve library is needed
  at runtime.
- Hardened GCM, including a four-target optimized-assembly gate that requires
  GHASH's one fixed-counter backedge, reviewed in-loop arithmetic-mask shape,
  absence of loop calls/indirect control, and five normal-path `u128` clearing
  calls; streaming AEAD, ECDSA DER/scalars, Poly1305, HMAC, ChaCha20 counter
  exhaustion, KEM/PKE key parsing, and exact-size secret ownership.

## Breaking migration notes

- Every operation that requires randomness now takes a caller-owned CSPRNG.
  Hidden `OsRng`, `thread_rng`, zero-nonce, and implicit random-generation
  helpers were removed.
- Rename `Kyber512/768/1024` to `MlKem512/768/1024` and
  `Dilithium2/3/5` to `MlDsa44/65/87`. Do not relabel old keys,
  signatures, or ciphertext because the formats and algorithms differ.
- Low-level GCM is key-only; supply a nonce to each operation. GCM tags are
  restricted to 12–16 bytes, with 16 bytes preferred.
- Version-1 streaming ciphertext is rejected. The historical custom XChaCha
  format can be decrypted only through the explicitly trusted
  [migration tool](https://github.com/ioi-foundation/dcrypt/tree/v3.0.0/migration/legacy-xchacha20poly1305).
- B-283/sect283k1 and P-192 arithmetic, KEM, PKE, and signature surfaces were
  removed. P-224 remains for approximately 112-bit transition and
  interoperability needs; prefer P-256 or stronger for new deployments.
- The v3 ECDH-KEM and ECIES transcript is intentionally wire-incompatible with
  older ciphertext.
- Standard BLS applications should use the high-level Basic, Augmentation, or
  PoP types. Ethereum consensus applications must select the separately named
  Eth2 adapter and preserve its proof-registration precondition.

See the complete [v3 migration section](https://github.com/ioi-foundation/dcrypt/blob/v3.0.0/CHANGELOG.md#migration)
before upgrading.

## Validation scope

The release gate includes all workspace tests and doctests; the complete
35-target ACVP harness; exact 240-case ML-KEM and 615-case ML-DSA suites;
RFC 9380, BLS draft-07, EIP-2333, Ethereum consensus, XChaCha, ECDSA, and
retained-curve interoperability oracles; Linux x86-64, Linux AArch64, WASM,
and bare-metal `no_std` builds; Miri; Loom; target assembly inspection;
statistical timing regressions; cargo-audit; cargo-deny; AES-CBC property tests;
and deterministic 1,000-run campaigns for every fuzz target. Every packaged
`.crate` archive is re-scanned and verified in a clean-room build.

## Upgrade

```toml
dcrypt = "3.0.0"
```

Full details: [CHANGELOG.md](https://github.com/ioi-foundation/dcrypt/blob/v3.0.0/CHANGELOG.md)
· [v1.2.3...v3.0.0](https://github.com/ioi-foundation/dcrypt/compare/v1.2.3...v3.0.0)
