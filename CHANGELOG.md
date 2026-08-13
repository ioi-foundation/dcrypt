# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- Removed the process-global error registry and legacy `Result` compatibility
  extension traits scheduled for the future v4 API. Callers now propagate
  failures with `Result`/`?`, use standard combinators and caller-owned
  diagnostics, and invoke the existing explicit symmetric error converters.
  See `docs/migration/V4-ERROR-API.md`. This source change does not itself bump
  package versions or authorize a release.

## [3.0.0] - 2026-08-09

### Added

- Added dcrypt-owned, safe-Rust implementations of final FIPS 203
  `MlKem512`, `MlKem768`, and `MlKem1024`, including distinct validation rules
  for externally supplied encapsulation keys and decapsulation-key internals,
  final implicit rejection, and exact-size protected secret exports.
- Added complete high-level BLS12-381 minimum-public-key signature profiles for
  CFRG BLS draft-07 Basic, Message Augmentation, and Proof of Possession, plus a
  separately named Ethereum PoP-v4 adapter. The implementation includes owned
  RFC 9380 G1/G2 hash-to-curve, strict point decoding, protected non-copying
  secret keys, fixed domain separation tags, proof-aware aggregation, and the
  Ethereum empty-public-key fast-aggregate rule. No external hash-to-curve
  implementation is used at runtime.
- Added an isolated, non-published, decrypt-only migration tool for ciphertext
  produced by the historical dcrypt construction named
  `XChaCha20Poly1305`. The tool requires an explicit format acknowledgement,
  validates historical key encodings, never overwrites output, and publishes
  completed plaintext only through same-filesystem atomic hard linking.
- Added an excluded verification workspace for standards and interoperability
  comparators. Comparator implementations are not reachable from any published
  crate's normal or build dependency graph. Later Package B lineage review
  determines whether a comparator can count as independent assurance evidence.

### Security

- Withdrew `v2.0.0`. That release retains important remediations for the four
  published stop-ship advisories, but its published implementation and
  normal/build dependency closure violate dcrypt's zero-unsafe,
  zero-native-code, and zero-FFI policy. This policy violation is not, by
  itself, evidence of a new cryptographic exploit in `v2.0.0`.
- Designated `v3.0.0` as the supported corrective release. `v1.2.3` contains
  critical defects and is not a safe fallback; withdrawn `v2.0.0` and every
  earlier release remain unsupported. The immutable `v2.0.0` tag is retained
  for provenance.
- Removed the affected sect283k1/ECDH-B283 implementation. Published artifacts
  from `0.9.0-beta.1` through withdrawn `2.0.0` accepted an order-two peer point
  without subgroup validation and used an incorrect group-order constant,
  allowing a malicious ciphertext to expose secret-scalar parity and, for one
  parity, produce a predictable KEM secret. See
  `docs/security/V3-TRADITIONAL-EC-REMOVALS.md`.
- Retained P-224 for approximately 112-bit transition/interoperability uses and
  removed low-level P-192 plus its ECDH, ECIES, and ECDSA public surfaces. NIST
  SP 800-186 limits P-192 to legacy use.
- Replaced the former G1/G2 hash-to-curve paths with exact RFC 9380 simplified
  SWU and isogeny maps, fixed XMD/hash-to-field byte interpretation, and made
  compressed point decoding enforce canonical encoding and subgroup membership.
  The high-level BLS public-key parser additionally rejects identity.
- Removed the former `Kyber*` implementation, which did not implement final
  FIPS 203 ML-KEM despite being presented as such, and replaced it with the
  final-standard `MlKem*` surface.
- Removed the historical all-zero-nonce XChaCha convenience operations. Reusing
  those operations under a key reused both the ChaCha20 keystream and Poly1305
  one-time key. The supported API requires an explicit nonce for every
  operation.
- Replaced the nonstandard construction exposed as `XChaCha20Poly1305` by every
  published `dcrypt-algorithms` and `dcrypt-symmetric` version from
  `0.9.0-beta.1` through `1.2.3`. Explicit-nonce ciphertext from those releases
  is not standard XChaCha20-Poly1305 and is accepted only by the isolated
  decrypt-only migration tool.
- Replaced GHASH's byte-mask field multiplication, which optimizing compilers
  transformed into branches on secret-derived accumulator bits, with a fixed
  128-iteration whole-width masked implementation. The affected low-level GCM,
  symmetric AES-GCM, and P-384/P-521 ECIES paths were present in every
  published version from `0.9.0-beta.1` through withdrawn `2.0.0`. No practical
  key recovery or end-to-end forgery has been demonstrated from this compiler
  behavior.
- Extended exact-size secret ownership and best-effort explicit clearing across
  hashes, XOFs, MACs, KDFs, password hashing, key generation, KEMs, and signature
  operations. Secret APIs no longer return `Vec`-backed buffers with
  inaccessible spare capacity. These safe-Rust clearing operations are an
  implementation hardening measure, not a promise that every compiler or
  platform physically erases all historical register and stack copies.
- Added a fail-closed implementation-boundary gate over every packaged crate and
  every classified excluded workspace. It rejects unsafe Rust, FFI, native
  sources/linking, OS entropy, unclassified workspaces, closure drift, inexact
  internal pins, and generated build output outside the declared contract.

### Changed

- All randomness-consuming public operations now take a caller-provided
  `CryptoRng + RngCore` and propagate partial-write failures after clearing the
  destination. Published dcrypt crates no longer bundle an operating-system RNG.
- Replaced runtime RustCrypto/libcrux cryptographic backends with dcrypt-owned
  implementations. The published normal/build closure is reduced to exact
  `base64 0.22.1` and `hex 0.4.3` dependencies and contains no unsafe Rust,
  native code, FFI, build scripts, or native-link metadata.
- Restored and corrected the dcrypt-owned ML-DSA implementation for all FIPS 204
  parameter sets, including final message/context domain separation, 64-byte
  `tr`, `RejBoundedPoly`, canonical hints, expanded-key coherence, deterministic
  signing, and caller-randomized hedged signing.
- Replaced the Ed25519 backend with dcrypt-owned safe-Rust field, scalar, and
  Edwards arithmetic. Verification rejects noncanonical, identity, small-order,
  and non-torsion-free points and requires canonical `S < L`; signing uses a
  fixed-step secret-scalar path.
- Implemented standard XChaCha20-Poly1305 using owned HChaCha20 composed with the
  owned ChaCha20-Poly1305 implementation. Nonces are explicit and the legacy
  custom wire construction is available only through the migration tool.
- Secret byte ownership now uses exact-size boxed slices. Secret serialization,
  KDF/MAC output, key material, and replacement paths avoid `Vec` capacity and
  clear initialized bytes on replacement and drop.
- Traditional P-224/P-256/P-384/P-521/secp256k1 scalar imports now require a
  canonical nonzero value below the group order. Point decoders require
  canonical field coordinates, a valid SEC 1 prefix, and an on-curve,
  non-identity point at KEM/PKE boundaries.
- Versioned ECDH-KEM and ECIES KDF transcripts bind the shared x-coordinate,
  ephemeral encoded point, and recipient encoded public key. ECIES rejects
  malformed nonce lengths before performing ECDH.
- Workspace facade features now activate the promised traditional,
  post-quantum, and hybrid crates consistently across `std`, `alloc`, and
  supported `no_std` profiles.

### Removed

- Removed the low-level BLS `msm` entry point that claimed secret-scalar
  suitability without protecting its Pippenger scratch. `msm_vartime` remains
  explicitly limited to public scalars; standard Basic, Augmentation, PoP, and
  Eth2 signing continue to use the protected fixed-step secret multiplier.
- Removed the unused `SecureOperation`, `SecureOperationExt`, and
  `SecureOperationBuilder` placeholders, whose interfaces could not enforce
  their advertised cleanup behavior.
- Removed B-283/sect283k1 and P-192 arithmetic, ECDH-KEM, ECIES, signature,
  parameter, benchmark, and facade surfaces. B-283 contained a demonstrated
  small-subgroup failure; P-192 is limited by NIST to legacy use.
- Removed placeholder or nonfunctional Falcon, Rainbow, SPHINCS+, McEliece,
  NTRU, Saber, DH, DSA, and RSA surfaces rather than presenting unavailable
  algorithms as implemented.
- Removed pre-standard `Kyber*` and `Dilithium*` public compatibility names.
  Final-standard APIs use `MlKem*` and `MlDsa*` names and encodings.
- Removed implicit key, salt, and nonce generation backed by `OsRng`,
  `thread_rng`, or `getrandom`, along with all runtime libcrux, dalek,
  RustCrypto AEAD, `libc`, native-intrinsic, and FFI dependency paths.

### Validation

- Redesigned the statistical timing regression gate around prepared, reusable
  same-address state and an exactly balanced paired A/B schedule. Each of the
  exact 29 blocking cases contributes one fixed-seed paired-randomization
  p-value to a single suite-wide Holm correction at family alpha 0.01; a case
  blocks only when the adjusted test rejects and the magnitude of its paired
  mean exceeds the unchanged practical threshold. Paired-bootstrap intervals,
  Welch tests, and KS tests remain descriptive, while the versioned `paired-v1`
  noise profile cannot consume legacy-harness baselines.
- Exact repository ACVP-format gates cover 240 ML-KEM cases (75 key generation, 75
  encapsulation, 30 decapsulation, and 60 key-validation cases) and all 615
  ML-DSA cases (75 key generation, 360 signature generation, and 180 signature
  verification cases) across every standardized parameter set. The local
  fixture bytes are content-bound; their upstream acquisition provenance is
  unverified.
- RFC 9380 vectors, corroborative G1/G2 hash-to-curve and encoding comparisons,
  four published EIP-2333 master-key vectors, draft-07 BLS domain separation,
  and Ethereum aggregate behavior cover the standard BLS surface.
- The release workflow packages and scans all twelve crates, compiles supported
  Linux x86-64, Linux AArch64, WASM, and bare-metal `no_std` profiles, and runs
  workspace tests/doctests, Miri, Loom, deterministic 1,000-run campaigns for
  every fuzz target, statistical timing
  regressions, cargo-audit, cargo-deny, isolated comparator checks, and clean-room
  package verification. The exact release source is also compiled for the four
  declared GHASH targets and checked for one fixed-counter backedge, no loop
  calls or indirect/table/Thumb-IT control, the reviewed in-loop mask/shift/
  reduction shape, and exactly five normal-path `u128` clearing calls. Passing
  these gates is not an independent audit, formal verification, FIPS
  validation, or proof of constant-time behavior outside that recorded scope.

### Migration

- Randomized constructors, key generation, encapsulation, signing, nonce/salt
  generation, streaming encryption, and file encryption now require a mutable
  caller-owned cryptographic RNG and return randomness failures. Callers must
  choose, seed, and protect that RNG outside dcrypt.
- Migrate `Kyber512/768/1024` to `MlKem512/768/1024` and
  `Dilithium2/3/5` to `MlDsa44/65/87`. Historical keys, signatures, and
  ciphertexts are not relabeled because their formats and algorithms differ.
- Standard BLS callers should use the high-level Basic, Augmentation, or Proof
  of Possession profile. Ethereum consensus integrations must select the
  separately named Eth2 adapter and retain the protocol's proof-registration
  precondition; do not assemble ciphersuites from low-level pairing primitives.
- The v3 ECDH-KEM and ECIES transcript version is intentionally wire-incompatible
  with older ciphertext. Removed B-283/P-192 objects require a protocol and key
  migration, not reinterpretation as a retained curve.

## [2.0.0] - 2026-08-08

### Changed
- Replaced the local release automation with a fail-closed three-phase workflow:
  non-mutating rehearsal, clean-tree version/tag preparation, and publication
  from an already-pushed tagged commit. The publish verifier now uses Cargo
  metadata, rejects non-publishable or version-skewed crates, performs live
  target-version checks with an identified crates.io client, and returns a
  failing status for unmet requirements.
- Moved every workspace crate and internal path dependency to the stable
  `2.0.0` line so the breaking remediations cannot be confused with the
  affected `1.2.3` release.
- Replaced the custom Ed25519 arithmetic with strict `ed25519-dalek`
  verification. Public keys and signature `R` values must now be canonical,
  torsion-free, non-small-order points, and signatures require canonical
  `S < L`. Secret scalar multiplication is delegated to a maintained backend
  designed for constant-time operation; concrete compiler/target assurance
  remains a separate release gate.
- Made low-level GCM key-only: every encryption/decryption operation now consumes
  the nonce supplied to its operation builder. Tags are restricted to 12--16
  bytes (16 by default), the supported 96-, 120-, and 128-bit IV paths follow
  SP 800-38D, and counter/message limits fail closed.
- Replaced the custom construction named `XChaCha20Poly1305` with the standard
  RustCrypto XChaCha20-Poly1305 implementation and test vectors published with
  the CFRG XChaCha draft. Removed zero-nonce convenience operations; ciphertext
  from the former construction is intentionally not accepted by the standard
  API. These are published draft vectors, not an official RFC or NIST vector
  suite.
- Replaced both streaming AEAD encodings with authenticated, version-2 frames.
  The version, algorithm, stream identifier, sequence, lengths, final flag, and
  caller AAD are authenticated; readers enforce sequence and size bounds and
  retain pending plaintext across partial reads. Version-1 streams are rejected.
- Replaced dcrypt's custom Dilithium implementation with libcrux's portable ML-DSA backend for key generation, signing, verification, and paired expanded-key validation, and added the canonical `MlDsa44`, `MlDsa65`, and `MlDsa87` type names. The historical `Dilithium2/3/5` spellings remain source-compatible aliases to the standards-compliant implementation. The `fips204` candidate comparator is now a differential-test dependency only; its implementation independence remains unresolved.
- Versioned the ECDSA-P384 + ML-DSA-65 hybrid framing as v2. Version-1 hybrid objects containing the nonstandard dcrypt Dilithium format are rejected rather than being relabeled as FIPS 204 objects.
- ECDSA signatures now use strict DER INTEGER parsing, reject negative and
  non-minimal encodings, reject noncanonical scalar values, emit low-`s`
  signatures, and reject high-`s` verification inputs on every supported
  prime-field curve.
- `ErrorRegistry` now uses synchronized, type-checked ownership instead of raw
  erased pointers. Misleading constant-time `Result` helpers are deprecated in
  favor of explicitly named error-recording operations.
- `SecretVec` now dereferences to `[u8]` instead of `Vec<u8>` and provides
  explicit resizing methods that wipe removed bytes, spare capacity, and
  replaced allocations during truncation, shrinking, growth, and drop.
- Standalone Poly1305 is single-use: cloning and reset/reuse under a one-time key
  are no longer exposed, and `finalize` consumes the authenticator. HMAC performs
  full-width length comparison and wipes key-derived hash states.
- ChaCha20 counter-limited processing and seek operations are fallible and return
  `Result`; callers must propagate counter-exhaustion errors instead of assuming
  wraparound is possible.

### Security
- Added a pinned security-validation workflow for formatting, all-target and
  all-feature workspace checks, crate tests, exact ML-DSA ACVP outputs,
  workspace-wide RustSec/cargo-deny policy, Miri coverage of the public error
  and secret-buffer APIs, and the repository's statistical timing suite. Added
  cargo-fuzz targets for signature/key/point/hybrid/ciphertext/stream decoders
  and a Loom schedule model for ErrorRegistry replacement and clearing.
- Removed three safe-API memory-safety failures in the global error registry:
  mismatched deallocation, unchecked generic type confusion, and concurrent
  use-after-free.
- Added negative Ed25519 tests for the identity-key universal forgery,
  small-order/noncanonical points, and `S + L` malleability.
- Streaming decryption now rejects truncation, frame omission, frame replay or
  reordering within a stream, unauthenticated final markers, oversized frames,
  counter exhaustion, trailing frames, and algorithm/version confusion. Replay
  of a complete, otherwise-valid stream remains an application-layer concern;
  bind streams to external sessions/objects or maintain replay state where that
  threat matters.
- ChaCha20 and GCM reject input before block counters can wrap. Generic GCM key
  sizing is derived from its block cipher, and its former panicking `zeroed()`
  path has been removed.
- P-256 hash and x-coordinate intermediates are reduced modulo the group order,
  while externally supplied and generated private scalars are strictly checked;
  ECDH now rejection-samples until it obtains a valid scalar.
- ML-DSA expanded private keys now emit the full 64-byte `tr = SHAKE256(pk, 64)` field required by FIPS 204. Paired import rejects the former 32-byte field plus synthetic padding through `tr` and sign/verify coherence checks. Bare expanded bytes have no version tag, so provenance or versioned framing is required to distinguish overlapping syntactic encodings reliably.
- Bare expanded-key imports are syntactically decoded but do not attempt public-key derivation. `from_bytes_with_public_key` verifies `tr` and performs a libcrux sign/verify coherence check, caches the paired public key, and is required when callers need `secret_key.public_key()` after import.
- ML-DSA signature decoding now rejects duplicate or unsorted hint indices, non-monotonic hint boundaries, and nonzero unused hint bytes.
- Added repository ACVP-format key-generation known-answer gates and bidirectional interoperability tests between libcrux-backed dcrypt operations and the `fips204` candidate comparator for all three parameter sets. Package B review does not accept this as independent assurance evidence, and upstream acquisition provenance for the local ACVP-format fixtures is unverified.

### Migration
- The remediation release is SemVer-major. It must not be published as `1.2.x`:
  `v1.2.3` remains affected; `v2.0.0` is the first release containing these
  remediations, but it has since been withdrawn as described above.
- This release is intentionally incompatible with affected dcrypt formats.
  Version-1 streaming data, the former custom XChaCha construction, legacy
  dcrypt Dilithium objects, and version-1 ECDSA/ML-DSA hybrid objects are not
  silently accepted or relabeled.
- Low-level GCM construction is key-only and the nonce is supplied by each
  operation. `new_with_tag_len` accepts only 12--16-byte tags; callers using
  constructor nonces or 1--11-byte tags must migrate (16-byte tags are
  preferred).
- ECDSA verification requires exact DER with positive, minimally encoded
  INTEGERs, `1 <= r,s < n`, and low `s`. Previously accepted negative,
  non-minimal, trailing-data, out-of-range, or high-`s` encodings now fail.
- Poly1305 no longer implements `Clone` or exposes `reset`, and `finalize(self)`
  consumes the instance. Create a new authenticator with a fresh one-time key for
  every message.
- ChaCha20 processing/seek methods that can exhaust a block counter are fallible;
  update call sites to handle their `Result` values.
- `SecretVec` dereferences to a slice. Code that resized through `Vec` methods
  must call the explicit wiping `resize`, `truncate`, `clear`, `push`, `pop`,
  `reserve`, or `extend_from_slice` methods as appropriate.
- `ErrorRegistry::store` requires `Send + 'static`, while typed retrieval
  requires `Clone + Send + 'static`. Prefer returning errors directly instead of
  using process-global last-error state.
- Applications that used the ignored GCM operation nonce must rotate affected
  keys and re-encrypt. Applications accepting external Ed25519 keys must audit
  historical authorizations. Existing version-1 streams cannot retrospectively
  prove completeness or order.
- Incident review must also cover short GCM tags, acceptance of overlong HMAC
  tags, Poly1305 one-time-key reuse through clone/reset, ECDSA signature-byte
  malleability, and historical `SecretVec` allocation copies. See
  `SECURITY.md` for the corresponding response guidance.

## [1.2.3] – 2026-04-03
### Changed
- Reworked ML-DSA/Dilithium signing to keep a fixed public attempt window while moving per-attempt `cs1`, `cs2`, and `ct0` products into the NTT domain and serializing only the selected candidate once.
- Aligned the ML-DSA signer and verifier hint flow with the FIPS 204 `MakeHint(-ct0, w - cs2 + ct0)` / `UseHint` contract.

### Fixed
- Corrected the ML-DSA `Decompose` special-case handling used by high-bit reconstruction, fixing edge cases that could inflate retry counts and break hint reconstruction.

### Security
- ML-DSA constant-time signing now uses the formal FIPS 204 Appendix C, Table 3 loop bound (`814`) as its public fixed signing window instead of an empirical-only cap.
- Added assurance tests that keep the fixed signing window above the FIPS minimum and regression tests that exercise the deterministic signing-attempt profile.

### Performance
- Optimized ML-DSA constant-time signing relative to the earlier fixed-1000 fallback by combining NTT-domain challenge products with one-shot constant-time candidate selection and final packing.

## [1.2.0] – 2025-12-08
### Added
- **RFC 9380 hash-to-curve** for BLS12-381 (G₁ + G₂), including:
  - `expand_message_xmd` (SHA-256)
  - Simplified SWU map for G1
  - Simplified SWU + 3-isogeny map for G2
  - Public APIs:  
    - `G1Projective::hash_to_curve`  
    - `G2Projective::hash_to_curve`  
  - `hash_to_curve_g1` / `hash_to_curve_g2` exported at module level.
- **Hash-to-field primitives**:  
  - `Fp::from_bytes_wide(&[u8; 64])`  
  - `Fp2::from_bytes_wide(&[u8; 128])`  
- **Convenience conversions**: `impl From<u64> for Fp`.

### Changed
- **Constant-time MSM hardening** for both G₁ and G₂:
  - Replaced variable-time bucket accumulation with `subtle::Choice`-based conditional selects.
  - Fixed window size for CT MSM for predictable timing behaviour.
  - Added `alloc`-gated vectorized MSM support, preserving `no_std` compatibility.
- Updated internal BLS12-381 field/module structure to expose `R2` where needed for Montgomery reduction paths.

### Documentation
- Fully updated `docs/algorithms/ec/bls12_381/README.md`:
  - New sections for hash-to-curve, hash-to-field, and BLS signatures.
  - Improved examples for pairing, MSM, subgroup checks, and serialization.
  - Added standards-compliance notes (RFC 9380, Eth2 serialization).

### Security
- MSM constant-time path now eliminates data-dependent branching.  
- All hash-to-curve outputs include cofactor clearing and subgroup correctness.

### Performance
- Faster variable-time MSM due to log₂(n)-based window heuristics.  
- More predictable behaviour for CT MSM on production validator workloads.

---

## [1.1.1] – 2025-12-03
### Added
- Support for zero-copy constructors: `Into<Vec<u8>>` for `SecretVec`, `Key`, `PublicKey`, and `Ciphertext`.  
- `From<Vec<u8>>` implementations for core secret/data types to allow direct ownership transfer without allocation.  
### Changed
- Refactored AEAD, Hybrid KEM, and ECIES code paths to move buffers where possible and pass slices otherwise; removed unnecessary cloning.  
- Updated plaintext/ciphertext handling to use the new zero-copy constructors where relevant.  
### Performance
- Reduced redundant allocations and lowered peak memory usage for large ciphertexts and secret data.  
### Security
- Introduced move-based `SecretVec` ownership. A later audit found that its
  `Vec` representation could retain inaccessible spare capacity; v3 replaces
  secret storage with exact-size ownership and best-effort clearing.

## [1.1.0] – 2025-11-24  
### Added
- Gen-2 timing-regression harness: bootstrap confidence intervals, KS-based
  distribution tests, Holm-Bonferroni multi-signal correction, and persistent
  noise profiling.
### Changed
- No public API surface changed. The statistical harness added regression
  evidence across noisy environments; it did not prove constant-time behavior.
### Security / Assurance
- Added statistical timing-regression evidence for selected cryptographic
  routines across the tested environments and CI runners.

## [1.0.0] – 2025-11-21  
### Added
- Initial stable release of dcrypt under IOI Foundation: symmetric crypto,
  post-quantum KEM, hybrid constructions, PKE, and AEAD modules.
- Initial `no_std` feature surface, modular crate structure, and clearing
  wrappers for selected sensitive state. Later audits identified important
  implementation and assurance gaps; all pre-v3 releases are unsupported.
- Public-key, secret-key, ciphertext, encryption/decryption, encapsulation, and
  serialization APIs.
### Changed
- Stabilized API surface after beta series; breaking changes from prior betas resolved.  
### Fixed
- Bug fixes across classical and PQC modules; improved test coverage and baseline for cryptographic correctness.  
### Security
- Introduced `SerializeSecret` for explicit secret exports. Later audits
  identified allocation-lifecycle and ownership gaps; v3 uses exact-size
  protected ownership while retaining bounded slice access.

[Unreleased]: https://github.com/ioi-foundation/dcrypt/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/ioi-foundation/dcrypt/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/ioi-foundation/dcrypt/compare/v1.2.3...v2.0.0
[1.2.3]: https://github.com/ioi-foundation/dcrypt/compare/v1.2.2...v1.2.3  
[1.2.0]: https://github.com/ioi-foundation/dcrypt/compare/v1.1.1...v1.2.0  
[1.1.1]: https://github.com/ioi-foundation/dcrypt/compare/v1.1.0...v1.1.1  
[1.1.0]: https://github.com/ioi-foundation/dcrypt/releases/tag/v1.1.0  
[1.0.0]: https://github.com/ioi-foundation/dcrypt/releases/tag/v1.0.0  
