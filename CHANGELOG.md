# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Withdrew `v2.0.0`. That release retains important remediations for the four
  published stop-ship advisories, but its published implementation and
  normal/build dependency closure violate dcrypt's zero-unsafe,
  zero-native-code, and zero-FFI policy. This policy violation is not, by
  itself, evidence of a new cryptographic exploit in `v2.0.0`.
- Declared that no current release is supported: `v1.2.3` contains critical
  defects and is not a safe fallback, while earlier releases remain unsupported
  and uncleared. The immutable `v2.0.0` tag is retained for provenance.
- Established `v3.0.0` as the planned corrective line because the implementation
  boundary and caller-supplied-randomness contract require breaking changes.

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
- Replaced dcrypt's custom Dilithium implementation with libcrux's portable ML-DSA backend for key generation, signing, verification, and paired expanded-key validation, and added the canonical `MlDsa44`, `MlDsa65`, and `MlDsa87` type names. The historical `Dilithium2/3/5` spellings remain source-compatible aliases to the standards-compliant implementation. The independent `fips204` implementation is now a differential-test dependency only.
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
- Added NIST ACVP key-generation known-answer gates and bidirectional interoperability tests between libcrux-backed dcrypt operations and the independent `fips204` API for all three parameter sets.

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
- Strengthened zeroization guarantees: moving raw key / ciphertext data into `SecretVec` or `Ciphertext` ensures original memory can be zero-wiped reliably.

## [1.1.0] – 2025-11-24  
### Added
- Gen-2 constant-time verification harness: bootstrap CI + p-value statistical tests, KS-based distribution tests, Holm–Bonferroni multi-signal correction, and persistent noise profiling. :contentReference[oaicite:1]{index=1}  
### Changed
- No public API surface changed — backward-compatible. This is an assurance-level upgrade verifying timing behaviour across noisy environments and CI runners. :contentReference[oaicite:2]{index=2}  
### Security / Assurance
- Provides statistically robust evidence that core cryptographic routines exhibit constant-time behaviour under diverse environments and CI runners. :contentReference[oaicite:3]{index=3}

## [1.0.0] – 2025-11-21  
### Added
- Initial stable release of dcrypt under IOI Foundation: symmetric crypto, post-quantum KEM, hybrid constructions, PKE, AEAD modules. :contentReference[oaicite:4]{index=4}  
- `no_std` support for embedded environments; modular crate structure; constant-time implementations; automatic zeroization for sensitive data. :contentReference[oaicite:5]{index=5}  
- Full API: public key, secret key, ciphertext types; encryption/decryption and key-encapsulation; serialization/deserialization. :contentReference[oaicite:6]{index=6}  
### Changed
- Stabilized API surface after beta series; breaking changes from prior betas resolved.  
### Fixed
- Bug fixes across classical and PQC modules; improved test coverage and baseline for cryptographic correctness.  
### Security
- Secret key material cannot be exposed via `AsRef/AsMut` — only safe, explicit serialization/export allowed.  

[Unreleased]: https://github.com/ioi-foundation/dcrypt/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/ioi-foundation/dcrypt/compare/v1.2.3...v2.0.0
[1.2.3]: https://github.com/ioi-foundation/dcrypt/compare/v1.2.2...v1.2.3  
[1.2.0]: https://github.com/ioi-foundation/dcrypt/compare/v1.1.1...v1.2.0  
[1.1.1]: https://github.com/ioi-foundation/dcrypt/compare/v1.1.0...v1.1.1  
[1.1.0]: https://github.com/ioi-foundation/dcrypt/releases/tag/v1.1.0  
[1.0.0]: https://github.com/ioi-foundation/dcrypt/releases/tag/v1.0.0  
