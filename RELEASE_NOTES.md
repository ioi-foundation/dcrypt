# dcrypt 4.0.0 — Cryptography, measured

## Built to be attacked before it is trusted.

dcrypt 4 introduces **evidence-native cryptography**: the release is
accompanied by a machine-readable Assurance Profile and a self-contained visual
report generated directly from its release laboratory.

The profile is bound to the exact source, dependency closure, toolchain, target
set, and package artifacts users install. It exposes each result separately—no
opaque security score and no manually maintained dashboard.

`4.0.0` becomes the supported dcrypt release when this reviewed candidate is
published. Until then, `3.0.0` remains the supported corrective release. Every
pre-v3 release remains unsupported; withdrawn `2.0.0` is not a safe replacement.

## The v4 Assurance Profile

The final versioned release subject must satisfy:

| Security signal | v4 result | Evidence class |
| :--- | ---: | :--- |
| Injected artifact faults | **432 / 432 detected** | Calibrated simulation |
| Leakage-detector calibration | **20,000 samples per class** | Calibrated simulation |
| Timing-sensitive paths | **29 cases × 2 complete passes** | Measured product evidence |
| Historical vulnerability classes | **11 / 11 replayed** | Measured product evidence |
| Post-quantum vector cases | **855 exact cases** | Repository-corpus correctness |
| Publishable packages | **12 / 12 byte-equal rebuilds** | Measured product evidence |
| Software inventories | **5 deterministic SBOMs** | Measured product evidence |
| Configured build targets | **4 target profiles** | Build and compiler-shape evidence |

The release workflow regenerates these outputs after version preparation, then
checks that the presentation reproduces byte-for-byte from the laboratory
evidence. The JSON profile and interactive HTML report are attached to the
GitHub release draft automatically by the reviewed handoff command.

## The dcrypt Open Security Lab

The v4 laboratory executes the product and calibrates the detection machinery
used to evaluate it:

- replays all eleven documented dcrypt vulnerability classes;
- executes the complete post-quantum standards-vector target;
- performs a fresh 29-case timing baseline and complete reproduction on a
  disclosed, qualified CPU;
- checks optimized BLS secret-scalar and GHASH compiler shapes;
- builds the supported Linux, WebAssembly, and embedded `no_std` profiles;
- produces deterministic CycloneDX inventories for five classified workspaces;
- assembles all twelve publishable packages twice and requires byte equality;
- introduces deterministic positive and negative leakage controls;
- injects every single-bit mutation in the declared artifact-fault model; and
- signs and immediately verifies a canonical manifest of the emitted evidence.

Simulation and measured product evidence remain visibly distinct. The positive
leakage control establishes that the deterministic analysis pipeline detects a
known seeded signal; the negative control guards against a false positive. The
432-fault campaign exhausts its declared single-bit artifact model. Neither is
presented as measurement on a particular physical device.

## A smaller implementation boundary

The published implementation and its normal/build dependency closure remain
subject to dcrypt's fail-closed policy: no unsafe Rust, native code, or FFI.
Randomized operations receive caller-owned `CryptoRng + RngCore`; the library
does not silently select an operating-system RNG.

External implementations remain confined to excluded verification workspaces.
Comparator results with unresolved independence or shared lineage are not
presented as independent assurance evidence.

## Breaking v4 API change

v4 removes the process-global error registry and the legacy `Result`
compatibility extension traits. Applications should use ordinary `Result`
propagation, standard combinators, caller-owned diagnostics,
`Error::with_context`, `Error::with_message`, and the explicit symmetric error
converters.

This removes global mutable error state and the misleading `secure_unwrap`
naming. It does not change historical advisory ranges or silently preserve
legacy compatibility behavior. See
[`docs/migration/V4-ERROR-API.md`](https://github.com/ioi-foundation/dcrypt/blob/v4.0.0/docs/migration/V4-ERROR-API.md).

Applications upgrading from a pre-v3 release must also follow the full v3
cryptographic migration boundary: caller-owned randomness, corrected
ML-KEM/ML-DSA names and encodings, explicit AEAD nonces, strict parsing, removed
B-283/P-192 surfaces, corrected XChaCha20-Poly1305, and versioned streaming
formats. Do not relabel historical keys, signatures, or ciphertext.

## Security continuity

v4 preserves the supported remediations for the eleven findings disclosed by
the v3 corrective campaign and turns every one into a mandatory release replay.
Those regressions cover memory unsafety, Ed25519 forgery, GCM nonce handling,
stream framing, B-283 validation, BLS subgroup validation and hash-to-curve,
pre-standard Kyber behavior, XChaCha nonce/construction defects, and optimized
GHASH branching.

Updating software does not retroactively restore the confidentiality,
authenticity, or provenance of data processed by an affected historical
release. Review [SECURITY.md](https://github.com/ioi-foundation/dcrypt/blob/v4.0.0/SECURITY.md)
and the published advisories when migrating historical deployments.

## Claim boundary

The Assurance Profile demonstrates the exact software executions and calibrated
simulation models it records. dcrypt 4.0.0 does not claim:

- FIPS module validation;
- formal verification;
- completion of an independent cryptographic audit;
- physical leakage, fault-injection, or erasure resistance;
- native runtime validation on an untested platform; or
- administrative independence of the first-party laboratory producer.

The repository corpus's ML-DSA and ML-KEM expected fields pass exactly, but its
upstream fixture acquisition history remains unauthenticated. This is
correctness evidence, not NIST validation.

## Install

```toml
dcrypt = "4.0.0"
```

Start with the
[Assurance Profile model](https://github.com/ioi-foundation/dcrypt/blob/v4.0.0/docs/assurance/README.md),
[Open Security Lab](https://github.com/ioi-foundation/dcrypt/blob/v4.0.0/docs/assurance/OPEN-SECURITY-LAB.md),
and [reproduction guide](https://github.com/ioi-foundation/dcrypt/blob/v4.0.0/docs/assurance/REPRODUCE.md).

Full changes:
[CHANGELOG.md](https://github.com/ioi-foundation/dcrypt/blob/v4.0.0/CHANGELOG.md) ·
[v3.0.0...v4.0.0](https://github.com/ioi-foundation/dcrypt/compare/v3.0.0...v4.0.0)
