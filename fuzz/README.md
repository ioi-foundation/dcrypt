# dcrypt fuzz targets

This package is deliberately excluded from the release workspace. Every target
forbids unsafe Rust and has an explicit per-input ceiling. The original seven
targets exercise public entry points that accept attacker-controlled encodings:

- `signature_decoders`: ECDSA DER, P-384 SEC1 points, strict Ed25519 keys and
  signatures, and final FIPS 204 ML-DSA key/signature encodings.
- `hybrid_decoders`: versioned hybrid public-key, secret-key, and signature
  framing, including malformed component lengths.
- `symmetric_decoders`: serialized keys/nonces/ciphertext packages and raw AEAD
  decryption inputs.
- `stream_frames`: raw and normalized version-2 stream headers and adversarial
  frame lengths for both AES-GCM and ChaCha20-Poly1305 readers.
- `kem_decoders`: canonical and malformed FIPS 203 ML-KEM key/ciphertext
  encodings plus the retained P-224/P-256/P-384/P-521/K-256 ECDH-KEM types.
- `bls12_381_decoders`: compressed and uncompressed G1/G2 encodings, strict
  subgroup/identity validation, canonical or wide scalar inputs, and the
  high-level BLS secret/public/signature/proof parser contracts.
- `legacy_xchacha_migration`: both arbitrary unauthenticated inputs and
  synthesized authenticated ciphertext for the isolated legacy decryptor. Two
  committed seeds force successful decryption with and without AAD; the
  delimiter-based split does not cap AAD at 255 bytes.

Ten additional targets exercise repository-internal semantic invariants without
adding an external implementation or comparator to the fuzz dependency closure:

- `ml_kem_semantic`: all three parameter sets; key/ciphertext serialization,
  encapsulation/decapsulation agreement, and same-size implicit rejection.
- `ml_dsa_semantic`: all three parameter sets; deterministic and hedged signing,
  contexts, roundtrips, and message/signature rejection.
- `bls12_381_semantic`: Basic, Augmented, PoP, and Ethereum profiles, aggregation,
  domain separation, and pairing/multi-Miller agreement.
- `ed25519_semantic`: deterministic sign/verify, strict imports, tampering, and
  identity rejection.
- `ecdsa_semantic`: bounded per-input states for P-224/P-256/P-384/P-521
  deterministic RFC6979 signing, sign/verify, key and strict DER roundtrips,
  wrong-message rejection, and wrong-signature rejection.
- `ecdh_semantic`: every supported ECDH KEM curve, serialization, shared-secret
  agreement, and modified-encapsulation handling.
- `aes_gcm_semantic`: AES-128/192/256 block roundtrips and AES-128/256-GCM
  authenticated roundtrips, tampering, and GHASH boundary states.
- `chacha_semantic`: ChaCha20 chunking, Poly1305 chunking, and authenticated
  ChaCha20-Poly1305/XChaCha20-Poly1305 roundtrips and negatives.
- `ecies_semantic`: every supported ECIES curve, authenticated roundtrips,
  tampering, AAD mismatch, and truncated framing.
- `hybrid_semantic`: every supported hybrid KEM plus the ECDSA-P384/ML-DSA-65
  hybrid signature, including serialization and component-failure behavior.

`stream_frames` also synthesizes valid AES-GCM and ChaCha20-Poly1305 streams,
reads them with adversarial chunk sizes, and rejects authenticated corruption
and AAD mismatch.

## Per-iteration resource bounds

All 17 sources declare `#![forbid(unsafe_code)]`; no target adds native, FFI,
or production dependencies. Input and harness work are bounded as follows:

| Targets | Maximum retained input | Harness and implementation-loop notes |
| --- | ---: | --- |
| `bls12_381_decoders`, `ml_kem_semantic`, `ed25519_semantic` | 4 KiB | No unbounded harness loop; fixed-size keys, ciphertexts, or signatures plus input-sized tamper buffers. |
| `ecdsa_semantic`, `ecdh_semantic`, `hybrid_semantic` | 4 KiB | No unbounded harness loop. ECDSA selects exactly one of six property states per input: at most one EC key generation, two RFC6979 signatures, one verification, two key imports, or one signature import. Production ECDSA RFC6979 signing and EC key generation/encapsulation contain rejection loops without source-level iteration caps. They are runner-timeout-bounded here and remain explicit release blockers pending a separately reviewed bound. Hybrid signing inherits the ECDSA condition. |
| `hybrid_decoders`, `kem_decoders`, `signature_decoders` | 16 KiB | Expansion loops have exact public encoding lengths; framed copies are bounded by retained input. |
| `ml_dsa_semantic` | 2 KiB | No unbounded harness loop. Each ML-DSA signing call executes the production implementation's fixed 814-attempt signing window; deterministic state seeds sign twice and hedged seeds sign once. |
| `bls12_381_semantic` | 2 KiB | No unbounded harness loop; fixed-size values and at most two-key aggregation. Production BLS key generation has an uncapped zero-scalar rejection loop; it is runner-timeout-bounded and remains an explicit release blocker pending a separately reviewed bound. |
| `ecies_semantic` | 32 KiB | No unbounded harness loop; plaintext is additionally capped at 16 KiB. |
| `aes_gcm_semantic`, `chacha_semantic`, `symmetric_decoders`, `legacy_xchacha_migration`, `stream_frames` | 64 KiB | AEAD plaintext is capped at 32 KiB where synthesized; semantic stream plaintext is capped at 4 KiB. AES checks exactly five block-boundary cases. Raw/rejection stream loops permit at most 4,096 reads, and semantic roundtrips at most 4,098 reads, of 1--64 bytes; normalized framing and output remain input-bounded. |

Recursive harness code is absent, so stack growth is constant with respect to
input. The runner supplies independent wall-time, RSS, and single-allocation
ceilings; those process controls complement, rather than replace, source bounds.
Timeout enforcement does not convert an uncapped production rejection loop into
a bounded implementation claim. ECIES inherits EC key-generation rejection
behavior and is blocked on the same source-level condition.

Build all targets with `cargo +nightly fuzz build`. Never pass `fuzz/seeds/`
directly to cargo-fuzz: libFuzzer treats its primary corpus as writable. The
authoritative smoke runner copies reviewed seeds into a private writable
temporary corpus, uses a private artifact directory, verifies the source seed
tree did not change, and applies the applicable dictionary:

```text
python3 assurance/fuzzing/run-fuzz-smoke.py --mode pr
```

For manual experiments, first copy a target's reviewed seeds into a new private
temporary directory and set `-artifact_prefix` to a different private temporary
directory. Do not point either writable location at `fuzz/seeds`,
`fuzz/corpus`, or `fuzz/artifacts`.

The PR smoke job compiles every enumerated target and runs each one for exactly
1,000 executions with seed `424242` against a private temporary copy of the
target's explicit reviewed `fuzz/seeds/<target>/` directory. Staging the corpus
prevents both ignored local campaign inputs from changing PR behavior and
libFuzzer from mutating source seeds. The semantic harnesses require their
target-specific framing, and the reviewed state seeds force every advertised
parameter/profile branch before mutation. This bounded deterministic smoke can
catch repeatable regressions. It is not a sustained campaign, does not meet the
operational core-hour or freshness budgets, and is not evidence that the crate
is “continuously” or “deeply” fuzzed.

The small inputs under `seeds/` and token sets under `dictionaries/` are reviewed
bootstrap material for persistent campaigns. They are intentionally separate
from ignored local working corpora. Their provenance is documented beside the
bytes. Persistent campaign storage, trusted writers, coverage history,
sanitizer attestations, and operational budgets require separate fail-closed
assurance records; repository configuration alone does not prove they occurred.

No target treats the Package B verification comparators as an independent
oracle. Their shared or unknown lineages permit only separately labelled,
corroborative differential signals. The semantic assertions here are first-party
invariants and do not clear any ledger, interoperability, or audit blocker.
