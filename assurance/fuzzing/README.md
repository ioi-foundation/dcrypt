# Package C fuzz assurance

The authoritative binding status is the exact value generated into `policy.json`
from the reviewed constants in `fuzzing_lib.py`; this prose deliberately does
not duplicate a stage-specific status claim.

This subtree is the fail-closed structural framework for Package C. It does not
claim persistent campaign time, per-target sanitizer instrumentation, coverage,
freshness, trusted-writer storage, crash handoff, external filing, independent
oracle coverage, or release readiness. `verify.py --release` intentionally
returns `3` (`HOLD`) while any such blocker remains.

The normative policy and exact 17-target registry live in reviewed Python code.
Canonical generated JSON cannot redefine them: literal semantic SHA-256 anchors
in `fuzzing_lib.py` reject a coherent data-only rebind. All JSON uses UTF-8/NFC,
sorted keys, two-space indentation, a final newline, no duplicate keys, and no
floating-point values. Every schema object is closed.

## Exact commands

Run structural verification and adversarial controls without network access:

```sh
python3 -B assurance/fuzzing/generate.py --check
python3 -B assurance/fuzzing/verify.py --ci
python3 -B assurance/fuzzing/selftest.py
```

Every CI, full replay, publish, and release gate must also execute both private
live controls and retain their canonical JSON only as ephemeral job evidence:

```sh
python3 -B assurance/fuzzing/sanitizer_positive.py --execute
python3 -B assurance/fuzzing/crash_lifecycle.py --execute
```

The checked-in `local-sanitizer-requirements.json` and
`crash-lifecycle-status.json` contain deterministic requirements with zero
host observations. They are not proof artifacts and cannot satisfy promotion;
only an rc0 live invocation in the current gate can do so. Live JSON binds the
measured host linker and ELF inspector, their versions and executable hashes,
the actual linker argv, target/fixture binary and symbol-table hashes, reports,
the exact rustc and sanitizer runtime, and the fixed 8192-KiB stack limit.

Release verification is a deliberate terminal HOLD:

```sh
python3 -B assurance/fuzzing/verify.py --release
```

The exact PR smoke contract is:

```sh
python3 -B assurance/fuzzing/run-fuzz-smoke.py --mode pr
```

The four ledger-compatible groups are `kem`, `signatures`, `symmetric`, and
`hybrid`. They form an exact, duplicate-free partition of all 17 targets. Use
`--group GROUP --execute` for one group or `--group GROUP --print-plan` for a
nonexecuting private-path plan. The runner validates the canonical manifest,
stages reviewed seed bytes into a 0700 private temporary corpus with 0600 files,
keeps dictionaries read-only, applies exact caps and ignore=0 controls, and
requires exactly 1,000 executions. Deterministic smoke is not campaign evidence.

Workflow consumers may query the code-pinned registry:

```sh
python3 -B assurance/fuzzing/select-fuzz-targets.py --all-targets
python3 -B assurance/fuzzing/select-fuzz-targets.py --seed-dir-for TARGET
python3 -B assurance/fuzzing/select-fuzz-targets.py --dictionary-for TARGET
python3 -B assurance/fuzzing/select-fuzz-targets.py --input-cap-for TARGET
python3 -B assurance/fuzzing/select-fuzz-targets.py --timeout-for TARGET
```

`-` means no reviewed seed/dictionary source. A selector seed directory is a
read-only staging source and must never be passed directly as writable corpus.
Changed rows/paths can be selected with canonical LF-terminated sorted files via
`--changed-rows-file` or `--changed-paths-file`; Git mode uses `--base` and
`--head`. Unknown security-root changes select all targets. Gaps and noncritical
rows return explicit machine-readable HOLD records rather than silent emptiness.

## Evidence boundaries

The checked-in row map contains all 9,298 atomic rows: exactly 372 critical
family rows are assigned to planned semantic targets, and all 8,926 other rows
are explicit blockers. All 9,298 remain release-blocked. Shared or unknown
Package B comparator lineage is corroborative only and cannot satisfy mapping.

The live controls execute an ASan stack overflow, an address-mode `Box::leak`
under the exact target `ASAN_OPTIONS`, and a supplemental standalone LSan
`Box::leak`, all as real safe-Rust children. They use the exact 2026-08-08
distribution compiler (rustc commit dated 2026-08-07), measured host
linker/inspector identities, pinned runtime digests, defined-ELF-function
inspection, and real report matching. Per-target integrated leak-detection
proof additionally binds the exact ASan runtime archive and the defined
`__asan_init`, `__lsan_enable`, `__lsan_disable`, and
`__lsan_do_recoverable_leak_check` functions; `__lsan_init` is required only
for the supplemental standalone-LSan control. A successful current run proves
only that the current job's control mechanism detected its fixtures. A panic is
never sanitizer proof, and these controls do not prove instrumentation or
campaign execution for any fuzz target.

The crash lifecycle uses private temporary storage, an actual safe-Rust failing
child, deterministic minimization/deduplication, a closed simulated-unfiled
handoff, private regression replay, and a second fixed child. The synthetic
`CRASH` fixture bytes are public reviewed test source; no generated/private
crash artifact, real campaign input, binary, or log is written to the repository
or an external system.

No tool in this subtree authorizes network activity, external writes, corpus
promotion, crash publication, issue filing, signing, or release. Generator writes
are restricted to the documented generated outputs under this subtree. Final
source/evidence subject hashes must be integrated and independently reviewed
before the structural subject-binding gate can pass. Operational evidence and
release readiness remain HOLD after that structural transition.

After the final non-assurance R commit is reviewed, committed, and represented
by a freshly generated `assurance/subject-manifest.json`, the only authorized
binding transition is:

```sh
python3 -B assurance/fuzzing/rebind-final-subject.py \
  --expected-commit R_COMMIT --expected-tree R_TREE --dry-run
python3 -B assurance/fuzzing/rebind-final-subject.py \
  --expected-commit R_COMMIT --expected-tree R_TREE --apply
python3 -B assurance/fuzzing/rebind-final-subject.py \
  --expected-commit R_COMMIT --expected-tree R_TREE --check
```

Before commit, the tool requires the exact reviewed 20-path Package B evidence
inventory, partitioned into 16 changed paths and four exact-R invariant paths,
plus the exact 35-file Package C closure. The R-to-A changed closure is therefore
exactly 51 paths. The tool rejects every staged, missing, surplus, non-assurance,
wrong-mode, linked, or special path. Dry-run emits a
canonical path/mode/hash candidate manifest and restores exact original bytes
and filesystem modes. Apply permits only the six literal
status/commit/tree/manifest/policy/registry assignments plus canonical generator
outputs. It restores every known transaction file on failure, never deletes an
unknown path that appears concurrently, and revalidates the exact protected
`.gitignore` topology after each invoked check and before success. After commit,
check requires A to be the sole child of R, verifies the exact R..A closure,
protects `.gitignore`, and replays generation, structural verification, and
adversarial selftests. A data-only, partial, or coherent surplus rebind is
rejected.
