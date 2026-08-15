# dcrypt maintainer tools

This directory contains local maintenance, benchmark, and release tooling. The
release scripts are version-controlled because they are part of the release
security boundary; generated snapshots and benchmark build products remain
ignored.

## Non-skippable implementation boundary

Every readiness check and every release mode runs
`verify-implementation-boundary.sh` before proceeding. The checker uses the
tracked lockfile and both all-feature and no-default-feature Cargo graphs,
traverses only normal/build edges from the exact published-root set, enforces an
exact external-package policy snapshot, audits Cargo target sources, builds and
unpacks every actual `.crate` archive, and requires a top-level
`#![forbid(unsafe_code)]` at each packaged crate root. It rejects unsafe Rust,
native code or file magic, FFI/ABI/link/assembly boundaries, internal OS
entropy, and test oracles outside a separate non-published verification
workspace. Force-warn JSON audits and generated build-output scans run for both
feature profiles on Linux x86-64, Linux AArch64, WebAssembly, and the declared
`no_std` target; separate per-package checks require no-default-feature graphs
to remain `std`-free.

Owned excluded workspaces are declared explicitly in
`implementation-boundary.toml`. Each must be independently locked,
non-published, excluded from the release workspace, free of oracle and
native/FFI/OS-entropy dependencies, and equal its exact external-package
snapshot. The checker scans its complete normal/build closure and actively
compiles every target for unsafe-code diagnostics and native build output. The
root `workspace.exclude` list must exactly equal the policy's verification,
fuzz, and owned-workspace classifications. Release rehearsal and preparation
enumerate that policy rather than hard-coding paths: they validate exact path
pins, refresh every classified lockfile, format each workspace, test the
verification and owned categories, and build and run every target in the fuzz
category with a fixed seed and bounded campaign. The release
script also runs `cargo audit` and `cargo deny` against every classified
manifest or tracked lockfile. Those test-only checks provide dependency
visibility for oracle and fuzz tooling; they do not make those implementations
part of the published dependency closure or the zero-native release claim.

The policy has no unsafe/native exceptions and the gate has no release-mode
bypass. `--skip-checks` skips only the separate format, audit/deny, Miri, and
fuzz checks. Other CI jobs run independently so a boundary failure does not
hide their diagnostics.

The default non-mutating rehearsal is strict: missing `cargo-audit`,
`cargo-deny`, nightly Miri, or `cargo-fuzz` tooling is a failure, just as it is
for prepare and execute. The explicitly reported `--skip-checks` development
option is the only way to bypass those tool-dependent checks, and its result is
not release evidence.

Publish readiness also runs `verify-bls-secret-assembly.sh`. It compiles the
protected G1 and G2 scalar-multiplication bridges with one generic codegen unit
for Linux x86-64, Linux AArch64, WebAssembly, and Thumb. Checkout and Cargo
source roots are remapped to deterministic virtual paths, and the gate requires
exactly one regular primary-crate assembly file per target. It reads that file
once as raw bytes and accepts only the reviewed whole-emission SHA-256 for the
exact Rust 1.93.1 or Rust 1.97.1 compiler profile before also checking each
optimized entry point's public-control branch and target-specific mask-selection
shape. The raw fingerprint binds out-of-function directives, aliases,
relocations, metadata, and local constants as well as the protected bodies.
This deterministic compiler-emission regression is intentionally
non-skippable for release modes.

It is not a general constant-time proof: a compiler update that changes the
emission must be reviewed on every target before the checked profile and hashes
are updated. Set `DCRYPT_KEEP_BLS_ASSEMBLY=1` to retain the emitted files for
that manual review.

Publish readiness also runs `verify-ghash-assembly.sh`. It compiles the owned
GHASH multiplication entry point with one generic codegen unit for the same
four targets and fails closed unless the function has exactly one conditional
branch, binds its backedge to the reviewed fixed counter, contains no calls or
indirect/table/Thumb-IT control in the loop, retains the reviewed whole-width
mask, field-shift, and reduction operations inside that loop, and makes exactly
five reviewed `u128` clearing calls on the normal post-loop path. The default
unwind build permits only the exact reviewed clearing calls and unreachable
`panic_in_cleanup` target as indirect x86 calls outside the loop. This catches
LLVM transformations that replace a source-level masked addend with a branch
on a secret-derived GHASH accumulator bit. Set
`DCRYPT_KEEP_GHASH_ASSEMBLY=1` to retain the emitted files for manual review.

## v4 portable-software laboratory

`run-v4-lab-simulation.py` is the non-skippable evidence producer for the v4
portable release profile. It replays all eleven historical advisory commands,
runs the complete 855-case ML-DSA/ML-KEM repository corpus, generates and
verifies five deterministic CycloneDX SBOMs, packages all twelve publishable
crates twice, runs the implementation/target and compiler-shape gates, and
requires two complete statistical timing-family passes on a qualified pinned
CPU. Deterministic positive/negative TVLA controls and an exhaustive single-bit
artifact-fault control test the named simulation models.

The runner writes a canonical evidence manifest, signs it with an ephemeral
Ed25519 key, immediately verifies that signature, and destroys the private key.
The public key and signature establish one coherent run; they are not an
external identity or independent-attestation claim. See
`assurance/release-lab/README.md` for reproduction and verification commands.

`generate-v4-assurance-report.py` validates the lab artifact digests, exact
command closure, structured 29-case timing results, simulation controls,
historical replay, vector count, packages, SBOMs, and signature result. It then
emits `assurance-profile.json` and a self-contained `assurance-report.html`.
The complete lab invokes it automatically. Use `--check` to prove an existing
presentation still reproduces byte-for-byte from the lab evidence.

## Release model

Releases use three explicit phases. Uploading is never combined with versioning
or pushing source, and the default mode is non-mutating.

### 1. Rehearse

```bash
tools/release-dcrypt.sh --version 4.0.0
```

The rehearsal checks the target version on crates.io, verifies Cargo metadata
and exact internal dependency versions, runs the complete ACVP target, the
AES-CBC property target, the separate statistical timing target, and the other
release gates. Secret-bearing and rejection-path timing checks are blocking;
the ML-DSA verification comparison is retained as an explicitly non-blocking
public-input diagnostic because its messages, signatures, public key, validity,
canonical-hint work, and `SampleInBall` rejection work are all public. The
rehearsal then checks package file lists and previews the `cargo-release`
version changes. It does not edit, commit, tag, push, or publish anything.

For a quick script-only rehearsal while developing the workflow:

```bash
tools/release-dcrypt.sh --version 4.0.0 --skip-tests --skip-checks
```

Skipped gates are always reported. Do not use skipped gates as the evidence for
an actual release.

### 2. Prepare locally

First finalize `CHANGELOG.md` and `SECURITY.md` for the chosen version, review
and commit all implementation changes, and start from a clean working tree.
Then run:

```bash
tools/release-dcrypt.sh --version 3.0.0 --prepare
```

Preparation:

- refuses a dirty tree or an already-published target version;
- reruns the release gates;
- updates every workspace crate and exact internal dependency in lockstep;
- creates only the expected version commit when needed; and
- creates a local annotated `v<version>` tag.

It does not push or publish. The printed handoff deliberately separates review
from release publication:

1. Push the exact commit to a `release-candidate/v<version>` branch without the
   tag.
2. Require every trusted check to pass for that exact commit SHA.
3. Fast-forward the release branch and push it together with the already
   reviewed annotated tag in one `git push --atomic` operation.
4. Verify the remote branch and peeled annotated tag both resolve to the
   reviewed SHA.
5. Create and review a GitHub draft with
   `gh release create --draft --verify-tag` and reviewed release notes.
6. Only then run the execute phase.

Do not push the release tag merely to start candidate CI; tags are immutable
release provenance, not rehearsal refs.

### 3. Publish crates from the verified draft and pushed tag

```bash
tools/release-dcrypt.sh --version 3.0.0 --execute
```

Live publication requires all of the following:

- a clean working tree at the requested version;
- the local tag pointing to `HEAD`;
- the same tag and commit already present on `origin`;
- the release commit present on the corresponding remote branch;
- trusted checks passed for that exact commit and a reviewed GitHub draft
  created from the verified tag;
- all enabled release gates passing; and
- an interactive confirmation containing the exact version.

`verify-remote-release-ready.py` enforces the remote portion through read-only,
authenticated queries. It requires `origin/master` to equal `HEAD`, matching
local and remote annotated-tag objects and peeled commits, every reviewed
GitHub Actions check to be successful for that exact SHA and issued by the
trusted Actions app, a private draft release for the exact tag, and either an
empty registry target or an explicitly authorized valid publication prefix.
Every present registry record must have a positive crates.io version ID, remain
unyanked, and exactly match the reviewed local package's feature map and direct
dependency metadata. After the implementation-boundary packages are built, its
report must be bound to exact `HEAD`, the tracked lockfile, and the release
policy; its SHA-256 archive checksums must also match crates.io byte for byte.
The execute flow runs this gate before the long local suite, immediately before
the prompt, and once more after the prompt before the first upload so a stale
interactive confirmation cannot authorize changed remote state. The initially
verified registry prefix is frozen across that window; concurrent publication
requires stopping, inspecting, and resuming explicitly.

Each crate is first checked with `cargo publish --dry-run`, published in
dependency order, and fully reverified through the crates.io API before the
next crate is attempted. Existing records are never skipped based on existence
alone, and every transition requires the exact expected leaf-first prefix
length so stale registry responses cannot advance the loop. The complete
12-crate registry state is checked again before success is reported. The order
is:

1. `dcrypt-internal`
2. `dcrypt-params`
3. `dcrypt-api`
4. `dcrypt-common`
5. `dcrypt-algorithms`
6. `dcrypt-symmetric`
7. `dcrypt-kem`
8. `dcrypt-sign`
9. `dcrypt-pke`
10. `dcrypt-utils`
11. `dcrypt-hybrid`
12. `dcrypt`

`dcrypt-tests` is explicitly non-publishable.

### Recovering a partial crates.io release

The registry is authoritative. If publication stops after one or more crates
were uploaded, inspect crates.io and resume with:

```bash
tools/release-dcrypt.sh --version 3.0.0 --execute --resume auto
```

To require that every preceding crate exists before resuming at a particular
crate:

```bash
tools/release-dcrypt.sh --version 3.0.0 \
  --execute --resume dcrypt-kem
```

The local `.release-state.json` is diagnostic only and is ignored by Git. It can
be removed safely with:

```bash
tools/release-dcrypt.sh --reset-state
```

## Standalone readiness verification

```bash
tools/verify-publish-ready.sh
tools/verify-publish-ready.sh --version 3.0.0 --require-unpublished
```

The verifier uses `cargo metadata` rather than parsing TOML with regular
expressions. It first runs the non-skippable implementation-boundary checker,
then checks package metadata, publish policy, a single shared version, exact
internal dependency requirements, cargo-release availability, credential
configuration, and optionally target-version availability. Any failed
requirement produces a nonzero exit status.

## Benchmark updates

`update-benchmarks.sh` hashes crate sources and benchmark inputs, runs changed
Criterion suites, and updates `BENCHMARKS.md`:

```bash
tools/update-benchmarks.sh
tools/update-benchmarks.sh --force
tools/update-benchmarks.sh dcrypt-kem dcrypt-sign
```

Benchmark changes must be reviewed and committed before release preparation is
rerun. The release script never sweeps unrelated changes into a release commit.
