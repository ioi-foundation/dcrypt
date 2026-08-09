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

The policy has no unsafe/native exceptions and the gate has no release-mode
bypass. `--skip-checks` skips only the separate format, audit/deny, Miri, and
fuzz checks. Other CI jobs run independently so a boundary failure does not
hide their diagnostics.

## Release model

Releases use three explicit phases. Uploading is never combined with versioning
or pushing source, and the default mode is non-mutating.

### 1. Rehearse

```bash
tools/release-dcrypt.sh --version 3.0.0
```

The rehearsal checks the target version on crates.io, verifies Cargo metadata
and exact internal dependency versions, runs the release gates, checks package
file lists, and previews the `cargo-release` version changes. It does not edit,
commit, tag, push, or publish anything.

For a quick script-only rehearsal while developing the workflow:

```bash
tools/release-dcrypt.sh --version 3.0.0 --skip-tests --skip-checks
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

It does not push or publish. Review the resulting commit and tag, then push the
current branch and tag using the exact commands printed by the script.

### 3. Publish the pushed tag

```bash
tools/release-dcrypt.sh --version 3.0.0 --execute
```

Live publication requires all of the following:

- a clean working tree at the requested version;
- the local tag pointing to `HEAD`;
- the same tag and commit already present on `origin`;
- the release commit present on the corresponding remote branch;
- all enabled release gates passing; and
- an interactive confirmation containing the exact version.

Each crate is first checked with `cargo publish --dry-run`, published in
dependency order, and verified through the crates.io API before the next crate
is attempted. The order is:

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
