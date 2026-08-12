# Offline oracle-workspace provisioning

This directory provides a cold dependency bundle, an exact subject snapshot,
and a fail-closed runner for six regression targets in the isolated
`verification/` workspace. It does **not** establish comparator independence,
accept an oracle, or clear an assurance row. All oracle-lineage statuses remain
blocked pending their separate provenance and implementation-independence
reviews.

## Normative root and non-self-binding subject

`manifest.json` is the single canonical normative root. Its exact SHA-256 is
code-pinned in `bundle_lib.py`; merely rewriting a coherent manifest and its
referenced inputs fails verification. The manifest binds:

- the exact path and SHA-256 of `verification/Cargo.toml` and `Cargo.lock`;
- all 138 crates.io archives in that lock, including canonical static HTTPS
  URLs, lock checksum, byte/member/unpacked totals, license expression and
  license-file digests, and published `.cargo_vcs_info.json` claims;
- the release/locked/offline Cargo invocation, stable Rust and Cargo commit
  identities, host triple, linker path, sandbox policy, and every host-tool
  provenance blocker;
- six exact test targets, their source-file SHA-256 values, and all 30 exact
  test names; and
- the SHA-256 and count of `subject-inputs.json`, which binds an exact prior Git
  commit/tree and every file in the test execution closure.

The VCS, repository, license, and package metadata extracted from a `.crate`
archive are publisher claims. This package checks that those claims match the
downloaded archive; it does not independently establish upstream lineage.

A manifest cannot safely bind its own containing commit. The subject binding is
therefore explicitly a prior-commit candidate, not a self-binding claim. The
binding tools/artifacts are excluded from the execution subject at exactly:

- `verification/oracle-provisioning/**` (this independently reviewed and later
  Git/assurance-bound tool package);
- `verification/clean-room-protocol-reference/**` (a separate scaffold, not an
  input to these six Cargo targets); and
- `verification/target/**` plus `target/**` under each path dependency
  (generated build output).

The included closure contains all other tracked `verification/**` files,
including `verification/src`, every test source, `PROVENANCE.md`, and all 20
Ethereum YAML vectors; all tracked files in the seven recursively discovered
path-dependency roots; root `Cargo.toml`, `Cargo.lock`, and `src`; every root
workspace member manifest required during Cargo workspace discovery; and every
file or recorded absence under root and verification `.cargo` configuration
directories. It also derives each path package's ancestor `Cargo.toml` search,
binds every present candidate and recorded absence (currently
`crates/Cargo.toml`), and freezes the root package's `build.rs`, `src`, `tests`,
`examples`, and `benches` auto-target discovery state. Generation and
verification enforce the exact exclusions, reject untracked additions within a
scope or formerly absent discovery paths, and reject missing, changed, linked,
or special inputs.

After **all** non-assurance subject commits are complete, perform the final
tightly scoped rebind:

```bash
repo_root=$(git rev-parse --show-toplevel)
subject_commit=$(git -C "$repo_root" rev-parse HEAD)
python3 -B "$repo_root/verification/oracle-provisioning/rebind-final-subject.py" \
  --repo-root "$repo_root" \
  --subject-commit "$subject_commit" \
  --write
python3 -B "$repo_root/verification/oracle-provisioning/rebind-final-subject.py" \
  --repo-root "$repo_root" \
  --subject-commit "$subject_commit"
git -C "$repo_root" diff -- \
  verification/oracle-provisioning/subject-inputs.json \
  verification/oracle-provisioning/manifest.json \
  verification/oracle-provisioning/bundle_lib.py
```

The writer changes only those three named files. Review and commit that rebind
separately. A subsequent assurance/evidence commit must bind the rebind commit.
If any subject input changes afterward, repeat this sequence. Package-B changes
also invalidate Package A's rehearsal freeze as already documented there.
Persistent verification permits committed changes after the bound subject only
under `assurance/**` and in those exact three generated rebind files. A later
change to any other provisioning tool (including the acquisition, replay, or
test runner) invalidates the binding instead of inheriting its authority.

## Online cold acquisition

The archives total exactly 12,398,448 bytes and are not committed. Run
acquisition on a network-enabled host with empty `HOME` and `CARGO_HOME`. The
output path must not exist. `acquire.py` issues one non-cacheable HTTPS GET to
each exact `static.crates.io` URL and rejects redirects, missing/extra files,
byte/checksum/metadata mismatches, links, special members, unsafe paths,
nonzero-size directory entries, concatenated/trailing gzip data, and per-file or
aggregate safety-limit violations.

```bash
repo_root=$(git rev-parse --show-toplevel)
acquire_root=$(mktemp -d)
mkdir -m 700 "$acquire_root/empty-home" "$acquire_root/empty-cargo-home"
env -i \
  PATH=/usr/bin:/bin \
  HOME="$acquire_root/empty-home" \
  CARGO_HOME="$acquire_root/empty-cargo-home" \
  PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8 LC_ALL=C.UTF-8 TZ=UTC \
  /usr/bin/python3 -B \
  "$repo_root/verification/oracle-provisioning/acquire.py" \
  --manifest "$repo_root/verification/oracle-provisioning/manifest.json" \
  --lock "$repo_root/verification/Cargo.lock" \
  --output "$acquire_root/archives"
/usr/bin/python3 -B \
  "$repo_root/verification/oracle-provisioning/verify-bundle.py" \
  --manifest "$repo_root/verification/oracle-provisioning/manifest.json" \
  --lock "$repo_root/verification/Cargo.lock" \
  --archives "$acquire_root/archives"
```

For an acquisition audit, run the Python command under external `strace -f -qq
-e trace=%file -o file-access.trace` and verify that no Cargo registry/cache
path or populated acquisition `CARGO_HOME` was read. Transfer the exact
repository candidate and complete `archives/` directory to the offline host.

## Cold, no-network replay

The replay host must separately provision the exact stable toolchain named in
the manifest, Python 3, bubblewrap, strace, the pinned system compiler/linker,
and a compatible Linux kernel/host image. Their distributions are not included
or authenticated by this package and remain explicit blockers. A successful
run is regression evidence only.

Materialize into a new path and replay:

```bash
repo_root=$(git rev-parse --show-toplevel)
replay_root=$(mktemp -d)
python3 -B "$repo_root/verification/oracle-provisioning/materialize.py" \
  --manifest "$repo_root/verification/oracle-provisioning/manifest.json" \
  --lock "$repo_root/verification/Cargo.lock" \
  --archives /transfer/archives \
  --repo-root "$repo_root" \
  --output "$replay_root/materialized"
python3 -B "$repo_root/verification/oracle-provisioning/replay.py" \
  --manifest "$repo_root/verification/oracle-provisioning/manifest.json" \
  --lock "$repo_root/verification/Cargo.lock" \
  --archives /transfer/archives \
  --materialized "$replay_root/materialized" \
  --toolchain-root \
    /provisioned/rustup/toolchains/1.93.1-x86_64-unknown-linux-gnu
```

Materialization creates and verifies a byte-exact read-only subject snapshot,
the 138-crate Cargo directory source, a virtual-path Cargo source config, and a
new empty `CARGO_HOME`. Replay is single-use. It rejects extra or pre-existing
outputs, then invokes each target explicitly with `--test`, `--release`,
`--locked`, and `--offline`; first it requires the exact sorted test-name set
and zero ignored tests, then it requires one exact success summary with no
failed, ignored, measured, or filtered tests.

The external strace process supervises a bubblewrap process using
`--unshare-all`. There is no host-root bind. The sandbox has explicit read-only
mounts for `/usr`, the dynamic-loader cache, toolchain, runner, subject, vendor,
config, and normative manifest; writable mounts only for empty `CARGO_HOME` and
target output; new `/dev` and `/proc`; a new tmpfs `/tmp`; and empty `/run` and
`/var/run`, hiding all host runtime sockets. The network trace parser rejects
unknown/incomplete lines and every syscall outside exact AF_UNIX jobserver and
namespace-local AF_NETLINK setup forms. In particular any `connect`, internet
family, or unrecognized socket/type fails even when the syscall itself failed.

## Reproducibility and adversarial tests

```bash
python3 -B verification/oracle-provisioning/build-manifest.py \
  --lock verification/Cargo.lock \
  --archives /transfer/archives > /tmp/oracle-manifest.rebuilt.json
cmp verification/oracle-provisioning/manifest.json \
  /tmp/oracle-manifest.rebuilt.json

python3 -B verification/oracle-provisioning/selftest.py \
  --manifest verification/oracle-provisioning/manifest.json \
  --lock verification/Cargo.lock \
  --archives /transfer/archives \
  --repo-root "$(git rev-parse --show-toplevel)"
```

The self-test covers canonical acceptance plus missing/extra/corrupt files;
symlink, hardlink, FIFO, path traversal, noncanonical path, privileged mode,
directory-size, gzip concatenation/trailing-data, and generated-checksum
rejection; package and aggregate caps; exact vendor modes/content; exact
subject missing/extra/config/vector, ancestor-workspace, build-script, and
auto-target discovery changes; changed locks; coherent manifest and subject
rewrites without the reviewed code pin; and strict network syscall allowlisting.
It also proves that the persistent post-subject policy rejects a
committed replay/security-tool change even when the three generated binding
files and assurance paths remain allowed.

No command in this package changes a crate, tag, release, advisory, external
vendor state, production dependency, or oracle acceptance status.
