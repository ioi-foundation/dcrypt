# Assurance ledger

`ledger.toml` binds the repository commit/tree, all in-scope lockfiles, the
implementation-boundary policy, pinned rustdoc toolchain, evidence artifacts,
the independently curated semantic map, derived atomic operations, complete
ACVP-vector manifest, public-API snapshot, and generated algorithm inventory.
`IMPLEMENTATION-BASELINE.md` separately preserves the pre-change branch,
commit/tree, toolchains, lockfiles, and the exact pre-existing `.gitignore`
state. The source-subject manifest binds every tracked byte in the final
non-assurance parent commit except that preserved user-owned `.gitignore`;
`assurance/` is content-addressed by the ledger/evidence graph to avoid a
self-referential Git subject.
Checked-in evidence with an `informational` verdict is a regression/source
layer only; it is not an independent audit, deep fuzz campaign, independent
interoperability result, or dedicated side-channel result.

Run the deterministic negative fixtures without Cargo or network access:

```text
python3 -B assurance/verify-assurance-ledger.py --self-test
```

Confirm that reviewed semantics, cross-crate aliases, blocked gap rows, the
vector manifest, snapshot classifications, and human-readable inventory are
byte-for-byte reproducible:

```text
python3 -B assurance/generate-assurance-ledger.py --check
```

Normal CI and release verification invoke that generator check exactly once
inside the verifier. The generator never infers a supported claim. Its only
semantic input is `curated-operations.toml`; it derives exact public aliases and
fail-closed `semantic-review = "required"` rows for every remaining callable,
trait method, public field, and enum variant.

The ACVP vector manifest proves the bytes of the repository's ACVP-format
corpus. No verified upstream URL, version, or download digest was found, so the
ledger records upstream vector provenance as an explicit release-blocking
limitation rather than calling that corpus official NIST ACVP evidence.

Run the required PR/CI inventory check using the exact pinned rustdoc and
locked, offline dependency state:

```text
python3 -B assurance/verify-assurance-ledger.py --mode ci
```

Release verification must also use live rustdoc. It additionally evaluates
evidence expiry against the verifier host's current UTC date, rejects every
blocked atomic row, and requires `pass` evidence for every ready row:

```text
python3 -B assurance/verify-assurance-ledger.py --mode release
```

`--snapshot-only` is a local diagnostic and is deliberately rejected in
release mode. `--refresh-snapshot` leaves every new or declaration-changed API
unit `UNCLASSIFIED` and exits nonzero until a reviewer assigns an allowed
classification and exact operation references. Reviewers must update both
sides of each API-to-operation association and regenerate the supported-
algorithm document; digest drift remains a hard failure.

The snapshot is deterministic JSON with one compact API unit per line so an
export change has a localized diff. `atomic-operations.toml` keeps curated rows
explicit and stores the 8,000+ unreviewed low-level rows through one immutable
fail-closed defaults table plus compact exact-binding records. The verifier
expands that representation before applying the same atomic schema and release
checks. The generated Markdown lists only authoritative curated rows, summarizes
the blocked backlog by crate/surface, and records the marker-only X25519 status.

The inventory profiles are target-qualified live rustdoc runs for x86-64 Linux,
AArch64 Linux, wasm32, and the declared Thumb `no_std` boundary profiles. The
source-policy gate rejects public target-conditioned exports not represented by
those profiles. Native macOS/Windows runtime evidence remains a later assurance
leg and is not claimed here.

The current ledger intentionally blocks release readiness for every atomic row
until the declared external-audit, independent-oracle, persistent-fuzz, and
dedicated side-channel gaps are closed with independently replayable evidence.
That deliberate blocked state is an honest result: classification completeness
does not mean assurance evidence is complete.
