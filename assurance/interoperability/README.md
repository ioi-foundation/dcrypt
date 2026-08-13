# dcrypt interoperability assurance

This directory is the fail-closed Package B interoperability completeness
control. It inventories exact public operation atoms and candidate oracle
provenance. It does not assert that current harnesses or third-party packages are
independent assurance evidence.

`matrix.json` deterministically expands 552 curated executable atomic rows over
their exact public path and rustdoc feature/target profile bindings. The expected
result is 6,184 operation atoms. Fourteen curated public metadata rows expand to
56 explicit `not-applicable` atoms with a rationale. All 8,632 unreviewed atomic
gaps are retained as individual digest-bound blockers. The resulting 14,816
interoperability blockers are a distinct completeness count and neither add to
nor clear the assurance ledger's 9,198 atomic release blockers.

Every executable matrix key includes the crate and public path, algorithm,
parameter set, operation, encoding/wire format, profile/mode/DST/context/prehash,
feature/target profile, direction, oracle identity and immutable provenance,
implementation lineage/shared dependencies, and case identity. Blocked rows use
explicit `bidirectional-required`, `unassigned`, and `required-coverage` values;
no required key is omitted.

## Deterministic commands

Generate tracked artifacts:

```text
python3 -B assurance/interoperability/generate-interoperability-matrix.py
```

Check byte-for-byte regeneration and all structural gates:

```text
python3 -B assurance/interoperability/generate-interoperability-matrix.py --check
python3 -B assurance/interoperability/verify-interoperability.py --mode ci
python3 -B assurance/interoperability/interoperability-selftest.py
```

The release command is expected to exit 3 while blockers remain:

```text
python3 -B assurance/interoperability/verify-interoperability.py --mode release
```

These commands are offline. They use only Python's standard library and tracked
repository inputs. Oracle execution is not yet authorized as evidence: the
candidate dossiers lack one or more independently verified source commit,
acquisition record, pinned offline source archive, complete lineage verdict, or
independent replay record.

Generated JSON uses UTF-8, Unicode code-point key ordering, compact separators,
and one final newline. TOML control records are parsed with the standard-library
parser and hashed through that same canonical JSON value encoding, while their
exact source bytes are independently SHA-256-bound as generation inputs.
The generator also inventories and binds every regular file beneath
`verification/tests/` and `verification/vectors/`, plus the verification crate
source, README, manifest, and lockfile; missing, added, changed, non-regular, or
symlinked preservation inputs make the tracked matrix stale or fail validation.

## Promotion is disabled in schema v1

`policy.toml` fixes `evidence-promotion-enabled = false`. The dossier schema has
no `accepted` status, the override schema requires an empty array, and the matrix
schema permits no passing row and requires exactly zero passing atoms. The code
independently enforces each invariant. No checked-in maintainer-edited TOML,
ordinary repository file, claimed reviewer string, or locally chosen command can
authorize promotion in this version.

A future reviewed schema version must add separately typed canonical evidence
and review records. At minimum those records must bind the exact dossier record
hash; oracle archive and complete dependency-closure manifest hashes; acquisition
manifest; license bytes; exact dcrypt subject commit and tree; atom, canonical
key, direction, and case; executed argv, environment policy, and tool hashes;
stdout and result hashes; offline sandbox attestation; and separately produced
independent replay output. Until that format and its trust model are reviewed,
every executable atom remains blocked.

The isolation gate recomputes all 138 external packages reachable from the
verification lockfile root and binds their names, versions, sources, checksums,
count, and set digest. It scans dependencies, dev-dependencies,
build-dependencies, and every target-specific variant in all twelve published
manifests. The exact path/package mapping and canonical TOML record hash of
each published manifest are code- and policy-bound; coherently rebinding the
policy to a substituted manifest copy or adding an external package unknown to
the verification closure therefore fails closed. The production lockfile is
likewise code-bound. The only production exceptions are the exact pre-existing
`base64@0.22.1` and `hex@0.4.3` implementation-boundary baseline. Three exact
pre-existing non-production test declarations shared with the closure are
code-bound by manifest, dependency kind, alias, package, and version; they are
not wildcard exceptions and cannot admit an oracle package.

The policy `as-of` date defines the reviewed document's validity window; it is
not a replay clock. CI and release validation compare every dossier, matrix row,
and gap expiry against the actual current UTC date, so an unchanged checkout
fails closed after its 2026-11-09 expiry.

GHASH is currently a private implementation detail. Its mandatory family record
is a blocked private-evidence disposition, not an invented public API atom. A
future isolated differential test may cover it without changing dcrypt's public
semantics.
