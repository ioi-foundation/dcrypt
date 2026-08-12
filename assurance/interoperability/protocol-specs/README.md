# Protocol-specification candidate

This directory freezes the current ECIES, hybrid KEM, and hybrid-signature bytes before any clean-room reference is written.

- `current-behavior.json` is the normative machine-readable registry.
- `protocol-spec.schema.json` is its closed JSON Schema.
- `CURRENT-BEHAVIOR.md` is the reviewer-oriented rendering and limitation record.
- `verify-protocol-specs.py` validates canonical form, schema closure, reviewed constants, the exact subject commit/tree, every canonical subject-manifest row against immutable Git blobs, the separately bound curated classifications, the role-complete critical subset, symlink exclusion, and the artifact manifest without network access or third-party packages. It independently pins reviewed digests for the normative registry, schema, this package guide, authoritative human rendering, and final-rebind tool.
- `protocol-specs-selftest.py` performs coherently rehashed mutations of every normative JSON leaf plus explicit schema, source-role, transcript, error, rendering, release-evidence, path, digest, symlink, synthetic-incomplete-repository, export, feature-manifest, ML-KEM alias/parameter, and ML-DSA encoding/signing attacks and requires each corruption to fail.
- `rebind-final-subject.py` is the explicit, review-gated transition from the current interim binding to a final-subject candidate after every Package B non-assurance change has been committed and the canonical subject manifest has been regenerated. Before mutation it requires the exact eight-artifact set, reviewed modes, single-link regular files, and committed `HEAD` bytes; it independently requires the curated classifications to equal both committed `HEAD` and the immutable reviewed digest. Normalized semantic pins permit changes only to `subject_binding`, critical-source SHA fields, the one binding paragraph, verifier binding constants/pins, and `ARTIFACTS.sha256`. It requires the expected commit and tree on the command line; it does not infer or silently bless a subject.
- `ARTIFACTS.sha256` checks directory completeness and binds every artifact except itself, but it is deliberately not the semantic trust anchor. The verifier-owned expected digests prevent a changed artifact plus recomputed manifest from passing. Those embedded digests cannot authenticate the verifier that contains them; reviewed Git subject/evidence binding remains authoritative and must bind the verifier's exact bytes. A manifest cannot safely bind its own bytes.

Run from the repository root:

```sh
python3 assurance/interoperability/protocol-specs/verify-protocol-specs.py
python3 assurance/interoperability/protocol-specs/protocol-specs-selftest.py
```

Before the explicit final rebind, both commands exit zero while the registry reports zero accepted oracles, no interoperability or release-unblocking effect, blocked clean-room acceptance, and `interim-rebind-required` subject status; `verify-protocol-specs.py --require-final-subject` must fail. After the reviewed final rebind, the ordinary verifier and adversarial self-test still exit zero, and the final-subject command below must also pass.

After all non-assurance Package B changes are reviewed and committed, update the assurance ledger to that exact prior commit/tree, run the repository's documented subject-manifest refresh, and then run:

```sh
python3 assurance/interoperability/protocol-specs/rebind-final-subject.py \
  --expected-commit <exact-40-hex-subject-commit> \
  --expected-tree <exact-40-hex-subject-tree>
python3 assurance/interoperability/protocol-specs/verify-protocol-specs.py \
  --require-final-subject --check-current-subject
python3 assurance/interoperability/protocol-specs/protocol-specs-selftest.py
python3 assurance/interoperability/protocol-specs/rebind-final-subject.py \
  --finalize-transaction
```

The rebind stages candidate bytes outside the worktree, atomically replaces only four allowlisted destinations, and catches every `BaseException` to restore and byte-verify all originals. A complete verified transaction is retained in Git-private storage until the explicit finalization above, so a reviewer can instead run `--rollback-transaction`. An interrupted incomplete transaction is detected on the next invocation, restored byte-exactly, and reported as a failure that must be rerun; a partial application never reports `PASS`.

Review the complete rebind diff before finalizing and before the subsequent assurance/evidence commit. The bound subject commit necessarily precedes that evidence commit; no manifest can safely bind its own containing commit.

This package does not change implementation behavior. It must not be cited as cross-implementation evidence or used to clear an atomic assurance row.
