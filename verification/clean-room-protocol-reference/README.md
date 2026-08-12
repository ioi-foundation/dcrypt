# Blocked clean-room protocol-reference scaffold

This subtree is a non-cryptographic Package B scaffold. It does not implement ECIES, a hybrid KEM, or a hybrid signature. It contains no accepted reference backend, fixture, execution record, interoperability evidence, or release-unblocking evidence. Its only runtime behavior is a process-isolated, canonical JSON refusal.

The suite registry copies framing dimensions from the independently reviewed current-behavior source package as an input contract. It binds commit `f00be3676dd01643c46a51b2c56be01159ee4796`, tree `8bc8826d8b0340557c25c526db54a35601ad0924`, the exact Git blob `df50ccdcab03e3e5a8e3f734391268ef18180221` at `assurance/interoperability/protocol-specs/current-behavior.json`, its SHA-256 `07c79d695b906a0cd7a7be4f10f473c0414438390f3d0bdc18c2e9017d6b6035`, and semantic-projection SHA-256 `37b0ecf19b57cf4c526af6bcfbbbf51a3f6bfe034dd19e50a0040fd8742c8eff`. The projection removes only the subject binding and critical-source SHA values that the reviewed final-subject rebind tool is allowed to replace. This immutable source-package binding records the source-package GO without claiming that a current final subject rebind has happened. It is not a reference implementation authorization: the reference-source and backend-dossier allowlists remain empty and all cryptographic work remains blocked.

## Boundaries

- `runner.py` accepts only the canonical ASCII JSON form described by `request.schema.json`, creates a fresh challenge, sanitizes the child environment, changes to a fresh temporary directory, and invokes `worker.py` as a distinct `python -I -S -B` process.
- `worker.py` imports no local project module and implements no cryptography. Status probes return a scaffold-only refusal. Every cryptographic operation first requires a demonstrably distinct OS network namespace and then encounters the deliberately empty backend allowlist.
- A backend status in JSON cannot authorize itself. A future independently reviewed source archive and provenance dossier must receive exact allowlist pins through a reviewed source change. The protocol contract is authenticated from the immutable reviewed Git source blob and semantic projection. The current working contract may be either that exact interim binding or an exact final-subject rebind shape whose manifest, Git commit/tree, curated digest, critical-source digests, complete stage-0 index and current non-assurance path/digest/mode sets, and five declared-absent build inputs all verify; unmerged, intent-to-add, skip-worktree, and assume-unchanged index state is rejected. `assurance/**` and the six documented non-subject paths remain excluded at every layer, so the assurance-only final protocol rebind does not require a later non-assurance scaffold edit. Fixture and execution schemas intentionally cap their committed collections at zero in this version, so producing evidence also requires a reviewed schema/version change.
- Requests and responses are closed, canonical, challenge-bound, and request-digest-bound. A response from an earlier run cannot be reused as a current output.
- The backend dossier schema records a distribution artifact, origin revision, license, implementation language, three non-reuse attestations, two independent approvals, owner, reviewer, review deadline, and expiry. The committed slot is `not-installed`, contains no backend, and has no approvals.
- No dcrypt implementation source, generated code, project import, local path dependency, or production dependency is used here. The current-behavior contract is a specification input only, never an implementation source.

The suite registry has explicit suite and version IDs plus the byte-framing dimensions needed for four ECIES suites, five hybrid-KEM suites, and one hybrid-signature suite. These are marked `reviewed-source-contract-copy-no-evidence`, not verified interoperability facts. The wire ambiguities and compatibility risks remain normative in the separate protocol-specification artifact.

## Run

From the repository root:

```sh
python3 verification/clean-room-protocol-reference/verify-scaffold.py
python3 verification/clean-room-protocol-reference/scaffold-selftest.py
python3 verification/clean-room-protocol-reference/runner.py \
  --request verification/clean-room-protocol-reference/status.request.json
```

The verifier and self-tests must exit zero. The runner intentionally exits 3 and emits a canonical refusal containing `accepted_fixture_count: 0`, `accepted_evidence_count: 0`, `status: refused`, and `release_status: release-blocked`.

The self-tests cover malformed, noncanonical, duplicate, and extra-member requests; suite smuggling into status; same-process worker import; output reuse; network-enabled cryptographic execution; immutable Git commit/tree/path/blob pins; a coherent legitimate final-subject rebind that passes without changing this scaffold after its subject commit; coherent bound-commit and current-worktree attacks for all five declared-absent build inputs; current subject byte/path drift; staged byte/mode/removal drift; unmerged and intent-to-add entries; hidden index flags; hardlinked or executable-bit artifacts; semantic, prose, evidence, source-binding, and working-path substitution; symlink and special-file protocol paths; forged backend/fixture/execution/protocol acceptance; local implementation source/path references; and an opened schema. It also proves that assurance and all six documented subject exclusions stay outside the final closure. Coherently rewriting `ARTIFACTS.sha256` or a working-copy digest does not make any promotion pass.

This scaffold must not be cited as interoperability or cryptographic assurance evidence and must not clear any assurance blocker.
