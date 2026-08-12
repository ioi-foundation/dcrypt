# Blocked clean-room protocol-reference scaffold

This subtree is a non-cryptographic Package B scaffold. It does not implement ECIES, a hybrid KEM, or a hybrid signature. It contains no accepted reference backend, fixture, execution record, interoperability evidence, or release-unblocking evidence. Its only runtime behavior is a process-isolated, canonical JSON refusal.

The suite registry copies framing dimensions from the separately reviewed current-behavior contract as an input contract. Its contract digest is deliberately `null` with status `pending-final-seal`; this must be rebound after that contract receives its final independent seal. Until then, both digest allowlists in `runner.py` are empty and all cryptographic work remains blocked.

## Boundaries

- `runner.py` accepts only the canonical ASCII JSON form described by `request.schema.json`, creates a fresh challenge, sanitizes the child environment, changes to a fresh temporary directory, and invokes `worker.py` as a distinct `python -I -S -B` process.
- `worker.py` imports no local project module and implements no cryptography. Status probes return a scaffold-only refusal. Every cryptographic operation first requires a demonstrably distinct OS network namespace and then encounters the deliberately empty backend allowlist.
- A backend status in JSON cannot authorize itself. A future independently reviewed source archive and provenance dossier must receive an exact digest pin through a reviewed source change. The protocol contract must likewise receive an exact digest pin. Fixture and execution schemas intentionally cap their committed collections at zero in this version, so producing evidence also requires a reviewed schema/version change.
- Requests and responses are closed, canonical, challenge-bound, and request-digest-bound. A response from an earlier run cannot be reused as a current output.
- The backend dossier schema records a distribution artifact, origin revision, license, implementation language, three non-reuse attestations, two independent approvals, owner, reviewer, review deadline, and expiry. The committed slot is `not-installed`, contains no backend, and has no approvals.
- No dcrypt implementation source, generated code, project import, local path dependency, or production dependency is used here. The current-behavior contract is a specification input only, never an implementation source.

The suite registry has explicit suite and version IDs plus the byte-framing dimensions needed for four ECIES suites, five hybrid-KEM suites, and one hybrid-signature suite. These are marked `unreviewed-contract-copy`, not verified interoperability facts. The wire ambiguities and compatibility risks remain normative in the separate protocol-specification artifact.

## Run

From the repository root:

```sh
python3 verification/clean-room-protocol-reference/verify-scaffold.py
python3 verification/clean-room-protocol-reference/scaffold-selftest.py
python3 verification/clean-room-protocol-reference/runner.py \
  --request verification/clean-room-protocol-reference/status.request.json
```

The verifier and self-tests must exit zero. The runner intentionally exits 3 and emits a canonical refusal containing `accepted_fixture_count: 0`, `accepted_evidence_count: 0`, `status: refused`, and `release_status: release-blocked`.

The self-tests cover malformed, noncanonical, duplicate, and extra-member requests; suite smuggling into status; same-process worker import; output reuse; network-enabled cryptographic execution; forged backend/fixture/execution/protocol acceptance; local implementation source/path references; and an opened schema. Coherently rewriting `ARTIFACTS.sha256` does not make any promotion pass.

This scaffold must not be cited as interoperability or cryptographic assurance evidence and must not clear any assurance blocker.
