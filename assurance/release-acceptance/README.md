# Package G release-acceptance foundation

This directory is the pre-version, fail-closed Package G foundation for a
future dcrypt 4.0.0 release. It keeps the workspace at 3.0.0 and does not
authorize version preparation, evidence acceptance, signing, tagging, pushing,
publishing, promotion, yanking, GitHub access, crates.io access, or network
access. The current release verdict is always `HOLD` with exit code 3.

`policy.toml` is the reviewed semantic authority. `package-g.json`,
`schema.json`, and `ARTIFACTS.json` are canonical generated views. Structural
CI can return zero only for the exact foundation. Release verification exposes
three CLI phases: `foundation`, `prepublish`, and `postpublish`. The separate
`registry-prefix` role is a typed operational state record, never a release
acceptance CLI phase. Every valid release phase returns 3 in schema v1. Malformed, inconsistent, untrusted,
or bypassed state returns 1; command-line misuse returns 2.

The typed future roles are `prepublish-candidate`,
`registry-prefix-candidate`, and `postpublish-candidate`. They are consumer
contracts only: this package has no capture or rebind tool and cannot ingest or
accept a record. A prepublish record requires an explicitly deferred empty
registry. A registry-prefix record permits exactly a prefix of length 0 through
12 in the reviewed publication order. A postpublish record requires all twelve
registry artifacts and exact local-candidate/registry/downloaded equality, with
each download additionally bound to the corresponding administratively
independent producer output. Every one of those roles remains untrusted and
nonpromotable, including a length-12 prefix and a complete postpublish
candidate. The closed `acceptance` role is disabled and rejected by v1.

The policy binds the exact Package F completion commit `A_F`, its `R_F` and
`S_F` parents, and requires a future G commit to have `A_F` as its sole parent
and exactly the reviewed fourteen-path change closure. It deliberately makes no claim about
the identity of that future commit. `.gitignore` must be either the exact clean
committed bytes or the exact protected preexisting local delta; no third state
is accepted.

Package B through F semantics remain immutable nonpromotion antecedents read
from the exact `A_F` Git blobs, not mutable worktree substitutes. The
threat-model release command is an explicit structural dependency: its current
exit code 1 is a valid upstream blocker mapped to G's `HOLD` exit code 3, never
to success. The reviewed workflow and three release consumers activate the G
contract before any release workload, provider, credential, or network action.

The dependency exception rejects on equality at 2026-09-10. The historical
advisory inventory has a review deadline of 2026-09-10 but remains an active
replay blocker regardless of deadline; this foundation does not invent an
expiry rule for it. Ledger and threat-model records are bound through
2026-11-09 and reject only after that date under their present policy. No
registry presence is a precondition for prepublish evidence. Foundation checks
evaluate these boundaries from the verifier's trusted UTC date; no record can
supply or override that clock.

Run only local structural checks with bytecode disabled:

```text
PYTHONDONTWRITEBYTECODE=1 python3 -B assurance/release-acceptance/generate.py --check
PYTHONDONTWRITEBYTECODE=1 python3 -B assurance/release-acceptance/verify.py --ci --phase foundation
PYTHONDONTWRITEBYTECODE=1 python3 -B assurance/release-acceptance/selftest.py
PYTHONDONTWRITEBYTECODE=1 python3 -B assurance/release-acceptance/verify.py --release --phase foundation
```

The final command must return 3. A zero result would be a defect, not release
authorization.
