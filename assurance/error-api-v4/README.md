# Package E: v4 error API removal assurance

Package E records and verifies the deliberately breaking removal of dcrypt's
process-global error registry and legacy `Result` compatibility extensions.
The reviewed authority is `reviewed-inventory.toml`; the generated
`package-e.json`, `schema.json`, and `ARTIFACTS.json` are reproducible views of
that authority and of the repository's exact pre- and post-removal inventories.

This package is a migration foundation, not a release authorization. The
workspace remains at version 3.0.0, package publication is ineligible, and the
release gate is unconditionally `HOLD` with exit code 3. A separately reviewed
version transition is required before any v4 release can be prepared.

The structural CI entry point is:

```text
python3 -B assurance/error-api-v4/verify.py --ci
```

The release entry point repeats structural verification and returns 3:

```text
python3 -B assurance/error-api-v4/verify.py --release
```

`capture.py` imports an already-produced private bundle whose exact raw closure
is declared by a mode-0600 `candidate.json`. It copies only the declared
artifacts into a new private destination using descriptor-relative, no-follow,
no-replace operations, bounded enumeration, byte/hash verification, fsync, and
verified cleanup. Only downstream-migration and external-review candidates are
capture-admissible, and both remain untrusted and nonpromotable. The generated
local-removal proof is not capturable, and the schema-defined acceptance role is
unconditionally disabled in v1. Capture executes no commands, performs no
network activity, and makes no trust, acceptance, or promotion decision.

Capture requires a normal checkout with a real `.git` directory so it can bind
repository exclusion by descriptor identity. A checkout represented by a
`.git` gitfile is unsupported and fails closed.

`rebind-final-subject.py` is the later literal topology/final-closure
transaction authority; its reviewed anchors must be finalized only after the
global Package E cascade reaches a fixed point.

The user-facing replacement guide is `docs/migration/V4-ERROR-API.md`, and the
bounded downstream compile/behavior fixture is
`tests/tests/error_api_v4_migration.rs`.
