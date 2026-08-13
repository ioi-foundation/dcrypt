# Package D side-channel and secret-flow foundation

Package D is a fail-closed inventory and evidence-ingestion boundary.  It maps
all 9,198 atomic assurance rows, every production Rust source, the repository's
29 local statistical timing controls, the reviewed BLS/GHASH compiler-output
controls, future dedicated fixed-vs-random and secret-taint profiles, and the
minimum physical-evidence disposition policy.

This package does **not** claim that local timing tests are dudect tests, that a
dedicated host exists, that branch/address taint analysis has run, that compiler
output closes transitive secret flow, that physical power/EM evidence exists, or
that an external auditor accepted any result.  Structural CI may pass while the
release gate remains `HOLD` with exit status 3.

Generate and verify the checked-in closure with:

```text
python3 -B assurance/side-channel/generate.py
python3 -B assurance/side-channel/generate.py --check
python3 -B assurance/side-channel/verify.py --ci
python3 -B assurance/side-channel/selftest.py
```

`capture.py` only copies an already-produced private candidate bundle into a
new private destination.  It never runs measurement tools, uses the network,
validates trust, accepts evidence, or promotes a row.  Package D v1 rejects
physical and acceptance bundles because no eligible profile is provisioned.
Capture v1 is intentionally limited to a normal checkout whose `.git` is a
directory; linked-worktree gitfiles are rejected rather than resolved.
The checked-in dedicated timing profiles are preregistered structural contracts:
their profile digests bind class construction, dedicated-host, observation,
sampling, stopping, and multiple-test policy.  Capture checks that binding and
the exact declared artifacts, but it does not interpret an operator's opaque
configuration bytes or turn them into accepted evidence.  Independent replay
and review remain required before any operational disposition can change.

`rebind-final-subject.py` is the Package D final-subject topology verifier.  It
is intentionally separate from capture and generation: rebinding reviewed Git
state must never be confused with importing operational evidence.
