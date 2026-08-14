# v4 portable-software release profile

This profile is the release decision that succeeds Package G's deliberately
nonterminal foundation.  It does not rewrite or promote Packages A through G.
Those packages remain the evidence ledger for a stronger, independently
reviewed assurance claim.

The profile permits a dcrypt 4.0.0 source release after the repository's full
software release gates pass.  It makes no claim of physical leakage or fault
resistance, native runtime validation on an untested platform, FIPS validation,
formal verification, or an independent cryptographic audit.  Those are
deployment/certification claims, not claims made by this portable Rust crate
release.

The separately reproducible laboratory in `assurance/release-lab/` supplies
empirical product checks and calibrated simulation evidence for every claim
that can be tested without a particular device or administrative identity.

This distinction follows `VERSION_STRATEGY.md`, which requires disclosure that
independent review remains outstanding instead of claiming that local gates are
an independent audit.  It is not permission to skip a known exploitable
finding, the existing test/lint/Miri/fuzz/timing/assembly gates, historical
advisory regressions, package-byte review, or registry checksum verification.

Run the structural decision and adversarial checks with:

```text
python3 -B assurance/release-profile/verify.py --phase prepublish
python3 -B assurance/release-profile/selftest.py
```

`prepublish` authorizes release rehearsal and version preparation, not a live
upload.  The normal candidate-branch, protected-check, immutable-tag, registry,
and post-publication verification state machine remains mandatory.
