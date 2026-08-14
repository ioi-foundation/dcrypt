# OpenAI Daybreak adversarial review: v4 release boundary

Review date: 2026-08-14
Reviewed foundation: `088b2d2fe1e7d7cc3591cfde5040d447010a74bd`

OpenAI Daybreak adversarial review examined the Package A--G acceptance chain,
the eleven mandatory threat models, platform/physical evidence, supply-chain
evidence, historical replay, and all release-tool consumers.  It found that the
Package G v1 policy is deliberately a non-accepting certification foundation:
it cannot be made to pass by supplying local evidence, and its stronger
independent/physical certification claims cannot honestly be produced by a
single repository operator or a simulated device.

No concrete Critical or High code vulnerability was identified during this
review.  The existing Critical/High classifications are missing-evidence risks
in candidate certification models, not confirmed code vulnerabilities.  They
remain visible in Package G and are not represented as independently reviewed
or physically measured evidence.

For the v4 portable-software release, Daybreak recommends the following bounded
disposition, implemented by `assurance/release-profile/policy.toml`:

- execute every software release gate and all eleven historical regressions on
  the exact candidate;
- build the supported target matrix and reject unsafe/native/FFI/hidden entropy
  boundaries;
- produce deterministic SBOMs, byte-repeat all twelve crate packages, sign the
  laboratory evidence manifest, and require the registry checksum comparison;
- use the open simulated laboratory only for its named Hamming-weight leakage,
  artifact-fault, and signature-integrity models; and
- exclude physical leakage/fault/erasure, untested native runtime, formal/FIPS,
  independent audit, and independent rebuild certification from v4 claims.

This document is model-assisted first-party threat-review evidence.  It binds
the scope and records an adversarial review, but it does not claim administrative
independence, a human third-party cryptographic audit, physical-device testing,
or an external signing identity.  Those higher certification states remain a
visible HOLD and can be completed later without changing the portable v4 claim.
