# Package C fuzz-assurance coverage

Status: **STABLE-final-subject-bound**.

This document is generated. Mapping is scope intent only; it is not persistent
campaign, sanitizer, coverage, crash, or release evidence.

## Counts

- Total atomic rows: 9298
- Exact critical-family rows mapped: 372
- Explicit blocker rows: 8926
- Release-blocked rows: 9298

## Planned semantic targets

| Target | Atomic rows | Status |
|---|---:|---|
| `aes_gcm_semantic` | 70 | candidate / unaccepted / unprovisioned |
| `bls12_381_semantic` | 74 | candidate / unaccepted / unprovisioned |
| `chacha_semantic` | 40 | candidate / unaccepted / unprovisioned |
| `ecdh_semantic` | 30 | candidate / unaccepted / unprovisioned |
| `ecdsa_semantic` | 24 | candidate / unaccepted / unprovisioned |
| `ecies_semantic` | 24 | candidate / unaccepted / unprovisioned |
| `ed25519_semantic` | 8 | candidate / unaccepted / unprovisioned |
| `hybrid_semantic` | 36 | candidate / unaccepted / unprovisioned |
| `ml_dsa_semantic` | 42 | candidate / unaccepted / unprovisioned |
| `ml_kem_semantic` | 24 | candidate / unaccepted / unprovisioned |

## Release disposition

Release verification returns 3. No row is promoted by this structural framework.
Final source/evidence subject hashes must be integrated and independently reviewed.
