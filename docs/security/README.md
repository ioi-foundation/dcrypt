# Security advisories

The ten findings below are published as GitHub Security Advisories. The first
four findings and the v2 withdrawal are tracked by
[RustSec advisory-db PR #3124](https://github.com/RustSec/advisory-db/pull/3124);
RustSec submissions for the six additional v3 findings are part of the
coordinated disclosure. The repository-local `DCRYPT-*` identifiers are
project tracking identifiers, not assigned RustSec IDs.

`v2.0.0` fixes the four specific findings below, but the release is
[withdrawn](V2.0.0-WITHDRAWAL.md) because its implementation and normal/build
dependency closure violate dcrypt's zero-unsafe, zero-native-code, and zero-FFI
policy. `v1.2.3` is critically affected and is not a safe fallback. No dcrypt
release before `v3.0.0` is supported; `v3.0.0` is the supported replacement.

- [DCRYPT-2026-0001: error-registry memory unsafety](DCRYPT-2026-0001.md) — [GHSA-7hc7-h3f2-r4j6](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-7hc7-h3f2-r4j6)
- [DCRYPT-2026-0002: Ed25519 verification permits universal forgery](DCRYPT-2026-0002.md) — [GHSA-7j32-2mpw-c784](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-7j32-2mpw-c784)
- [DCRYPT-2026-0003: GCM operation nonce ignored](DCRYPT-2026-0003.md) — [GHSA-h9f2-fgp8-vc4h](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-h9f2-fgp8-vc4h)
- [DCRYPT-2026-0004: unauthenticated streaming framing](DCRYPT-2026-0004.md) — [GHSA-8cwp-4826-jg9f](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-8cwp-4826-jg9f)

The v3 audit identified six additional release-blocking findings. Their
coordinated GitHub advisories were published with the corrective release. CVEs
have been requested but may not yet be assigned; the
`DCRYPT-*` names remain repository-local tracking identifiers.

The custom construction shipped under the `XChaCha20Poly1305` name in tagged
source from `v0.5.0` through `v1.2.3` is supported only by an isolated
[decrypt-only migration tool](../../migration/legacy-xchacha20poly1305/README.md).
It is not standard XChaCha20-Poly1305 and is not part of the v3 published API.

- [DCRYPT-2026-0005: sect283k1 validation permits a predictable ECDH-KEM secret](DCRYPT-2026-0005.md) — [GHSA-w3jf-cj7j-jmc5](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-w3jf-cj7j-jmc5)
- [DCRYPT-2026-0006: BLS12-381 G1 decoders bypass subgroup validation](DCRYPT-2026-0006.md) — [GHSA-rcw6-8w42-2cg2](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-rcw6-8w42-2cg2)
- [DCRYPT-2026-0007: BLS12-381 hash-to-curve is incompatible with RFC 9380](DCRYPT-2026-0007.md) — [GHSA-g6wj-4vqj-4923](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-g6wj-4vqj-4923)
- [DCRYPT-2026-0008: Kyber implementation is not final FIPS 203 ML-KEM](DCRYPT-2026-0008.md) — [GHSA-xcw2-2p85-wmmp](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-xcw2-2p85-wmmp)
- [DCRYPT-2026-0009: zero-nonce XChaCha operations reuse a one-time nonce](DCRYPT-2026-0009.md) — [GHSA-vwrw-2qvx-3rh9](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-vwrw-2qvx-3rh9)
- [DCRYPT-2026-0010: XChaCha20-Poly1305 APIs used a nonstandard construction](DCRYPT-2026-0010.md) — [GHSA-xj38-xmch-9j4w](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-xj38-xmch-9j4w)

See the [traditional-EC removal notice](V3-TRADITIONAL-EC-REMOVALS.md) for the
full B-283 parameter comparison, published-artifact boundary, regression
evidence, and migration guidance. Implementation-policy and other hardening
findings remain tracked in `SECURITY.md` and `CHANGELOG.md` unless a distinct
vulnerability impact is established.
