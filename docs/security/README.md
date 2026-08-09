# Security advisories

The four stop-ship findings are published as GitHub Security Advisories and are
also tracked by [RustSec advisory-db PR #3123](https://github.com/RustSec/advisory-db/pull/3123).
The repository-local `DCRYPT-*` identifiers are project tracking identifiers,
not assigned RustSec IDs.

`v2.0.0` fixes the four specific findings below, but the release is
[withdrawn](V2.0.0-WITHDRAWAL.md) because its implementation and normal/build
dependency closure violate dcrypt's zero-unsafe, zero-native-code, and zero-FFI
policy. `v1.2.3` is critically affected and is not a safe fallback. No dcrypt
release is currently supported.

- [DCRYPT-2026-0001: error-registry memory unsafety](DCRYPT-2026-0001.md) — [GHSA-7hc7-h3f2-r4j6](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-7hc7-h3f2-r4j6)
- [DCRYPT-2026-0002: Ed25519 identity-key forgery](DCRYPT-2026-0002.md) — [GHSA-7j32-2mpw-c784](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-7j32-2mpw-c784)
- [DCRYPT-2026-0003: GCM operation nonce ignored](DCRYPT-2026-0003.md) — [GHSA-h9f2-fgp8-vc4h](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-h9f2-fgp8-vc4h)
- [DCRYPT-2026-0004: unauthenticated streaming framing](DCRYPT-2026-0004.md) — [GHSA-8cwp-4826-jg9f](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-8cwp-4826-jg9f)

The v3 audit identified five additional release-blocking findings. They are
documented under repository-local identifiers while coordinated GitHub
advisories are prepared; the identifiers below are not assigned GHSA, CVE, or
RustSec IDs:

The custom construction shipped under the `XChaCha20Poly1305` name in tagged
source from `v0.5.0` through `v1.2.3` is supported only by an isolated
[decrypt-only migration tool](../../migration/legacy-xchacha20poly1305/README.md).
It is not standard XChaCha20-Poly1305 and is not part of the published API.

- [DCRYPT-2026-0005: sect283k1 validation permits a predictable ECDH-KEM secret](DCRYPT-2026-0005.md)
- [DCRYPT-2026-0006: BLS12-381 G1 decoders bypass subgroup validation](DCRYPT-2026-0006.md)
- [DCRYPT-2026-0007: BLS12-381 hash-to-curve is incompatible with RFC 9380](DCRYPT-2026-0007.md)
- [DCRYPT-2026-0008: Kyber implementation is not final FIPS 203 ML-KEM](DCRYPT-2026-0008.md)
- [DCRYPT-2026-0009: zero-nonce XChaCha operations reuse a one-time nonce](DCRYPT-2026-0009.md)

See the [traditional-EC removal notice](V3-TRADITIONAL-EC-REMOVALS.md) for the
full B-283 parameter comparison, published-artifact boundary, regression
evidence, and migration guidance. Implementation-policy and other hardening
findings remain tracked in `SECURITY.md` and `CHANGELOG.md` unless a distinct
vulnerability impact is established.
