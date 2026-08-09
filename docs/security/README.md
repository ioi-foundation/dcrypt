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

The remaining compatibility and hardening findings are tracked in the
workspace `SECURITY.md` and `CHANGELOG.md`.

The custom construction shipped under the `XChaCha20Poly1305` name from
`v0.7.0-pre` through `v1.2.3` is supported only by an isolated
[decrypt-only migration tool](../../migration/legacy-xchacha20poly1305/README.md).
It is not standard XChaCha20-Poly1305 and is not part of the published API.

The v3 audit also identified a subgroup-validation failure in the former
sect283k1/ECDH-B283 surface. See the
[traditional-EC removal notice](V3-TRADITIONAL-EC-REMOVALS.md) for the affected
tag range, evidence, impact, and migration guidance.
