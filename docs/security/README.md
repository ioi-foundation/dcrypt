# Security advisories

These are repository-local disclosure drafts. Their `DCRYPT-*` identifiers are
not assigned RustSec IDs, and the documents have not been published to the
RustSec advisory database or GitHub Security Advisories.

`v1.2.3` is confirmed affected. Exact introduction ranges for earlier releases
remain under review, so the drafts do not yet make claims about every historical
version. `v2.0.0` is the first patched release; the drafts remain local until
they are separately published through the applicable advisory channels.

- [DCRYPT-2026-0001: error-registry memory unsafety](DCRYPT-2026-0001.md)
- [DCRYPT-2026-0002: Ed25519 identity-key forgery](DCRYPT-2026-0002.md)
- [DCRYPT-2026-0003: GCM operation nonce ignored](DCRYPT-2026-0003.md)
- [DCRYPT-2026-0004: unauthenticated streaming framing](DCRYPT-2026-0004.md)

The remaining compatibility and hardening findings are tracked in the
workspace `SECURITY.md` and `CHANGELOG.md`.
