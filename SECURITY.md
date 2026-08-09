# Security Policy

At IOI Foundation, we take the security of our software products seriously. This document outlines our policy for reporting security vulnerabilities and our process for handling them.

## Current security status

`v1.2.3` is confirmed affected by multiple serious security defects and must
not be treated as production-safe cryptography. Earlier releases have not been
cleared and remain unsupported while their exact introduced-version ranges are
investigated. The confirmed defects include safe-API memory unsoundness,
Ed25519 authentication bypass, GCM nonce
reuse, an unauthenticated streaming format, a nonstandard construction exposed
as XChaCha20-Poly1305, unsafe GCM tag truncation, and nonstandard objects exposed
as FIPS 204 ML-DSA.

`v2.0.0` contains breaking remediations and regression tests for these findings
and is the first patched release. It passed the repository's release validation
gates, but has not received an independent post-remediation security audit or
FIPS validation. Because the remediations change public APIs and reject affected
wire formats, they are published as a SemVer-major release rather than another
`1.2.x` release. Updating does not retroactively secure data, signatures, or
binaries created by affected releases.

## Supported Versions

| Version | Security status |
| ------- | --------------- |
| `v2.0.0` | Current remediated line; not independently audited or FIPS validated |
| `v1.2.3` | Confirmed affected; do not use for production cryptography |
| Earlier releases | Exact affected ranges under investigation; unsupported and not cleared |

## Migration and incident response

Users of an affected release should assume the following:

- Low-level GCM operations may have reused the constructor nonce even when an
  operation nonce was supplied. Identify affected keys, rotate them, and
  re-encrypt; a software update alone cannot restore confidentiality or
  authenticity.
- Attacker-controlled Ed25519 public keys may have enabled forged
  authorizations. Audit registered keys, trust stores, signatures, and actions
  authorized by them.
- Version-1 streaming ciphertext cannot prove that frames were not truncated,
  omitted, replayed, or reordered within a stream. The remediated implementation
  rejects the old framing rather than silently treating it as authenticated
  version 2 data. Version 2 detects those frame-level attacks within a stream;
  preventing replay of an entire otherwise-valid stream remains the
  application's responsibility and requires external session/context binding or
  replay state.
- Ciphertext emitted by the former `XChaCha20Poly1305` type is a dcrypt-specific
  legacy format, not standard XChaCha20-Poly1305. The remediated API does not
  silently decrypt or relabel it.
- Former `Dilithium2/3/5` keys and signatures are dcrypt-specific legacy objects,
  not FIPS 204 encodings, and must not be relabeled as standard objects.
  Versioned hybrid framing rejects them, and paired expanded-key import detects
  them through `tr` and sign/verify coherence checks. Bare expanded secret bytes
  carry no version tag, so provenance is required for reliable migration.
- GCM deployments that enabled tags shorter than 12 bytes had materially reduced
  forgery resistance. Inventory accepted tag sizes, investigate authentication
  failures or attacker-controlled verification attempts, rotate affected keys,
  and re-encrypt with tags of at least 12 bytes (16 bytes preferred).
- HMAC verification in affected releases could accept a valid tag with certain
  amounts of trailing data because the length difference was narrowed to eight
  bits. Audit protocols that accepted variable-length tags and do not treat
  historical acceptance as proof that the supplied byte string was canonical.
- Standalone Poly1305 could be cloned or reset under the same one-time key. If an
  application used either capability, assume the affected authentication keys
  and tags may be compromised, rotate the parent key material, and redesign key
  derivation so each Poly1305 key is used exactly once.
- ECDSA accepted high-`s` signatures and noncanonical DER encodings. Historical
  signatures may therefore have alternate byte encodings; audit systems that use
  signature bytes as unique identifiers, cache keys, receipts, or consensus
  values. The remediated verifier intentionally rejects those encodings.
- `SecretVec` could leave removed bytes or copies of prior allocations in freed
  or out-of-length memory. Consider secrets exposed through process memory,
  crash dumps, swap, or allocator reuse; rotate sensitive values where that
  exposure matters and remove retained diagnostic artifacts.

Artifacts older than `v2.0.0` should be considered affected until their exact
introduced-version ranges are established. Maintainers should yank affected
crates where operationally feasible and publish separate advisories for the
memory-unsafety, Ed25519 bypass, GCM nonce misuse, and streaming protocol
failures.

Repository-local, RustSec-style disclosure drafts for those four stop-ship
issues are indexed in [`docs/security/README.md`](docs/security/README.md). Their
identifiers are not assigned RustSec IDs and they have not yet been externally
published.

## Reporting a Vulnerability

If you have discovered a security vulnerability in this project, please do not report it publicly.

### How to Report

Please email **team@ioi.network** with a description of the vulnerability. If possible, include:

*   A clear description of the vulnerability.
*   Steps to reproduce the issue.
*   Affected component(s) and version(s).
*   Any proposed fixes or mitigations.
*   The potential impact of the vulnerability.

### Our Response Process

1.  **Acknowledgment:** We will acknowledge your report within 48 hours.
2.  **Assessment:** We will investigate the report to confirm the vulnerability and determine its severity.
3.  **Resolution:** We will work on a fix and test it thoroughly.
4.  **Disclosure:** Once the vulnerability is patched, we will release an update and may publish a security advisory. We will credit you for the discovery if you wish.

We are committed to working with you to resolve the issue promptly. We ask that you refrain from publicly disclosing the vulnerability until we have had a reasonable opportunity to address it.

Thank you for helping keep our project secure!
