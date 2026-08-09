# Release and Version Strategy

## Security release boundary

`v1.2.3` is confirmed affected by the vulnerabilities listed in
[`SECURITY.md`](SECURITY.md). Exact introduced-version ranges for earlier
releases remain under investigation. `v2.0.0` is the first remediated release;
it passed the repository validation gates but has not received an independent
post-remediation audit or FIPS validation.

The remediation is versioned `2.0.0` and must remain on the new SemVer-major
line. It must not be published as `1.2.x` or another backwards-compatible
update. This boundary is required because the remediation deliberately changes
public APIs and rejects affected serialized formats.

## Required migration notes

Every release candidate must document these breaking changes:

- Low-level GCM is key-only; each operation supplies its nonce, and tag lengths
  are restricted to 12--16 bytes (16 preferred).
- ECDSA accepts only exact DER with positive, minimally encoded INTEGERs,
  `1 <= r,s < n`, and low `s`.
- Poly1305 is single-use: `Clone` and `reset` are removed, and `finalize`
  consumes the instance.
- ChaCha20 processing and seek operations that can exhaust the block counter
  return `Result` and must be handled.
- `SecretVec` dereferences to `[u8]`; size changes use its explicit wiping
  methods instead of `Vec` mutation through dereference.
- `ErrorRegistry::store` requires `Send + 'static`, and typed retrieval requires
  `Clone + Send + 'static`.
- Streaming AEAD, standard XChaCha20-Poly1305, ML-DSA, and the
  ECDSA-P384/ML-DSA-65 hybrid use new or corrected encodings. Legacy objects
  must not be silently relabeled. Versioned formats reject v1 objects; bare
  ML-DSA expanded-secret bytes require provenance or paired validation because
  they carry no self-identifying version.

## Release gates

The new major release is gated on:

1. Complete the full workspace test and lint matrix, Miri coverage for public
   APIs, parser fuzzing, interoperability/KAT suites, and side-channel checks
   described in the security review.
2. Clearly disclose that independent cryptographic and protocol review of the
   remediated implementation remains outstanding. Passing self-roundtrip tests
   is not presented as an independent audit.
3. Verify that release notes identify `v1.2.3` as confirmed affected, state that
   earlier introduced-version ranges remain under investigation, and link
   incident-response guidance for historical data and keys.
4. Verify that all crates in the release use the same new major version and that
   no dependency requirement can resolve back to an affected `1.x` crate.
5. Run the repository's publish-readiness and dry-run tooling, inspect the exact
   artifacts, and publish only after all blockers are closed.

Affected `1.x` versions should be yanked where operationally feasible. A yank is
not a patch and does not change the security status of already downloaded
artifacts.
