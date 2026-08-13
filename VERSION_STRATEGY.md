# Release and Version Strategy

## Future v4 error API boundary (unreleased)

The removal of the process-global error registry and the legacy `Result`
compatibility extension traits is source-breaking and may ship only on a future
SemVer-major v4 line. The repository remains at its current package versions
until a separately authorized release-preparation step updates all twelve
published crates together.

Callers must migrate to ordinary `Result` propagation and combinators,
caller-owned diagnostics, the inherent `Error::with_context` and
`Error::with_message` methods, and the explicit symmetric error converters. See
[`docs/migration/V4-ERROR-API.md`](docs/migration/V4-ERROR-API.md). This boundary
does not alter historical advisory ranges, supported-version statements, or
yank policy.

## Security release boundary

Every published pre-v2 line contains one or more vulnerabilities documented in
[`docs/security`](docs/security/README.md). `v2.0.0` retained the first four
stop-ship remediations but was withdrawn after the v3 audit found additional
algorithm, validation, and implementation-policy failures. Its immutable tag is
historical provenance, not a supported upgrade target.

The supported corrective release is versioned `3.0.0` and must remain on the
new SemVer-major line. It must not be published as `2.0.1`, `1.2.x`, or another
backwards-compatible update. This boundary is required because the correction
changes randomness ownership and public APIs, removes affected algorithms, and
rejects legacy serialized formats. Passing repository gates is not an
independent cryptographic audit, formal verification, or FIPS validation.

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
- Randomized key, nonce, salt, signing, encapsulation, streaming, and file APIs
  require a caller-owned `CryptoRng`; dcrypt does not obtain operating-system
  entropy.
- `Kyber*`/`Dilithium*`, B-283, and P-192 public surfaces are removed. Migrate
  to the final-standard `MlKem*`/`MlDsa*` names and retained curves rather than
  relabeling old objects.
- Standard BLS callers use the complete high-level Basic, Augmentation, or PoP
  profile. Ethereum consensus callers select the separately named Eth2 adapter.

## Release gates

The new major release is gated on:

1. Complete the full workspace test and lint matrix, Miri coverage for public
   APIs, parser fuzzing, interoperability/KAT suites, and side-channel checks
   described in the security review.
2. Clearly disclose that independent cryptographic and protocol review of the
   remediated implementation remains outstanding. Passing self-roundtrip tests
   is not presented as an independent audit.
3. Verify that release notes identify all unsupported/yanked lines, link each
   advisory's artifact-derived affected range, and provide incident-response
   guidance for historical data and keys.
4. Verify that all crates in the release use the same new major version and that
   no dependency requirement can resolve back to an affected `1.x` crate.
5. Run the repository's publish-readiness and dry-run tooling, inspect the exact
   artifacts, and publish only after all blockers are closed.

Every affected pre-v3 package/version should be yanked after `3.0.0` is live and
verified. A yank is not a patch and does not change the security status of
already downloaded artifacts or existing lockfiles.
