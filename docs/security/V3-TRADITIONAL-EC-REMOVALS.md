# v3 traditional-EC removals and sect283k1 validation failure

## Status and affected releases

The `sect283k1` implementation and its `EcdhB283k` wrapper are release
blockers and are deleted in v3. The published crates.io artifacts from
`v0.9.0-beta.1` through the withdrawn `v2.0.0` must be treated as affected.
The `dcrypt-algorithms` and `dcrypt-kem` `v0.9.0-beta.1` artifacts already
contain the affected B-283 sources; their artifact VCS metadata points to
`f308c73`, even though the repository's local beta.1 tag ancestry does not.
Published-artifact contents therefore take precedence over that stale tag for
the affected-version boundary. `v3.0.0` is the supported replacement and does
not contain the B-283 surface.

This repository record accompanies
[GHSA-w3jf-cj7j-jmc5](https://github.com/ioi-foundation/dcrypt/security/advisories/GHSA-w3jf-cj7j-jmc5).
`DCRYPT-2026-0005` remains a repository-local identifier; consult the GHSA for
the current CVE and RustSec assignment status.

## Evidence

SEC 2 v2 defines the `sect283k1` subgroup order as:

```text
01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61
```

The removed implementation instead used:

```text
01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE96E404282DD3232283E5
```

It also accepted the on-curve point `(x, y) = (0, 1)` as a non-identity
compressed public key or KEM ciphertext. On the binary curve
`y^2 + xy = x^3 + 1`, that point has order two. The parser checked only the
curve equation and did not perform the SEC 1/NIST full-validation requirement
`[n]Q = O`. This matters because `sect283k1` has cofactor 4.

For `EcdhB283k::decapsulate`, multiplying this accepted point by a recipient
secret produced either the identity (and an observable error) or the same
order-two point. In the latter case its x-coordinate was the public constant
zero, and the remaining KDF transcript fields were public. An attacker could
therefore distinguish secret-scalar parity and predict the derived KEM secret
for one parity. That violates the contributory behavior required of ECDH and
invalidates the security claims of the wrapper.

The source history, affected-tag calculation, constant comparison, and parser
behavior were rechecked during the v3 remediation review. The authoritative
parameter and validation references are SEC 2 v2, SEC 1 v2, and NIST
SP 800-56A Revision 3.

The excluded `verification/tests/legacy_b283_advisory.rs` fixture preserves the
relevant removed parser, order-two scalar-multiplication, decapsulation, and
serializer control flow. It demonstrates that both `0x02 || 0^288` and
`0x03 || 0^288` parse as `(0, 1)`, odd scalars yield the known all-zero shared
x-coordinate, even scalars yield the rejected identity, and attempting to
serialize the accepted x-zero point panics at the removed
`x.invert().unwrap()` operation.

## Remediation

V3 removes all of the following rather than retaining a misleadingly named or
insufficiently validated construction:

- `dcrypt_algorithms::ec::b283k` and its parameter surface;
- `dcrypt_kem::ecdh::EcdhB283k` and associated key/ciphertext types;
- B-283 hybrid dimensions, exports, tests, documentation, and benchmarks.

There is no wire-compatible migration. Applications that accepted attacker-
controlled B-283 public keys or ciphertexts must treat the resulting keys and
protected data as potentially compromised, rotate long-term keys, and audit
protocol outcomes. Migrate to a separately reviewed retained suite; do not
reinterpret old B-283 encodings as another curve.

## P-192 removal and P-224 status

V3 also removes low-level P-192, ECDH-P192, ECIES-P192, and ECDSA-P192. NIST
SP 800-186 permits P-192 only for legacy use, so a general v3 API must not
create new P-192 protection.

P-224 remains available for transition and interoperability at approximately
112-bit security. It is not the preferred choice for new high-security
deployments; use P-256 or stronger unless a protocol requires P-224.
