# ML-DSA signatures (`sign/dilithium`)

The historical `dilithium` module now exposes final-standard FIPS 204 ML-DSA.
Key generation, signing, verification, sampling, arithmetic, and encoding are
dcrypt-owned safe Rust. The implementation passes the official ACVP vectors and
is checked against independent implementations in the excluded verification
workspace, but dcrypt is not formally verified, independently audited, or FIPS
validated. The preferred type names are
`MlDsa44`, `MlDsa65`, and `MlDsa87`. `Dilithium2`, `Dilithium3`, and
`Dilithium5` remain source-level aliases only; they do not restore compatibility
with objects emitted by the confirmed-affected dcrypt `v1.2.3`. The exact
introduction range in earlier releases remains under investigation.

The public API supports deterministic pure ML-DSA as well as hedged signing with
an explicit caller-provided `CryptoRng`, with optional contexts. The test harness
exercises pure/context, prehash, internal-message, and externally supplied-`mu`
interfaces against official expected results. `fips204`, libcrux, and RustCrypto
are isolated, non-published verification-workspace oracles and never process keys
in the published runtime implementation.

## Encoding boundary

The adapter accepts and emits the exact final FIPS 204 key and signature sizes.
Expanded private keys contain the standard 64-byte
`tr = SHAKE256(public_key, 64)` value. Signature parsing enforces canonical hint
encoding, including strictly increasing indices, monotonic boundaries, and zero
unused padding.

Legacy dcrypt keys used a 32-byte `tr` followed by synthetic padding, and legacy
signatures admitted noncanonical hints. They are nonstandard objects and are
not knowingly migrated or relabeled. A bare expanded secret has no version tag,
so provenance/versioned framing is required to distinguish formats reliably;
paired import rejects legacy keys through `tr` and sign/verify coherence checks.

A bare final-standard expanded key imported with
`DilithiumSecretKey::from_bytes` is fully validated: dcrypt recomputes
`A*s1+s2`, `t1`, `t0`, the public key, and the 64-byte `tr`, then requires a
canonical re-encoding. The derived public key is retained. The paired import
additionally requires the supplied public key to equal that derived key.

## Usage

```rust
use dcrypt::api::Signature;
use dcrypt::sign::MlDsa65;
use rand::rngs::OsRng;

# fn main() -> dcrypt::api::Result<()> {
let (public_key, secret_key) = MlDsa65::keypair(&mut OsRng)?;
let message = b"ML-DSA test message";
let signature = MlDsa65::sign_with_rng(message, &secret_key, &mut OsRng)?;
MlDsa65::verify(message, &signature, &public_key)?;
# Ok(())
# }
```

## Validation

The test suite covers all three parameter sets, exact serialization sizes,
canonical negative cases, all 615 NIST ACVP expected results, and bidirectional
cross-implementation tests with three independent test-only oracles.

See [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) for the
standard. See the workspace `SECURITY.md` before using any published dcrypt
version.
