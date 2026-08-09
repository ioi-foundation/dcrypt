# ML-DSA signatures (`sign/dilithium`)

The historical `dilithium` module now exposes final-standard FIPS 204 ML-DSA.
Key generation, signing, and verification use libcrux's portable backend. Its
field arithmetic, NTT polynomial arithmetic, and serialization components are
formally verified, but dcrypt as a whole is not formally verified, independently
audited, or FIPS validated. The preferred type names are
`MlDsa44`, `MlDsa65`, and `MlDsa87`. `Dilithium2`, `Dilithium3`, and
`Dilithium5` remain source-level aliases only; they do not restore compatibility
with objects emitted by the confirmed-affected dcrypt `v1.2.3`. The exact
introduction range in earlier releases remains under investigation.

The public `Signature` wrapper implements randomized pure ML-DSA with an empty
context. The test harness exercises libcrux's full pure/context, prehash, and
internal ACVP interfaces against official expected results; the externally
supplied-`mu` interface alone uses RustCrypto in tests because libcrux does not
expose it. Wrapper-level key/signature behavior also has bidirectional
differential tests. Test-only implementations do not process untrusted keys at
runtime.

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

A bare final-standard expanded key can be syntactically decoded with
`DilithiumSecretKey::from_bytes`, but libcrux does not expose public-key
derivation from that representation. Prefer `from_bytes_with_public_key`, which
checks the 64-byte `tr`, performs a libcrux sign/verify coherence check, and
caches the paired public key. Calling `public_key()` after a bare import returns
an error rather than invoking a second secret-arithmetic implementation.

## Usage

```rust
use dcrypt::api::Signature;
use dcrypt::sign::MlDsa65;
use rand::rngs::OsRng;

# fn main() -> dcrypt::api::Result<()> {
let (public_key, secret_key) = MlDsa65::keypair(&mut OsRng)?;
let message = b"ML-DSA test message";
let signature = MlDsa65::sign(message, &secret_key)?;
MlDsa65::verify(message, &signature, &public_key)?;
# Ok(())
# }
```

## Validation

The test suite covers all three parameter sets, exact serialization sizes,
canonical negative cases, full backend-level NIST ACVP expected results, and
cross-imported wrapper keys/signatures between libcrux and the independent
test-only implementation.

See [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) for the
standard. See the workspace `SECURITY.md` before using any published dcrypt
version.
