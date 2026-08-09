# dcrypt fuzz targets

This package is deliberately excluded from the release workspace. It exercises
public entry points that accept attacker-controlled encodings:

- `signature_decoders`: ECDSA DER, P-384 SEC1 points, strict Ed25519 keys and
  signatures, and final FIPS 204 ML-DSA key/signature encodings.
- `hybrid_decoders`: versioned hybrid public-key, secret-key, and signature
  framing, including malformed component lengths.
- `symmetric_decoders`: serialized keys/nonces/ciphertext packages and raw AEAD
  decryption inputs.
- `stream_frames`: raw and normalized version-2 stream headers and adversarial
  frame lengths for both AES-GCM and ChaCha20-Poly1305 readers.
- `kem_decoders`: canonical and malformed FIPS 203 ML-KEM key/ciphertext
  encodings plus the retained P-224/P-256/P-384/P-521/K-256 ECDH-KEM types.
- `bls12_381_decoders`: compressed and uncompressed G1/G2 encodings, strict
  subgroup/identity validation, and canonical or wide scalar inputs.
- `legacy_xchacha_migration`: both arbitrary unauthenticated inputs and
  synthesized authenticated ciphertext for the isolated legacy decryptor. Two
  committed seeds force successful decryption with and without AAD; the
  delimiter-based split does not cap AAD at 255 bytes.

Build all targets with `cargo +nightly fuzz build`. Run an individual target,
for example, with `cargo +nightly fuzz run stream_frames`.

The CI job compiles every target. Sustained fuzz campaigns and corpus/artifact
retention are release operations and should run outside the ordinary pull
request time budget.
