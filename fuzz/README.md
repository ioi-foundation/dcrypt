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

Build all targets with `cargo +nightly fuzz build`. Run an individual target,
for example, with `cargo +nightly fuzz run stream_frames`.

The CI job compiles every target. Sustained fuzz campaigns and corpus/artifact
retention are release operations and should run outside the ordinary pull
request time budget.
