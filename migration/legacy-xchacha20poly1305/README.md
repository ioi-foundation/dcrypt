# dcrypt v1 custom XChaCha migration tool

This non-published, decrypt-only tool exists solely for ciphertext known to have
been created by dcrypt v1's nonstandard construction named
`XChaCha20Poly1305`. It cannot encrypt, and standard XChaCha20-Poly1305
ciphertext is intentionally rejected.

Do not guess provenance from key or nonce length. Establish it from application
records before migration, preserve the original ciphertext for incident review,
and rotate the key after authenticated decryption and re-encryption with a
supported construction.

The key file must contain exactly 32 raw bytes. The output path must not exist;
the tool creates it with mode `0600` on Unix. Example:

```console
cargo run --release --manifest-path migration/legacy-xchacha20poly1305/Cargo.toml -- \
  --provenance dcrypt-v1-custom-xchacha20poly1305 \
  --key-file legacy.key \
  --nonce-hex 00112233445566778899aabbccddeeff0011223344556677 \
  --ciphertext-file legacy.bin \
  --output-file plaintext.bin
```

Supply `--aad-file` if the original encryption authenticated associated data.
