# Historical custom XChaCha migration tool

This non-published, decrypt-only tool exists solely for ciphertext known to
have been created by the nonstandard construction present in tagged dcrypt
source from `v0.5.0` through `v1.2.3` under the name `XChaCha20Poly1305`. It cannot
encrypt, and standard XChaCha20-Poly1305 ciphertext is intentionally rejected.
The [provenance record](PROVENANCE.md) identifies the historical source and the
fixed artifact-derived vector used by the tests.

Do not guess provenance from key or nonce length, and do not treat an
authentication failure as a format detector. Establish provenance from
application records before migration. The required `--acknowledge-format`
value is an operator acknowledgement, not authentication of the input's
origin.

Preserve the original ciphertext for incident review. After authenticated
decryption, re-encrypt with a supported construction and fresh caller-supplied
randomness, rotate the legacy key, and securely remove temporary plaintext and
raw-key files according to the host platform's storage model.

## Inputs

- Supply exactly one key input. `--key-file` accepts a regular file containing
  exactly 32 raw key bytes. `--serialized-key-file` strictly accepts the
  exact historical `DCRYPT-CHACHA20POLY1305-KEY:<base64>` or
  `dcrypt-CHACHA20POLY1305-KEY:<base64>` representation, with at most one
  trailing LF or CRLF. Published artifacts used the uppercase form through
  `dcrypt-symmetric` `1.0.0` and the lowercase form beginning with `1.0.1`;
  tagged source made that transition at `v1.0.0`. Both readers are bounded.
  Keep either file owner-only (for example mode `0600` on Unix).
- Supply exactly one nonce input. `--nonce-hex` accepts exactly 48 hexadecimal
  characters; `--nonce-base64` strictly accepts the base64 representation
  emitted by the historical 24-byte nonce type.
- `--ciphertext-file` contains the raw ciphertext followed by its 16-byte tag.
- `--aad-file` is required when the original encryption supplied associated
  data. Omitting or changing it makes authentication fail.
- `--output-file` must not exist. A fully written and file-synchronized staging
  file (mode `0600` on Unix) is published without clobbering through a
  same-directory hard link. The staging link is then removed, and the parent
  directory is synchronized on Unix. If cleanup or durability fails, the error
  names every path at which plaintext may remain. Treat that diagnostic as a
  stop condition and do not delete the original ciphertext. Abrupt process or
  host termination can also leave a private
  `.dcrypt-xchacha-migration-*.tmp` staging file beside the requested output;
  inspect that directory before retrying or declaring migration complete.
  On platforms without Unix modes, first restrict the destination directory's
  ACL to the migration account.

Historical high-level APIs commonly used the serialized-key and base64-nonce
forms above. Prefer the explicit file/nonce options instead of an ad hoc
conversion pipeline. Never place key material directly in a command-line
argument, environment variable, shell history, or world-readable temporary
file.

## Invocation

Run from the repository root:

```console
cargo run --release --locked \
  --manifest-path migration/legacy-xchacha20poly1305/Cargo.toml -- \
  --acknowledge-format dcrypt-v0.5.0-through-v1.2.3-custom-xchacha20poly1305 \
  --key-file legacy.key \
  --nonce-hex 00112233445566778899aabbccddeeff0011223344556677 \
  --ciphertext-file legacy.bin \
  --output-file plaintext.bin
```

Use `--help` by itself for the usage summary. Every option may be supplied only
once; malformed invocations fail with a nonzero status.
