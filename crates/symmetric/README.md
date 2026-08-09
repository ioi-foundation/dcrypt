# dcrypt-symmetric

High-level AEAD and authenticated streaming adapters for dcrypt.

> Security notice: `v1.2.3` is confirmed affected, earlier releases have not
> been cleared, and `v2.0.0` is the first remediated release. In particular,
> v1.2.3's streaming format is structurally
> unauthenticated and its XChaCha20-Poly1305 implementation is not the standard
> construction. The remediated release has not received an independent
> post-remediation audit or FIPS validation. See the workspace `SECURITY.md`
> before using it.

## Implemented interfaces

- AES-128-GCM and AES-256-GCM with 96-bit nonces and 128-bit tags.
- ChaCha20-Poly1305 with 96-bit nonces.
- Standard XChaCha20-Poly1305 with 192-bit nonces.
- Versioned `DCRSTRM2` streaming with authenticated metadata, strict sequence
  numbers, bounded 16 KiB frames, authenticated finality, and partial-read
  buffering.

The former dcrypt XChaCha format is intentionally not accepted by the standard
API. Treat ciphertext created by confirmed-affected `v1.2.3` as a distinct
legacy format. Earlier ciphertext also requires provenance and format review
because its exact affected range has not been established. Migrate legacy data
only through an explicitly trusted, application-specific process.

The streaming module currently requires `std`. The crate's historical
`no_std` feature surface is not a supported or validated build configuration.

## Development dependency

Use the remediated major release and pin the exact version selected for review:

```toml
[dependencies]
dcrypt-symmetric = "=2.0.0"
```

## AES-256-GCM

```rust
use dcrypt_symmetric::{Aead, Aes256Gcm, Aes256Key, Result, SymmetricCipher};

fn round_trip() -> Result<()> {
    let key = Aes256Key::generate();
    let cipher = Aes256Gcm::new(&key)?;
    let nonce = Aes256Gcm::generate_nonce();
    let aad = b"record-type/example";
    let plaintext = b"authenticated plaintext";

    let ciphertext = cipher.encrypt(&nonce, plaintext, Some(aad))?;
    let recovered = cipher.decrypt(&nonce, &ciphertext, Some(aad))?;
    assert_eq!(recovered, plaintext);
    Ok(())
}
```

Every GCM nonce must be unique for its key. Random generation alone may be
inappropriate for very high message counts; select a nonce-allocation strategy
for the surrounding protocol.

## Authenticated streaming

Encryption must be explicitly finalized. Dropping an encryptor does not emit
the authenticated final frame.

```rust
use dcrypt_symmetric::streaming::chacha20poly1305::{
    ChaCha20Poly1305DecryptStream, ChaCha20Poly1305EncryptStream,
};
use dcrypt_symmetric::streaming::{StreamingDecrypt, StreamingEncrypt};
use dcrypt_symmetric::{ChaCha20Poly1305Key, Result};
use std::io::Cursor;

fn streaming_round_trip() -> Result<()> {
    let key = ChaCha20Poly1305Key::generate();
    let aad = Some(b"unique-record-id/42".as_slice());

    let mut encryptor = ChaCha20Poly1305EncryptStream::new(Vec::new(), &key, aad)?;
    encryptor.write(b"first chunk")?;
    encryptor.write(b" and second chunk")?;
    let ciphertext = encryptor.finalize()?;

    let mut decryptor =
        ChaCha20Poly1305DecryptStream::new(Cursor::new(ciphertext), &key, aad)?;
    let mut plaintext = Vec::new();
    let mut buffer = [0u8; 7];
    loop {
        let read = decryptor.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        plaintext.extend_from_slice(&buffer[..read]);
    }

    assert_eq!(plaintext, b"first chunk and second chunk");
    Ok(())
}
```

The frame sequence prevents frame replay within one stream. Preventing replay
of an entire valid stream remains an application responsibility; bind a unique
record/session identifier in AAD and track it externally.

## Assurance boundary

Key wrappers attempt to zero owned storage, but cannot guarantee erasure of
caller copies, registers, compiler temporaries, or allocator history. No
blanket constant-time, production-safety, FIPS-validation, or `no_std` claim is
made for this release.
