# dcrypt-symmetric

High-level AEAD and authenticated streaming adapters for dcrypt.

The unreleased v3 API never obtains entropy from the operating system. Every
randomized key, nonce, salt, package, and stream constructor takes a mutable
caller-owned `CryptoRng`, and failures from that source are returned to the
caller. Byte-array constructors and encryption methods with an explicit nonce
remain available.

Implemented interfaces:

- AES-128-GCM and AES-256-GCM with 96-bit nonces and 128-bit tags.
- ChaCha20-Poly1305 with 96-bit nonces.
- Standard XChaCha20-Poly1305 with 192-bit nonces.
- Versioned `DCRSTRM2` streaming with authenticated metadata, strict sequence
  numbers, bounded 16 KiB frames, authenticated finality, and partial-read
  buffering.

The former dcrypt XChaCha format is intentionally not accepted by the standard
API. Every published `dcrypt-symmetric` release from `0.9.0-beta.1` through
`1.2.3` exposed that construction. Treat its ciphertext as a distinct legacy
format and migrate it only in an isolated, explicitly trusted process.

## Dependency

Pin the exact release selected for review:

```toml
[dependencies]
dcrypt-symmetric = "=3.0.0"
```

The allocation-backed core works without `std`:

```toml
dcrypt-symmetric = { version = "=3.0.0", default-features = false, features = ["alloc"] }
```

Authenticated I/O streaming is available only with the default `std` feature.

## AES-256-GCM

```rust
use dcrypt_symmetric::{Aead, Aes256Gcm, Aes256Key, CryptoRng, Result, SymmetricCipher};

fn round_trip(rng: &mut impl CryptoRng) -> Result<()> {
    let key = Aes256Key::generate(rng)?;
    let nonce = Aes256Gcm::generate_nonce(rng)?;
    let cipher = Aes256Gcm::new(&key)?;
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
use dcrypt_symmetric::{ChaCha20Poly1305Key, CryptoRng, Result};
use std::io::Cursor;

fn streaming_round_trip(rng: &mut impl CryptoRng) -> Result<()> {
    let key = ChaCha20Poly1305Key::generate(rng)?;
    let aad = Some(b"unique-record-id/42".as_slice());

    let mut encryptor =
        ChaCha20Poly1305EncryptStream::new(Vec::new(), &key, aad, rng)?;
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
record or session identifier in AAD and track it externally.

Key wrappers erase their owned storage on drop, but cannot guarantee erasure of
caller copies, registers, compiler temporaries, or allocator history. No FIPS
validation or independent post-remediation audit is claimed.
