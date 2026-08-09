# Streaming Symmetric Encryption (`symmetric/streaming`)

This module provides APIs for streaming symmetric encryption and decryption using the authenticated `DCRSTRM2` version-2 dcrypt stream format. Version 1 is intentionally rejected because its unauthenticated terminator, counters, and lengths could not prove stream completeness or ordering.

## Core Traits

1.  **`StreamingEncrypt<W: Write>`**:
    *   **Purpose**: Defines the interface for a streaming encryption context.
    *   **Methods**:
        *   `write(&mut self, data: &[u8]) -> Result<()>`: Encrypts a chunk of plaintext `data` and writes the resulting ciphertext to the underlying writer `W`. This can be called multiple times.
        *   `finalize(self) -> Result<W>`: Encrypts any remaining plaintext, writes an authenticated final frame, flushes the writer, and returns it. This method consumes the encryptor and must be called explicitly.

2.  **`StreamingDecrypt<R: Read>`**:
    *   **Purpose**: Defines the interface for a streaming decryption context.
    *   **Methods**:
        *   `read(&mut self, buf: &mut [u8]) -> Result<usize>`: Reads encrypted data from the underlying reader `R`, decrypts it, and fills `buf` with the resulting plaintext. Returns the number of plaintext bytes written to `buf`. Returns `Ok(0)` if the end of the stream is reached and successfully authenticated.

## Implemented Streaming Schemes

The module provides streaming implementations for the AEAD ciphers available in `dcrypt-symmetric`:

1.  **ChaCha20Poly1305 Streaming (`chacha20poly1305.rs`)**:
    *   `ChaCha20Poly1305EncryptStream<W>` and `ChaCha20Poly1305DecryptStream<R>` use bounded 16 KiB frames and preserve plaintext across arbitrarily small caller read buffers.

2.  **AES-GCM Streaming (`gcm.rs`)**:
    *   **`Aes128GcmEncryptStream<W: Write>`** and **`Aes256GcmEncryptStream<W: Write>`**.
    *   **`Aes128GcmDecryptStream<R: Read>`** and **`Aes256GcmDecryptStream<R: Read>`**.
    *   Uses the same authenticated version-2 framing as ChaCha20-Poly1305 with a distinct authenticated algorithm identifier.

Every frame authenticates the protocol version, algorithm identifier, random stream identifier, base nonce, expected 64-bit sequence number, plaintext and ciphertext lengths, final-frame flag, and caller AAD. Frames are limited to 16 KiB and caller AAD to 1 MiB before allocation. The decryptor rejects sequence mismatches, missing final frames, trailing data, oversized lengths, unknown flags, and counter exhaustion before releasing unauthenticated plaintext.

## Utility Functions

The modules also provide convenient file encryption/decryption functions that wrap the streaming APIs:
- In `chacha20poly1305.rs`:
    * `encrypt_file<R: Read, W: Write>(...) -> Result<()>`
    * `decrypt_file<R: Read, W: Write>(...) -> Result<()>`
- In `gcm.rs`:
    * `encrypt_file_aes128<R: Read, W: Write>(...) -> Result<()>`
    * `decrypt_file_aes128<R: Read, W: Write>(...) -> Result<()>`
    * `encrypt_file_aes256<R: Read, W: Write>(...) -> Result<()>`
    * `decrypt_file_aes256<R: Read, W: Write>(...) -> Result<()>`

## Usage Example (AES-128-GCM Streaming)

```rust
use dcrypt_symmetric::aes::Aes128Key;
use dcrypt_symmetric::streaming::gcm::{Aes128GcmEncryptStream, Aes128GcmDecryptStream};
use dcrypt_symmetric::streaming::{StreamingEncrypt, StreamingDecrypt};
use dcrypt_symmetric::error::Result;
use std::io::{Cursor, Read, Write}; // For in-memory Read/Write

fn streaming_aes128_gcm_example() -> Result<()> {
    let key = Aes128Key::generate();
    let aad = Some(b"Authenticated context for streaming");

    // --- Encryption ---
    let mut ciphertext_buffer = Vec::new(); // In-memory buffer for encrypted data
    // The final authenticated frame is written only by explicit finalization.
    {
        let mut writer_cursor = Cursor::new(&mut ciphertext_buffer);
        let mut encrypt_stream = Aes128GcmEncryptStream::new(writer_cursor, &key, aad)?;

        encrypt_stream.write(b"This is the first segment of a long message.")?;
        encrypt_stream.write(b"Followed by a second segment.")?;
        encrypt_stream.write(b"And finally, the last segment.")?;

        // Finalize the stream (consumes the encrypt_stream)
        let _ = encrypt_stream.finalize()?;
    }

    println!("Total encrypted data size (incl. header & metadata): {} bytes", ciphertext_buffer.len());

    // --- Decryption ---
    let mut reader_cursor = Cursor::new(ciphertext_buffer);
    let mut decrypt_stream = Aes128GcmDecryptStream::new(reader_cursor, &key, aad)?;

    let mut decrypted_data = Vec::new();
    let mut read_buf = [0u8; 1024]; // Buffer to read decrypted chunks into

    loop {
        let bytes_read = decrypt_stream.read(&mut read_buf)?;
        if bytes_read == 0 { // End of stream
            break;
        }
        decrypted_data.extend_from_slice(&read_buf[..bytes_read]);
    }

    let original_message = b"This is the first segment of a long message.Followed by a second segment.And finally, the last segment.";
    assert_eq!(original_message, decrypted_data.as_slice());
    println!("Streaming decryption successful: {}", String::from_utf8_lossy(&decrypted_data));

    Ok(())
}

// fn main() {
//     streaming_aes128_gcm_example().expect("Streaming AES-128-GCM example failed.");
// }
```

## Security Considerations

-   **Nonce Derivation**: Each stream gets a random base nonce and random stream identifier. Per-frame nonces are derived from the internally enforced 64-bit sequence number; exhaustion is an error.
-   **AAD**: Caller AAD (at most 1 MiB) and all framing metadata are authenticated on every frame.
-   **Error Handling**: `std::io::Error`s from read/write operations are converted to `symmetric::error::Error::Io`. AEAD decryption errors (tag mismatch) will result in `Error::Primitive(PrimitiveError::Authentication { .. })`.
-   **Stream Integrity**: The authenticated final-frame flag and strict expected sequence number make truncation, omission, in-stream frame replay, and reordering fail closed. A complete, otherwise valid ciphertext stream can still be replayed to a fresh decryptor. Applications that require whole-object replay protection must bind a unique record or session identifier in caller AAD and track it externally.
