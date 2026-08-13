//! Version-2 authenticated streaming ChaCha20-Poly1305 adapters.
//!
//! The unauthenticated version-1 marker/counter format is intentionally not
//! accepted by these types.

use super::framed::{FramedDecryptStream, FramedEncryptStream};
use super::{StreamingDecrypt, StreamingEncrypt};
use crate::aead::chacha20poly1305::{ChaCha20Poly1305Cipher, ChaCha20Poly1305Key};
use crate::error::{from_io_error, Result};
use dcrypt_internal::{CryptoRng, Zeroizing};
use std::io::{Read, Write};

/// ChaCha20-Poly1305 writer using authenticated version-2 frames.
pub type ChaCha20Poly1305EncryptStream<W> = FramedEncryptStream<W, ChaCha20Poly1305Cipher>;
/// ChaCha20-Poly1305 reader using authenticated version-2 frames.
pub type ChaCha20Poly1305DecryptStream<R> = FramedDecryptStream<R, ChaCha20Poly1305Cipher>;

/// Encrypt a reader into the authenticated ChaCha20-Poly1305 stream format.
pub fn encrypt_file<R: Read, W: Write, Rng: CryptoRng + ?Sized>(
    mut reader: R,
    writer: W,
    key: &ChaCha20Poly1305Key,
    aad: Option<&[u8]>,
    rng: &mut Rng,
) -> Result<()> {
    let mut stream = ChaCha20Poly1305EncryptStream::new(writer, key, aad, rng)?;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    loop {
        let read = reader.read(&mut buffer[..]).map_err(from_io_error)?;
        if read == 0 {
            break;
        }
        stream.write(&buffer[..read])?;
    }
    stream.finalize()?;
    Ok(())
}

/// Decrypt an authenticated ChaCha20-Poly1305 stream into a writer.
pub fn decrypt_file<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    key: &ChaCha20Poly1305Key,
    aad: Option<&[u8]>,
) -> Result<()> {
    let mut stream = ChaCha20Poly1305DecryptStream::new(reader, key, aad)?;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    loop {
        let read = stream.read(&mut buffer[..])?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).map_err(from_io_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::framed::FRAME_PLAINTEXT_MAX;
    use dcrypt_internal::ChaCha20Rng;
    use std::io::Cursor;

    #[test]
    fn round_trip_across_frames_with_tiny_reads() {
        let key = ChaCha20Poly1305Key::new([0x24; 32]);
        let plaintext = vec![0xa5; FRAME_PLAINTEXT_MAX + 333];
        let mut rng = ChaCha20Rng::from_seed([0x55; 32]);
        let mut encryptor =
            ChaCha20Poly1305EncryptStream::new(Vec::new(), &key, Some(b"aad"), &mut rng).unwrap();
        encryptor.write(&plaintext).unwrap();
        let ciphertext = encryptor.finalize().unwrap();

        let mut decryptor =
            ChaCha20Poly1305DecryptStream::new(Cursor::new(ciphertext), &key, Some(b"aad"))
                .unwrap();
        let mut recovered = Vec::new();
        let mut buffer = [0u8; 7];
        loop {
            let read = decryptor.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            recovered.extend_from_slice(&buffer[..read]);
        }
        assert_eq!(recovered, plaintext);
    }
}
