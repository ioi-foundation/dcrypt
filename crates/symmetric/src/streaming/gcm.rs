//! Version-2 authenticated streaming AES-GCM adapters.
//!
//! Version 1 used unauthenticated markers, counters, and lengths and is
//! intentionally not accepted by these types.

use super::framed::{FramedDecryptStream, FramedEncryptStream};
use super::{StreamingDecrypt, StreamingEncrypt};
use crate::aead::gcm::{Aes128Gcm, Aes256Gcm};
use crate::aes::keys::{Aes128Key, Aes256Key};
use crate::error::{Result, SymmetricResultExt};
use dcrypt_internal::{CryptoRng, Zeroizing};
use std::io::{Read, Write};

/// AES-128-GCM writer using authenticated version-2 frames.
pub type Aes128GcmEncryptStream<W> = FramedEncryptStream<W, Aes128Gcm>;
/// AES-128-GCM reader using authenticated version-2 frames.
pub type Aes128GcmDecryptStream<R> = FramedDecryptStream<R, Aes128Gcm>;
/// AES-256-GCM writer using authenticated version-2 frames.
pub type Aes256GcmEncryptStream<W> = FramedEncryptStream<W, Aes256Gcm>;
/// AES-256-GCM reader using authenticated version-2 frames.
pub type Aes256GcmDecryptStream<R> = FramedDecryptStream<R, Aes256Gcm>;

/// Encrypt a reader into the authenticated AES-128-GCM stream format.
pub fn encrypt_file_aes128<R: Read, W: Write, Rng: CryptoRng + ?Sized>(
    mut reader: R,
    writer: W,
    key: &Aes128Key,
    aad: Option<&[u8]>,
    rng: &mut Rng,
) -> Result<()> {
    let mut stream = Aes128GcmEncryptStream::new(writer, key, aad, rng)?;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    loop {
        let read = reader.read(&mut buffer[..]).map_io_err()?;
        if read == 0 {
            break;
        }
        stream.write(&buffer[..read])?;
    }
    stream.finalize()?;
    Ok(())
}

/// Decrypt an authenticated AES-128-GCM stream into a writer.
pub fn decrypt_file_aes128<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    key: &Aes128Key,
    aad: Option<&[u8]>,
) -> Result<()> {
    let mut stream = Aes128GcmDecryptStream::new(reader, key, aad)?;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    loop {
        let read = stream.read(&mut buffer[..])?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).map_io_err()?;
    }
    Ok(())
}

/// Encrypt a reader into the authenticated AES-256-GCM stream format.
pub fn encrypt_file_aes256<R: Read, W: Write, Rng: CryptoRng + ?Sized>(
    mut reader: R,
    writer: W,
    key: &Aes256Key,
    aad: Option<&[u8]>,
    rng: &mut Rng,
) -> Result<()> {
    let mut stream = Aes256GcmEncryptStream::new(writer, key, aad, rng)?;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    loop {
        let read = reader.read(&mut buffer[..]).map_io_err()?;
        if read == 0 {
            break;
        }
        stream.write(&buffer[..read])?;
    }
    stream.finalize()?;
    Ok(())
}

/// Decrypt an authenticated AES-256-GCM stream into a writer.
pub fn decrypt_file_aes256<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    key: &Aes256Key,
    aad: Option<&[u8]>,
) -> Result<()> {
    let mut stream = Aes256GcmDecryptStream::new(reader, key, aad)?;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    loop {
        let read = stream.read(&mut buffer[..])?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).map_io_err()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::streaming::framed::{FRAME_HEADER_SIZE, FRAME_PLAINTEXT_MAX, HEADER_SIZE};
    use dcrypt_internal::ChaCha20Rng;
    use std::io::Cursor;

    fn encrypted(plaintext: &[u8]) -> (Vec<u8>, Aes128Key) {
        let key = Aes128Key::new([0x42; 16]);
        let mut rng = ChaCha20Rng::from_seed([0x66; 32]);
        let mut stream =
            Aes128GcmEncryptStream::new(Vec::new(), &key, Some(b"context"), &mut rng).unwrap();
        stream.write(plaintext).unwrap();
        (stream.finalize().unwrap(), key)
    }

    fn decrypt_all(bytes: Vec<u8>, key: &Aes128Key, read_size: usize) -> Result<Vec<u8>> {
        let mut stream = Aes128GcmDecryptStream::new(Cursor::new(bytes), key, Some(b"context"))?;
        let mut plaintext = Vec::new();
        let mut buffer = vec![0u8; read_size];
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            plaintext.extend_from_slice(&buffer[..read]);
        }
        Ok(plaintext)
    }

    #[test]
    fn caller_seeded_stream_header_is_deterministic() {
        let (left, _) = encrypted(b"same input");
        let (right, _) = encrypted(b"same input");
        assert_eq!(left, right);
    }

    #[test]
    fn partial_reads_preserve_complete_plaintext() {
        let plaintext = vec![0x5a; FRAME_PLAINTEXT_MAX * 2 + 777];
        let (ciphertext, key) = encrypted(&plaintext);
        assert_eq!(decrypt_all(ciphertext, &key, 13).unwrap(), plaintext);
    }

    #[test]
    fn truncation_cannot_be_successful_eof() {
        let plaintext = vec![0x33; FRAME_PLAINTEXT_MAX + 1];
        let (mut ciphertext, key) = encrypted(&plaintext);
        ciphertext.truncate(ciphertext.len() - (FRAME_HEADER_SIZE + 1 + 16));
        assert!(decrypt_all(ciphertext, &key, 1024).is_err());
    }

    #[test]
    fn replay_reorder_and_omission_are_rejected() {
        let plaintext = vec![0x21; FRAME_PLAINTEXT_MAX * 2 + 1];
        let (ciphertext, key) = encrypted(&plaintext);

        let mut wrong_sequence = ciphertext.clone();
        wrong_sequence[HEADER_SIZE + 7] = 1;
        assert!(decrypt_all(wrong_sequence, &key, 4096).is_err());

        let first_ciphertext_len = u32::from_be_bytes(
            ciphertext[HEADER_SIZE + 13..HEADER_SIZE + 17]
                .try_into()
                .unwrap(),
        ) as usize;
        let second_offset = HEADER_SIZE + FRAME_HEADER_SIZE + first_ciphertext_len;
        let mut omitted = ciphertext.clone();
        omitted.drain(HEADER_SIZE..second_offset);
        assert!(decrypt_all(omitted, &key, 4096).is_err());
    }

    #[test]
    fn transmitted_lengths_are_bounded_before_allocation() {
        let (mut ciphertext, key) = encrypted(b"small");
        ciphertext[HEADER_SIZE + 9..HEADER_SIZE + 13].copy_from_slice(&u32::MAX.to_be_bytes());
        ciphertext[HEADER_SIZE + 13..HEADER_SIZE + 17].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decrypt_all(ciphertext, &key, 32).is_err());
    }

    #[test]
    fn final_flag_and_user_aad_are_authenticated() {
        let (mut ciphertext, key) = encrypted(b"authenticated finality");
        ciphertext[HEADER_SIZE + 8] = 0;
        assert!(decrypt_all(ciphertext, &key, 1024).is_err());

        let (ciphertext, key) = encrypted(b"authenticated context");
        let mut stream =
            Aes128GcmDecryptStream::new(Cursor::new(ciphertext), &key, Some(b"wrong")).unwrap();
        assert!(stream.read(&mut [0u8; 64]).is_err());
    }

    #[test]
    fn legacy_v1_header_is_disabled() {
        let key = Aes128Key::new([0x42; 16]);
        let legacy = vec![0u8; HEADER_SIZE];
        assert!(Aes128GcmDecryptStream::new(Cursor::new(legacy), &key, None).is_err());
    }

    #[test]
    fn bytes_and_replayed_frames_after_final_are_rejected() {
        let (ciphertext, key) = encrypted(b"complete");

        let mut arbitrary_trailing = ciphertext.clone();
        arbitrary_trailing.push(0x80);
        assert!(decrypt_all(arbitrary_trailing, &key, 3).is_err());

        let mut replayed_final = ciphertext.clone();
        replayed_final.extend_from_slice(&ciphertext[HEADER_SIZE..]);
        assert!(decrypt_all(replayed_final, &key, 3).is_err());
    }
}
