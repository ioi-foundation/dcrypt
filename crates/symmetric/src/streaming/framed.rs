//! Versioned, authenticated framing shared by streaming AEAD adapters.

use crate::aead::chacha20poly1305::{
    ChaCha20Poly1305Cipher, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce,
};
use crate::aead::gcm::{Aes128Gcm, Aes256Gcm, GcmNonce};
use crate::aes::keys::{Aes128Key, Aes256Key};
use crate::cipher::{Aead, SymmetricCipher};
use crate::error::{fill_random, validate_stream_state, Result, SymmetricResultExt};
use crate::streaming::{StreamingDecrypt, StreamingEncrypt};
use dcrypt_internal::{CryptoRng, Zeroize, Zeroizing};
use std::io::{Read, Write};

pub(crate) const MAGIC: &[u8; 8] = b"DCRSTRM2";
pub(crate) const VERSION: u8 = 2;
pub(crate) const STREAM_ID_SIZE: usize = 16;
pub(crate) const NONCE_SIZE: usize = 12;
pub(crate) const HEADER_SIZE: usize = 8 + 1 + 1 + STREAM_ID_SIZE + NONCE_SIZE;
pub(crate) const FRAME_HEADER_SIZE: usize = 8 + 1 + 4 + 4;
pub(crate) const FRAME_PLAINTEXT_MAX: usize = 16 * 1024;
pub(crate) const TAG_SIZE: usize = 16;
const USER_AAD_MAX: usize = 1024 * 1024;

fn invalid(details: &'static str) -> crate::Error {
    validate_stream_state(false, "stream format", details)
        .expect_err("false validation condition must fail")
}

/// Internal adapter allowing the framing logic to be shared without exposing
/// nonce construction details from the individual high-level AEADs.
pub trait FramedAead: Sized {
    type Key;

    const ALGORITHM_ID: u8;

    fn from_key(key: &Self::Key) -> Result<Self>;
    fn seal(&self, nonce: &[u8; NONCE_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    fn open(&self, nonce: &[u8; NONCE_SIZE], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
}

macro_rules! impl_gcm_framed_aead {
    ($cipher:ty, $key:ty, $id:expr) => {
        impl FramedAead for $cipher {
            type Key = $key;
            const ALGORITHM_ID: u8 = $id;

            fn from_key(key: &Self::Key) -> Result<Self> {
                <Self as SymmetricCipher>::new(key)
            }

            fn seal(
                &self,
                nonce: &[u8; NONCE_SIZE],
                plaintext: &[u8],
                aad: &[u8],
            ) -> Result<Vec<u8>> {
                <Self as Aead>::encrypt(self, &GcmNonce::new(*nonce), plaintext, Some(aad))
            }

            fn open(
                &self,
                nonce: &[u8; NONCE_SIZE],
                ciphertext: &[u8],
                aad: &[u8],
            ) -> Result<Vec<u8>> {
                <Self as Aead>::decrypt(self, &GcmNonce::new(*nonce), ciphertext, Some(aad))
            }
        }
    };
}

impl_gcm_framed_aead!(Aes128Gcm, Aes128Key, 1);
impl_gcm_framed_aead!(Aes256Gcm, Aes256Key, 2);

impl FramedAead for ChaCha20Poly1305Cipher {
    type Key = ChaCha20Poly1305Key;
    const ALGORITHM_ID: u8 = 3;

    fn from_key(key: &Self::Key) -> Result<Self> {
        <Self as SymmetricCipher>::new(key)
    }

    fn seal(&self, nonce: &[u8; NONCE_SIZE], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        <Self as Aead>::encrypt(
            self,
            &ChaCha20Poly1305Nonce::new(*nonce),
            plaintext,
            Some(aad),
        )
    }

    fn open(&self, nonce: &[u8; NONCE_SIZE], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        <Self as Aead>::decrypt(
            self,
            &ChaCha20Poly1305Nonce::new(*nonce),
            ciphertext,
            Some(aad),
        )
    }
}

fn derive_nonce(base_nonce: &[u8; NONCE_SIZE], sequence: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = *base_nonce;
    for (dst, src) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *dst ^= src;
    }
    nonce
}

fn frame_aad(
    algorithm_id: u8,
    stream_id: &[u8; STREAM_ID_SIZE],
    base_nonce: &[u8; NONCE_SIZE],
    sequence: u64,
    final_frame: bool,
    plaintext_len: u32,
    ciphertext_len: u32,
    user_aad: &[u8],
) -> Result<Vec<u8>> {
    let user_aad_len = u64::try_from(user_aad.len()).map_err(|_| invalid("AAD is too long"))?;
    let capacity = HEADER_SIZE
        .checked_add(FRAME_HEADER_SIZE)
        .and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(user_aad.len()))
        .ok_or_else(|| invalid("AAD length overflow"))?;
    let mut aad = Vec::with_capacity(capacity);
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.push(algorithm_id);
    aad.extend_from_slice(stream_id);
    aad.extend_from_slice(base_nonce);
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.push(u8::from(final_frame));
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(&ciphertext_len.to_be_bytes());
    aad.extend_from_slice(&user_aad_len.to_be_bytes());
    aad.extend_from_slice(user_aad);
    Ok(aad)
}

/// AEAD stream writer for the authenticated v2 frame format.
pub struct FramedEncryptStream<W: Write, C: FramedAead> {
    writer: W,
    cipher: C,
    buffer: Zeroizing<Vec<u8>>,
    user_aad: Zeroizing<Vec<u8>>,
    sequence: u64,
    stream_id: [u8; STREAM_ID_SIZE],
    base_nonce: [u8; NONCE_SIZE],
    finalized: bool,
}

impl<W: Write, C: FramedAead> FramedEncryptStream<W, C> {
    /// Starts an authenticated stream using caller-owned randomness for its
    /// stream identifier and base nonce.
    pub fn new<Rng: CryptoRng + ?Sized>(
        mut writer: W,
        key: &C::Key,
        aad: Option<&[u8]>,
        rng: &mut Rng,
    ) -> Result<Self> {
        let user_aad = aad.unwrap_or(&[]);
        validate_stream_state(
            user_aad.len() <= USER_AAD_MAX,
            "stream AAD",
            "AAD exceeds the 1 MiB limit",
        )?;

        let cipher = C::from_key(key)?;
        let mut stream_id = [0u8; STREAM_ID_SIZE];
        fill_random(rng, &mut stream_id, "stream identifier generation")?;
        let mut base_nonce = [0u8; NONCE_SIZE];
        fill_random(rng, &mut base_nonce, "stream base nonce generation")?;

        writer.write_all(MAGIC).map_io_err()?;
        writer.write_all(&[VERSION]).map_io_err()?;
        writer.write_all(&[C::ALGORITHM_ID]).map_io_err()?;
        writer.write_all(&stream_id).map_io_err()?;
        writer.write_all(&base_nonce).map_io_err()?;

        Ok(Self {
            writer,
            cipher,
            buffer: Zeroizing::new(Vec::with_capacity(FRAME_PLAINTEXT_MAX)),
            user_aad: Zeroizing::new(user_aad.to_vec()),
            sequence: 0,
            stream_id,
            base_nonce,
            finalized: false,
        })
    }

    fn write_frame(&mut self, plaintext: &[u8], final_frame: bool) -> Result<()> {
        validate_stream_state(
            plaintext.len() <= FRAME_PLAINTEXT_MAX,
            "stream frame",
            "plaintext frame exceeds 16 KiB",
        )?;
        validate_stream_state(
            final_frame || !plaintext.is_empty(),
            "stream frame",
            "non-final frames must not be empty",
        )?;
        validate_stream_state(
            final_frame || self.sequence != u64::MAX,
            "stream counter",
            "sequence counter exhausted",
        )?;

        let plaintext_len = u32::try_from(plaintext.len())
            .map_err(|_| invalid("plaintext frame length does not fit u32"))?;
        let ciphertext_len = plaintext_len
            .checked_add(TAG_SIZE as u32)
            .ok_or_else(|| invalid("ciphertext frame length overflow"))?;
        let nonce = derive_nonce(&self.base_nonce, self.sequence);
        let aad = frame_aad(
            C::ALGORITHM_ID,
            &self.stream_id,
            &self.base_nonce,
            self.sequence,
            final_frame,
            plaintext_len,
            ciphertext_len,
            &self.user_aad,
        )?;
        let ciphertext = self.cipher.seal(&nonce, plaintext, &aad)?;
        validate_stream_state(
            ciphertext.len() == ciphertext_len as usize,
            "stream cipher",
            "AEAD returned an unexpected ciphertext length",
        )?;

        self.writer
            .write_all(&self.sequence.to_be_bytes())
            .map_io_err()?;
        self.writer
            .write_all(&[u8::from(final_frame)])
            .map_io_err()?;
        self.writer
            .write_all(&plaintext_len.to_be_bytes())
            .map_io_err()?;
        self.writer
            .write_all(&ciphertext_len.to_be_bytes())
            .map_io_err()?;
        self.writer.write_all(&ciphertext).map_io_err()?;

        if final_frame {
            self.finalized = true;
        } else {
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| invalid("sequence counter exhausted"))?;
        }
        Ok(())
    }

    fn flush_non_final(&mut self) -> Result<()> {
        let frame = core::mem::replace(
            &mut self.buffer,
            Zeroizing::new(Vec::with_capacity(FRAME_PLAINTEXT_MAX)),
        );
        self.write_frame(&frame, false)
    }
}

impl<W: Write, C: FramedAead> StreamingEncrypt<W> for FramedEncryptStream<W, C> {
    fn write(&mut self, mut data: &[u8]) -> Result<()> {
        validate_stream_state(!self.finalized, "stream write", "stream already finalized")?;

        while !data.is_empty() {
            let available = FRAME_PLAINTEXT_MAX - self.buffer.len();
            let take = available.min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buffer.len() == FRAME_PLAINTEXT_MAX {
                self.flush_non_final()?;
            }
        }
        Ok(())
    }

    fn finalize(mut self) -> Result<W> {
        validate_stream_state(
            !self.finalized,
            "stream finalize",
            "stream already finalized",
        )?;
        let final_plaintext = core::mem::replace(&mut self.buffer, Zeroizing::new(Vec::new()));
        self.write_frame(&final_plaintext, true)?;
        self.writer.flush().map_io_err()?;
        Ok(self.writer)
    }
}

/// AEAD stream reader for the authenticated v2 frame format.
pub struct FramedDecryptStream<R: Read, C: FramedAead> {
    reader: R,
    cipher: C,
    user_aad: Zeroizing<Vec<u8>>,
    expected_sequence: u64,
    stream_id: [u8; STREAM_ID_SIZE],
    base_nonce: [u8; NONCE_SIZE],
    pending: Zeroizing<Vec<u8>>,
    pending_offset: usize,
    final_seen: bool,
    finished: bool,
}

impl<R: Read, C: FramedAead> FramedDecryptStream<R, C> {
    /// Parse a version-2 stream header and prepare to authenticate frames.
    pub fn new(mut reader: R, key: &C::Key, aad: Option<&[u8]>) -> Result<Self> {
        let user_aad = aad.unwrap_or(&[]);
        validate_stream_state(
            user_aad.len() <= USER_AAD_MAX,
            "stream AAD",
            "AAD exceeds the 1 MiB limit",
        )?;

        let mut header = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header).map_io_err()?;
        validate_stream_state(
            &header[..MAGIC.len()] == MAGIC,
            "stream header",
            "unsupported legacy or malformed stream format",
        )?;
        validate_stream_state(
            header[8] == VERSION,
            "stream header",
            "unsupported stream version",
        )?;
        validate_stream_state(
            header[9] == C::ALGORITHM_ID,
            "stream header",
            "stream algorithm does not match decryptor",
        )?;

        let mut stream_id = [0u8; STREAM_ID_SIZE];
        stream_id.copy_from_slice(&header[10..10 + STREAM_ID_SIZE]);
        let mut base_nonce = [0u8; NONCE_SIZE];
        base_nonce.copy_from_slice(&header[10 + STREAM_ID_SIZE..]);

        Ok(Self {
            reader,
            cipher: C::from_key(key)?,
            user_aad: Zeroizing::new(user_aad.to_vec()),
            expected_sequence: 0,
            stream_id,
            base_nonce,
            pending: Zeroizing::new(Vec::new()),
            pending_offset: 0,
            final_seen: false,
            finished: false,
        })
    }

    fn load_frame(&mut self) -> Result<()> {
        validate_stream_state(
            !self.final_seen,
            "stream frame",
            "data appeared after the final frame",
        )?;

        let mut frame_header = [0u8; FRAME_HEADER_SIZE];
        self.reader.read_exact(&mut frame_header).map_io_err()?;
        let sequence = u64::from_be_bytes(frame_header[..8].try_into().expect("fixed slice"));
        let flags = frame_header[8];
        let plaintext_len =
            u32::from_be_bytes(frame_header[9..13].try_into().expect("fixed slice"));
        let ciphertext_len =
            u32::from_be_bytes(frame_header[13..17].try_into().expect("fixed slice"));

        validate_stream_state(
            sequence == self.expected_sequence,
            "stream sequence",
            "frame replay, omission, or reordering detected",
        )?;
        validate_stream_state(flags <= 1, "stream frame", "unknown frame flags")?;
        let final_frame = flags == 1;
        validate_stream_state(
            final_frame || plaintext_len != 0,
            "stream frame",
            "non-final frames must not be empty",
        )?;
        validate_stream_state(
            plaintext_len as usize <= FRAME_PLAINTEXT_MAX,
            "stream frame",
            "plaintext frame length exceeds 16 KiB",
        )?;
        validate_stream_state(
            ciphertext_len == plaintext_len + TAG_SIZE as u32,
            "stream frame",
            "inconsistent frame lengths",
        )?;
        validate_stream_state(
            ciphertext_len as usize <= FRAME_PLAINTEXT_MAX + TAG_SIZE,
            "stream frame",
            "ciphertext frame length exceeds the allocation limit",
        )?;
        validate_stream_state(
            final_frame || sequence != u64::MAX,
            "stream counter",
            "sequence counter exhausted",
        )?;

        // Allocation occurs only after every transmitted length is bounded and
        // cross-checked against the fixed AEAD tag size.
        let mut ciphertext = Zeroizing::new(vec![0u8; ciphertext_len as usize]);
        self.reader.read_exact(&mut ciphertext).map_io_err()?;
        let nonce = derive_nonce(&self.base_nonce, sequence);
        let aad = frame_aad(
            C::ALGORITHM_ID,
            &self.stream_id,
            &self.base_nonce,
            sequence,
            final_frame,
            plaintext_len,
            ciphertext_len,
            &self.user_aad,
        )?;
        let plaintext = self.cipher.open(&nonce, &ciphertext, &aad)?;
        validate_stream_state(
            plaintext.len() == plaintext_len as usize,
            "stream cipher",
            "AEAD returned an unexpected plaintext length",
        )?;

        self.pending = Zeroizing::new(plaintext);
        self.pending_offset = 0;
        self.final_seen = final_frame;
        if !final_frame {
            self.expected_sequence = self
                .expected_sequence
                .checked_add(1)
                .ok_or_else(|| invalid("sequence counter exhausted"))?;
        }
        Ok(())
    }

    fn copy_pending(&mut self, output: &mut [u8]) -> usize {
        let remaining = &self.pending[self.pending_offset..];
        let take = remaining.len().min(output.len());
        output[..take].copy_from_slice(&remaining[..take]);
        self.pending_offset += take;
        if self.pending_offset == self.pending.len() {
            self.pending.zeroize();
            self.pending.clear();
            self.pending_offset = 0;
        }
        take
    }

    fn finish_at_physical_eof(&mut self) -> Result<usize> {
        let mut trailing = [0u8; 1];
        loop {
            match self.reader.read(&mut trailing) {
                Ok(0) => {
                    self.finished = true;
                    return Ok(0);
                }
                Ok(_) => return Err(invalid("trailing data after authenticated final frame")),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(crate::error::from_io_error(error)),
            }
        }
    }
}

impl<R: Read, C: FramedAead> StreamingDecrypt<R> for FramedDecryptStream<R, C> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() || self.finished {
            return Ok(0);
        }

        if self.pending_offset < self.pending.len() {
            return Ok(self.copy_pending(output));
        }
        if self.final_seen {
            return self.finish_at_physical_eof();
        }

        self.load_frame()?;
        if self.pending.is_empty() && self.final_seen {
            return self.finish_at_physical_eof();
        }
        Ok(self.copy_pending(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::keys::Aes128Key;
    use dcrypt_internal::{random::Error as RandomError, ChaCha20Rng, RngCore};

    struct FailSecondFill {
        calls: usize,
    }

    impl RngCore for FailSecondFill {
        fn try_fill_bytes(
            &mut self,
            destination: &mut [u8],
        ) -> core::result::Result<(), RandomError> {
            self.calls += 1;
            destination.fill(0x7f);
            if self.calls == 2 {
                Err(RandomError)
            } else {
                Ok(())
            }
        }
    }

    impl CryptoRng for FailSecondFill {}

    #[test]
    fn sequence_exhaustion_is_rejected_before_nonce_reuse() {
        let key = Aes128Key::new([0x42; 16]);
        let mut rng = ChaCha20Rng::from_seed([0x33; 32]);
        let mut stream =
            FramedEncryptStream::<Vec<u8>, Aes128Gcm>::new(Vec::new(), &key, None, &mut rng)
                .unwrap();
        stream.sequence = u64::MAX;

        let frame = vec![0x5a; FRAME_PLAINTEXT_MAX];
        assert!(StreamingEncrypt::write(&mut stream, &frame).is_err());
        assert_eq!(stream.sequence, u64::MAX);
    }

    #[test]
    fn stream_header_is_not_written_when_randomness_fails() {
        let key = Aes128Key::new([0x42; 16]);
        let mut output = Vec::new();
        let mut rng = FailSecondFill { calls: 0 };
        let result =
            FramedEncryptStream::<&mut Vec<u8>, Aes128Gcm>::new(&mut output, &key, None, &mut rng);
        assert!(matches!(
            result,
            Err(crate::Error::RandomGenerationError { .. })
        ));
        assert!(output.is_empty());
    }
}
