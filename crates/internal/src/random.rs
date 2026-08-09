//! Caller-supplied randomness traits.
//!
//! dcrypt intentionally provides no operating-system RNG. Applications choose
//! and own their entropy source and pass it into every randomized operation.

use core::fmt;

use crate::zeroing::{Zeroize, ZeroizeOnDrop};

/// An error returned by a fallible caller-provided randomness source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("caller-provided randomness source failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// The byte-oriented randomness interface used by dcrypt.
pub trait RngCore {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = crate::zeroing::Zeroizing::new([0u8; 4]);
        self.fill_bytes(&mut bytes[..]);
        u32::from(bytes[0])
            | (u32::from(bytes[1]) << 8)
            | (u32::from(bytes[2]) << 16)
            | (u32::from(bytes[3]) << 24)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = crate::zeroing::Zeroizing::new([0u8; 8]);
        self.fill_bytes(&mut bytes[..]);
        let mut value = crate::zeroing::Zeroizing::new(0u64);
        for (index, byte) in bytes.iter().enumerate() {
            *value |= u64::from(*byte) << (index * 8);
        }
        *value
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        try_fill_bytes_zeroing_on_error(self, destination)
            .expect("caller-provided randomness source failed")
    }

    /// Fill `destination`, propagating failures from the caller's entropy
    /// source rather than silently substituting weak randomness.
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error>;
}

impl<R: RngCore + ?Sized> RngCore for &mut R {
    fn next_u32(&mut self) -> u32 {
        (**self).next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        (**self).next_u64()
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        try_fill_bytes_zeroing_on_error(&mut **self, destination)
            .expect("caller-provided randomness source failed")
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        (**self).try_fill_bytes(destination)
    }
}

/// Fill a destination and clear it completely if the RNG reports failure.
///
/// `RngCore` implementations are caller supplied and may write only part of a
/// destination before returning an error. Secret constructors use this helper
/// so those partial bytes never remain live on an error path.
pub fn try_fill_bytes_zeroing_on_error<R: RngCore + ?Sized>(
    rng: &mut R,
    destination: &mut [u8],
) -> Result<(), Error> {
    let result = rng.try_fill_bytes(destination);
    if result.is_err() {
        destination.zeroize();
    }
    result
}

/// Marker for generators suitable for cryptographic use.
pub trait CryptoRng: RngCore {}

impl<R: CryptoRng + ?Sized> CryptoRng for &mut R {}

/// A deterministic ChaCha20 generator seeded entirely by its caller.
///
/// This type never obtains operating-system entropy. A caller that uses it for
/// cryptography must provide a fresh, unpredictable 32-byte seed and must not
/// reuse that seed across independent generator instances.
#[derive(Clone)]
pub struct ChaCha20Rng {
    key: [u32; 8],
    counter: u32,
    buffer: [u8; 64],
    offset: usize,
    exhausted: bool,
}

impl ChaCha20Rng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = crate::zeroing::Zeroizing::new(seed);
        let mut generator = Self {
            key: [0u32; 8],
            counter: 0,
            buffer: [0u8; 64],
            offset: 64,
            exhausted: false,
        };
        for index in 0..8 {
            let offset = index * 4;
            generator.key[index] = u32::from(seed[offset])
                | (u32::from(seed[offset + 1]) << 8)
                | (u32::from(seed[offset + 2]) << 16)
                | (u32::from(seed[offset + 3]) << 24);
        }
        generator
    }

    fn refill(&mut self) -> Result<(), Error> {
        if self.exhausted {
            return Err(Error);
        }
        chacha20_block(&self.key, self.counter, &mut self.buffer);
        self.offset = 0;
        if self.counter == u32::MAX {
            self.exhausted = true;
        } else {
            self.counter += 1;
        }
        Ok(())
    }
}

impl RngCore for ChaCha20Rng {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
        let mut written = 0;
        while written < destination.len() {
            if self.offset == self.buffer.len() && self.refill().is_err() {
                destination.zeroize();
                return Err(Error);
            }
            let available = self.buffer.len() - self.offset;
            let take = core::cmp::min(available, destination.len() - written);
            destination[written..written + take]
                .copy_from_slice(&self.buffer[self.offset..self.offset + take]);
            self.offset += take;
            written += take;
        }
        Ok(())
    }
}

impl CryptoRng for ChaCha20Rng {}

impl Zeroize for ChaCha20Rng {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.counter.zeroize();
        self.buffer.zeroize();
        self.offset.zeroize();
        self.exhausted.zeroize();
    }
}

impl Drop for ChaCha20Rng {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ChaCha20Rng {}

#[inline(always)]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u32; 8], counter: u32, output: &mut [u8; 64]) {
    let initial = crate::zeroing::Zeroizing::new([
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        counter,
        0,
        0,
        0,
    ]);
    let mut state = crate::zeroing::Zeroizing::new(*initial);
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    for index in 0..16 {
        let word = crate::zeroing::Zeroizing::new(state[index].wrapping_add(initial[index]));
        for byte in 0..4 {
            output[index * 4 + byte] = (*word >> (byte * 8)) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{chacha20_block, try_fill_bytes_zeroing_on_error, ChaCha20Rng, Error, RngCore};
    use crate::zeroing::Zeroize;

    struct PartiallyFailingRng;

    impl RngCore for PartiallyFailingRng {
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Error> {
            let written = core::cmp::min(3, destination.len());
            destination[..written].fill(0xA5);
            Err(Error)
        }
    }

    #[test]
    fn defensive_fill_erases_partial_rng_output_on_error() {
        let mut rng = PartiallyFailingRng;
        let mut destination = crate::zeroing::Zeroizing::new([0xCC; 8]);
        assert!(try_fill_bytes_zeroing_on_error(&mut rng, &mut destination[..]).is_err());
        assert_eq!(*destination, [0; 8]);
    }

    #[test]
    fn chacha_rng_erases_partial_output_when_counter_exhausts() {
        let mut rng = ChaCha20Rng::from_seed([9; 32]);
        rng.counter = u32::MAX;
        rng.offset = rng.buffer.len();

        let mut destination = crate::zeroing::Zeroizing::new([0xCC; 65]);
        assert!(rng.try_fill_bytes(&mut destination[..]).is_err());
        assert_eq!(*destination, [0; 65]);
    }

    #[test]
    fn zero_key_zero_nonce_block_matches_rfc_8439_primitive() {
        let expected = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        let mut actual = crate::zeroing::Zeroizing::new([0u8; 64]);
        chacha20_block(&[0u32; 8], 0, &mut actual);
        assert_eq!(*actual, expected);
    }

    #[test]
    fn chunking_does_not_change_the_stream() {
        let seed = crate::zeroing::Zeroizing::new([0x42; 32]);
        let mut whole = ChaCha20Rng::from_seed(*seed);
        let mut chunked = ChaCha20Rng::from_seed(*seed);
        let mut left = crate::zeroing::Zeroizing::new([0u8; 137]);
        let mut right = crate::zeroing::Zeroizing::new([0u8; 137]);
        whole.fill_bytes(&mut left[..]);
        chunked.fill_bytes(&mut right[..3]);
        chunked.fill_bytes(&mut right[3..91]);
        chunked.fill_bytes(&mut right[91..]);
        assert_eq!(*left, *right);
    }

    #[test]
    fn explicit_zeroize_clears_generator_state() {
        let mut generator = ChaCha20Rng::from_seed([0x42; 32]);
        let mut output = crate::zeroing::Zeroizing::new([0u8; 8]);
        generator.fill_bytes(&mut output[..]);
        generator.zeroize();
        assert_eq!(generator.key, [0; 8]);
        assert_eq!(generator.counter, 0);
        assert_eq!(generator.buffer, [0; 64]);
        assert_eq!(generator.offset, 0);
        assert!(!generator.exhausted);
    }
}
