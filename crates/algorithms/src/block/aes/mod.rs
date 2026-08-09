//! AES block cipher implementations
//!
//! This module implements the Advanced Encryption Standard (AES) block cipher
//! as specified in FIPS 197.
//!
//! ## Constant-Time Guarantees
//!
//! This implementation mitigates timing side-channel attacks by:
//! - Using branchless arithmetic for GF(2^8) operations
//! - Using bitsliced S-box implementations instead of table lookups
//! - Ensuring consistent memory access patterns
//! - Validating keys before use to prevent silent failure
//!
//! Note: On platforms where AES hardware acceleration is available, consider using
//! hardware instructions for better side-channel resistance.

use super::BlockCipher;
use super::CipherAlgorithm;
use crate::error::{validate, Result};
use crate::types::SecretBytes;
use core::sync::atomic::{compiler_fence, Ordering};
use dcrypt_common::security::SecretBuffer;
use dcrypt_internal::random::{try_fill_bytes_zeroing_on_error, CryptoRng, RngCore};
use dcrypt_internal::zeroing::{Zeroize, ZeroizeOnDrop, Zeroizing};
use dcrypt_params::utils::symmetric::{
    AES128_KEY_SIZE, AES192_KEY_SIZE, AES256_KEY_SIZE, AES_BLOCK_SIZE,
};

/// Round constants for AES key expansion
const RCON: [u32; 11] = [
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
    0x80000000, 0x1b000000, 0x36000000,
];

/// Multiply two bytes in GF(2⁸) with AES's reduction poly x⁸ + x⁴ + x³ + x + 1
#[inline(always)]
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        // mask = 0xFF if b&1==1 else 0x00
        let mask = (b & 1).wrapping_neg();
        p ^= a & mask;
        let hi = a & 0x80;
        a <<= 1;
        // if hi was set, reduce by 0x1B
        a ^= ((hi != 0) as u8) * 0x1B;
        b >>= 1;
    }
    p
}

/// Raise to the 254th power (b⁻¹ in GF(2⁸)) in constant time
#[inline(always)]
fn gf_inv(x: u8) -> u8 {
    // always do the full exponentiation, even for x==0
    let x2 = gf_mul(x, x);
    let x4 = gf_mul(x2, x2);
    let x8 = gf_mul(x4, x4);
    let x16 = gf_mul(x8, x8);
    let x32 = gf_mul(x16, x16);
    let x64 = gf_mul(x32, x32);
    let x128 = gf_mul(x64, x64);
    // now multiply together x128·x64·x32·x16·x8·x4·x2
    let mut y = gf_mul(x128, x64);
    y = gf_mul(y, x32);
    y = gf_mul(y, x16);
    y = gf_mul(y, x8);
    y = gf_mul(y, x4);
    y = gf_mul(y, x2);

    // now mask to zero if original x was zero
    // mask = 0xFF if x!=0, else 0x00
    let mask = ((x != 0) as u8).wrapping_neg();
    y & mask
}

/// AES forward S-box: inv(x) ⊕ ROTL(inv(x),1–4) ⊕ 0x63
#[inline(always)]
fn bitsliced_sbox(x: u8) -> u8 {
    let i = gf_inv(x);
    i ^ i.rotate_left(1) ^ i.rotate_left(2) ^ i.rotate_left(3) ^ i.rotate_left(4) ^ 0x63
}

/// AES inverse S-box: undo affine then invert
#[inline(always)]
fn bitsliced_inv_sbox(x: u8) -> u8 {
    // undo affine: y = A(i)⊕0x63  ⇒  i = A⁻¹(y)
    let y = x ^ 0x63;
    // A⁻¹ is convolution by t¹ + t³ + t⁶ mod (t⁸+1)
    let u = y.rotate_left(1) ^ y.rotate_left(3) ^ y.rotate_left(6);
    gf_inv(u)
}

/// Converts 4 bytes to a u32 in big-endian order
#[inline(always)]
fn bytes_to_u32(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 24)
        | ((bytes[1] as u32) << 16)
        | ((bytes[2] as u32) << 8)
        | (bytes[3] as u32)
}

/// Converts a u32 to 4 bytes in big-endian order
#[inline(always)]
fn u32_to_bytes(word: u32) -> [u8; 4] {
    [
        (word >> 24) as u8,
        (word >> 16) as u8,
        (word >> 8) as u8,
        word as u8,
    ]
}

/// Rotates a word left by 8 bits (1 byte)
#[inline(always)]
fn rotate_word(word: u32) -> u32 {
    word.rotate_left(8)
}

/// Substitutes each byte in a word using the AES S-box, with bitsliced implementation
#[inline(always)]
fn sub_word(word: u32) -> u32 {
    let bytes = u32_to_bytes(word);
    let sub_bytes = [
        bitsliced_sbox(bytes[0]),
        bitsliced_sbox(bytes[1]),
        bitsliced_sbox(bytes[2]),
        bitsliced_sbox(bytes[3]),
    ];
    bytes_to_u32(&sub_bytes)
}

/// Type-level constants for AES-128
pub enum Aes128Algorithm {}

impl CipherAlgorithm for Aes128Algorithm {
    const KEY_SIZE: usize = AES128_KEY_SIZE;
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;

    fn name() -> &'static str {
        "AES-128"
    }
}

/// Type-level constants for AES-192
pub enum Aes192Algorithm {}

impl CipherAlgorithm for Aes192Algorithm {
    const KEY_SIZE: usize = AES192_KEY_SIZE;
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;

    fn name() -> &'static str {
        "AES-192"
    }
}

/// Type-level constants for AES-256
pub enum Aes256Algorithm {}

impl CipherAlgorithm for Aes256Algorithm {
    const KEY_SIZE: usize = AES256_KEY_SIZE;
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;

    fn name() -> &'static str {
        "AES-256"
    }
}

/// AES-128 block cipher
#[derive(Clone)]
pub struct Aes128 {
    round_keys: SecretBuffer<176>, // 11 rounds × 16 bytes
}

/// AES-192 block cipher
#[derive(Clone)]
pub struct Aes192 {
    round_keys: SecretBuffer<208>, // 13 rounds × 16 bytes
}

/// AES-256 block cipher
#[derive(Clone)]
pub struct Aes256 {
    round_keys: SecretBuffer<240>, // 15 rounds × 16 bytes
}

macro_rules! impl_aes_zeroize {
    ($name:ident) => {
        impl Zeroize for $name {
            fn zeroize(&mut self) {
                self.round_keys.zeroize();
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }

        impl ZeroizeOnDrop for $name {}
    };
}

impl_aes_zeroize!(Aes128);
impl_aes_zeroize!(Aes192);
impl_aes_zeroize!(Aes256);

// Add CipherAlgorithm implementations for AES structs
impl CipherAlgorithm for Aes128 {
    const KEY_SIZE: usize = AES128_KEY_SIZE;
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;

    fn name() -> &'static str {
        "AES-128"
    }
}

impl CipherAlgorithm for Aes192 {
    const KEY_SIZE: usize = AES192_KEY_SIZE;
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;

    fn name() -> &'static str {
        "AES-192"
    }
}

impl CipherAlgorithm for Aes256 {
    const KEY_SIZE: usize = AES256_KEY_SIZE;
    const BLOCK_SIZE: usize = AES_BLOCK_SIZE;

    fn name() -> &'static str {
        "AES-256"
    }
}

impl Aes128 {
    /// Performs AES-128 key expansion
    fn expand_key(key: &[u8]) -> Result<SecretBuffer<176>> {
        validate::length("AES-128 key", key.len(), AES128_KEY_SIZE)?;

        let mut round_keys_u32 = [0u32; 44];

        // Initial key schedule
        for i in 0..4 {
            round_keys_u32[i] = bytes_to_u32(&key[i * 4..(i + 1) * 4]);
        }

        // Key expansion
        for i in 4..44 {
            let mut temp = round_keys_u32[i - 1];
            if i % 4 == 0 {
                temp = sub_word(rotate_word(temp)) ^ RCON[i / 4];
            }
            round_keys_u32[i] = round_keys_u32[i - 4] ^ temp;
        }

        // Convert to bytes
        let mut round_key_bytes = [0u8; 176];
        for i in 0..44 {
            let bytes = u32_to_bytes(round_keys_u32[i]);
            round_key_bytes[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        Ok(SecretBuffer::new(round_key_bytes))
    }

    /// SubBytes step with bitsliced implementation
    fn sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = bitsliced_sbox(*byte);
        }
        // ensure no reordering around our bit-ops
        compiler_fence(Ordering::SeqCst);
    }

    /// ShiftRows step
    fn shift_rows(state: &mut [u8; 16]) {
        let mut temp = [0u8; 16];
        temp.copy_from_slice(state);
        state[0] = temp[0];
        state[4] = temp[4];
        state[8] = temp[8];
        state[12] = temp[12];
        state[1] = temp[5];
        state[5] = temp[9];
        state[9] = temp[13];
        state[13] = temp[1];
        state[2] = temp[10];
        state[6] = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];
        state[3] = temp[15];
        state[7] = temp[3];
        state[11] = temp[7];
        state[15] = temp[11];
    }

    /// Multiply by 2 in GF(2^8)
    #[inline(always)]
    fn mul2(byte: u8) -> u8 {
        let high = byte >> 7;
        (byte << 1) ^ (high * 0x1B)
    }

    /// MixColumns step
    fn mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let i = c * 4;
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];
            state[i] = Self::mul2(s0) ^ Self::mul2(s1) ^ s1 ^ s2 ^ s3;
            state[i + 1] = s0 ^ Self::mul2(s1) ^ Self::mul2(s2) ^ s2 ^ s3;
            state[i + 2] = s0 ^ s1 ^ Self::mul2(s2) ^ Self::mul2(s3) ^ s3;
            state[i + 3] = Self::mul2(s0) ^ s0 ^ s1 ^ s2 ^ Self::mul2(s3);
        }
    }

    /// AddRoundKey step using precomputed bytes for constant-time behavior
    fn add_round_key(state: &mut [u8; 16], round_key_bytes: &[u8]) -> Result<()> {
        // Use validation utility for length check
        validate::min_length("AES round key", round_key_bytes.len(), 16)?;

        for i in 0..16 {
            state[i] ^= round_key_bytes[i];
        }
        Ok(())
    }

    /// Inverse SubBytes with bitsliced implementation
    fn inv_sub_bytes(state: &mut [u8; 16]) {
        for byte in state.iter_mut() {
            *byte = bitsliced_inv_sbox(*byte);
        }
        compiler_fence(Ordering::SeqCst);
    }

    /// Inverse ShiftRows
    fn inv_shift_rows(state: &mut [u8; 16]) {
        let mut temp = [0u8; 16];
        temp.copy_from_slice(state);
        state[0] = temp[0];
        state[4] = temp[4];
        state[8] = temp[8];
        state[12] = temp[12];
        state[1] = temp[13];
        state[5] = temp[1];
        state[9] = temp[5];
        state[13] = temp[9];
        state[2] = temp[10];
        state[6] = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];
        state[3] = temp[7];
        state[7] = temp[11];
        state[11] = temp[15];
        state[15] = temp[3];
    }

    /// GF(2^8) multiplies for InvMixColumns
    #[inline(always)]
    fn mul14(byte: u8) -> u8 {
        Self::mul2(Self::mul2(Self::mul2(byte))) ^ Self::mul2(Self::mul2(byte)) ^ Self::mul2(byte)
    }
    #[inline(always)]
    fn mul13(byte: u8) -> u8 {
        Self::mul2(Self::mul2(Self::mul2(byte))) ^ Self::mul2(Self::mul2(byte)) ^ byte
    }
    #[inline(always)]
    fn mul11(byte: u8) -> u8 {
        Self::mul2(Self::mul2(Self::mul2(byte))) ^ Self::mul2(byte) ^ byte
    }
    #[inline(always)]
    fn mul9(byte: u8) -> u8 {
        Self::mul2(Self::mul2(Self::mul2(byte))) ^ byte
    }

    /// Inverse MixColumns
    fn inv_mix_columns(state: &mut [u8; 16]) {
        for c in 0..4 {
            let i = c * 4;
            let s0 = state[i];
            let s1 = state[i + 1];
            let s2 = state[i + 2];
            let s3 = state[i + 3];
            state[i] = Self::mul14(s0) ^ Self::mul11(s1) ^ Self::mul13(s2) ^ Self::mul9(s3);
            state[i + 1] = Self::mul9(s0) ^ Self::mul14(s1) ^ Self::mul11(s2) ^ Self::mul13(s3);
            state[i + 2] = Self::mul13(s0) ^ Self::mul9(s1) ^ Self::mul14(s2) ^ Self::mul11(s3);
            state[i + 3] = Self::mul11(s0) ^ Self::mul13(s1) ^ Self::mul9(s2) ^ Self::mul14(s3);
        }
    }
}

impl BlockCipher for Aes128 {
    type Algorithm = Aes128Algorithm;
    type Key = SecretBytes<16>;

    fn new(key: &Self::Key) -> Self {
        let round_keys =
            Self::expand_key(key.as_ref()).expect("AES-128 key expansion should not fail");

        Aes128 { round_keys }
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        // Use validation utility for length check
        validate::length("AES block", block.len(), AES_BLOCK_SIZE)?;

        // Access round keys through SecretBuffer
        let round_key_bytes = self.round_keys.as_ref();

        // Warm the cache by touching all round key bytes
        let mut _warm: u8 = 0;
        for &b in round_key_bytes {
            _warm = _warm.wrapping_add(b);
        }
        compiler_fence(Ordering::SeqCst);

        // Copy block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        // Initial round - AddRoundKey
        Self::add_round_key(&mut state, &round_key_bytes[0..16])?;

        // Main rounds
        for round in 1..10 {
            Self::sub_bytes(&mut state);
            Self::shift_rows(&mut state);
            Self::mix_columns(&mut state);

            let offset = round * 16;
            Self::add_round_key(&mut state, &round_key_bytes[offset..offset + 16])?;
        }

        // Final round
        Self::sub_bytes(&mut state);
        Self::shift_rows(&mut state);
        Self::add_round_key(&mut state, &round_key_bytes[160..176])?;

        // Copy state back to block
        block.copy_from_slice(&state);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        // Use validation utility for length check
        validate::length("AES block", block.len(), AES_BLOCK_SIZE)?;

        // Access round keys through SecretBuffer
        let round_key_bytes = self.round_keys.as_ref();

        // Warm the cache by touching all round key bytes
        let mut _warm: u8 = 0;
        for &b in round_key_bytes {
            _warm = _warm.wrapping_add(b);
        }
        compiler_fence(Ordering::SeqCst);

        // Copy block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        // Initial round - AddRoundKey (final round key)
        Self::add_round_key(&mut state, &round_key_bytes[160..176])?;

        // Main rounds in reverse
        for round in (1..10).rev() {
            Self::inv_shift_rows(&mut state);
            Self::inv_sub_bytes(&mut state);

            let offset = round * 16;
            Self::add_round_key(&mut state, &round_key_bytes[offset..offset + 16])?;
            Self::inv_mix_columns(&mut state);
        }

        // Final round
        Self::inv_shift_rows(&mut state);
        Self::inv_sub_bytes(&mut state);
        Self::add_round_key(&mut state, &round_key_bytes[0..16])?;

        // Copy state back to block
        block.copy_from_slice(&state);
        Ok(())
    }

    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key> {
        let mut key_data = Zeroizing::new([0u8; AES128_KEY_SIZE]);
        try_fill_bytes_zeroing_on_error(rng, &mut key_data[..])?;
        Ok(SecretBytes::new(*key_data))
    }
}

// AES-192 implementation

impl Aes192 {
    /// Performs AES-192 key expansion
    fn expand_key(key: &[u8]) -> Result<SecretBuffer<208>> {
        validate::length("AES-192 key", key.len(), AES192_KEY_SIZE)?;

        let mut round_keys_u32 = [0u32; 52];

        // Initial key schedule
        for i in 0..6 {
            round_keys_u32[i] = bytes_to_u32(&key[i * 4..(i + 1) * 4]);
        }

        // Key expansion
        for i in 6..52 {
            let mut temp = round_keys_u32[i - 1];
            if i % 6 == 0 {
                temp = sub_word(rotate_word(temp)) ^ RCON[i / 6];
            }
            round_keys_u32[i] = round_keys_u32[i - 6] ^ temp;
        }

        // Convert to bytes
        let mut round_key_bytes = [0u8; 208];
        for i in 0..52 {
            let bytes = u32_to_bytes(round_keys_u32[i]);
            round_key_bytes[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        Ok(SecretBuffer::new(round_key_bytes))
    }
}

impl BlockCipher for Aes192 {
    type Algorithm = Aes192Algorithm;
    type Key = SecretBytes<24>;

    fn new(key: &Self::Key) -> Self {
        let round_keys =
            Self::expand_key(key.as_ref()).expect("AES-192 key expansion should not fail");

        Aes192 { round_keys }
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        // Use validation utility for length check
        validate::length("AES block", block.len(), AES_BLOCK_SIZE)?;

        // Access round keys through SecretBuffer
        let round_key_bytes = self.round_keys.as_ref();

        // Warm the cache by touching all round key bytes
        let mut _warm: u8 = 0;
        for &b in round_key_bytes {
            _warm = _warm.wrapping_add(b);
        }
        compiler_fence(Ordering::SeqCst);

        // Copy block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        // Initial round - AddRoundKey
        Aes128::add_round_key(&mut state, &round_key_bytes[0..16])?;

        // Main rounds
        for round in 1..12 {
            Aes128::sub_bytes(&mut state);
            Aes128::shift_rows(&mut state);
            Aes128::mix_columns(&mut state);

            let offset = round * 16;
            Aes128::add_round_key(&mut state, &round_key_bytes[offset..offset + 16])?;
        }

        // Final round
        Aes128::sub_bytes(&mut state);
        Aes128::shift_rows(&mut state);
        Aes128::add_round_key(&mut state, &round_key_bytes[192..208])?;

        // Copy state back to block
        block.copy_from_slice(&state);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        // Use validation utility for length check
        validate::length("AES block", block.len(), AES_BLOCK_SIZE)?;

        // Access round keys through SecretBuffer
        let round_key_bytes = self.round_keys.as_ref();

        // Warm the cache by touching all round key bytes
        let mut _warm: u8 = 0;
        for &b in round_key_bytes {
            _warm = _warm.wrapping_add(b);
        }
        compiler_fence(Ordering::SeqCst);

        // Copy block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        // Initial round - AddRoundKey (final round key)
        Aes128::add_round_key(&mut state, &round_key_bytes[192..208])?;

        // Main rounds in reverse
        for round in (1..12).rev() {
            Aes128::inv_shift_rows(&mut state);
            Aes128::inv_sub_bytes(&mut state);

            let offset = round * 16;
            Aes128::add_round_key(&mut state, &round_key_bytes[offset..offset + 16])?;
            Aes128::inv_mix_columns(&mut state);
        }

        // Final round
        Aes128::inv_shift_rows(&mut state);
        Aes128::inv_sub_bytes(&mut state);
        Aes128::add_round_key(&mut state, &round_key_bytes[0..16])?;

        // Copy state back to block
        block.copy_from_slice(&state);
        Ok(())
    }

    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key> {
        let mut key_data = Zeroizing::new([0u8; AES192_KEY_SIZE]);
        try_fill_bytes_zeroing_on_error(rng, &mut key_data[..])?;
        Ok(SecretBytes::new(*key_data))
    }
}

// AES-256 implementation

impl Aes256 {
    /// Performs AES-256 key expansion
    fn expand_key(key: &[u8]) -> Result<SecretBuffer<240>> {
        validate::length("AES-256 key", key.len(), AES256_KEY_SIZE)?;

        let mut round_keys_u32 = [0u32; 60];

        // Initial key schedule
        for i in 0..8 {
            round_keys_u32[i] = bytes_to_u32(&key[i * 4..(i + 1) * 4]);
        }

        // Key expansion
        for i in 8..60 {
            let mut temp = round_keys_u32[i - 1];
            if i % 8 == 0 {
                temp = sub_word(rotate_word(temp)) ^ RCON[i / 8];
            } else if i % 8 == 4 {
                temp = sub_word(temp);
            }
            round_keys_u32[i] = round_keys_u32[i - 8] ^ temp;
        }

        // Convert to bytes
        let mut round_key_bytes = [0u8; 240];
        for i in 0..60 {
            let bytes = u32_to_bytes(round_keys_u32[i]);
            round_key_bytes[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }

        Ok(SecretBuffer::new(round_key_bytes))
    }
}

impl BlockCipher for Aes256 {
    type Algorithm = Aes256Algorithm;
    type Key = SecretBytes<32>;

    fn new(key: &Self::Key) -> Self {
        let round_keys =
            Self::expand_key(key.as_ref()).expect("AES-256 key expansion should not fail");

        Aes256 { round_keys }
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        // Use validation utility for length check
        validate::length("AES block", block.len(), AES_BLOCK_SIZE)?;

        // Access round keys through SecretBuffer
        let round_key_bytes = self.round_keys.as_ref();

        // Warm the cache by touching all round key bytes
        let mut _warm: u8 = 0;
        for &b in round_key_bytes {
            _warm = _warm.wrapping_add(b);
        }
        compiler_fence(Ordering::SeqCst);

        // Copy block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        // Initial round - AddRoundKey
        Aes128::add_round_key(&mut state, &round_key_bytes[0..16])?;

        // Main rounds
        for round in 1..14 {
            Aes128::sub_bytes(&mut state);
            Aes128::shift_rows(&mut state);
            Aes128::mix_columns(&mut state);

            let offset = round * 16;
            Aes128::add_round_key(&mut state, &round_key_bytes[offset..offset + 16])?;
        }

        // Final round
        Aes128::sub_bytes(&mut state);
        Aes128::shift_rows(&mut state);
        Aes128::add_round_key(&mut state, &round_key_bytes[224..240])?;

        // Copy state back to block
        block.copy_from_slice(&state);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        // Use validation utility for length check
        validate::length("AES block", block.len(), AES_BLOCK_SIZE)?;

        // Access round keys through SecretBuffer
        let round_key_bytes = self.round_keys.as_ref();

        // Warm the cache by touching all round key bytes
        let mut _warm: u8 = 0;
        for &b in round_key_bytes {
            _warm = _warm.wrapping_add(b);
        }
        compiler_fence(Ordering::SeqCst);

        // Copy block to state array
        let mut state = [0u8; 16];
        state.copy_from_slice(block);

        // Initial round - AddRoundKey (final round key)
        Aes128::add_round_key(&mut state, &round_key_bytes[224..240])?;

        // Main rounds in reverse
        for round in (1..14).rev() {
            Aes128::inv_shift_rows(&mut state);
            Aes128::inv_sub_bytes(&mut state);

            let offset = round * 16;
            Aes128::add_round_key(&mut state, &round_key_bytes[offset..offset + 16])?;
            Aes128::inv_mix_columns(&mut state);
        }

        // Final round
        Aes128::inv_shift_rows(&mut state);
        Aes128::inv_sub_bytes(&mut state);
        Aes128::add_round_key(&mut state, &round_key_bytes[0..16])?;

        // Copy state back to block
        block.copy_from_slice(&state);
        Ok(())
    }

    fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self::Key> {
        let mut key_data = Zeroizing::new([0u8; AES256_KEY_SIZE]);
        try_fill_bytes_zeroing_on_error(rng, &mut key_data[..])?;
        Ok(SecretBytes::new(*key_data))
    }
}

#[cfg(test)]
mod tests;
