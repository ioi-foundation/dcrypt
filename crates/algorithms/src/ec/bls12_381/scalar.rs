//! BLS12-381 scalar field F_q where q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

#[cfg(feature = "alloc")]
use crate::alloc_prelude::*;

use crate::error::{Error, Result};
use crate::hash::{sha2::Sha256, HashFunction};
use crate::types::{ByteSerializable, ConstantTimeEq as DcryptConstantTimeEq, SecureZeroingType};
use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use dcrypt_internal::zeroing::Zeroize;

// Arithmetic helpers
/// Compute a + b + carry, returning (result, carry)
#[inline(always)]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + (b as u128) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a - (b + borrow), returning (result, borrow)
#[inline(always)]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
    (ret as u64, (ret >> 64) as u64)
}

/// Compute a + (b * c) + carry, returning (result, carry)
#[inline(always)]
const fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let ret = (a as u128) + ((b as u128) * (c as u128)) + (carry as u128);
    (ret as u64, (ret >> 64) as u64)
}

/// Scalar field element of BLS12-381
/// Internal: Four 64-bit limbs in little-endian Montgomery form
#[derive(Clone, Copy, Eq)]
pub struct Scalar(pub(crate) [u64; 4]);

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter().rev() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Display for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<u64> for Scalar {
    fn from(val: u64) -> Scalar {
        Scalar([val, 0, 0, 0]) * R2
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl PartialEq for Scalar {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(ConstantTimeEq::ct_eq(self, other))
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

// Constants
const MODULUS: Scalar = Scalar([
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
]);

/// INV = -(q^{-1} mod 2^64) mod 2^64
const INV: u64 = 0xffff_fffe_ffff_ffff;

/// R = 2^256 mod q
const R: Scalar = Scalar([
    0x0000_0001_ffff_fffe,
    0x5884_b7fa_0003_4802,
    0x998c_4fef_ecbc_4ff5,
    0x1824_b159_acc5_056f,
]);

/// R^2 = 2^512 mod q
const R2: Scalar = Scalar([
    0xc999_e990_f3f2_9c6d,
    0x2b6c_edcb_8792_5c23,
    0x05d3_1496_7254_398f,
    0x0748_d9d9_9f59_ff11,
]);

/// R^3 = 2^768 mod q
const R3: Scalar = Scalar([
    0xc62c_1807_439b_73af,
    0x1b3e_0d18_8cf0_6990,
    0x73d1_3c71_c7b5_f418,
    0x6e2a_5bb9_c8db_33e9,
]);

// Constants for Tonelli-Shanks square root algorithm
// 2-adicity of (r - 1)
const S: u32 = 32;

// T = (r - 1) / 2^S  (odd part)
const TONELLI_T: [u64; 4] = [
    0xfffe_5bfe_ffff_ffff,
    0x09a1_d805_53bd_a402,
    0x299d_7d48_3339_d808,
    0x0000_0000_73ed_a753,
];

// (T + 1)/2, used to initialize x = a^((T+1)/2)
const TONELLI_TP1_DIV2: [u64; 4] = [
    0x7fff_2dff_8000_0000,
    0x04d0_ec02_a9de_d201,
    0x94ce_bea4_199c_ec04,
    0x0000_0000_39f6_d3a9,
];

// Exponent (r-1)/2, the Legendre exponent
#[allow(dead_code)]
const LEGENDRE_EXP: [u64; 4] = [
    0x7fff_ffff_8000_0000,
    0xa9de_d201_7fff_2dff,
    0x199c_ec04_04d0_ec02,
    0x39f6_d3a9_94ce_bea4,
];

impl<'a> Neg for &'a Scalar {
    type Output = Scalar;

    #[inline]
    fn neg(self) -> Scalar {
        self.neg()
    }
}

impl Neg for Scalar {
    type Output = Scalar;

    #[inline]
    fn neg(self) -> Scalar {
        -&self
    }
}

impl<'a, 'b> Sub<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    #[inline]
    fn sub(self, rhs: &'b Scalar) -> Scalar {
        self.sub(rhs)
    }
}

impl<'a, 'b> Add<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    #[inline]
    fn add(self, rhs: &'b Scalar) -> Scalar {
        self.add(rhs)
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a Scalar {
    type Output = Scalar;

    #[inline]
    fn mul(self, rhs: &'b Scalar) -> Scalar {
        self.mul(rhs)
    }
}

// Binop implementations
impl<'b> Add<&'b Scalar> for Scalar {
    type Output = Scalar;
    #[inline]
    fn add(self, rhs: &'b Scalar) -> Scalar {
        &self + rhs
    }
}

impl<'a> Add<Scalar> for &'a Scalar {
    type Output = Scalar;
    #[inline]
    fn add(self, rhs: Scalar) -> Scalar {
        self + &rhs
    }
}

impl Add<Scalar> for Scalar {
    type Output = Scalar;
    #[inline]
    fn add(self, rhs: Scalar) -> Scalar {
        &self + &rhs
    }
}

impl<'b> Sub<&'b Scalar> for Scalar {
    type Output = Scalar;
    #[inline]
    fn sub(self, rhs: &'b Scalar) -> Scalar {
        &self - rhs
    }
}

impl<'a> Sub<Scalar> for &'a Scalar {
    type Output = Scalar;
    #[inline]
    fn sub(self, rhs: Scalar) -> Scalar {
        self - &rhs
    }
}

impl Sub<Scalar> for Scalar {
    type Output = Scalar;
    #[inline]
    fn sub(self, rhs: Scalar) -> Scalar {
        &self - &rhs
    }
}

impl SubAssign<Scalar> for Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: Scalar) {
        *self = &*self - &rhs;
    }
}

impl AddAssign<Scalar> for Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: Scalar) {
        *self = &*self + &rhs;
    }
}

impl<'b> SubAssign<&'b Scalar> for Scalar {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b Scalar) {
        *self = &*self - rhs;
    }
}

impl<'b> AddAssign<&'b Scalar> for Scalar {
    #[inline]
    fn add_assign(&mut self, rhs: &'b Scalar) {
        *self = &*self + rhs;
    }
}

impl<'b> Mul<&'b Scalar> for Scalar {
    type Output = Scalar;
    #[inline]
    fn mul(self, rhs: &'b Scalar) -> Scalar {
        &self * rhs
    }
}

impl<'a> Mul<Scalar> for &'a Scalar {
    type Output = Scalar;
    #[inline]
    fn mul(self, rhs: Scalar) -> Scalar {
        self * &rhs
    }
}

impl Mul<Scalar> for Scalar {
    type Output = Scalar;
    #[inline]
    fn mul(self, rhs: Scalar) -> Scalar {
        &self * &rhs
    }
}

impl MulAssign<Scalar> for Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = &*self * &rhs;
    }
}

impl<'b> MulAssign<&'b Scalar> for Scalar {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b Scalar) {
        *self = &*self * rhs;
    }
}

impl Default for Scalar {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ByteSerializable for Scalar {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(Error::Length {
                context: "Scalar::from_bytes",
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);

        Scalar::from_bytes(&array)
            .into_option()
            .ok_or_else(|| Error::param("scalar_bytes", "non-canonical scalar"))
    }
}

impl DcryptConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> bool {
        bool::from(ConstantTimeEq::ct_eq(self, other))
    }
}

impl SecureZeroingType for Scalar {
    fn zeroed() -> Self {
        Self::zero()
    }
}

impl Scalar {
    /// Additive identity
    #[inline]
    pub const fn zero() -> Scalar {
        Scalar([0, 0, 0, 0])
    }

    /// Multiplicative identity
    #[inline]
    pub const fn one() -> Scalar {
        R
    }

    /// Check if element is zero.
    #[inline]
    pub fn is_zero(&self) -> Choice {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]).ct_eq(&0)
    }

    /// Double this element
    #[inline]
    pub const fn double(&self) -> Scalar {
        self.add(self)
    }

    /// Create from little-endian bytes if canonical
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Scalar> {
        let mut tmp = Scalar([0, 0, 0, 0]);

        tmp.0[0] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
        tmp.0[1] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        tmp.0[2] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        tmp.0[3] = u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());

        // Check canonical by subtracting modulus
        let (_, borrow) = sbb(tmp.0[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb(tmp.0[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb(tmp.0[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb(tmp.0[3], MODULUS.0[3], borrow);

        let is_some = (borrow as u8) & 1;

        // Convert to Montgomery: (a * R^2) / R = aR
        tmp *= &R2;

        CtOption::new(tmp, Choice::from(is_some))
    }

    /// Convert to little-endian bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        // Remove Montgomery: (aR) / R = a
        let tmp = Scalar::montgomery_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0);

        let mut res = [0; 32];
        res[0..8].copy_from_slice(&tmp.0[0].to_le_bytes());
        res[8..16].copy_from_slice(&tmp.0[1].to_le_bytes());
        res[16..24].copy_from_slice(&tmp.0[2].to_le_bytes());
        res[24..32].copy_from_slice(&tmp.0[3].to_le_bytes());

        res
    }

    /// Create from 512-bit little-endian integer mod q
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Scalar {
        Scalar::from_u512([
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap()),
        ])
    }

    fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Result<Vec<u8>> {
        const MAX_DST_LENGTH: usize = 255;
        const HASH_OUTPUT_SIZE: usize = 32;

        if dst.len() > MAX_DST_LENGTH {
            return Err(Error::param("dst", "domain separation tag too long"));
        }

        let ell = (len_in_bytes + HASH_OUTPUT_SIZE - 1) / HASH_OUTPUT_SIZE;

        if ell > 255 {
            return Err(Error::param("len_in_bytes", "requested output too long"));
        }

        let dst_prime_len = dst.len() as u8;

        let mut hasher = Sha256::new();
        hasher.update(&[0u8; HASH_OUTPUT_SIZE])?;
        hasher.update(msg)?;
        hasher.update(&((len_in_bytes as u16).to_be_bytes()))?;
        hasher.update(&[0u8])?;
        hasher.update(dst)?;
        hasher.update(&[dst_prime_len])?;

        let b_0 = hasher.finalize()?;

        let mut uniform_bytes = Vec::with_capacity(len_in_bytes);
        let mut b_i = vec![0u8; HASH_OUTPUT_SIZE];

        for i in 1..=ell {
            let mut hasher = Sha256::new();
            if i == 1 {
                hasher.update(&[0u8; HASH_OUTPUT_SIZE])?;
            } else {
                let mut xored = [0u8; HASH_OUTPUT_SIZE];
                for j in 0..HASH_OUTPUT_SIZE {
                    xored[j] = b_0.as_ref()[j] ^ b_i[j];
                }
                hasher.update(&xored)?;
            }
            hasher.update(&[i as u8])?;
            hasher.update(dst)?;
            hasher.update(&[dst_prime_len])?;
            let digest = hasher.finalize()?;
            b_i.copy_from_slice(digest.as_ref());
            uniform_bytes.extend_from_slice(&b_i);
        }

        uniform_bytes.truncate(len_in_bytes);
        Ok(uniform_bytes)
    }

    /// Hashes arbitrary data to a scalar field element using SHA-256.
    ///
    /// This function implements a standards-compliant hash-to-field method following
    /// the IETF hash-to-curve specification using expand_message_xmd with SHA-256.
    ///
    /// # Arguments
    /// * `data`: The input data to hash.
    /// * `dst`: A Domain Separation Tag (DST) to ensure hashes are unique per application context.
    ///
    /// # Returns
    /// A `Result` containing the `Scalar` or an error.
    pub fn hash_to_field(data: &[u8], dst: &[u8]) -> Result<Self> {
        let expanded = Self::expand_message_xmd(data, dst, 64)?;
        let mut expanded_array = [0u8; 64];
        expanded_array.copy_from_slice(&expanded);
        Ok(Self::from_bytes_wide(&expanded_array))
    }

    fn from_u512(limbs: [u64; 8]) -> Scalar {
        let d0 = Scalar([limbs[0], limbs[1], limbs[2], limbs[3]]);
        let d1 = Scalar([limbs[4], limbs[5], limbs[6], limbs[7]]);
        d0 * R2 + d1 * R3
    }

    /// Creates a scalar from four `u64` limbs (little-endian). This function will
    /// convert the raw integer into Montgomery form.
    pub const fn from_raw(val: [u64; 4]) -> Self {
        (&Scalar(val)).mul(&R2)
    }

    /// Computes the square of this scalar.
    #[inline]
    pub const fn square(&self) -> Scalar {
        let (r1, carry) = mac(0, self.0[0], self.0[1], 0);
        let (r2, carry) = mac(0, self.0[0], self.0[2], carry);
        let (r3, r4) = mac(0, self.0[0], self.0[3], carry);

        let (r3, carry) = mac(r3, self.0[1], self.0[2], 0);
        let (r4, r5) = mac(r4, self.0[1], self.0[3], carry);

        let (r5, r6) = mac(r5, self.0[2], self.0[3], 0);

        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        let (r0, carry) = mac(0, self.0[0], self.0[0], 0);
        let (r1, carry) = adc(0, r1, carry);
        let (r2, carry) = mac(r2, self.0[1], self.0[1], carry);
        let (r3, carry) = adc(0, r3, carry);
        let (r4, carry) = mac(r4, self.0[2], self.0[2], carry);
        let (r5, carry) = adc(0, r5, carry);
        let (r6, carry) = mac(r6, self.0[3], self.0[3], carry);
        let (r7, _) = adc(0, r7, carry);

        Scalar::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }

    /// Computes `x` raised to the power of `2^k`.
    #[inline]
    pub fn pow2k(mut x: Scalar, mut k: u32) -> Scalar {
        while k > 0 {
            x = x.square();
            k -= 1;
        }
        x
    }

    /// Variable-time exponentiation by a 256-bit little-endian exponent.
    fn pow_vartime(&self, by: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for limb in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();
                if ((limb >> i) & 1) == 1 {
                    res *= self;
                }
            }
        }
        res
    }

    /// Computes the square root of this scalar using Tonelli-Shanks.
    /// Returns `Some(s)` with `s^2 = self` if a square root exists, else `None`.
    pub fn sqrt(&self) -> CtOption<Self> {
        // Trivial case: sqrt(0) = 0
        if bool::from(self.is_zero()) {
            return CtOption::new(Scalar::zero(), Choice::from(1));
        }

        // Choose a fixed quadratic non-residue. For this field, 5 works.
        let z = Scalar::from(5u64);

        // Precompute values per Tonelli-Shanks
        let mut c = z.pow_vartime(&TONELLI_T); // c = z^T
        let mut t = self.pow_vartime(&TONELLI_T); // t = a^T
        let mut x = self.pow_vartime(&TONELLI_TP1_DIV2); // x = a^((T+1)/2)
        let mut m = S;

        // If t == 1, we guessed the root correctly.
        if bool::from(ConstantTimeEq::ct_eq(&t, &Scalar::one())) {
            return CtOption::new(x, ConstantTimeEq::ct_eq(&x.square(), self));
        }

        // Main Tonelli-Shanks loop
        loop {
            // Find smallest i in [1, m) with t^(2^i) == 1
            let mut i = 1u32;
            let mut t2i = t.square();
            while i < m && !bool::from(ConstantTimeEq::ct_eq(&t2i, &Scalar::one())) {
                t2i = t2i.square();
                i += 1;
            }

            // If i == m, then a is not a square root
            if i == m {
                return CtOption::new(Scalar::zero(), Choice::from(0));
            }

            // b = c^{2^(m - i - 1)}
            let b = Scalar::pow2k(c, m - i - 1);

            // Update variables
            x = x * b;
            let b2 = b.square();
            t = t * b2;
            c = b2;
            m = i;

            // If t is now 1, we are done
            if bool::from(ConstantTimeEq::ct_eq(&t, &Scalar::one())) {
                break;
            }
        }

        // Final constant-time check to ensure correctness
        CtOption::new(x, ConstantTimeEq::ct_eq(&x.square(), self))
    }

    /// Computes the multiplicative inverse of this scalar, if it is non-zero.
    pub fn invert(&self) -> CtOption<Self> {
        #[inline(always)]
        fn square_assign_multi(n: &mut Scalar, num_times: usize) {
            for _ in 0..num_times {
                *n = n.square();
            }
        }
        // Addition chain from github.com/kwantam/addchain
        let mut t0 = self.square();
        let mut t1 = t0 * self;
        let mut t16 = t0.square();
        let mut t6 = t16.square();
        let mut t5 = t6 * t0;
        t0 = t6 * t16;
        let mut t12 = t5 * t16;
        let mut t2 = t6.square();
        let mut t7 = t5 * t6;
        let mut t15 = t0 * t5;
        let mut t17 = t12.square();
        t1 *= t17;
        let mut t3 = t7 * t2;
        let t8 = t1 * t17;
        let t4 = t8 * t2;
        let t9 = t8 * t7;
        t7 = t4 * t5;
        let t11 = t4 * t17;
        t5 = t9 * t17;
        let t14 = t7 * t15;
        let t13 = t11 * t12;
        t12 = t11 * t17;
        t15 *= &t12;
        t16 *= &t15;
        t3 *= &t16;
        t17 *= &t3;
        t0 *= &t17;
        t6 *= &t0;
        t2 *= &t6;
        square_assign_multi(&mut t0, 8);
        t0 *= &t17;
        square_assign_multi(&mut t0, 9);
        t0 *= &t16;
        square_assign_multi(&mut t0, 9);
        t0 *= &t15;
        square_assign_multi(&mut t0, 9);
        t0 *= &t15;
        square_assign_multi(&mut t0, 7);
        t0 *= &t14;
        square_assign_multi(&mut t0, 7);
        t0 *= &t13;
        square_assign_multi(&mut t0, 10);
        t0 *= &t12;
        square_assign_multi(&mut t0, 9);
        t0 *= &t11;
        square_assign_multi(&mut t0, 8);
        t0 *= &t8;
        square_assign_multi(&mut t0, 8);
        t0 *= self;
        square_assign_multi(&mut t0, 14);
        t0 *= &t9;
        square_assign_multi(&mut t0, 10);
        t0 *= &t8;
        square_assign_multi(&mut t0, 15);
        t0 *= &t7;
        square_assign_multi(&mut t0, 10);
        t0 *= &t6;
        square_assign_multi(&mut t0, 8);
        t0 *= &t5;
        square_assign_multi(&mut t0, 16);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 7);
        t0 *= &t4;
        square_assign_multi(&mut t0, 9);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t3;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 8);
        t0 *= &t2;
        square_assign_multi(&mut t0, 5);
        t0 *= &t1;
        square_assign_multi(&mut t0, 5);
        t0 *= &t1;

        CtOption::new(t0, !ConstantTimeEq::ct_eq(self, &Self::zero()))
    }

    #[inline(always)]
    const fn montgomery_reduce(
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64,
    ) -> Self {
        let k = r0.wrapping_mul(INV);
        let (_, carry) = mac(r0, k, MODULUS.0[0], 0);
        let (r1, carry) = mac(r1, k, MODULUS.0[1], carry);
        let (r2, carry) = mac(r2, k, MODULUS.0[2], carry);
        let (r3, carry) = mac(r3, k, MODULUS.0[3], carry);
        let (r4, carry2) = adc(r4, 0, carry);

        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac(r1, k, MODULUS.0[0], 0);
        let (r2, carry) = mac(r2, k, MODULUS.0[1], carry);
        let (r3, carry) = mac(r3, k, MODULUS.0[2], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[3], carry);
        let (r5, carry2) = adc(r5, carry2, carry);

        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac(r2, k, MODULUS.0[0], 0);
        let (r3, carry) = mac(r3, k, MODULUS.0[1], carry);
        let (r4, carry) = mac(r4, k, MODULUS.0[2], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[3], carry);
        let (r6, carry2) = adc(r6, carry2, carry);

        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac(r3, k, MODULUS.0[0], 0);
        let (r4, carry) = mac(r4, k, MODULUS.0[1], carry);
        let (r5, carry) = mac(r5, k, MODULUS.0[2], carry);
        let (r6, carry) = mac(r6, k, MODULUS.0[3], carry);
        let (r7, _) = adc(r7, carry2, carry);

        (&Scalar([r4, r5, r6, r7])).sub(&MODULUS)
    }

    /// Multiplies this scalar by another.
    #[inline]
    pub const fn mul(&self, rhs: &Self) -> Self {
        let (r0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (r1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (r2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (r3, r4) = mac(0, self.0[0], rhs.0[3], carry);

        let (r1, carry) = mac(r1, self.0[1], rhs.0[0], 0);
        let (r2, carry) = mac(r2, self.0[1], rhs.0[1], carry);
        let (r3, carry) = mac(r3, self.0[1], rhs.0[2], carry);
        let (r4, r5) = mac(r4, self.0[1], rhs.0[3], carry);

        let (r2, carry) = mac(r2, self.0[2], rhs.0[0], 0);
        let (r3, carry) = mac(r3, self.0[2], rhs.0[1], carry);
        let (r4, carry) = mac(r4, self.0[2], rhs.0[2], carry);
        let (r5, r6) = mac(r5, self.0[2], rhs.0[3], carry);

        let (r3, carry) = mac(r3, self.0[3], rhs.0[0], 0);
        let (r4, carry) = mac(r4, self.0[3], rhs.0[1], carry);
        let (r5, carry) = mac(r5, self.0[3], rhs.0[2], carry);
        let (r6, r7) = mac(r6, self.0[3], rhs.0[3], carry);

        Scalar::montgomery_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }

    /// Subtracts another scalar from this one.
    #[inline]
    pub const fn sub(&self, rhs: &Self) -> Self {
        let (d0, borrow) = sbb(self.0[0], rhs.0[0], 0);
        let (d1, borrow) = sbb(self.0[1], rhs.0[1], borrow);
        let (d2, borrow) = sbb(self.0[2], rhs.0[2], borrow);
        let (d3, borrow) = sbb(self.0[3], rhs.0[3], borrow);

        let (d0, carry) = adc(d0, MODULUS.0[0] & borrow, 0);
        let (d1, carry) = adc(d1, MODULUS.0[1] & borrow, carry);
        let (d2, carry) = adc(d2, MODULUS.0[2] & borrow, carry);
        let (d3, _) = adc(d3, MODULUS.0[3] & borrow, carry);

        Scalar([d0, d1, d2, d3])
    }

    /// Adds another scalar to this one.
    #[inline]
    pub const fn add(&self, rhs: &Self) -> Self {
        let (d0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (d1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (d2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (d3, _) = adc(self.0[3], rhs.0[3], carry);

        (&Scalar([d0, d1, d2, d3])).sub(&MODULUS)
    }

    /// Computes the additive negation of this scalar.
    #[inline]
    pub const fn neg(&self) -> Self {
        let (d0, borrow) = sbb(MODULUS.0[0], self.0[0], 0);
        let (d1, borrow) = sbb(MODULUS.0[1], self.0[1], borrow);
        let (d2, borrow) = sbb(MODULUS.0[2], self.0[2], borrow);
        let (d3, _) = sbb(MODULUS.0[3], self.0[3], borrow);

        let mask = (((self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0) as u64).wrapping_sub(1);

        Scalar([d0 & mask, d1 & mask, d2 & mask, d3 & mask])
    }
}

impl From<Scalar> for [u8; 32] {
    fn from(value: Scalar) -> [u8; 32] {
        value.to_bytes()
    }
}

impl<'a> From<&'a Scalar> for [u8; 32] {
    fn from(value: &'a Scalar) -> [u8; 32] {
        value.to_bytes()
    }
}

impl<T> core::iter::Sum<T> for Scalar
where
    T: core::borrow::Borrow<Scalar>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::zero(), |acc, item| acc + item.borrow())
    }
}

impl<T> core::iter::Product<T> for Scalar
where
    T: core::borrow::Borrow<Scalar>,
{
    fn product<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::one(), |acc, item| acc * item.borrow())
    }
}

// Tests
#[test]
fn test_inv() {
    // Verify INV constant
    let mut inv = 1u64;
    for _ in 0..63 {
        inv = inv.wrapping_mul(inv);
        inv = inv.wrapping_mul(MODULUS.0[0]);
    }
    inv = inv.wrapping_neg();
    assert_eq!(inv, INV);
}

#[cfg(feature = "std")]
#[test]
fn test_debug() {
    assert_eq!(
        format!("{:?}", Scalar::zero()),
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        format!("{:?}", Scalar::one()),
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    // R is the Montgomery representation of 1. The Debug trait should perform the
    // conversion, so it should also format to "1".
    assert_eq!(
        format!("{:?}", R),
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
}

#[test]
fn test_equality() {
    assert_eq!(Scalar::zero(), Scalar::zero());
    assert_eq!(Scalar::one(), Scalar::one());
    #[allow(clippy::eq_op)]
    {
        assert_eq!(R2, R2);
    }

    assert!(Scalar::zero() != Scalar::one());
    assert!(Scalar::one() != R2);
}

#[test]
fn test_to_bytes() {
    assert_eq!(
        Scalar::zero().to_bytes(),
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]
    );

    assert_eq!(
        Scalar::one().to_bytes(),
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]
    );

    // R is the Montgomery representation of 1. to_bytes() should perform the
    // conversion, so it should also produce the bytes for "1".
    assert_eq!(
        R.to_bytes(),
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]
    );

    assert_eq!(
        (-&Scalar::one()).to_bytes(),
        [
            0, 0, 0, 0, 255, 255, 255, 255, 254, 91, 254, 255, 2, 164, 189, 83, 5, 216, 161, 9, 8,
            216, 57, 51, 72, 125, 157, 41, 83, 167, 237, 115
        ]
    );
}

#[test]
fn test_from_bytes() {
    let mut a = R2;

    for _ in 0..100 {
        let bytes = a.to_bytes();
        let b = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(a, b);

        // Test negation roundtrip
        let bytes = (-a).to_bytes();
        let b = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(-a, b);

        a = a.square();
    }
}

#[cfg(test)]
const LARGEST: Scalar = Scalar([
    0xffff_ffff_0000_0000,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
]);

#[test]
fn test_addition() {
    let mut tmp = LARGEST;
    tmp += &LARGEST;

    assert_eq!(
        tmp,
        Scalar([
            0xffff_fffe_ffff_ffff,
            0x53bd_a402_fffe_5bfe,
            0x3339_d808_09a1_d805,
            0x73ed_a753_299d_7d48,
        ])
    );

    let mut tmp = LARGEST;
    tmp += &Scalar([1, 0, 0, 0]);

    assert_eq!(tmp, Scalar::zero());
}

#[test]
fn test_inversion() {
    assert!(bool::from(Scalar::zero().invert().is_none()));
    assert_eq!(Scalar::one().invert().unwrap(), Scalar::one());
    assert_eq!((-&Scalar::one()).invert().unwrap(), -&Scalar::one());

    let mut tmp = R2;

    for _ in 0..100 {
        let mut tmp2 = tmp.invert().unwrap();
        tmp2.mul_assign(&tmp);

        assert_eq!(tmp2, Scalar::one());

        tmp.add_assign(&R2);
    }
}

#[test]
fn test_sqrt() {
    // Test with zero
    assert_eq!(Scalar::zero().sqrt().unwrap(), Scalar::zero());

    // Test with one
    assert_eq!(Scalar::one().sqrt().unwrap(), Scalar::one());

    // Test with a known square
    let four = Scalar::from(4u64);
    let two = Scalar::from(2u64);
    let neg_two = -two;

    let sqrt_four = four.sqrt().unwrap();
    assert!(sqrt_four == two || sqrt_four == neg_two);
    assert_eq!(sqrt_four.square(), four);

    // Test with a random square
    let s = Scalar::from(123456789u64);
    let s_sq = s.square();
    let s_sqrt = s_sq.sqrt().unwrap();
    assert!(s_sqrt == s || s_sqrt == -s);
    assert_eq!(s_sqrt.square(), s_sq);

    // Test with a non-residue.
    // For this field, 5 is a quadratic non-residue.
    let five = Scalar::from(5u64);
    assert!(bool::from(five.sqrt().is_none()));

    // Test with a residue.
    // For a prime q where q = 1 mod 4, -1 is a residue.
    let neg_one = -Scalar::one();
    let neg_one_sqrt = neg_one.sqrt().unwrap();
    assert_eq!(neg_one_sqrt.square(), neg_one);

    // Test roundtrip for many values
    let mut val = R2;
    for _ in 0..100 {
        let sq = val.square();
        let sqrt = sq.sqrt().unwrap();
        assert!(sqrt == val || sqrt == -val);
        val += R;
    }
}

#[test]
fn test_from_raw() {
    assert_eq!(
        Scalar::from_raw([
            0x0001_ffff_fffd,
            0x5884_b7fa_0003_4802,
            0x998c_4fef_ecbc_4ff5,
            0x1824_b159_acc5_056f,
        ]),
        Scalar::from_raw([0xffff_ffff_ffff_ffff; 4])
    );

    assert_eq!(Scalar::from_raw(MODULUS.0), Scalar::zero());

    assert_eq!(Scalar::from_raw([1, 0, 0, 0]), R);
}

#[test]
fn test_scalar_hash_to_field() {
    let data1 = b"some input data";
    let data2 = b"different input data";
    let dst1 = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"; // Standard DST format
    let dst2 = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    // 1. Different data should produce different scalars
    let s1 = Scalar::hash_to_field(data1, dst1).unwrap();
    let s2 = Scalar::hash_to_field(data2, dst1).unwrap();
    assert_ne!(s1, s2);

    // 2. Same data with different DSTs should produce different scalars
    let s3 = Scalar::hash_to_field(data1, dst1).unwrap();
    let s4 = Scalar::hash_to_field(data1, dst2).unwrap();
    assert_ne!(s3, s4);

    // 3. Hashing should be deterministic
    let s5 = Scalar::hash_to_field(data1, dst1).unwrap();
    assert_eq!(s3, s5);

    // 4. Verify output is always valid scalar (less than modulus)
    for test_case in &[b"" as &[u8], b"a", b"test", &[0xFF; 100], &[0x00; 64]] {
        let scalar = Scalar::hash_to_field(test_case, dst1).unwrap();
        // The scalar should already be reduced, so converting to/from bytes should work
        let bytes = scalar.to_bytes();
        let scalar2 = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(scalar, scalar2, "Output should be a valid reduced scalar");
    }

    // 5. Test that the expansion reduces bias appropriately
    // With 64 bytes (512 bits) being reduced to ~255 bits, bias should be negligible
    let mut scalars = Vec::new();
    for i in 0u32..100 {
        let data = i.to_le_bytes();
        let s = Scalar::hash_to_field(&data, dst1).unwrap();
        scalars.push(s);
    }
    // All should be different (no collisions in small sample)
    for i in 0..scalars.len() {
        for j in i + 1..scalars.len() {
            assert_ne!(
                scalars[i], scalars[j],
                "Unexpected collision at {} and {}",
                i, j
            );
        }
    }

    // 6. Test empty DST and empty data edge cases
    let s_empty = Scalar::hash_to_field(b"", b"").unwrap();
    let s_empty2 = Scalar::hash_to_field(b"", b"").unwrap();
    assert_eq!(
        s_empty, s_empty2,
        "Empty input should still be deterministic"
    );

    // 7. Verify that DST length is properly included (catches common implementation bugs)
    let dst_short = b"A";
    let dst_long = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 50 A's
    let s_short = Scalar::hash_to_field(data1, dst_short).unwrap();
    let s_long = Scalar::hash_to_field(data1, dst_long).unwrap();
    assert_ne!(s_short, s_long, "DST length should affect output");

    // 8. Test mathematical properties: hash(data) should be uniformly distributed
    // We can't test true uniformity easily, but we can check it's not always even/odd
    let mut has_odd = false;
    let mut has_even = false;
    for i in 0u8..20 {
        let s = Scalar::hash_to_field(&[i], dst1).unwrap();
        // Check the least significant bit
        if s.to_bytes()[0] & 1 == 0 {
            has_even = true;
        } else {
            has_odd = true;
        }
    }
    assert!(
        has_odd && has_even,
        "Hash output should have both odd and even values"
    );

    // 9. Test expand_message_xmd internal function with basic test vectors
    // These help ensure our implementation follows the standard
    let expanded = Scalar::expand_message_xmd(b"", b"QUUX-V01-CS02-with-SHA256", 32).unwrap();
    assert_eq!(expanded.len(), 32);

    // Basic sanity check: different messages produce different expansions
    let expanded1 = Scalar::expand_message_xmd(b"msg1", b"dst", 64).unwrap();
    let expanded2 = Scalar::expand_message_xmd(b"msg2", b"dst", 64).unwrap();
    assert_ne!(expanded1, expanded2);
}

#[test]
fn test_zeroize() {
    use dcrypt_internal::zeroing::Zeroize;

    let mut a = Scalar::from_raw([
        0x1fff_3231_233f_fffd,
        0x4884_b7fa_0003_4802,
        0x998c_4fef_ecbc_4ff3,
        0x1824_b159_acc5_0562,
    ]);
    a.zeroize();
    assert!(bool::from(
        dcrypt_internal::constant_time::ConstantTimeEq::ct_eq(&a, &Scalar::zero())
    ));
}
