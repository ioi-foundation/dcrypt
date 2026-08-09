// algorithms/src/ec/bls12_381/field/fp.rs

//! BLS12-381 base field `GF(p)` where p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

// Standard library imports
use core::fmt;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use dcrypt_internal::constant_time::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use dcrypt_internal::random::{CryptoRng, Error as RandomError};
use dcrypt_internal::zeroing::Zeroize;

// ============================================================================
// Arithmetic Helper Functions
// ============================================================================

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

// ============================================================================
// Field Constants
// ============================================================================

/// Field modulus p
const MODULUS: [u64; 6] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// Montgomery parameter INV = -(p^{-1} mod 2^64) mod 2^64
const INV: u64 = 0x89f3_fffc_fffc_fffd;

/// Montgomery R = 2^384 mod p
const R: Fp = Fp([
    0x7609_0000_0002_fffd,
    0xebf4_000b_c40c_0002,
    0x5f48_9857_53c7_58ba,
    0x77ce_5853_7052_5745,
    0x5c07_1a97_a256_ec6d,
    0x15f6_5ec3_fa80_e493,
]);

/// Montgomery R^2 = 2^768 mod p
pub(crate) const R2: Fp = Fp([
    0xf4df_1f34_1c34_1746,
    0x0a76_e6a6_09d1_04f1,
    0x8de5_476c_4c95_b6d5,
    0x67eb_88a9_939d_83c0,
    0x9a79_3e85_b519_952d,
    0x1198_8fe5_92ca_e3aa,
]);

/// Montgomery R^3 = 2^1152 mod p
const R3: Fp = Fp([
    0xed48_ac6b_d94c_a1e0,
    0x315f_831e_03a7_adf8,
    0x9a53_352a_615e_29dd,
    0x34c0_4e5e_921e_1761,
    0x2512_d435_6572_4728,
    0x0aa6_3460_9175_5d4d,
]);

// ============================================================================
// Field Element Type
// ============================================================================

/// Element in Montgomery form: Fp(a) = aR mod p, with R = 2^384
#[derive(Copy, Clone)]
pub struct Fp(pub(crate) [u64; 6]);

// ============================================================================
// Field Operations (Extracted Functions)
// ============================================================================

impl Fp {
    /// Performs modular reduction after addition
    #[inline]
    const fn subtract_p(&self) -> Fp {
        let (r0, borrow) = sbb(self.0[0], MODULUS[0], 0);
        let (r1, borrow) = sbb(self.0[1], MODULUS[1], borrow);
        let (r2, borrow) = sbb(self.0[2], MODULUS[2], borrow);
        let (r3, borrow) = sbb(self.0[3], MODULUS[3], borrow);
        let (r4, borrow) = sbb(self.0[4], MODULUS[4], borrow);
        let (r5, borrow) = sbb(self.0[5], MODULUS[5], borrow);

        // Use borrow as mask for conditional select
        let r0 = (self.0[0] & borrow) | (r0 & !borrow);
        let r1 = (self.0[1] & borrow) | (r1 & !borrow);
        let r2 = (self.0[2] & borrow) | (r2 & !borrow);
        let r3 = (self.0[3] & borrow) | (r3 & !borrow);
        let r4 = (self.0[4] & borrow) | (r4 & !borrow);
        let r5 = (self.0[5] & borrow) | (r5 & !borrow);

        Fp([r0, r1, r2, r3, r4, r5])
    }

    /// Performs full multiplication of two field elements
    #[inline]
    const fn multiply_impl(&self, rhs: &Fp) -> ([u64; 12], u64) {
        let (t0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (t1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (t2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (t3, carry) = mac(0, self.0[0], rhs.0[3], carry);
        let (t4, carry) = mac(0, self.0[0], rhs.0[4], carry);
        let (t5, t6) = mac(0, self.0[0], rhs.0[5], carry);

        let (t1, carry) = mac(t1, self.0[1], rhs.0[0], 0);
        let (t2, carry) = mac(t2, self.0[1], rhs.0[1], carry);
        let (t3, carry) = mac(t3, self.0[1], rhs.0[2], carry);
        let (t4, carry) = mac(t4, self.0[1], rhs.0[3], carry);
        let (t5, carry) = mac(t5, self.0[1], rhs.0[4], carry);
        let (t6, t7) = mac(t6, self.0[1], rhs.0[5], carry);

        let (t2, carry) = mac(t2, self.0[2], rhs.0[0], 0);
        let (t3, carry) = mac(t3, self.0[2], rhs.0[1], carry);
        let (t4, carry) = mac(t4, self.0[2], rhs.0[2], carry);
        let (t5, carry) = mac(t5, self.0[2], rhs.0[3], carry);
        let (t6, carry) = mac(t6, self.0[2], rhs.0[4], carry);
        let (t7, t8) = mac(t7, self.0[2], rhs.0[5], carry);

        let (t3, carry) = mac(t3, self.0[3], rhs.0[0], 0);
        let (t4, carry) = mac(t4, self.0[3], rhs.0[1], carry);
        let (t5, carry) = mac(t5, self.0[3], rhs.0[2], carry);
        let (t6, carry) = mac(t6, self.0[3], rhs.0[3], carry);
        let (t7, carry) = mac(t7, self.0[3], rhs.0[4], carry);
        let (t8, t9) = mac(t8, self.0[3], rhs.0[5], carry);

        let (t4, carry) = mac(t4, self.0[4], rhs.0[0], 0);
        let (t5, carry) = mac(t5, self.0[4], rhs.0[1], carry);
        let (t6, carry) = mac(t6, self.0[4], rhs.0[2], carry);
        let (t7, carry) = mac(t7, self.0[4], rhs.0[3], carry);
        let (t8, carry) = mac(t8, self.0[4], rhs.0[4], carry);
        let (t9, t10) = mac(t9, self.0[4], rhs.0[5], carry);

        let (t5, carry) = mac(t5, self.0[5], rhs.0[0], 0);
        let (t6, carry) = mac(t6, self.0[5], rhs.0[1], carry);
        let (t7, carry) = mac(t7, self.0[5], rhs.0[2], carry);
        let (t8, carry) = mac(t8, self.0[5], rhs.0[3], carry);
        let (t9, carry) = mac(t9, self.0[5], rhs.0[4], carry);
        let (t10, t11) = mac(t10, self.0[5], rhs.0[5], carry);

        ([t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11], 0)
    }

    /// Performs squaring using dedicated squaring algorithm
    #[inline]
    const fn square_impl(&self) -> ([u64; 12], u64) {
        let (t1, carry) = mac(0, self.0[0], self.0[1], 0);
        let (t2, carry) = mac(0, self.0[0], self.0[2], carry);
        let (t3, carry) = mac(0, self.0[0], self.0[3], carry);
        let (t4, carry) = mac(0, self.0[0], self.0[4], carry);
        let (t5, t6) = mac(0, self.0[0], self.0[5], carry);

        let (t3, carry) = mac(t3, self.0[1], self.0[2], 0);
        let (t4, carry) = mac(t4, self.0[1], self.0[3], carry);
        let (t5, carry) = mac(t5, self.0[1], self.0[4], carry);
        let (t6, t7) = mac(t6, self.0[1], self.0[5], carry);

        let (t5, carry) = mac(t5, self.0[2], self.0[3], 0);
        let (t6, carry) = mac(t6, self.0[2], self.0[4], carry);
        let (t7, t8) = mac(t7, self.0[2], self.0[5], carry);

        let (t7, carry) = mac(t7, self.0[3], self.0[4], 0);
        let (t8, t9) = mac(t8, self.0[3], self.0[5], carry);

        let (t9, t10) = mac(t9, self.0[4], self.0[5], 0);

        let t11 = t10 >> 63;
        let t10 = (t10 << 1) | (t9 >> 63);
        let t9 = (t9 << 1) | (t8 >> 63);
        let t8 = (t8 << 1) | (t7 >> 63);
        let t7 = (t7 << 1) | (t6 >> 63);
        let t6 = (t6 << 1) | (t5 >> 63);
        let t5 = (t5 << 1) | (t4 >> 63);
        let t4 = (t4 << 1) | (t3 >> 63);
        let t3 = (t3 << 1) | (t2 >> 63);
        let t2 = (t2 << 1) | (t1 >> 63);
        let t1 = t1 << 1;

        let (t0, carry) = mac(0, self.0[0], self.0[0], 0);
        let (t1, carry) = adc(t1, 0, carry);
        let (t2, carry) = mac(t2, self.0[1], self.0[1], carry);
        let (t3, carry) = adc(t3, 0, carry);
        let (t4, carry) = mac(t4, self.0[2], self.0[2], carry);
        let (t5, carry) = adc(t5, 0, carry);
        let (t6, carry) = mac(t6, self.0[3], self.0[3], carry);
        let (t7, carry) = adc(t7, 0, carry);
        let (t8, carry) = mac(t8, self.0[4], self.0[4], carry);
        let (t9, carry) = adc(t9, 0, carry);
        let (t10, carry) = mac(t10, self.0[5], self.0[5], carry);
        let (t11, _) = adc(t11, 0, carry);

        ([t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11], 0)
    }

    /// Check if value is greater than (p-1)/2
    fn is_lexicographically_largest(&self) -> bool {
        // Convert from Montgomery form for comparison
        let tmp = Self::montgomery_reduce(
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], 0, 0, 0, 0, 0, 0,
        );

        // Check if > (p-1)/2
        let (_, borrow) = sbb(tmp.0[0], 0xdcff_7fff_ffff_d556, 0);
        let (_, borrow) = sbb(tmp.0[1], 0x0f55_ffff_58a9_ffff, borrow);
        let (_, borrow) = sbb(tmp.0[2], 0xb398_6950_7b58_7b12, borrow);
        let (_, borrow) = sbb(tmp.0[3], 0xb23b_a5c2_79c2_895f, borrow);
        let (_, borrow) = sbb(tmp.0[4], 0x258d_d3db_21a5_d66b, borrow);
        let (_, borrow) = sbb(tmp.0[5], 0x0d00_88f5_1cbf_f34d, borrow);

        borrow == 0
    }
}

// ============================================================================
// Core Field Operations
// ============================================================================

impl Fp {
    /// Additive identity
    #[inline]
    pub const fn zero() -> Fp {
        Fp([0, 0, 0, 0, 0, 0])
    }

    /// Multiplicative identity
    #[inline]
    pub const fn one() -> Fp {
        R
    }

    /// Check if element is zero
    pub fn is_zero(&self) -> Choice {
        self.ct_eq(&Fp::zero())
    }

    /// Create without checking canonicity.
    pub const fn from_raw_unchecked(v: [u64; 6]) -> Fp {
        Fp(v)
    }

    /// Add two field elements
    #[inline]
    pub const fn add(&self, rhs: &Fp) -> Fp {
        let (d0, carry) = adc(self.0[0], rhs.0[0], 0);
        let (d1, carry) = adc(self.0[1], rhs.0[1], carry);
        let (d2, carry) = adc(self.0[2], rhs.0[2], carry);
        let (d3, carry) = adc(self.0[3], rhs.0[3], carry);
        let (d4, carry) = adc(self.0[4], rhs.0[4], carry);
        let (d5, _) = adc(self.0[5], rhs.0[5], carry);

        (&Fp([d0, d1, d2, d3, d4, d5])).subtract_p()
    }

    /// Subtract two field elements
    #[inline]
    pub const fn sub(&self, rhs: &Fp) -> Fp {
        (&rhs.neg()).add(self)
    }

    /// Negate a field element
    #[inline]
    pub const fn neg(&self) -> Fp {
        let (d0, borrow) = sbb(MODULUS[0], self.0[0], 0);
        let (d1, borrow) = sbb(MODULUS[1], self.0[1], borrow);
        let (d2, borrow) = sbb(MODULUS[2], self.0[2], borrow);
        let (d3, borrow) = sbb(MODULUS[3], self.0[3], borrow);
        let (d4, borrow) = sbb(MODULUS[4], self.0[4], borrow);
        let (d5, _) = sbb(MODULUS[5], self.0[5], borrow);

        // Mask if zero
        let mask = (((self.0[0] | self.0[1] | self.0[2] | self.0[3] | self.0[4] | self.0[5]) == 0)
            as u64)
            .wrapping_sub(1);

        Fp([
            d0 & mask,
            d1 & mask,
            d2 & mask,
            d3 & mask,
            d4 & mask,
            d5 & mask,
        ])
    }

    /// Multiply two field elements
    #[inline]
    pub const fn mul(&self, rhs: &Fp) -> Fp {
        let (t0, carry) = mac(0, self.0[0], rhs.0[0], 0);
        let (t1, carry) = mac(0, self.0[0], rhs.0[1], carry);
        let (t2, carry) = mac(0, self.0[0], rhs.0[2], carry);
        let (t3, carry) = mac(0, self.0[0], rhs.0[3], carry);
        let (t4, carry) = mac(0, self.0[0], rhs.0[4], carry);
        let (t5, t6) = mac(0, self.0[0], rhs.0[5], carry);

        let (t1, carry) = mac(t1, self.0[1], rhs.0[0], 0);
        let (t2, carry) = mac(t2, self.0[1], rhs.0[1], carry);
        let (t3, carry) = mac(t3, self.0[1], rhs.0[2], carry);
        let (t4, carry) = mac(t4, self.0[1], rhs.0[3], carry);
        let (t5, carry) = mac(t5, self.0[1], rhs.0[4], carry);
        let (t6, t7) = mac(t6, self.0[1], rhs.0[5], carry);

        let (t2, carry) = mac(t2, self.0[2], rhs.0[0], 0);
        let (t3, carry) = mac(t3, self.0[2], rhs.0[1], carry);
        let (t4, carry) = mac(t4, self.0[2], rhs.0[2], carry);
        let (t5, carry) = mac(t5, self.0[2], rhs.0[3], carry);
        let (t6, carry) = mac(t6, self.0[2], rhs.0[4], carry);
        let (t7, t8) = mac(t7, self.0[2], rhs.0[5], carry);

        let (t3, carry) = mac(t3, self.0[3], rhs.0[0], 0);
        let (t4, carry) = mac(t4, self.0[3], rhs.0[1], carry);
        let (t5, carry) = mac(t5, self.0[3], rhs.0[2], carry);
        let (t6, carry) = mac(t6, self.0[3], rhs.0[3], carry);
        let (t7, carry) = mac(t7, self.0[3], rhs.0[4], carry);
        let (t8, t9) = mac(t8, self.0[3], rhs.0[5], carry);

        let (t4, carry) = mac(t4, self.0[4], rhs.0[0], 0);
        let (t5, carry) = mac(t5, self.0[4], rhs.0[1], carry);
        let (t6, carry) = mac(t6, self.0[4], rhs.0[2], carry);
        let (t7, carry) = mac(t7, self.0[4], rhs.0[3], carry);
        let (t8, carry) = mac(t8, self.0[4], rhs.0[4], carry);
        let (t9, t10) = mac(t9, self.0[4], rhs.0[5], carry);

        let (t5, carry) = mac(t5, self.0[5], rhs.0[0], 0);
        let (t6, carry) = mac(t6, self.0[5], rhs.0[1], carry);
        let (t7, carry) = mac(t7, self.0[5], rhs.0[2], carry);
        let (t8, carry) = mac(t8, self.0[5], rhs.0[3], carry);
        let (t9, carry) = mac(t9, self.0[5], rhs.0[4], carry);
        let (t10, t11) = mac(t10, self.0[5], rhs.0[5], carry);

        Self::montgomery_reduce(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11)
    }

    /// Square this element
    #[inline]
    pub const fn square(&self) -> Self {
        let result = self.square_impl();
        Self::montgomery_reduce(
            result.0[0],
            result.0[1],
            result.0[2],
            result.0[3],
            result.0[4],
            result.0[5],
            result.0[6],
            result.0[7],
            result.0[8],
            result.0[9],
            result.0[10],
            result.0[11],
        )
    }

    /// Sum of products using interleaved multiplication and reduction
    #[inline]
    pub(crate) fn sum_of_products<const T: usize>(a: [Fp; T], b: [Fp; T]) -> Fp {
        // Interleave multiplication and reduction for efficiency
        let (u0, u1, u2, u3, u4, u5) =
            (0..6).fold((0, 0, 0, 0, 0, 0), |(u0, u1, u2, u3, u4, u5), j| {
                // Accumulate products for digit j
                let (t0, t1, t2, t3, t4, t5, t6) = (0..T).fold(
                    (u0, u1, u2, u3, u4, u5, 0),
                    |(t0, t1, t2, t3, t4, t5, t6), i| {
                        let (t0, carry) = mac(t0, a[i].0[j], b[i].0[0], 0);
                        let (t1, carry) = mac(t1, a[i].0[j], b[i].0[1], carry);
                        let (t2, carry) = mac(t2, a[i].0[j], b[i].0[2], carry);
                        let (t3, carry) = mac(t3, a[i].0[j], b[i].0[3], carry);
                        let (t4, carry) = mac(t4, a[i].0[j], b[i].0[4], carry);
                        let (t5, carry) = mac(t5, a[i].0[j], b[i].0[5], carry);
                        let (t6, _) = adc(t6, 0, carry);

                        (t0, t1, t2, t3, t4, t5, t6)
                    },
                );

                // Montgomery reduction step
                let k = t0.wrapping_mul(INV);
                let (_, carry) = mac(t0, k, MODULUS[0], 0);
                let (r1, carry) = mac(t1, k, MODULUS[1], carry);
                let (r2, carry) = mac(t2, k, MODULUS[2], carry);
                let (r3, carry) = mac(t3, k, MODULUS[3], carry);
                let (r4, carry) = mac(t4, k, MODULUS[4], carry);
                let (r5, carry) = mac(t5, k, MODULUS[5], carry);
                let (r6, _) = adc(t6, 0, carry);

                (r1, r2, r3, r4, r5, r6)
            });

        (&Fp([u0, u1, u2, u3, u4, u5])).subtract_p()
    }

    /// Montgomery reduction algorithm
    #[inline(always)]
    pub(crate) const fn montgomery_reduce(
        t0: u64,
        t1: u64,
        t2: u64,
        t3: u64,
        t4: u64,
        t5: u64,
        t6: u64,
        t7: u64,
        t8: u64,
        t9: u64,
        t10: u64,
        t11: u64,
    ) -> Self {
        // Round 1
        let k = t0.wrapping_mul(INV);
        let (_, carry) = mac(t0, k, MODULUS[0], 0);
        let (r1, carry) = mac(t1, k, MODULUS[1], carry);
        let (r2, carry) = mac(t2, k, MODULUS[2], carry);
        let (r3, carry) = mac(t3, k, MODULUS[3], carry);
        let (r4, carry) = mac(t4, k, MODULUS[4], carry);
        let (r5, carry) = mac(t5, k, MODULUS[5], carry);
        let (r6, r7) = adc(t6, 0, carry);

        // Round 2
        let k = r1.wrapping_mul(INV);
        let (_, carry) = mac(r1, k, MODULUS[0], 0);
        let (r2, carry) = mac(r2, k, MODULUS[1], carry);
        let (r3, carry) = mac(r3, k, MODULUS[2], carry);
        let (r4, carry) = mac(r4, k, MODULUS[3], carry);
        let (r5, carry) = mac(r5, k, MODULUS[4], carry);
        let (r6, carry) = mac(r6, k, MODULUS[5], carry);
        let (r7, r8) = adc(t7, r7, carry);

        // Round 3
        let k = r2.wrapping_mul(INV);
        let (_, carry) = mac(r2, k, MODULUS[0], 0);
        let (r3, carry) = mac(r3, k, MODULUS[1], carry);
        let (r4, carry) = mac(r4, k, MODULUS[2], carry);
        let (r5, carry) = mac(r5, k, MODULUS[3], carry);
        let (r6, carry) = mac(r6, k, MODULUS[4], carry);
        let (r7, carry) = mac(r7, k, MODULUS[5], carry);
        let (r8, r9) = adc(t8, r8, carry);

        // Round 4
        let k = r3.wrapping_mul(INV);
        let (_, carry) = mac(r3, k, MODULUS[0], 0);
        let (r4, carry) = mac(r4, k, MODULUS[1], carry);
        let (r5, carry) = mac(r5, k, MODULUS[2], carry);
        let (r6, carry) = mac(r6, k, MODULUS[3], carry);
        let (r7, carry) = mac(r7, k, MODULUS[4], carry);
        let (r8, carry) = mac(r8, k, MODULUS[5], carry);
        let (r9, r10) = adc(t9, r9, carry);

        // Round 5
        let k = r4.wrapping_mul(INV);
        let (_, carry) = mac(r4, k, MODULUS[0], 0);
        let (r5, carry) = mac(r5, k, MODULUS[1], carry);
        let (r6, carry) = mac(r6, k, MODULUS[2], carry);
        let (r7, carry) = mac(r7, k, MODULUS[3], carry);
        let (r8, carry) = mac(r8, k, MODULUS[4], carry);
        let (r9, carry) = mac(r9, k, MODULUS[5], carry);
        let (r10, r11) = adc(t10, r10, carry);

        // Round 6
        let k = r5.wrapping_mul(INV);
        let (_, carry) = mac(r5, k, MODULUS[0], 0);
        let (r6, carry) = mac(r6, k, MODULUS[1], carry);
        let (r7, carry) = mac(r7, k, MODULUS[2], carry);
        let (r8, carry) = mac(r8, k, MODULUS[3], carry);
        let (r9, carry) = mac(r9, k, MODULUS[4], carry);
        let (r10, carry) = mac(r10, k, MODULUS[5], carry);
        let (r11, _) = adc(t11, r11, carry);

        (&Fp([r6, r7, r8, r9, r10, r11])).subtract_p()
    }
}

// ============================================================================
// Advanced Field Operations
// ============================================================================

impl Fp {
    /// Variable-time exponentiation
    pub fn pow_vartime(&self, by: &[u64; 6]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();
                if ((*e >> i) & 1) == 1 {
                    res *= self;
                }
            }
        }
        res
    }

    /// Compute square root if it exists
    #[inline]
    pub fn sqrt(&self) -> CtOption<Self> {
        // p ≡ 3 (mod 4), compute a^((p+1)/4)
        let sqrt = self.pow_vartime(&[
            0xee7f_bfff_ffff_eaab,
            0x07aa_ffff_ac54_ffff,
            0xd9cc_34a8_3dac_3d89,
            0xd91d_d2e1_3ce1_44af,
            0x92c6_e9ed_90d2_eb35,
            0x0680_447a_8e5f_f9a6,
        ]);

        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }

    /// Multiplicative inverse
    #[inline]
    pub fn invert(&self) -> CtOption<Self> {
        // Fermat's little theorem: a^(p-2)
        let t = self.pow_vartime(&[
            0xb9fe_ffff_ffff_aaa9,
            0x1eab_fffe_b153_ffff,
            0x6730_d2a0_f6b0_f624,
            0x6477_4b84_f385_12bf,
            0x4b1b_a7b6_434b_acd7,
            0x1a01_11ea_397f_e69a,
        ]);

        CtOption::new(t, !self.is_zero())
    }

    /// Check if element > (p-1)/2
    pub fn lexicographically_largest(&self) -> Choice {
        Choice::from(self.is_lexicographically_largest() as u8)
    }

    /// Decode a 512-bit integer (64 bytes) into a field element by reducing modulo p.
    /// Used for hash-to-field.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        // Parse 64 bytes as 8 u64 limbs (little endian)
        let d0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let d1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let d2 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let d3 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let d4 = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let d5 = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let d6 = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let d7 = u64::from_le_bytes(bytes[56..64].try_into().unwrap());

        // We split the 512-bit input into:
        // 1. Low 384 bits (d0..d5)
        // 2. High 128 bits (d6..d7)
        //
        // Value = Low + High * 2^384
        //
        // In Montgomery form (which Fp uses internally):
        // result = (Low + High * 2^384) * R mod p
        //        = Low * R + High * (2^384 * R) mod p
        //
        // We have precomputed constants:
        // R2 = R^2 = 2^768 mod p  => Low * R2 reduces to Low * R
        // R3 = R^3 = 2^1152 mod p => High * R3 reduces to High * R^2 = High * (2^384 * R)

        // Construct raw Fp wrappers (not yet in Montgomery form)
        let low = Fp([d0, d1, d2, d3, d4, d5]);
        let high = Fp([d6, d7, 0, 0, 0, 0]);

        // Perform the reduction using Montgomery multiplication
        // mul() computes a * b * R^-1
        // low.mul(R2)  = low * R^2 * R^-1 = low * R
        // high.mul(R3) = high * R^3 * R^-1 = high * R^2 = high * (2^384 * R)

        let term1 = low.mul(&R2);
        let term2 = high.mul(&R3);

        term1.add(&term2)
    }
}

// ============================================================================
// Serialization
// ============================================================================

impl Fp {
    /// Decode from big-endian bytes
    pub fn from_bytes(bytes: &[u8; 48]) -> CtOption<Fp> {
        let mut tmp = Fp([0, 0, 0, 0, 0, 0]);

        tmp.0[5] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
        tmp.0[4] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        tmp.0[3] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        tmp.0[2] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());
        tmp.0[1] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap());
        tmp.0[0] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap());

        // Check if < modulus
        let (_, borrow) = sbb(tmp.0[0], MODULUS[0], 0);
        let (_, borrow) = sbb(tmp.0[1], MODULUS[1], borrow);
        let (_, borrow) = sbb(tmp.0[2], MODULUS[2], borrow);
        let (_, borrow) = sbb(tmp.0[3], MODULUS[3], borrow);
        let (_, borrow) = sbb(tmp.0[4], MODULUS[4], borrow);
        let (_, borrow) = sbb(tmp.0[5], MODULUS[5], borrow);

        let is_some = (borrow as u8) & 1;

        // Convert to Montgomery form
        tmp *= &R2;

        CtOption::new(tmp, Choice::from(is_some))
    }

    /// Encode to big-endian bytes
    pub fn to_bytes(self) -> [u8; 48] {
        // Convert from Montgomery form
        let tmp = Fp::montgomery_reduce(
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], 0, 0, 0, 0, 0, 0,
        );

        let mut res = [0; 48];
        res[0..8].copy_from_slice(&tmp.0[5].to_be_bytes());
        res[8..16].copy_from_slice(&tmp.0[4].to_be_bytes());
        res[16..24].copy_from_slice(&tmp.0[3].to_be_bytes());
        res[24..32].copy_from_slice(&tmp.0[2].to_be_bytes());
        res[32..40].copy_from_slice(&tmp.0[1].to_be_bytes());
        res[40..48].copy_from_slice(&tmp.0[0].to_be_bytes());

        res
    }

    /// Create random field element
    pub(crate) fn random(mut rng: impl CryptoRng) -> Result<Fp, RandomError> {
        let mut bytes = [0u8; 96];
        rng.try_fill_bytes(&mut bytes)?;

        // Parse as big-endian to match Fp encoding
        Ok(Fp::from_u768([
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[64..72]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[72..80]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[80..88]).unwrap()),
            u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[88..96]).unwrap()),
        ]))
    }

    /// Reduce 768-bit number modulo p
    fn from_u768(limbs: [u64; 12]) -> Fp {
        // Split into two 384-bit parts and reduce
        let d1 = Fp([limbs[11], limbs[10], limbs[9], limbs[8], limbs[7], limbs[6]]);
        let d0 = Fp([limbs[5], limbs[4], limbs[3], limbs[2], limbs[1], limbs[0]]);
        d0 * R2 + d1 * R3
    }
}

// ============================================================================
// Trait Implementations
// ============================================================================

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tmp = self.to_bytes();
        write!(f, "0x")?;
        for &b in tmp.iter() {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl Default for Fp {
    fn default() -> Self {
        Fp::zero()
    }
}

impl From<u64> for Fp {
    fn from(val: u64) -> Fp {
        Fp([val, 0, 0, 0, 0, 0]) * R2
    }
}

impl Zeroize for Fp {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ConstantTimeEq for Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
            & self.0[4].ct_eq(&other.0[4])
            & self.0[5].ct_eq(&other.0[5])
    }
}

impl Eq for Fp {}
impl PartialEq for Fp {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl ConditionallySelectable for Fp {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Fp([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
            u64::conditional_select(&a.0[4], &b.0[4], choice),
            u64::conditional_select(&a.0[5], &b.0[5], choice),
        ])
    }
}

// Binary operation trait implementations
impl<'a> Neg for &'a Fp {
    type Output = Fp;
    #[inline]
    fn neg(self) -> Fp {
        self.neg()
    }
}

impl Neg for Fp {
    type Output = Fp;
    #[inline]
    fn neg(self) -> Fp {
        -&self
    }
}

impl<'a, 'b> Sub<&'b Fp> for &'a Fp {
    type Output = Fp;
    #[inline]
    fn sub(self, rhs: &'b Fp) -> Fp {
        self.sub(rhs)
    }
}

impl<'a, 'b> Add<&'b Fp> for &'a Fp {
    type Output = Fp;
    #[inline]
    fn add(self, rhs: &'b Fp) -> Fp {
        self.add(rhs)
    }
}

impl<'a, 'b> Mul<&'b Fp> for &'a Fp {
    type Output = Fp;
    #[inline]
    fn mul(self, rhs: &'b Fp) -> Fp {
        self.mul(rhs)
    }
}

// Additional binop implementations for convenience
impl<'b> Add<&'b Fp> for Fp {
    type Output = Fp;
    #[inline]
    fn add(self, rhs: &'b Fp) -> Fp {
        &self + rhs
    }
}

impl<'a> Add<Fp> for &'a Fp {
    type Output = Fp;
    #[inline]
    fn add(self, rhs: Fp) -> Fp {
        self + &rhs
    }
}

impl Add<Fp> for Fp {
    type Output = Fp;
    #[inline]
    fn add(self, rhs: Fp) -> Fp {
        &self + &rhs
    }
}

impl<'b> Sub<&'b Fp> for Fp {
    type Output = Fp;
    #[inline]
    fn sub(self, rhs: &'b Fp) -> Fp {
        &self - rhs
    }
}

impl<'a> Sub<Fp> for &'a Fp {
    type Output = Fp;
    #[inline]
    fn sub(self, rhs: Fp) -> Fp {
        self - &rhs
    }
}

impl Sub<Fp> for Fp {
    type Output = Fp;
    #[inline]
    fn sub(self, rhs: Fp) -> Fp {
        &self - &rhs
    }
}

impl SubAssign<Fp> for Fp {
    #[inline]
    fn sub_assign(&mut self, rhs: Fp) {
        *self = &*self - &rhs;
    }
}

impl AddAssign<Fp> for Fp {
    #[inline]
    fn add_assign(&mut self, rhs: Fp) {
        *self = &*self + &rhs;
    }
}

impl<'b> SubAssign<&'b Fp> for Fp {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b Fp) {
        *self = &*self - rhs;
    }
}

impl<'b> AddAssign<&'b Fp> for Fp {
    #[inline]
    fn add_assign(&mut self, rhs: &'b Fp) {
        *self = &*self + rhs;
    }
}

impl<'b> Mul<&'b Fp> for Fp {
    type Output = Fp;
    #[inline]
    fn mul(self, rhs: &'b Fp) -> Fp {
        &self * rhs
    }
}

impl<'a> Mul<Fp> for &'a Fp {
    type Output = Fp;
    #[inline]
    fn mul(self, rhs: Fp) -> Fp {
        self * &rhs
    }
}

impl Mul<Fp> for Fp {
    type Output = Fp;
    #[inline]
    fn mul(self, rhs: Fp) -> Fp {
        &self * &rhs
    }
}

impl MulAssign<Fp> for Fp {
    #[inline]
    fn mul_assign(&mut self, rhs: Fp) {
        *self = &*self * &rhs;
    }
}

impl<'b> MulAssign<&'b Fp> for Fp {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b Fp) {
        *self = &*self * rhs;
    }
}
