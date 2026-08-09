//! G₂ group implementation for BLS12-381.

use crate::error::{validate, Error, Result};
use core::borrow::Borrow;
use core::fmt;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use dcrypt_internal::random::{try_fill_bytes_zeroing_on_error, CryptoRng, Error as RandomError};
use dcrypt_internal::zeroing::Zeroize;

use super::field::fp::Fp;
use super::field::fp2::Fp2;
use super::scalar::secret_be_bytes_are_valid;
use super::Scalar;
#[cfg(feature = "alloc")]
use alloc::vec;

/// G₂ affine point representation.
#[derive(Copy, Clone, Debug)]
pub struct G2Affine {
    pub(crate) x: Fp2,
    pub(crate) y: Fp2,
    infinity: Choice,
}

impl Default for G2Affine {
    fn default() -> G2Affine {
        G2Affine::identity()
    }
}

impl Zeroize for G2Affine {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.infinity = Choice::from(0);
    }
}

impl fmt::Display for G2Affine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<'a> From<&'a G2Projective> for G2Affine {
    fn from(p: &'a G2Projective) -> G2Affine {
        let zinv = p.z.invert().unwrap_or(Fp2::zero());
        let x = p.x * zinv;
        let y = p.y * zinv;

        let tmp = G2Affine {
            x,
            y,
            infinity: Choice::from(0u8),
        };

        G2Affine::conditional_select(&tmp, &G2Affine::identity(), zinv.is_zero())
    }
}

impl From<G2Projective> for G2Affine {
    fn from(p: G2Projective) -> G2Affine {
        G2Affine::from(&p)
    }
}

impl ConstantTimeEq for G2Affine {
    fn ct_eq(&self, other: &Self) -> Choice {
        (self.infinity & other.infinity)
            | ((!self.infinity)
                & (!other.infinity)
                & self.x.ct_eq(&other.x)
                & self.y.ct_eq(&other.y))
    }
}

impl ConditionallySelectable for G2Affine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G2Affine {
            x: Fp2::conditional_select(&a.x, &b.x, choice),
            y: Fp2::conditional_select(&a.y, &b.y, choice),
            infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl Eq for G2Affine {}
impl PartialEq for G2Affine {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<'a> Neg for &'a G2Affine {
    type Output = G2Affine;

    #[inline]
    fn neg(self) -> G2Affine {
        G2Affine {
            x: self.x,
            y: Fp2::conditional_select(&-self.y, &Fp2::one(), self.infinity),
            infinity: self.infinity,
        }
    }
}

impl Neg for G2Affine {
    type Output = G2Affine;

    #[inline]
    fn neg(self) -> G2Affine {
        -&self
    }
}

impl<'a, 'b> Add<&'b G2Projective> for &'a G2Affine {
    type Output = G2Projective;

    #[inline]
    fn add(self, rhs: &'b G2Projective) -> G2Projective {
        rhs.add_mixed(self)
    }
}

impl<'a, 'b> Add<&'b G2Affine> for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn add(self, rhs: &'b G2Affine) -> G2Projective {
        self.add_mixed(rhs)
    }
}

impl<'a, 'b> Sub<&'b G2Projective> for &'a G2Affine {
    type Output = G2Projective;

    #[inline]
    fn sub(self, rhs: &'b G2Projective) -> G2Projective {
        self + &(-rhs)
    }
}

impl<'a, 'b> Sub<&'b G2Affine> for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn sub(self, rhs: &'b G2Affine) -> G2Projective {
        self + &(-rhs)
    }
}

impl<T> Sum<T> for G2Projective
where
    T: Borrow<G2Projective>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

// Binop implementations for G2Projective + G2Affine
impl<'b> Add<&'b G2Affine> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: &'b G2Affine) -> G2Projective {
        &self + rhs
    }
}
impl<'a> Add<G2Affine> for &'a G2Projective {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: G2Affine) -> G2Projective {
        self + &rhs
    }
}
impl Add<G2Affine> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: G2Affine) -> G2Projective {
        &self + &rhs
    }
}
impl<'b> Sub<&'b G2Affine> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: &'b G2Affine) -> G2Projective {
        &self - rhs
    }
}
impl<'a> Sub<G2Affine> for &'a G2Projective {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: G2Affine) -> G2Projective {
        self - &rhs
    }
}
impl Sub<G2Affine> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: G2Affine) -> G2Projective {
        &self - &rhs
    }
}
impl SubAssign<G2Affine> for G2Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: G2Affine) {
        *self = &*self - &rhs;
    }
}
impl AddAssign<G2Affine> for G2Projective {
    #[inline]
    fn add_assign(&mut self, rhs: G2Affine) {
        *self = &*self + &rhs;
    }
}
impl<'b> SubAssign<&'b G2Affine> for G2Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b G2Affine) {
        *self = &*self - rhs;
    }
}
impl<'b> AddAssign<&'b G2Affine> for G2Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &'b G2Affine) {
        *self = &*self + rhs;
    }
}

// Binop implementations for G2Affine + G2Projective
impl<'b> Add<&'b G2Projective> for G2Affine {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: &'b G2Projective) -> G2Projective {
        &self + rhs
    }
}
impl<'a> Add<G2Projective> for &'a G2Affine {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: G2Projective) -> G2Projective {
        self + &rhs
    }
}
impl Add<G2Projective> for G2Affine {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: G2Projective) -> G2Projective {
        &self + &rhs
    }
}
impl<'b> Sub<&'b G2Projective> for G2Affine {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: &'b G2Projective) -> G2Projective {
        &self - rhs
    }
}
impl<'a> Sub<G2Projective> for &'a G2Affine {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: G2Projective) -> G2Projective {
        self - &rhs
    }
}
impl Sub<G2Projective> for G2Affine {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: G2Projective) -> G2Projective {
        &self - &rhs
    }
}

/// Curve constant B = 4(u+1)
const B: Fp2 = Fp2 {
    c0: Fp::from_raw_unchecked([
        0xaa27_0000_000c_fff3,
        0x53cc_0032_fc34_000a,
        0x478f_e97a_6b0a_807f,
        0xb1d3_7ebe_e6ba_24d7,
        0x8ec9_733b_bf78_ab2f,
        0x09d6_4551_3d83_de7e,
    ]),
    c1: Fp::from_raw_unchecked([
        0xaa27_0000_000c_fff3,
        0x53cc_0032_fc34_000a,
        0x478f_e97a_6b0a_807f,
        0xb1d3_7ebe_e6ba_24d7,
        0x8ec9_733b_bf78_ab2f,
        0x09d6_4551_3d83_de7e,
    ]),
};

/// 3B for efficient doubling
const B3: Fp2 = Fp2::add(&Fp2::add(&B, &B), &B);

#[inline(always)]
fn mul_by_3b(a: Fp2) -> Fp2 {
    a * B3
}

impl G2Affine {
    /// Point at infinity.
    pub fn identity() -> G2Affine {
        G2Affine {
            x: Fp2::zero(),
            y: Fp2::one(),
            infinity: Choice::from(1u8),
        }
    }

    /// Fixed generator.
    pub fn generator() -> G2Affine {
        G2Affine {
            x: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0xf5f2_8fa2_0294_0a10,
                    0xb3f5_fb26_87b4_961a,
                    0xa1a8_93b5_3e2a_e580,
                    0x9894_999d_1a3c_aee9,
                    0x6f67_b763_1863_366b,
                    0x0581_9192_4350_bcd7,
                ]),
                c1: Fp::from_raw_unchecked([
                    0xa5a9_c075_9e23_f606,
                    0xaaa0_c59d_bccd_60c3,
                    0x3bb1_7e18_e286_7806,
                    0x1b1a_b6cc_8541_b367,
                    0xc2b6_ed0e_f215_8547,
                    0x1192_2a09_7360_edf3,
                ]),
            },
            y: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x4c73_0af8_6049_4c4a,
                    0x597c_fa1f_5e36_9c5a,
                    0xe7e6_856c_aa0a_635a,
                    0xbbef_b5e9_6e0d_495f,
                    0x07d3_a975_f0ef_25a2,
                    0x0083_fd8e_7e80_dae5,
                ]),
                c1: Fp::from_raw_unchecked([
                    0xadc0_fc92_df64_b05d,
                    0x18aa_270a_2b14_61dc,
                    0x86ad_ac6a_3be4_eba0,
                    0x7949_5c4e_c93d_a33a,
                    0xe717_5850_a43c_caed,
                    0x0b2b_c2a1_63de_1bf2,
                ]),
            },
            infinity: Choice::from(0u8),
        }
    }

    /// Compress to 96 bytes.
    pub fn to_compressed(&self) -> [u8; 96] {
        let x = Fp2::conditional_select(&self.x, &Fp2::zero(), self.infinity);
        let mut res = [0; 96];

        res[0..48].copy_from_slice(&x.c1.to_bytes());
        res[48..96].copy_from_slice(&x.c0.to_bytes());

        res[0] |= 1u8 << 7; // Compression flag
        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), self.infinity); // Infinity flag
        res[0] |= u8::conditional_select(
            &0u8,
            &(1u8 << 5),
            (!self.infinity) & self.y.lexicographically_largest(), // Sort flag
        );
        res
    }

    /// Serialize to 192 bytes uncompressed.
    pub fn to_uncompressed(&self) -> [u8; 192] {
        let mut res = [0; 192];
        let x = Fp2::conditional_select(&self.x, &Fp2::zero(), self.infinity);
        let y = Fp2::conditional_select(&self.y, &Fp2::zero(), self.infinity);

        res[0..48].copy_from_slice(&x.c1.to_bytes());
        res[48..96].copy_from_slice(&x.c0.to_bytes());
        res[96..144].copy_from_slice(&y.c1.to_bytes());
        res[144..192].copy_from_slice(&y.c0.to_bytes());

        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), self.infinity);
        res
    }

    /// Deserialize from uncompressed bytes with validation.
    pub fn from_uncompressed(bytes: &[u8; 192]) -> CtOption<Self> {
        Self::from_uncompressed_unchecked(bytes)
            .and_then(|p| CtOption::new(p, p.is_on_curve() & p.is_torsion_free()))
    }

    /// Internal decoder that omits curve and subgroup validation.
    pub(crate) fn from_uncompressed_unchecked(bytes: &[u8; 192]) -> CtOption<Self> {
        let compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((bytes[0] >> 6) & 1);
        let sort_flag_set = Choice::from((bytes[0] >> 5) & 1);

        let xc1 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[0..48]);
            tmp[0] &= 0b0001_1111;
            Fp::from_bytes(&tmp)
        };
        let xc0 = Fp::from_bytes(<&[u8; 48]>::try_from(&bytes[48..96]).unwrap());
        let yc1 = Fp::from_bytes(<&[u8; 48]>::try_from(&bytes[96..144]).unwrap());
        let yc0 = Fp::from_bytes(<&[u8; 48]>::try_from(&bytes[144..192]).unwrap());

        xc1.and_then(|xc1| {
            xc0.and_then(|xc0| {
                yc1.and_then(|yc1| {
                    yc0.and_then(|yc0| {
                        let x = Fp2 { c0: xc0, c1: xc1 };
                        let y = Fp2 { c0: yc0, c1: yc1 };

                        let p = G2Affine::conditional_select(
                            &G2Affine {
                                x,
                                y,
                                infinity: infinity_flag_set,
                            },
                            &G2Affine::identity(),
                            infinity_flag_set,
                        );
                        CtOption::new(
                            p,
                            ((!infinity_flag_set)
                                | (infinity_flag_set & x.is_zero() & y.is_zero()))
                                & (!compression_flag_set)
                                & (!sort_flag_set),
                        )
                    })
                })
            })
        })
    }

    /// Deserialize from compressed bytes with validation.
    pub fn from_compressed(bytes: &[u8; 96]) -> CtOption<Self> {
        Self::from_compressed_unchecked(bytes).and_then(|p| CtOption::new(p, p.is_torsion_free()))
    }

    /// Internal decoder that omits subgroup validation.
    pub(crate) fn from_compressed_unchecked(bytes: &[u8; 96]) -> CtOption<Self> {
        let compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((bytes[0] >> 6) & 1);
        let sort_flag_set = Choice::from((bytes[0] >> 5) & 1);

        let xc1 = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[0..48]);
            tmp[0] &= 0b0001_1111;
            Fp::from_bytes(&tmp)
        };
        let xc0 = Fp::from_bytes(<&[u8; 48]>::try_from(&bytes[48..96]).unwrap());

        xc1.and_then(|xc1| {
            xc0.and_then(|xc0| {
                let x = Fp2 { c0: xc0, c1: xc1 };
                CtOption::new(
                    G2Affine::identity(),
                    infinity_flag_set & compression_flag_set & (!sort_flag_set) & x.is_zero(),
                )
                .or_else(|| {
                    ((x.square() * x) + B).sqrt().and_then(|y| {
                        let y = Fp2::conditional_select(
                            &y,
                            &-y,
                            y.lexicographically_largest() ^ sort_flag_set,
                        );
                        CtOption::new(
                            G2Affine {
                                x,
                                y,
                                infinity: infinity_flag_set,
                            },
                            (!infinity_flag_set) & compression_flag_set,
                        )
                    })
                })
            })
        })
    }

    /// Check if point at infinity.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.infinity
    }

    /// Check if on curve y² = x³ + B.
    pub fn is_on_curve(&self) -> Choice {
        (self.y.square() - (self.x.square() * self.x)).ct_eq(&B) | self.infinity
    }

    /// Check subgroup membership using psi endomorphism.
    pub fn is_torsion_free(&self) -> Choice {
        // Algorithm from Section 4 of https://eprint.iacr.org/2021/1130
        // Updated proof: https://eprint.iacr.org/2022/352
        let p = G2Projective::from(*self);
        p.psi().ct_eq(&p.mul_by_x())
    }
}

/// G₂ projective point representation.
#[derive(Copy, Clone, Debug)]
pub struct G2Projective {
    pub(crate) x: Fp2,
    pub(crate) y: Fp2,
    pub(crate) z: Fp2,
}

impl Default for G2Projective {
    fn default() -> G2Projective {
        G2Projective::identity()
    }
}

impl Zeroize for G2Projective {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

impl fmt::Display for G2Projective {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<'a> From<&'a G2Affine> for G2Projective {
    fn from(p: &'a G2Affine) -> G2Projective {
        G2Projective {
            x: p.x,
            y: p.y,
            z: Fp2::conditional_select(&Fp2::one(), &Fp2::zero(), p.infinity),
        }
    }
}

impl From<G2Affine> for G2Projective {
    fn from(p: G2Affine) -> G2Projective {
        G2Projective::from(&p)
    }
}

impl ConstantTimeEq for G2Projective {
    fn ct_eq(&self, other: &Self) -> Choice {
        let x1 = self.x * other.z;
        let x2 = other.x * self.z;
        let y1 = self.y * other.z;
        let y2 = other.y * self.z;
        let self_is_zero = self.z.is_zero();
        let other_is_zero = other.z.is_zero();

        (self_is_zero & other_is_zero)
            | ((!self_is_zero) & (!other_is_zero) & x1.ct_eq(&x2) & y1.ct_eq(&y2))
    }
}

impl ConditionallySelectable for G2Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G2Projective {
            x: Fp2::conditional_select(&a.x, &b.x, choice),
            y: Fp2::conditional_select(&a.y, &b.y, choice),
            z: Fp2::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Eq for G2Projective {}
impl PartialEq for G2Projective {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<'a> Neg for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn neg(self) -> G2Projective {
        G2Projective {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl Neg for G2Projective {
    type Output = G2Projective;

    #[inline]
    fn neg(self) -> G2Projective {
        -&self
    }
}

impl<'a, 'b> Add<&'b G2Projective> for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn add(self, rhs: &'b G2Projective) -> G2Projective {
        self.add(rhs)
    }
}

impl<'a, 'b> Sub<&'b G2Projective> for &'a G2Projective {
    type Output = G2Projective;

    #[inline]
    fn sub(self, rhs: &'b G2Projective) -> G2Projective {
        self + &(-rhs)
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G2Projective {
    type Output = G2Projective;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        let mut bytes = other.to_bytes();
        let result = self.multiply(&bytes);
        bytes.zeroize();
        result
    }
}

impl<'a, 'b> Mul<&'b G2Projective> for &'a Scalar {
    type Output = G2Projective;

    #[inline]
    fn mul(self, rhs: &'b G2Projective) -> Self::Output {
        rhs * self
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G2Affine {
    type Output = G2Projective;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        let mut bytes = other.to_bytes();
        let result = G2Projective::from(self).multiply(&bytes);
        bytes.zeroize();
        result
    }
}

impl<'a, 'b> Mul<&'b G2Affine> for &'a Scalar {
    type Output = G2Projective;

    #[inline]
    fn mul(self, rhs: &'b G2Affine) -> Self::Output {
        rhs * self
    }
}

// Binop implementations for G2Projective
impl<'b> Add<&'b G2Projective> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: &'b G2Projective) -> G2Projective {
        &self + rhs
    }
}
impl<'a> Add<G2Projective> for &'a G2Projective {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: G2Projective) -> G2Projective {
        self + &rhs
    }
}
impl Add<G2Projective> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn add(self, rhs: G2Projective) -> G2Projective {
        &self + &rhs
    }
}
impl<'b> Sub<&'b G2Projective> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: &'b G2Projective) -> G2Projective {
        &self - rhs
    }
}
impl<'a> Sub<G2Projective> for &'a G2Projective {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: G2Projective) -> G2Projective {
        self - &rhs
    }
}
impl Sub<G2Projective> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn sub(self, rhs: G2Projective) -> G2Projective {
        &self - &rhs
    }
}
impl SubAssign<G2Projective> for G2Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: G2Projective) {
        *self = &*self - &rhs;
    }
}
impl AddAssign<G2Projective> for G2Projective {
    #[inline]
    fn add_assign(&mut self, rhs: G2Projective) {
        *self = &*self + &rhs;
    }
}
impl<'b> SubAssign<&'b G2Projective> for G2Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b G2Projective) {
        *self = &*self - rhs;
    }
}
impl<'b> AddAssign<&'b G2Projective> for G2Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &'b G2Projective) {
        *self = &*self + rhs;
    }
}

// Scalar multiplication implementations
impl<'b> Mul<&'b Scalar> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: &'b Scalar) -> G2Projective {
        &self * rhs
    }
}
impl<'a> Mul<Scalar> for &'a G2Projective {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: Scalar) -> G2Projective {
        self * &rhs
    }
}
impl Mul<Scalar> for G2Projective {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: Scalar) -> G2Projective {
        &self * &rhs
    }
}
impl MulAssign<Scalar> for G2Projective {
    #[inline]
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = &*self * &rhs;
    }
}
impl<'b> MulAssign<&'b Scalar> for G2Projective {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b Scalar) {
        *self = &*self * rhs;
    }
}

// Mixed scalar multiplication for G2Affine
impl<'b> Mul<&'b Scalar> for G2Affine {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: &'b Scalar) -> G2Projective {
        &self * rhs
    }
}
impl<'a> Mul<Scalar> for &'a G2Affine {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: Scalar) -> G2Projective {
        self * &rhs
    }
}
impl Mul<Scalar> for G2Affine {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: Scalar) -> G2Projective {
        &self * &rhs
    }
}

// Scalar * G2Affine
impl<'b> Mul<&'b G2Affine> for Scalar {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: &'b G2Affine) -> G2Projective {
        &self * rhs
    }
}
impl<'a> Mul<G2Affine> for &'a Scalar {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: G2Affine) -> G2Projective {
        self * &rhs
    }
}
impl Mul<G2Affine> for Scalar {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: G2Affine) -> G2Projective {
        &self * &rhs
    }
}

// Scalar * G2Projective
impl<'b> Mul<&'b G2Projective> for Scalar {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: &'b G2Projective) -> G2Projective {
        &self * rhs
    }
}
impl<'a> Mul<G2Projective> for &'a Scalar {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: G2Projective) -> G2Projective {
        self * &rhs
    }
}
impl Mul<G2Projective> for Scalar {
    type Output = G2Projective;
    #[inline]
    fn mul(self, rhs: G2Projective) -> G2Projective {
        &self * &rhs
    }
}

impl G2Projective {
    /// Point at infinity.
    pub fn identity() -> G2Projective {
        G2Projective {
            x: Fp2::zero(),
            y: Fp2::one(),
            z: Fp2::zero(),
        }
    }

    /// Fixed generator.
    pub fn generator() -> G2Projective {
        G2Projective {
            x: G2Affine::generator().x,
            y: G2Affine::generator().y,
            z: Fp2::one(),
        }
    }

    /// Multiply by a canonical, nonzero scalar encoded as a 32-byte
    /// big-endian secret key.
    ///
    /// This path validates and consumes the borrowed big-endian bytes directly:
    /// it does not construct the generic `Copy` scalar type or materialize a
    /// second byte-order representation. Multiplication uses exactly 256
    /// MSB-first rounds, always computes both the doubled and added candidate,
    /// and selects with a constant-time mask. Secret-derived point scratch is
    /// explicitly cleared after every round. Platform-specific compiler
    /// inspection is still required for a concrete side-channel claim.
    pub fn multiply_secret_be_bytes(&self, secret: &[u8; 32]) -> Result<Self> {
        if !bool::from(secret_be_bytes_are_valid(secret)) {
            return Err(Error::param(
                "secret_scalar",
                "scalar must be canonical and nonzero",
            ));
        }

        let mut accumulator = Self::identity();
        for byte in secret {
            for bit_index in (0..8).rev() {
                let mut doubled = accumulator.double();
                accumulator.zeroize();
                let mut added = doubled + self;
                let mut bit = Choice::from((byte >> bit_index) & 1);
                accumulator = Self::conditional_select(&doubled, &added, bit);
                bit.zeroize();
                doubled.zeroize();
                added.zeroize();
            }
        }
        Ok(accumulator)
    }

    /// Random non-identity element.
    pub fn random(mut rng: impl CryptoRng) -> core::result::Result<Self, RandomError> {
        loop {
            let x = Fp2::random(&mut rng)?;
            let mut sign = [0u8; 1];
            try_fill_bytes_zeroing_on_error(&mut rng, &mut sign)?;
            let flip_sign = sign[0] & 1 != 0;

            let p = ((x.square() * x) + B).sqrt().map(|y| G2Affine {
                x,
                y: if flip_sign { -y } else { y },
                infinity: 0.into(),
            });

            if p.is_some().into() {
                let p_proj = G2Projective::from(p.unwrap());
                let p_cleared = p_proj.clear_cofactor();
                if !bool::from(p_cleared.is_identity()) {
                    return Ok(p_cleared);
                }
            }
        }
    }

    // ============================================================================
    // START: New MSM Implementation
    // ============================================================================

    /// Multi-scalar multiplication using a variable-time Pippenger's algorithm.
    ///
    /// Every scalar passed to this low-level helper must be public. It contains
    /// input-dependent branches and does not provide secret-scratch ownership.
    /// Use [`Self::multiply_secret_be_bytes`] for secret scalar multiplication,
    /// or the high-level BLS APIs in `dcrypt-sign`.
    ///
    /// # Panics
    /// Panics if `points.len() != scalars.len()`.
    #[cfg(feature = "alloc")]
    pub fn msm_vartime(points: &[G2Affine], scalars: &[Scalar]) -> Result<Self> {
        if points.len() != scalars.len() {
            return Err(Error::Parameter {
                name: "points/scalars".into(),
                reason: "Input slices must have the same length".into(),
            });
        }
        Ok(Self::pippenger_vartime(points, scalars))
    }

    /// Internal public-input Pippenger implementation.
    #[cfg(feature = "alloc")]
    fn pippenger_vartime(points: &[G2Affine], scalars: &[Scalar]) -> Self {
        if points.is_empty() {
            return Self::identity();
        }

        let num_entries = points.len();
        let scalar_bits = 255; // BLS12-381 scalar size

        // 1. Choose window size `c` from the public batch length.
        let c = if num_entries < 32 {
            3
        } else {
            // Integer log2 equivalent: floor(log2(n)).
            // Works in no_std without libm.
            let log2 = (usize::BITS - num_entries.leading_zeros() - 1) as usize;
            log2 + 2
        };

        let num_windows = (scalar_bits + c - 1) / c;
        let num_buckets = 1 << c;
        let mut global_acc = Self::identity();

        // 2. Iterate through each window
        for w in (0..num_windows).rev() {
            let mut window_acc = Self::identity();
            let mut buckets = vec![Self::identity(); num_buckets];

            // 3. Populate buckets for the current window
            for i in 0..num_entries {
                let scalar_bytes = scalars[i].to_bytes();

                // Extract c-bit window from scalar
                let mut k = 0;
                for bit_idx in 0..c {
                    let total_bit_idx = w * c + bit_idx;
                    if total_bit_idx < scalar_bits {
                        let byte_idx = total_bit_idx / 8;
                        let inner_bit_idx = total_bit_idx % 8;
                        let byte = scalar_bytes[byte_idx];
                        let bit = (byte >> inner_bit_idx) & 1;
                        k |= (bit as usize) << bit_idx;
                    }
                }

                if k > 0 {
                    buckets[k - 1] = buckets[k - 1].add_mixed(&points[i]);
                }
            }

            // 4. Sum up buckets to get the window result
            let mut running_sum = Self::identity();
            for i in (0..num_buckets).rev() {
                running_sum = running_sum.add(&buckets[i]);
                window_acc = window_acc.add(&running_sum);
            }

            // 5. Add to global accumulator
            global_acc = global_acc.add(&window_acc);

            // Scale accumulator for next window if not the last one
            if w > 0 {
                for _ in 0..c {
                    global_acc = global_acc.double();
                }
            }
        }

        global_acc
    }

    // ============================================================================
    // END: New MSM Implementation
    // ============================================================================

    /// Point doubling.
    pub fn double(&self) -> G2Projective {
        let t0 = self.y.square();
        let z3 = t0 + t0;
        let z3 = z3 + z3;
        let z3 = z3 + z3;
        let t1 = self.y * self.z;
        let t2 = self.z.square();
        let t2 = mul_by_3b(t2);
        let x3 = t2 * z3;
        let y3 = t0 + t2;
        let z3 = t1 * z3;
        let t1 = t2 + t2;
        let t2 = t1 + t2;
        let t0 = t0 - t2;
        let y3 = t0 * y3;
        let y3 = x3 + y3;
        let t1 = self.x * self.y;
        let x3 = t0 * t1;
        let x3 = x3 + x3;

        let tmp = G2Projective {
            x: x3,
            y: y3,
            z: z3,
        };
        G2Projective::conditional_select(&tmp, &G2Projective::identity(), self.is_identity())
    }

    /// Point addition.
    pub fn add(&self, rhs: &G2Projective) -> G2Projective {
        let t0 = self.x * rhs.x;
        let t1 = self.y * rhs.y;
        let t2 = self.z * rhs.z;
        let t3 = self.x + self.y;
        let t4 = rhs.x + rhs.y;
        let t3 = t3 * t4;
        let t4 = t0 + t1;
        let t3 = t3 - t4;
        let t4 = self.y + self.z;
        let x3 = rhs.y + rhs.z;
        let t4 = t4 * x3;
        let x3 = t1 + t2;
        let t4 = t4 - x3;
        let x3 = self.x + self.z;
        let y3 = rhs.x + rhs.z;
        let x3 = x3 * y3;
        let y3 = t0 + t2;
        let y3 = x3 - y3;
        let x3 = t0 + t0;
        let t0 = x3 + t0;
        let t2 = mul_by_3b(t2);
        let z3 = t1 + t2;
        let t1 = t1 - t2;
        let y3 = mul_by_3b(y3);
        let x3 = t4 * y3;
        let t2 = t3 * t1;
        let x3 = t2 - x3;
        let y3 = y3 * t0;
        let t1 = t1 * z3;
        let y3 = t1 + y3;
        let t0 = t0 * t3;
        let z3 = z3 * t4;
        let z3 = z3 + t0;

        G2Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Mixed addition with affine point.
    pub fn add_mixed(&self, rhs: &G2Affine) -> G2Projective {
        let t0 = self.x * rhs.x;
        let t1 = self.y * rhs.y;
        let t3 = rhs.x + rhs.y;
        let t4 = self.x + self.y;
        let t3 = t3 * t4;
        let t4 = t0 + t1;
        let t3 = t3 - t4;
        let t4 = rhs.y * self.z;
        let t4 = t4 + self.y;
        let y3 = rhs.x * self.z;
        let y3 = y3 + self.x;
        let x3 = t0 + t0;
        let t0 = x3 + t0;
        let t2 = mul_by_3b(self.z);
        let z3 = t1 + t2;
        let t1 = t1 - t2;
        let y3 = mul_by_3b(y3);
        let x3 = t4 * y3;
        let t2 = t3 * t1;
        let x3 = t2 - x3;
        let y3 = y3 * t0;
        let t1 = t1 * z3;
        let y3 = t1 + y3;
        let t0 = t0 * t3;
        let z3 = z3 * t4;
        let z3 = z3 + t0;

        let tmp = G2Projective {
            x: x3,
            y: y3,
            z: z3,
        };
        G2Projective::conditional_select(&tmp, self, rhs.is_identity())
    }

    /// Scalar multiplication.
    fn multiply(&self, by: &[u8; 32]) -> G2Projective {
        let mut acc = G2Projective::identity();
        for &byte in by.iter().rev() {
            for i in (0..8).rev() {
                acc = acc.double();
                let bit = Choice::from((byte >> i) & 1u8);
                acc = G2Projective::conditional_select(&acc, &(acc + self), bit);
            }
        }
        acc
    }

    /// Clear cofactor.
    pub fn clear_cofactor(&self) -> G2Projective {
        let t1 = self.mul_by_x();
        let t2 = self.psi();
        self.double().psi2() + (t1 + t2).mul_by_x() - t1 - t2 - *self
    }

    /// Multiply by curve parameter x.
    fn mul_by_x(&self) -> G2Projective {
        let mut xself = G2Projective::identity();
        let mut x = super::BLS_X >> 1;
        let mut acc = *self;
        while x != 0 {
            acc = acc.double();
            if x % 2 == 1 {
                xself += acc;
            }
            x >>= 1;
        }
        if super::BLS_X_IS_NEGATIVE {
            xself = -xself;
        }
        xself
    }

    /// Apply psi endomorphism.
    fn psi(&self) -> G2Projective {
        // 1 / ((u+1) ^ ((q-1)/3))
        let psi_coeff_x = Fp2 {
            c0: Fp::zero(),
            c1: Fp::from_raw_unchecked([
                0x890d_c9e4_8675_45c3,
                0x2af3_2253_3285_a5d5,
                0x5088_0866_309b_7e2c,
                0xa20d_1b8c_7e88_1024,
                0x14e4_f04f_e2db_9068,
                0x14e5_6d3f_1564_853a,
            ]),
        };
        // 1 / ((u+1) ^ (p-1)/2)
        let psi_coeff_y = Fp2 {
            c0: Fp::from_raw_unchecked([
                0x3e2f_585d_a55c_9ad1,
                0x4294_213d_86c1_8183,
                0x3828_44c8_8b62_3732,
                0x92ad_2afd_1910_3e18,
                0x1d79_4e4f_ac7c_f0b9,
                0x0bd5_92fc_7d82_5ec8,
            ]),
            c1: Fp::from_raw_unchecked([
                0x7bcf_a7a2_5aa3_0fda,
                0xdc17_dec1_2a92_7e7c,
                0x2f08_8dd8_6b4e_bef1,
                0xd1ca_2087_da74_d4a7,
                0x2da2_5966_96ce_bc1d,
                0x0e2b_7eed_bbfd_87d2,
            ]),
        };

        G2Projective {
            x: self.x.frobenius_map() * psi_coeff_x,
            y: self.y.frobenius_map() * psi_coeff_y,
            z: self.z.frobenius_map(),
        }
    }

    /// Apply psi^2 endomorphism.
    fn psi2(&self) -> G2Projective {
        // 1 / 2 ^ ((q-1)/3)
        let psi2_coeff_x = Fp2 {
            c0: Fp::from_raw_unchecked([
                0xcd03_c9e4_8671_f071,
                0x5dab_2246_1fcd_a5d2,
                0x5870_42af_d385_1b95,
                0x8eb6_0ebe_01ba_cb9e,
                0x03f9_7d6e_83d0_50d2,
                0x18f0_2065_5463_8741,
            ]),
            c1: Fp::zero(),
        };

        G2Projective {
            x: self.x * psi2_coeff_x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Batch conversion to affine.
    pub fn batch_normalize(p: &[Self], q: &mut [G2Affine]) {
        assert_eq!(p.len(), q.len());
        let mut acc = Fp2::one();
        for (p, q) in p.iter().zip(q.iter_mut()) {
            q.x = acc;
            acc = Fp2::conditional_select(&(acc * p.z), &acc, p.is_identity());
        }
        acc = acc.invert().unwrap();
        for (p, q) in p.iter().rev().zip(q.iter_mut().rev()) {
            let skip = p.is_identity();
            let tmp = q.x * acc;
            acc = Fp2::conditional_select(&(acc * p.z), &acc, skip);
            q.x = p.x * tmp;
            q.y = p.y * tmp;
            q.infinity = Choice::from(0u8);
            *q = G2Affine::conditional_select(q, &G2Affine::identity(), skip);
        }
    }

    /// Check if point at infinity.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Check if on curve y² = x³ + B.
    pub fn is_on_curve(&self) -> Choice {
        (self.y.square() * self.z).ct_eq(&(self.x.square() * self.x + self.z.square() * self.z * B))
            | self.z.is_zero()
    }

    /// Deserialize a standard compressed group element and enforce subgroup
    /// membership. The canonical identity encoding is accepted; protocols such
    /// as BLS that prohibit identity inputs should use
    /// [`Self::from_bytes_validated`].
    pub fn from_bytes(bytes: &[u8; 96]) -> CtOption<Self> {
        G2Affine::from_compressed(bytes).map(G2Projective::from)
    }

    /// Deserialize a nonidentity standard compressed point from a byte slice,
    /// enforcing canonical field encodings, flag rules, curve membership, and
    /// subgroup membership.
    pub fn from_bytes_validated(bytes: &[u8]) -> Result<Self> {
        validate::length("G2Projective::from_bytes", bytes.len(), 96)?;
        let mut encoded = [0u8; 96];
        encoded.copy_from_slice(bytes);
        let point = Self::from_bytes(&encoded)
            .into_option()
            .ok_or_else(|| Error::Processing {
                operation: "G2 deserialization",
                details: "invalid encoding or point outside the prime-order subgroup",
            })?;
        if bool::from(point.is_identity()) {
            return Err(Error::param("point", "identity is not a valid BLS input"));
        }
        Ok(point)
    }

    /// Serialize to compressed bytes.
    pub fn to_bytes(&self) -> [u8; 96] {
        G2Affine::from(self).to_compressed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_decoders_reject_on_curve_non_subgroup_point() {
        // A point on E'(Fp2) whose order is not in the prime-order G2 subgroup.
        let point = G2Affine {
            x: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x89f5_50c8_13db_6431,
                    0xa50b_e8c4_56cd_8a1a,
                    0xa45b_3741_14ca_e851,
                    0xbb61_90f5_bf7f_ff63,
                    0x970c_a02c_3ba8_0bc7,
                    0x02b8_5d24_e840_fbac,
                ]),
                c1: Fp::from_raw_unchecked([
                    0x6888_bc53_d707_16dc,
                    0x3dea_6b41_1768_2d70,
                    0xd8f5_f930_500c_a354,
                    0x6b5e_cb65_56f5_c155,
                    0xc96b_ef04_3477_8ab0,
                    0x0508_1505_5150_06ad,
                ]),
            },
            y: Fp2 {
                c0: Fp::from_raw_unchecked([
                    0x3cf1_ea0d_434b_0f40,
                    0x1a0d_c610_e603_e333,
                    0x7f89_9561_60c7_2fa0,
                    0x25ee_03de_cf64_31c5,
                    0xeee8_e206_ec0f_e137,
                    0x0975_92b2_26df_ef28,
                ]),
                c1: Fp::from_raw_unchecked([
                    0x71e8_bb5f_2924_7367,
                    0xa5fe_049e_2118_31ce,
                    0x0ce6_b354_502a_3896,
                    0x93b0_1200_0997_314e,
                    0x6759_f3b6_aa5b_42ac,
                    0x1569_44c4_dfe9_2bbb,
                ]),
            },
            infinity: Choice::from(0u8),
        };
        assert!(bool::from(point.is_on_curve()));
        assert!(!bool::from(point.is_torsion_free()));

        let encoded = point.to_compressed();
        assert!(bool::from(
            G2Affine::from_compressed_unchecked(&encoded).is_some()
        ));
        assert!(bool::from(G2Projective::from_bytes(&encoded).is_none()));
        assert!(G2Projective::from_bytes_validated(&encoded).is_err());
        assert!(bool::from(G2Affine::from_compressed(&encoded).is_none()));
    }

    #[test]
    fn test_g2_msm() {
        let g = G2Affine::generator();
        let s1 = Scalar::from(5u64);
        let s2 = Scalar::from(6u64);
        let s3 = Scalar::from(7u64);

        let p1 = G2Affine::from(G2Projective::from(g) * s1); // [5]G
        let p2 = G2Affine::from(G2Projective::from(g) * s2); // [6]G
        let p3 = G2Affine::from(G2Projective::from(g) * s3); // [7]G

        let scalars = vec![s1, s2, s3];
        let points = vec![p1, p2, p3];

        // Expected result: 5*[5]G + 6*[6]G + 7*[7]G = (25 + 36 + 49)[G] = [110]G
        let expected = G2Projective::from(g) * Scalar::from(110u64);

        // Naive MSM for comparison
        let naive_result = (p1 * s1) + (p2 * s2) + (p3 * s3);
        assert_eq!(G2Affine::from(naive_result), G2Affine::from(expected));

        // Test msm_vartime
        let msm_result_vartime = G2Projective::msm_vartime(&points, &scalars).unwrap();
        assert_eq!(G2Affine::from(msm_result_vartime), G2Affine::from(expected));

        // Test empty input
        let empty_res = G2Projective::msm_vartime(&[], &[]).unwrap();
        assert_eq!(empty_res, G2Projective::identity());
    }
}
