//! G₁ group implementation for BLS12-381.

use crate::error::{validate, Error, Result};
use core::borrow::Borrow;
use core::fmt;
use core::iter::Sum;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use dcrypt_internal::constant_time::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use dcrypt_internal::random::{CryptoRng, Error as RandomError};
use dcrypt_internal::zeroing::Zeroize;

use super::field::fp::Fp;
use super::Scalar;
#[cfg(feature = "alloc")]
use alloc::vec;

/// G₁ affine point representation.
#[derive(Copy, Clone, Debug)]
pub struct G1Affine {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
    infinity: Choice,
}

impl Default for G1Affine {
    fn default() -> G1Affine {
        G1Affine::identity()
    }
}

impl Zeroize for G1Affine {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.infinity = Choice::from(0);
    }
}

impl fmt::Display for G1Affine {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<'a> From<&'a G1Projective> for G1Affine {
    fn from(p: &'a G1Projective) -> G1Affine {
        let zinv = p.z.invert().unwrap_or(Fp::zero());
        let x = p.x * zinv;
        let y = p.y * zinv;

        let tmp = G1Affine {
            x,
            y,
            infinity: Choice::from(0u8),
        };

        G1Affine::conditional_select(&tmp, &G1Affine::identity(), zinv.is_zero())
    }
}

impl From<G1Projective> for G1Affine {
    fn from(p: G1Projective) -> G1Affine {
        G1Affine::from(&p)
    }
}

impl ConstantTimeEq for G1Affine {
    fn ct_eq(&self, other: &Self) -> Choice {
        (self.infinity & other.infinity)
            | ((!self.infinity)
                & (!other.infinity)
                & self.x.ct_eq(&other.x)
                & self.y.ct_eq(&other.y))
    }
}

impl ConditionallySelectable for G1Affine {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G1Affine {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl Eq for G1Affine {}
impl PartialEq for G1Affine {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<'a> Neg for &'a G1Affine {
    type Output = G1Affine;

    #[inline]
    fn neg(self) -> G1Affine {
        G1Affine {
            x: self.x,
            y: Fp::conditional_select(&-self.y, &Fp::one(), self.infinity),
            infinity: self.infinity,
        }
    }
}

impl Neg for G1Affine {
    type Output = G1Affine;

    #[inline]
    fn neg(self) -> G1Affine {
        -&self
    }
}

impl<'a, 'b> Add<&'b G1Projective> for &'a G1Affine {
    type Output = G1Projective;

    #[inline]
    fn add(self, rhs: &'b G1Projective) -> G1Projective {
        rhs.add_mixed(self)
    }
}

impl<'a, 'b> Add<&'b G1Affine> for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn add(self, rhs: &'b G1Affine) -> G1Projective {
        self.add_mixed(rhs)
    }
}

impl<'a, 'b> Sub<&'b G1Projective> for &'a G1Affine {
    type Output = G1Projective;

    #[inline]
    fn sub(self, rhs: &'b G1Projective) -> G1Projective {
        self + &(-rhs)
    }
}

impl<'a, 'b> Sub<&'b G1Affine> for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn sub(self, rhs: &'b G1Affine) -> G1Projective {
        self + &(-rhs)
    }
}

impl<T> Sum<T> for G1Projective
where
    T: Borrow<G1Projective>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    {
        iter.fold(Self::identity(), |acc, item| acc + item.borrow())
    }
}

// Binop implementations for G1Projective with G1Affine
impl<'b> Add<&'b G1Affine> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: &'b G1Affine) -> G1Projective {
        &self + rhs
    }
}
impl<'a> Add<G1Affine> for &'a G1Projective {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: G1Affine) -> G1Projective {
        self + &rhs
    }
}
impl Add<G1Affine> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: G1Affine) -> G1Projective {
        &self + &rhs
    }
}
impl<'b> Sub<&'b G1Affine> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: &'b G1Affine) -> G1Projective {
        &self - rhs
    }
}
impl<'a> Sub<G1Affine> for &'a G1Projective {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: G1Affine) -> G1Projective {
        self - &rhs
    }
}
impl Sub<G1Affine> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: G1Affine) -> G1Projective {
        &self - &rhs
    }
}
impl SubAssign<G1Affine> for G1Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: G1Affine) {
        *self = &*self - &rhs;
    }
}
impl AddAssign<G1Affine> for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: G1Affine) {
        *self = &*self + &rhs;
    }
}
impl<'b> SubAssign<&'b G1Affine> for G1Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b G1Affine) {
        *self = &*self - rhs;
    }
}
impl<'b> AddAssign<&'b G1Affine> for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &'b G1Affine) {
        *self = &*self + rhs;
    }
}

// Binop implementations for G1Affine with G1Projective
impl<'b> Add<&'b G1Projective> for G1Affine {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: &'b G1Projective) -> G1Projective {
        &self + rhs
    }
}
impl<'a> Add<G1Projective> for &'a G1Affine {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: G1Projective) -> G1Projective {
        self + &rhs
    }
}
impl Add<G1Projective> for G1Affine {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: G1Projective) -> G1Projective {
        &self + &rhs
    }
}
impl<'b> Sub<&'b G1Projective> for G1Affine {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: &'b G1Projective) -> G1Projective {
        &self - rhs
    }
}
impl<'a> Sub<G1Projective> for &'a G1Affine {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: G1Projective) -> G1Projective {
        self - &rhs
    }
}
impl Sub<G1Projective> for G1Affine {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: G1Projective) -> G1Projective {
        &self - &rhs
    }
}

// Curve parameter b = 4
const B: Fp = Fp::from_raw_unchecked([
    0xaa27_0000_000c_fff3,
    0x53cc_0032_fc34_000a,
    0x478f_e97a_6b0a_807f,
    0xb1d3_7ebe_e6ba_24d7,
    0x8ec9_733b_bf78_ab2f,
    0x09d6_4551_3d83_de7e,
]);

/// Cube root of unity in Fp
pub const BETA: Fp = Fp::from_raw_unchecked([
    0x30f1_361b_798a_64e8,
    0xf3b8_ddab_7ece_5a2a,
    0x16a8_ca3a_c615_77f7,
    0xc26a_2ff8_74fd_029b,
    0x3636_b766_6070_1c6e,
    0x051b_a4ab_241b_6160,
]);

fn endomorphism(p: &G1Affine) -> G1Affine {
    let mut res = *p;
    res.x *= BETA;
    res
}

impl G1Affine {
    /// Point at infinity.
    pub fn identity() -> G1Affine {
        G1Affine {
            x: Fp::zero(),
            y: Fp::one(),
            infinity: Choice::from(1u8),
        }
    }

    /// Fixed generator.
    pub fn generator() -> G1Affine {
        G1Affine {
            x: Fp::from_raw_unchecked([
                0x5cb3_8790_fd53_0c16,
                0x7817_fc67_9976_fff5,
                0x154f_95c7_143b_a1c1,
                0xf0ae_6acd_f3d0_e747,
                0xedce_6ecc_21db_f440,
                0x1201_7741_9e0b_fb75,
            ]),
            y: Fp::from_raw_unchecked([
                0xbaac_93d5_0ce7_2271,
                0x8c22_631a_7918_fd8e,
                0xdd59_5f13_5707_25ce,
                0x51ac_5829_5040_5194,
                0x0e1c_8c3f_ad00_59c0,
                0x0bbc_3efc_5008_a26a,
            ]),
            infinity: Choice::from(0u8),
        }
    }

    /// Check if point at infinity.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.infinity
    }

    /// Curve membership check.
    pub fn is_on_curve(&self) -> Choice {
        (self.y.square() - (self.x.square() * self.x)).ct_eq(&B) | self.infinity
    }

    /// Subgroup check using endomorphism.
    pub fn is_torsion_free(&self) -> Choice {
        let minus_x_squared_times_p = G1Projective::from(self).mul_by_x().mul_by_x().neg();
        let endomorphism_p = endomorphism(self);
        minus_x_squared_times_p.ct_eq(&G1Projective::from(endomorphism_p))
    }

    /// Compress to 48 bytes.
    pub fn to_compressed(&self) -> [u8; 48] {
        let mut res = Fp::conditional_select(&self.x, &Fp::zero(), self.infinity).to_bytes();
        res[0] |= 1u8 << 7; // compression flag
        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), self.infinity); // infinity flag
        res[0] |= u8::conditional_select(
            &0u8,
            &(1u8 << 5),
            (!self.infinity) & self.y.lexicographically_largest(), // sign flag
        );
        res
    }

    /// Serialize to 96 bytes uncompressed.
    pub fn to_uncompressed(&self) -> [u8; 96] {
        let mut res = [0; 96];
        res[0..48].copy_from_slice(
            &Fp::conditional_select(&self.x, &Fp::zero(), self.infinity).to_bytes()[..],
        );
        res[48..96].copy_from_slice(
            &Fp::conditional_select(&self.y, &Fp::zero(), self.infinity).to_bytes()[..],
        );
        res[0] |= u8::conditional_select(&0u8, &(1u8 << 6), self.infinity);
        res
    }

    /// Deserialize from uncompressed bytes.
    pub fn from_uncompressed(bytes: &[u8; 96]) -> CtOption<Self> {
        Self::from_uncompressed_unchecked(bytes)
            .and_then(|p| CtOption::new(p, p.is_on_curve() & p.is_torsion_free()))
    }

    /// Internal decoder that omits curve and subgroup validation.
    pub(crate) fn from_uncompressed_unchecked(bytes: &[u8; 96]) -> CtOption<Self> {
        let compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((bytes[0] >> 6) & 1);
        let sort_flag_set = Choice::from((bytes[0] >> 5) & 1);
        let x = {
            let mut tmp = [0; 48];
            tmp.copy_from_slice(&bytes[0..48]);
            tmp[0] &= 0b0001_1111;
            Fp::from_bytes(&tmp)
        };
        let y = Fp::from_bytes(<&[u8; 48]>::try_from(&bytes[48..96]).unwrap());

        x.and_then(|x| {
            y.and_then(|y| {
                let p = G1Affine::conditional_select(
                    &G1Affine {
                        x,
                        y,
                        infinity: infinity_flag_set,
                    },
                    &G1Affine::identity(),
                    infinity_flag_set,
                );
                CtOption::new(
                    p,
                    ((!infinity_flag_set) | (infinity_flag_set & x.is_zero() & y.is_zero()))
                        & (!compression_flag_set)
                        & (!sort_flag_set),
                )
            })
        })
    }

    /// Deserialize from compressed bytes with dcrypt error handling
    pub fn from_compressed(bytes: &[u8; 48]) -> Result<Self> {
        Self::from_compressed_unchecked(bytes)
            .into_option() // Convert CtOption to Option
            .ok_or_else(|| Error::Parameter {
                name: "compressed_bytes".into(),
                reason: "invalid G1 point encoding".into(),
            })
            .and_then(|p| {
                if !bool::from(p.is_torsion_free()) {
                    Err(Error::param("point", "not in correct subgroup"))
                } else {
                    Ok(p)
                }
            })
    }

    /// Internal implementation keeping CtOption for constant-time operations
    pub(crate) fn from_compressed_unchecked(bytes: &[u8; 48]) -> CtOption<Self> {
        let compression_flag_set = Choice::from((bytes[0] >> 7) & 1);
        let infinity_flag_set = Choice::from((bytes[0] >> 6) & 1);
        let sort_flag_set = Choice::from((bytes[0] >> 5) & 1);
        let x = {
            let mut tmp = *bytes;
            tmp[0] &= 0b0001_1111;
            Fp::from_bytes(&tmp)
        };

        x.and_then(|x| {
            CtOption::new(
                G1Affine::identity(),
                infinity_flag_set & compression_flag_set & (!sort_flag_set) & x.is_zero(),
            )
            .or_else(|| {
                ((x.square() * x) + B).sqrt().and_then(|y| {
                    let y = Fp::conditional_select(
                        &y,
                        &-y,
                        y.lexicographically_largest() ^ sort_flag_set,
                    );
                    CtOption::new(
                        G1Affine {
                            x,
                            y,
                            infinity: infinity_flag_set,
                        },
                        (!infinity_flag_set) & compression_flag_set,
                    )
                })
            })
        })
    }
}

/// G₁ projective point representation.
#[derive(Copy, Clone, Debug)]
pub struct G1Projective {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
    pub(crate) z: Fp,
}

impl Default for G1Projective {
    fn default() -> G1Projective {
        G1Projective::identity()
    }
}

impl Zeroize for G1Projective {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

impl fmt::Display for G1Projective {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl<'a> From<&'a G1Affine> for G1Projective {
    fn from(p: &'a G1Affine) -> G1Projective {
        G1Projective {
            x: p.x,
            y: p.y,
            z: Fp::conditional_select(&Fp::one(), &Fp::zero(), p.infinity),
        }
    }
}

impl From<G1Affine> for G1Projective {
    fn from(p: G1Affine) -> G1Projective {
        G1Projective::from(&p)
    }
}

impl ConstantTimeEq for G1Projective {
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

impl ConditionallySelectable for G1Projective {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        G1Projective {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl Eq for G1Projective {}
impl PartialEq for G1Projective {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<'a> Neg for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn neg(self) -> G1Projective {
        G1Projective {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl Neg for G1Projective {
    type Output = G1Projective;

    #[inline]
    fn neg(self) -> G1Projective {
        -&self
    }
}

impl<'a, 'b> Add<&'b G1Projective> for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn add(self, rhs: &'b G1Projective) -> G1Projective {
        self.add(rhs)
    }
}

impl<'a, 'b> Sub<&'b G1Projective> for &'a G1Projective {
    type Output = G1Projective;

    #[inline]
    fn sub(self, rhs: &'b G1Projective) -> G1Projective {
        self + &(-rhs)
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G1Projective {
    type Output = G1Projective;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        self.multiply(&other.to_bytes())
    }
}

impl<'a, 'b> Mul<&'b G1Projective> for &'a Scalar {
    type Output = G1Projective;

    #[inline]
    fn mul(self, rhs: &'b G1Projective) -> Self::Output {
        rhs * self
    }
}

impl<'a, 'b> Mul<&'b Scalar> for &'a G1Affine {
    type Output = G1Projective;

    fn mul(self, other: &'b Scalar) -> Self::Output {
        G1Projective::from(self).multiply(&other.to_bytes())
    }
}

impl<'a, 'b> Mul<&'b G1Affine> for &'a Scalar {
    type Output = G1Projective;

    #[inline]
    fn mul(self, rhs: &'b G1Affine) -> Self::Output {
        rhs * self
    }
}

// Binop implementations for G1Projective
impl<'b> Add<&'b G1Projective> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: &'b G1Projective) -> G1Projective {
        &self + rhs
    }
}
impl<'a> Add<G1Projective> for &'a G1Projective {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: G1Projective) -> G1Projective {
        self + &rhs
    }
}
impl Add<G1Projective> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn add(self, rhs: G1Projective) -> G1Projective {
        &self + &rhs
    }
}
impl<'b> Sub<&'b G1Projective> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: &'b G1Projective) -> G1Projective {
        &self - rhs
    }
}
impl<'a> Sub<G1Projective> for &'a G1Projective {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: G1Projective) -> G1Projective {
        self - &rhs
    }
}
impl Sub<G1Projective> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn sub(self, rhs: G1Projective) -> G1Projective {
        &self - &rhs
    }
}
impl SubAssign<G1Projective> for G1Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: G1Projective) {
        *self = &*self - &rhs;
    }
}
impl AddAssign<G1Projective> for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: G1Projective) {
        *self = &*self + &rhs;
    }
}
impl<'b> SubAssign<&'b G1Projective> for G1Projective {
    #[inline]
    fn sub_assign(&mut self, rhs: &'b G1Projective) {
        *self = &*self - rhs;
    }
}
impl<'b> AddAssign<&'b G1Projective> for G1Projective {
    #[inline]
    fn add_assign(&mut self, rhs: &'b G1Projective) {
        *self = &*self + rhs;
    }
}

// Scalar multiplication binops for G1Projective
impl<'b> Mul<&'b Scalar> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: &'b Scalar) -> G1Projective {
        &self * rhs
    }
}
impl<'a> Mul<Scalar> for &'a G1Projective {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: Scalar) -> G1Projective {
        self * &rhs
    }
}
impl Mul<Scalar> for G1Projective {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: Scalar) -> G1Projective {
        &self * &rhs
    }
}
impl MulAssign<Scalar> for G1Projective {
    #[inline]
    fn mul_assign(&mut self, rhs: Scalar) {
        *self = &*self * &rhs;
    }
}
impl<'b> MulAssign<&'b Scalar> for G1Projective {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b Scalar) {
        *self = &*self * rhs;
    }
}

// Scalar multiplication binops for G1Affine
impl<'b> Mul<&'b Scalar> for G1Affine {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: &'b Scalar) -> G1Projective {
        &self * rhs
    }
}
impl<'a> Mul<Scalar> for &'a G1Affine {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: Scalar) -> G1Projective {
        self * &rhs
    }
}
impl Mul<Scalar> for G1Affine {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: Scalar) -> G1Projective {
        &self * &rhs
    }
}

// Scalar * G1Affine binops
impl<'b> Mul<&'b G1Affine> for Scalar {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: &'b G1Affine) -> G1Projective {
        &self * rhs
    }
}
impl<'a> Mul<G1Affine> for &'a Scalar {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: G1Affine) -> G1Projective {
        self * &rhs
    }
}
impl Mul<G1Affine> for Scalar {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: G1Affine) -> G1Projective {
        &self * &rhs
    }
}

// Scalar * G1Projective binops
impl<'b> Mul<&'b G1Projective> for Scalar {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: &'b G1Projective) -> G1Projective {
        &self * rhs
    }
}
impl<'a> Mul<G1Projective> for &'a Scalar {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: G1Projective) -> G1Projective {
        self * &rhs
    }
}
impl Mul<G1Projective> for Scalar {
    type Output = G1Projective;
    #[inline]
    fn mul(self, rhs: G1Projective) -> G1Projective {
        &self * &rhs
    }
}

#[inline(always)]
fn mul_by_3b(a: Fp) -> Fp {
    let a = a + a; // 2
    let a = a + a; // 4
    a + a + a // 12
}

impl G1Projective {
    /// Point at infinity.
    pub fn identity() -> G1Projective {
        G1Projective {
            x: Fp::zero(),
            y: Fp::one(),
            z: Fp::zero(),
        }
    }

    /// Fixed generator.
    pub fn generator() -> G1Projective {
        G1Projective {
            x: G1Affine::generator().x,
            y: G1Affine::generator().y,
            z: Fp::one(),
        }
    }

    /// Random point generation.
    pub fn random(mut rng: impl CryptoRng) -> core::result::Result<Self, RandomError> {
        loop {
            let x = Fp::random(&mut rng)?;
            let mut sign = [0u8; 1];
            rng.try_fill_bytes(&mut sign)?;
            let flip_sign = sign[0] & 1 != 0;

            let p = ((x.square() * x) + B).sqrt().map(|y| G1Affine {
                x,
                y: if flip_sign { -y } else { y },
                infinity: 0.into(),
            });

            if p.is_some().into() {
                let p_proj = G1Projective::from(p.unwrap());
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
    /// This method is faster for non-sensitive operations where timing side-channels
    /// are not a concern, as it contains input-dependent branches.
    ///
    /// # Panics
    /// Panics if `points.len() != scalars.len()`.
    #[cfg(feature = "alloc")]
    pub fn msm_vartime(points: &[G1Affine], scalars: &[Scalar]) -> Result<Self> {
        if points.len() != scalars.len() {
            return Err(Error::Parameter {
                name: "points/scalars".into(),
                reason: "Input slices must have the same length".into(),
            });
        }
        Ok(Self::pippenger(points, scalars, true))
    }

    /// Multi-scalar multiplication using a constant-time Pippenger's algorithm.
    ///
    /// This method is suitable for cryptographic operations where resistance to
    /// timing side-channels is required.
    ///
    /// # Panics
    /// Panics if `points.len() != scalars.len()`.
    #[cfg(feature = "alloc")]
    pub fn msm(points: &[G1Affine], scalars: &[Scalar]) -> Result<Self> {
        if points.len() != scalars.len() {
            return Err(Error::Parameter {
                name: "points/scalars".into(),
                reason: "Input slices must have the same length".into(),
            });
        }
        Ok(Self::pippenger(points, scalars, false))
    }

    /// Internal Pippenger's algorithm implementation.
    #[cfg(feature = "alloc")]
    fn pippenger(points: &[G1Affine], scalars: &[Scalar], is_vartime: bool) -> Self {
        if points.is_empty() {
            return Self::identity();
        }

        let num_entries = points.len();
        let scalar_bits = 255; // BLS12-381 scalar size

        // 1. Choose window size `c`.
        // If constant-time, we limit window size to avoid excessive bucket scanning.
        let c = if is_vartime {
            if num_entries < 32 {
                3
            } else {
                // Integer log2 equivalent: floor(log2(n))
                // Works in no_std without libm
                let log2 = (usize::BITS - num_entries.leading_zeros() - 1) as usize;
                log2 + 2
            }
        } else {
            // Fixed window size for constant time to ensure predictable performance.
            // c=4 means 16 buckets.
            4
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

                if is_vartime {
                    if k > 0 {
                        buckets[k - 1] = buckets[k - 1].add_mixed(&points[i]);
                    }
                } else {
                    // Constant-time bucket accumulation
                    // Iterate all buckets, conditionally add point if bucket index matches k-1.
                    // If k=0 (scalar chunk is 0), we don't add to any bucket (add identity).

                    for b in 0..num_buckets {
                        let bucket_idx = b + 1;
                        // Check whether k equals bucket_idx with the owned CT trait.
                        let choice = k.ct_eq(&bucket_idx);

                        let res = buckets[b].add_mixed(&points[i]);
                        buckets[b] = G1Projective::conditional_select(&buckets[b], &res, choice);
                    }
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
    pub fn double(&self) -> G1Projective {
        // Algorithm 9 from https://eprint.iacr.org/2015/1060.pdf
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

        let tmp = G1Projective {
            x: x3,
            y: y3,
            z: z3,
        };
        G1Projective::conditional_select(&tmp, &G1Projective::identity(), self.is_identity())
    }

    /// Point addition.
    pub fn add(&self, rhs: &G1Projective) -> G1Projective {
        // Algorithm 7 from https://eprint.iacr.org/2015/1060.pdf
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

        G1Projective {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Mixed addition with affine point.
    pub fn add_mixed(&self, rhs: &G1Affine) -> G1Projective {
        // Algorithm 8 from https://eprint.iacr.org/2015/1060.pdf
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

        let tmp = G1Projective {
            x: x3,
            y: y3,
            z: z3,
        };
        G1Projective::conditional_select(&tmp, self, rhs.is_identity())
    }

    fn multiply(&self, by: &[u8; 32]) -> G1Projective {
        let mut acc = G1Projective::identity();
        for &byte in by.iter().rev() {
            for i in (0..8).rev() {
                acc = acc.double();
                let bit = Choice::from((byte >> i) & 1u8);
                acc = G1Projective::conditional_select(&acc, &(acc + self), bit);
            }
        }
        acc
    }

    fn mul_by_x(&self) -> G1Projective {
        let mut xself = G1Projective::identity();
        let mut x = super::BLS_X >> 1;
        let mut tmp = *self;
        while x != 0 {
            tmp = tmp.double();
            if x % 2 == 1 {
                xself += tmp;
            }
            x >>= 1;
        }
        if super::BLS_X_IS_NEGATIVE {
            xself = -xself;
        }
        xself
    }

    /// Clear cofactor using [x - 1] method.
    pub fn clear_cofactor(&self) -> G1Projective {
        self - &self.mul_by_x()
    }

    /// Batch affine conversion.
    pub fn batch_normalize(p: &[Self], q: &mut [G1Affine]) {
        assert_eq!(p.len(), q.len());

        let mut acc = Fp::one();
        for (p, q) in p.iter().zip(q.iter_mut()) {
            q.x = acc;
            acc = Fp::conditional_select(&(acc * p.z), &acc, p.is_identity());
        }

        acc = acc.invert().unwrap();

        for (p, q) in p.iter().rev().zip(q.iter_mut().rev()) {
            let skip = p.is_identity();
            let tmp = q.x * acc;
            acc = Fp::conditional_select(&(acc * p.z), &acc, skip);
            q.x = p.x * tmp;
            q.y = p.y * tmp;
            q.infinity = Choice::from(0u8);
            *q = G1Affine::conditional_select(q, &G1Affine::identity(), skip);
        }
    }

    /// Check if point at infinity.
    #[inline]
    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Curve membership check.
    pub fn is_on_curve(&self) -> Choice {
        (self.y.square() * self.z).ct_eq(&(self.x.square() * self.x + self.z.square() * self.z * B))
            | self.z.is_zero()
    }

    /// Deserialize a standard compressed group element and enforce subgroup
    /// membership. The canonical identity encoding is accepted; protocols such
    /// as BLS that prohibit identity inputs should use
    /// [`Self::from_bytes_validated`].
    pub fn from_bytes(bytes: &[u8; 48]) -> CtOption<Self> {
        G1Affine::from_compressed_unchecked(bytes)
            .and_then(|point| CtOption::new(point, point.is_torsion_free()))
            .map(G1Projective::from)
    }

    /// Deserialize a nonidentity standard compressed point with strict BLS input
    /// validation: canonical encoding, curve membership, and subgroup membership.
    pub fn from_bytes_validated(bytes: &[u8]) -> Result<Self> {
        // Use dcrypt validation
        validate::length("G1Projective::from_bytes", bytes.len(), 48)?;

        let mut array = [0u8; 48];
        array.copy_from_slice(bytes);

        let point = Self::from_bytes(&array)
            .into_option()
            .ok_or_else(|| Error::Processing {
                operation: "G1 deserialization",
                details: "invalid encoding or point outside the prime-order subgroup",
            })?;
        if bool::from(point.is_identity()) {
            return Err(Error::param("point", "identity is not a valid BLS input"));
        }
        Ok(point)
    }

    /// Serialize to compressed bytes.
    pub fn to_bytes(&self) -> [u8; 48] {
        G1Affine::from(self).to_compressed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_decoders_reject_on_curve_non_subgroup_point() {
        // A point on E(Fp) whose order is not in the prime-order G1 subgroup.
        let point = G1Affine {
            x: Fp::from_raw_unchecked([
                0x0aba_f895_b97e_43c8,
                0xba4c_6432_eb9b_61b0,
                0x1250_6f52_adfe_307f,
                0x7502_8c34_3933_6b72,
                0x8474_4f05_b8e9_bd71,
                0x113d_554f_b095_54f7,
            ]),
            y: Fp::from_raw_unchecked([
                0x73e9_0e88_f5cf_01c0,
                0x3700_7b65_dd31_97e2,
                0x5cf9_a199_2f0d_7c78,
                0x4f83_c10b_9eb3_330d,
                0xf6a6_3f6f_07f6_0961,
                0x0c53_b5b9_7e63_4df3,
            ]),
            infinity: Choice::from(0u8),
        };
        assert!(bool::from(point.is_on_curve()));
        assert!(!bool::from(point.is_torsion_free()));

        let encoded = point.to_compressed();
        assert!(bool::from(
            G1Affine::from_compressed_unchecked(&encoded).is_some()
        ));
        assert!(bool::from(G1Projective::from_bytes(&encoded).is_none()));
        assert!(G1Projective::from_bytes_validated(&encoded).is_err());
        assert!(G1Affine::from_compressed(&encoded).is_err());

        // Identity public keys and signatures satisfy the min-pk pairing
        // equation for every message. Group-element decoding intentionally
        // accepts the canonical identity, while the strict BLS input decoder
        // rejects it; protocol code must use the latter for attacker inputs.
        use crate::ec::bls12_381::{pairing, G2Affine, G2Projective};
        let message_point = G2Affine::from(
            G2Projective::hash_to_curve(
                b"arbitrary message",
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
            )
            .unwrap(),
        );
        assert_eq!(
            pairing(&G1Affine::identity(), &message_point),
            pairing(&G1Affine::generator(), &G2Affine::identity())
        );
    }

    #[test]
    fn test_g1_msm() {
        let g = G1Affine::generator();
        let s1 = Scalar::from(2u64);
        let s2 = Scalar::from(3u64);
        let s3 = Scalar::from(4u64);

        let p1 = G1Affine::from(G1Projective::from(g) * s1); // [2]G
        let p2 = G1Affine::from(G1Projective::from(g) * s2); // [3]G
        let p3 = G1Affine::from(G1Projective::from(g) * s3); // [4]G

        let scalars = vec![s1, s2, s3];
        let points = vec![p1, p2, p3];

        // Expected result: 2*[2]G + 3*[3]G + 4*[4]G = (4 + 9 + 16)[G] = [29]G
        let expected = G1Projective::from(g) * Scalar::from(29u64);

        // Naive MSM for comparison
        let naive_result = (p1 * s1) + (p2 * s2) + (p3 * s3);
        assert_eq!(G1Affine::from(naive_result), G1Affine::from(expected));

        // Test msm_vartime
        let msm_result_vartime = G1Projective::msm_vartime(&points, &scalars).unwrap();
        assert_eq!(G1Affine::from(msm_result_vartime), G1Affine::from(expected));

        // Test msm
        let msm_result = G1Projective::msm(&points, &scalars).unwrap();
        assert_eq!(G1Affine::from(msm_result), G1Affine::from(expected));

        // Test empty input
        let empty_res = G1Projective::msm(&[], &[]).unwrap();
        assert_eq!(empty_res, G1Projective::identity());
    }
}
