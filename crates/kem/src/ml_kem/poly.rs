//! ML-KEM-specific polynomial arithmetic and canonical encoding.
//!
//! FIPS 203 uses a seven-layer NTT over `R_q = Z_q[X]/(X^256 + 1)`.
//! This is intentionally local to ML-KEM; the generic cyclic transform in the
//! algorithms crate is not interchangeable with the standardized transform.

use dcrypt_internal::zeroing::{Zeroize, Zeroizing};

use super::params::{N, POLY_BYTES, Q};

const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Poly {
    pub(crate) coeffs: [i16; N],
}

impl Poly {
    pub(crate) const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    pub(crate) fn ntt(&mut self) {
        let mut k = 1usize;
        let mut len = 128usize;
        while len >= 2 {
            let mut start = 0usize;
            while start < N {
                let zeta = ZETAS[k];
                k += 1;
                for j in start..start + len {
                    let t = fqmul(zeta, self.coeffs[j + len]);
                    self.coeffs[j + len] = self.coeffs[j].wrapping_sub(t);
                    self.coeffs[j] = self.coeffs[j].wrapping_add(t);
                }
                start += 2 * len;
            }
            len >>= 1;
        }
        self.reduce();
    }

    /// Inverse NTT, including the Montgomery scaling specified by FIPS 203.
    pub(crate) fn inv_ntt_tomont(&mut self) {
        let mut k = 127usize;
        let mut len = 2usize;
        while len <= 128 {
            let mut start = 0usize;
            while start < N {
                let zeta = ZETAS[k];
                k -= 1;
                for j in start..start + len {
                    let t = self.coeffs[j];
                    self.coeffs[j] = barrett_reduce(t.wrapping_add(self.coeffs[j + len]));
                    self.coeffs[j + len] = self.coeffs[j + len].wrapping_sub(t);
                    self.coeffs[j + len] = fqmul(zeta, self.coeffs[j + len]);
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        for coefficient in &mut self.coeffs {
            *coefficient = fqmul(*coefficient, 1_441);
        }
    }

    pub(crate) fn to_montgomery(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = fqmul(*coefficient, 1_353);
        }
    }

    pub(crate) fn reduce(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = freeze(*coefficient);
        }
    }

    pub(crate) fn add_assign(&mut self, other: &Self) {
        for (left, right) in self.coeffs.iter_mut().zip(other.coeffs.iter()) {
            *left = left.wrapping_add(*right);
        }
    }

    pub(crate) fn sub_assign(&mut self, other: &Self) {
        for (left, right) in self.coeffs.iter_mut().zip(other.coeffs.iter()) {
            *left = left.wrapping_sub(*right);
        }
    }

    pub(crate) fn base_mul(a: &Self, b: &Self) -> Zeroizing<Self> {
        let mut result = Zeroizing::new(Self::zero());
        for i in 0..64 {
            base_mul_pair(
                &mut result.coeffs[4 * i..4 * i + 2],
                &a.coeffs[4 * i..4 * i + 2],
                &b.coeffs[4 * i..4 * i + 2],
                ZETAS[64 + i],
            );
            base_mul_pair(
                &mut result.coeffs[4 * i + 2..4 * i + 4],
                &a.coeffs[4 * i + 2..4 * i + 4],
                &b.coeffs[4 * i + 2..4 * i + 4],
                -ZETAS[64 + i],
            );
        }
        result
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolyVec {
    pub(crate) polys: [Poly; 4],
}

impl PolyVec {
    pub(crate) fn zero() -> Self {
        Self {
            polys: core::array::from_fn(|_| Poly::zero()),
        }
    }

    pub(crate) fn ntt(&mut self, k: usize) {
        for poly in self.polys.iter_mut().take(k) {
            poly.ntt();
        }
    }

    pub(crate) fn inv_ntt_tomont(&mut self, k: usize) {
        for poly in self.polys.iter_mut().take(k) {
            poly.inv_ntt_tomont();
        }
    }

    pub(crate) fn reduce(&mut self, k: usize) {
        for poly in self.polys.iter_mut().take(k) {
            poly.reduce();
        }
    }
}

impl Zeroize for PolyVec {
    fn zeroize(&mut self) {
        self.polys.zeroize();
    }
}

fn base_mul_pair(result: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    let a0b0 = fqmul(a[0], b[0]);
    let a1b1 = fqmul(a[1], b[1]);
    result[0] = a0b0.wrapping_add(fqmul(a1b1, zeta));
    result[1] = fqmul(a[0], b[1]).wrapping_add(fqmul(a[1], b[0]));
}

#[inline]
fn montgomery_reduce(value: i32) -> i16 {
    // QINV = q^(-1) mod 2^16. Casting through i16 selects the signed low word,
    // exactly matching the reference implementation's defined arithmetic.
    let low = value.wrapping_mul(62_209) as i16 as i32;
    ((value - low * i32::from(Q)) >> 16) as i16
}

#[inline]
fn fqmul(left: i16, right: i16) -> i16 {
    montgomery_reduce(i32::from(left) * i32::from(right))
}

#[inline]
fn barrett_reduce(value: i16) -> i16 {
    const V: i32 = 20_159;
    let quotient = ((V * i32::from(value) + (1 << 25)) >> 26) as i16;
    value.wrapping_sub(quotient.wrapping_mul(Q))
}

#[inline]
pub(crate) fn freeze(value: i16) -> i16 {
    let reduced = i32::from(barrett_reduce(value));
    (reduced + ((reduced >> 31) & i32::from(Q))) as i16
}

/// FIPS 203 ByteEncode_d for a single polynomial.
pub(crate) fn encode(poly: &Poly, bits: usize, output: &mut [u8]) {
    debug_assert_eq!(output.len(), N * bits / 8);
    output.fill(0);
    let mask = (1u16 << bits) - 1;
    let mut bit_offset = 0usize;
    for &coefficient in &poly.coeffs {
        let value = (freeze(coefficient) as u16) & mask;
        for bit in 0..bits {
            output[bit_offset >> 3] |= (((value >> bit) & 1) as u8) << (bit_offset & 7);
            bit_offset += 1;
        }
    }
}

/// FIPS 203 ByteDecode_d. The caller checks the input length before calling.
pub(crate) fn decode(input: &[u8], bits: usize) -> Poly {
    debug_assert_eq!(input.len(), N * bits / 8);
    let mut result = Poly::zero();
    let mut bit_offset = 0usize;
    for coefficient in &mut result.coeffs {
        let mut value = 0u16;
        for bit in 0..bits {
            value |= u16::from((input[bit_offset >> 3] >> (bit_offset & 7)) & 1) << bit;
            bit_offset += 1;
        }
        *coefficient = value as i16;
    }
    result
}

pub(crate) fn decode_12_checked(input: &[u8]) -> Option<Poly> {
    if input.len() != POLY_BYTES {
        return None;
    }
    let poly = decode(input, 12);
    let mut canonical = 1u16;
    for &coefficient in &poly.coeffs {
        // Values are 12 bit. Underflow has bit 15 set exactly when c < q.
        canonical &= ((coefficient as u16).wrapping_sub(Q as u16) >> 15) & 1;
    }
    if canonical == 1 {
        Some(poly)
    } else {
        None
    }
}

pub(crate) fn compress(poly: &Poly, bits: usize) -> Poly {
    let mut result = Poly::zero();
    let modulus = 1u32 << bits;
    for (output, &coefficient) in result.coeffs.iter_mut().zip(poly.coeffs.iter()) {
        let coefficient = u32::from(freeze(coefficient) as u16);
        *output = ((((coefficient << bits) + u32::from(Q as u16) / 2) / u32::from(Q as u16))
            & (modulus - 1)) as i16;
    }
    result
}

pub(crate) fn decompress(poly: &Poly, bits: usize) -> Poly {
    let mut result = Poly::zero();
    for (output, &coefficient) in result.coeffs.iter_mut().zip(poly.coeffs.iter()) {
        *output = ((u32::from(coefficient as u16) * u32::from(Q as u16) + (1u32 << (bits - 1)))
            >> bits) as i16;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{decode, decode_12_checked, encode, Poly, POLY_BYTES, Q};

    #[test]
    fn twelve_bit_codec_round_trips_canonical_coefficients() {
        let mut polynomial = Poly::zero();
        for (index, coefficient) in polynomial.coeffs.iter_mut().enumerate() {
            *coefficient = (index as i16 * 31) % Q;
        }
        let mut bytes = [0u8; POLY_BYTES];
        encode(&polynomial, 12, &mut bytes);
        assert_eq!(decode(&bytes, 12), polynomial);
        assert_eq!(decode_12_checked(&bytes), Some(polynomial));
    }

    #[test]
    fn twelve_bit_decoder_rejects_non_canonical_coefficient() {
        let mut bytes = [0u8; POLY_BYTES];
        let q = Q as u16;
        bytes[0] = q as u8;
        bytes[1] = (q >> 8) as u8;
        assert!(decode_12_checked(&bytes).is_none());
    }

    /// Canonical-boundary decoder exercise intended for `cargo miri`.
    #[cfg(miri)]
    #[test]
    fn miri_twelve_bit_canonical_boundaries() {
        for value in [0u16, 1, Q as u16 - 1, Q as u16, Q as u16 + 1, 4095] {
            let mut bytes = [0u8; POLY_BYTES];
            bytes[0] = value as u8;
            bytes[1] = ((value >> 8) as u8) & 0x0f;
            assert_eq!(decode_12_checked(&bytes).is_some(), value < Q as u16);
        }
    }
}
