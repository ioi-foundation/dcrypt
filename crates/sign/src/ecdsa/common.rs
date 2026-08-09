//! Common utilities for ECDSA implementations

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_api::{error::Error as ApiError, Result as ApiResult, ZeroizingBytes};
use dcrypt_internal::{boxed_bytes_zeroed, Choice, Zeroize, Zeroizing};

fn nonce_error(_message: &'static str) -> ApiError {
    ApiError::InvalidParameter {
        context: "RFC 6979 nonce generation",
        #[cfg(feature = "std")]
        message: _message.into(),
    }
}

fn hmac_parts<H: HashFunction + Clone>(key: &[u8], parts: &[&[u8]]) -> ApiResult<ZeroizingBytes> {
    let mut mac = Hmac::<H>::new(key).map_err(ApiError::from)?;
    for part in parts {
        mac.update(part).map_err(ApiError::from)?;
    }
    mac.finalize().map_err(ApiError::from)
}

fn replace_zeroized(destination: &mut ZeroizingBytes, replacement: ZeroizingBytes) {
    *destination = replacement;
}

fn subtract_be(value: &mut [u8], modulus: &[u8]) {
    let mut borrow = 0u16;
    for index in (0..value.len()).rev() {
        let difference = value[index] as i16 - modulus[index] as i16 - borrow as i16;
        if difference < 0 {
            value[index] = (difference + 256) as u8;
            borrow = 1;
        } else {
            value[index] = difference as u8;
            borrow = 0;
        }
    }
}

fn shift_right_be(value: &mut [u8], shift: usize) {
    debug_assert!(shift < 8);
    if shift == 0 {
        return;
    }
    let mut carry = 0u8;
    for byte in value {
        let next_carry = *byte << (8 - shift);
        *byte = (*byte >> shift) | carry;
        carry = next_carry;
    }
}

/// RFC 6979 `bits2int`, returned as exactly `rolen = ceil(qlen / 8)` bytes.
fn bits2int(input: &[u8], qlen: usize, rolen: usize) -> ApiResult<ZeroizingBytes> {
    if qlen == 0 || rolen == 0 || qlen > rolen * 8 || qlen <= (rolen - 1) * 8 {
        return Err(nonce_error("invalid subgroup-order bit length"));
    }

    let mut output = Zeroizing::new(boxed_bytes_zeroed(rolen));
    if input.len() >= rolen {
        output.copy_from_slice(&input[..rolen]);
        shift_right_be(&mut output, rolen * 8 - qlen);
    } else {
        output[rolen - input.len()..].copy_from_slice(input);
    }
    Ok(output)
}

/// RFC 6979 `bits2octets`: reduce the leftmost `qlen` digest bits modulo q.
pub(crate) fn bits2octets(hash: &[u8], order: &[u8], qlen: usize) -> ApiResult<ZeroizingBytes> {
    let rolen = order.len();
    let mut output = bits2int(hash, qlen, rolen)?;
    if &output[..] >= order {
        subtract_be(&mut output, order);
    }
    Ok(output)
}

fn ct_valid_nonce(candidate: &[u8], order: &[u8]) -> Choice {
    if candidate.len() != order.len() {
        return Choice::from(0);
    }

    let mut nonzero = 0u8;
    let mut less = 0u8;
    let mut greater = 0u8;
    for (&candidate_byte, &order_byte) in candidate.iter().zip(order) {
        nonzero |= candidate_byte;
        let undecided = (less | greater) ^ 1;
        let byte_less = ((candidate_byte as u16).wrapping_sub(order_byte as u16) >> 15) as u8;
        let byte_greater = ((order_byte as u16).wrapping_sub(candidate_byte as u16) >> 15) as u8;
        less |= byte_less & undecided;
        greater |= byte_greater & undecided;
    }

    let is_nonzero = ((nonzero | nonzero.wrapping_neg()) >> 7) & 1;
    Choice::from(is_nonzero & less)
}

/// Stateful RFC 6979 section 3.2 nonce generator.
///
/// Keeping `K` and `V` alive matters for the astronomically unlikely ECDSA
/// retry case (`r = 0` or `s = 0`): the next nonce follows step H rather than
/// repeating the same deterministic candidate forever.
pub(crate) struct Rfc6979<H> {
    k: ZeroizingBytes,
    v: ZeroizingBytes,
    order: Vec<u8>,
    qlen: usize,
    candidate_was_returned: bool,
    hash: PhantomData<H>,
}

impl<H: HashFunction + Clone> Rfc6979<H> {
    pub(crate) fn new(
        secret_scalar: &[u8],
        message_hash: &[u8],
        order: &[u8],
        qlen: usize,
    ) -> ApiResult<Self> {
        if secret_scalar.len() != order.len() || !bool::from(ct_valid_nonce(secret_scalar, order)) {
            return Err(nonce_error("secret scalar is not canonical"));
        }
        let mut h1 = bits2octets(message_hash, order, qlen)?;
        let output_len = H::output_size();
        if output_len == 0 {
            return Err(nonce_error("hash output is empty"));
        }

        let mut k = Zeroizing::new(boxed_bytes_zeroed(output_len));
        let mut v = Zeroizing::new(boxed_bytes_zeroed(output_len));
        v.fill(1);
        let initialization = (|| -> ApiResult<()> {
            let next_k = hmac_parts::<H>(&k, &[&v, &[0], secret_scalar, &h1])?;
            replace_zeroized(&mut k, next_k);
            let next_v = hmac_parts::<H>(&k, &[&v])?;
            replace_zeroized(&mut v, next_v);
            let next_k = hmac_parts::<H>(&k, &[&v, &[1], secret_scalar, &h1])?;
            replace_zeroized(&mut k, next_k);
            let next_v = hmac_parts::<H>(&k, &[&v])?;
            replace_zeroized(&mut v, next_v);
            Ok(())
        })();
        h1.zeroize();
        if let Err(error) = initialization {
            k.zeroize();
            v.zeroize();
            return Err(error);
        }
        Ok(Self {
            k,
            v,
            order: order.to_vec(),
            qlen,
            candidate_was_returned: false,
            hash: PhantomData,
        })
    }

    fn retry_step(&mut self) -> ApiResult<()> {
        let next_k = hmac_parts::<H>(&self.k, &[&self.v, &[0]])?;
        replace_zeroized(&mut self.k, next_k);
        let next_v = hmac_parts::<H>(&self.k, &[&self.v])?;
        replace_zeroized(&mut self.v, next_v);
        Ok(())
    }

    pub(crate) fn next_nonce(&mut self) -> ApiResult<ZeroizingBytes> {
        if self.candidate_was_returned {
            self.retry_step()?;
            self.candidate_was_returned = false;
        }

        loop {
            let mut t = Zeroizing::new(boxed_bytes_zeroed(self.order.len()));
            let mut written = 0;
            while written < self.order.len() {
                let next_v = hmac_parts::<H>(&self.k, &[&self.v])?;
                replace_zeroized(&mut self.v, next_v);
                let needed = self.order.len() - written;
                let take = core::cmp::min(needed, self.v.len());
                t[written..written + take].copy_from_slice(&self.v[..take]);
                written += take;
            }

            let mut candidate = bits2int(&t, self.qlen, self.order.len())?;
            if bool::from(ct_valid_nonce(&candidate, &self.order)) {
                self.candidate_was_returned = true;
                return Ok(candidate);
            }
            candidate.zeroize();
            self.retry_step()?;
        }
    }
}

impl<H> Drop for Rfc6979<H> {
    fn drop(&mut self) {
        self.k.zeroize();
        self.v.zeroize();
        self.order.zeroize();
        self.qlen.zeroize();
        self.candidate_was_returned.zeroize();
    }
}

/// Return true when a canonical big-endian scalar lies above `order / 2`.
///
/// ECDSA admits both `(r, s)` and `(r, n - s)`. Requiring the lower half of
/// the scalar range gives signatures a unique representation.
pub(crate) fn is_high_s(s: &[u8], order: &[u8]) -> bool {
    if s.len() != order.len() {
        return true;
    }
    let mut carry = 0u8;
    for (&scalar_byte, &order_byte) in s.iter().zip(order) {
        let half_order_byte = (order_byte >> 1) | (carry << 7);
        let next_carry = order_byte & 1;
        if scalar_byte != half_order_byte {
            return scalar_byte > half_order_byte;
        }
        carry = next_carry;
    }
    false
}

/// Return true only for a fixed-width, non-zero scalar strictly below the
/// curve order. DER signature components are integers, not values to be
/// silently reduced modulo the order.
pub(crate) fn is_canonical_nonzero_scalar(value: &[u8], order: &[u8]) -> bool {
    value.len() == order.len() && value.iter().any(|&byte| byte != 0) && value < order
}

/// ECDSA signature components (r, s)
#[derive(Clone, Debug)]
pub struct SignatureComponents {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
}

impl SignatureComponents {
    /// Serialize signature to DER format
    pub fn to_der(&self) -> Vec<u8> {
        // DER encoding: SEQUENCE { INTEGER r, INTEGER s }
        let mut der = Vec::new();

        // Add SEQUENCE tag
        der.push(0x30);

        let r_bytes = self.encode_integer(&self.r);
        let s_bytes = self.encode_integer(&self.s);

        let mut sequence = Vec::with_capacity(2 + r_bytes.len() + 2 + s_bytes.len());
        sequence.push(0x02); // INTEGER tag
        Self::encode_length(&mut sequence, r_bytes.len());
        sequence.extend_from_slice(&r_bytes);

        sequence.push(0x02); // INTEGER tag
        Self::encode_length(&mut sequence, s_bytes.len());
        sequence.extend_from_slice(&s_bytes);

        Self::encode_length(&mut der, sequence.len());
        der.extend_from_slice(&sequence);
        der
    }

    /// Parse signature from DER format
    pub fn from_der(der: &[u8]) -> ApiResult<Self> {
        if der.len() < 2 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "DER signature too short".to_string(),
            });
        }

        // Check SEQUENCE tag
        if der[0] != 0x30 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "Invalid DER SEQUENCE tag".to_string(),
            });
        }

        let (seq_len, mut pos) = Self::parse_length(der, 1)?;
        let seq_end = pos
            .checked_add(seq_len)
            .ok_or_else(|| ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "DER sequence length overflow".to_string(),
            })?;

        if seq_end != der.len() {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "DER sequence length mismatch".to_string(),
            });
        }

        let r = Self::parse_integer(der, &mut pos, "r")?;
        let s = Self::parse_integer(der, &mut pos, "s")?;

        if pos != seq_end {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "Trailing data after ECDSA signature".to_string(),
            });
        }

        Ok(SignatureComponents {
            r: Self::decode_integer(&r),
            s: Self::decode_integer(&s),
        })
    }

    /// Encode integer for DER (add leading zero if high bit set)
    fn encode_integer(&self, bytes: &[u8]) -> Vec<u8> {
        let mut start = 0usize;
        while start + 1 < bytes.len() && bytes[start] == 0x00 {
            start += 1;
        }

        let trimmed = if bytes.is_empty() {
            &[0x00][..]
        } else {
            &bytes[start..]
        };

        if trimmed[0] & 0x80 == 0 {
            trimmed.to_vec()
        } else {
            let mut result = vec![0x00];
            result.extend_from_slice(trimmed);
            result
        }
    }

    /// Decode integer from DER (remove leading zeros)
    fn decode_integer(bytes: &[u8]) -> Vec<u8> {
        let mut result = bytes.to_vec();
        while result.len() > 1 && result[0] == 0x00 {
            result.remove(0);
        }
        result
    }

    fn encode_length(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
            return;
        }

        let mut buf = [0u8; core::mem::size_of::<usize>()];
        let mut written = 0usize;
        let mut value = len;

        while value > 0 {
            buf[buf.len() - 1 - written] = (value & 0xFF) as u8;
            value >>= 8;
            written += 1;
        }

        out.push(0x80 | written as u8);
        out.extend_from_slice(&buf[buf.len() - written..]);
    }

    fn parse_length(der: &[u8], pos: usize) -> ApiResult<(usize, usize)> {
        let first = *der.get(pos).ok_or_else(|| ApiError::InvalidSignature {
            context: "ECDSA DER parsing",
            #[cfg(feature = "std")]
            message: "Missing DER length".to_string(),
        })?;

        if first & 0x80 == 0 {
            return Ok((first as usize, pos + 1));
        }

        let num_len_bytes = (first & 0x7F) as usize;
        if num_len_bytes == 0 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "Indefinite DER lengths are not allowed".to_string(),
            });
        }
        if num_len_bytes > core::mem::size_of::<usize>() {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "DER length is too large".to_string(),
            });
        }

        let len_end = pos + 1 + num_len_bytes;
        let len_bytes = der
            .get(pos + 1..len_end)
            .ok_or_else(|| ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "Truncated DER length".to_string(),
            })?;

        if len_bytes.first() == Some(&0x00) {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "DER length must use minimal encoding".to_string(),
            });
        }

        let mut len = 0usize;
        for &byte in len_bytes {
            len = len
                .checked_shl(8)
                .ok_or_else(|| ApiError::InvalidSignature {
                    context: "ECDSA DER parsing",
                    #[cfg(feature = "std")]
                    message: "DER length overflow".to_string(),
                })?;
            len |= byte as usize;
        }

        if len < 0x80 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: "DER length must use short form".to_string(),
            });
        }

        Ok((len, len_end))
    }

    fn parse_integer(der: &[u8], pos: &mut usize, _name: &'static str) -> ApiResult<Vec<u8>> {
        let tag = *der.get(*pos).ok_or_else(|| ApiError::InvalidSignature {
            context: "ECDSA DER parsing",
            #[cfg(feature = "std")]
            message: format!("Missing DER INTEGER tag for {_name}"),
        })?;
        if tag != 0x02 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("Invalid DER INTEGER tag for {_name}"),
            });
        }
        *pos += 1;

        let (len, next_pos) = Self::parse_length(der, *pos)?;
        *pos = next_pos;
        if len == 0 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("DER INTEGER {_name} cannot be empty"),
            });
        }

        let int_end = pos
            .checked_add(len)
            .ok_or_else(|| ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("DER INTEGER {_name} length overflow"),
            })?;

        let value = der
            .get(*pos..int_end)
            .ok_or_else(|| ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("Truncated DER INTEGER {_name}"),
            })?;

        // ECDSA components are non-negative ASN.1 INTEGERs. Interpreting a
        // negative two's-complement INTEGER as an unsigned magnitude creates
        // multiple accepted encodings for the same mathematical value.
        if value[0] & 0x80 != 0 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("DER INTEGER {_name} must not be negative"),
            });
        }

        if value.len() > 1 && value[0] == 0x00 && value[1] & 0x80 == 0 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("DER INTEGER {_name} is not minimally encoded"),
            });
        }

        *pos = int_end;
        Ok(value.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcrypt_algorithms::hash::sha2::{Sha224, Sha256, Sha384, Sha512};

    fn rfc6979_vector<H: HashFunction + Clone>(
        secret_hex: &str,
        order_hex: &str,
        qlen: usize,
        expected_nonce_hex: &str,
    ) {
        let secret = hex::decode(secret_hex).unwrap();
        let order = hex::decode(order_hex).unwrap();
        let digest = H::digest(b"sample").unwrap();
        let mut generator = Rfc6979::<H>::new(&secret, digest.as_ref(), &order, qlen).unwrap();
        let nonce = generator.next_nonce().unwrap();
        let expected = hex::decode(expected_nonce_hex).unwrap();
        assert_eq!(nonce.as_slice(), expected.as_slice());
    }

    #[test]
    fn rfc6979_prime_curve_nonce_vectors() {
        // RFC 6979 appendices A.2.3 through A.2.7, message = "sample".
        rfc6979_vector::<Sha256>(
            "6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4",
            "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831",
            192,
            "32B1B6D7D42A05CB449065727A84804FB1A3E34D8F261496",
        );
        rfc6979_vector::<Sha224>(
            "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D",
            224,
            "C1D1F2F10881088301880506805FEB4825FE09ACB6816C36991AA06D",
        );
        rfc6979_vector::<Sha256>(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
            256,
            "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
        );
        rfc6979_vector::<Sha384>(
            concat!(
                "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8",
                "96D5724E4C70A825F872C9EA60D2EDF5"
            ),
            concat!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF",
                "581A0DB248B0A77AECEC196ACCC52973"
            ),
            384,
            concat!(
                "94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA",
                "2907E3E83BA95368623B8C4686915CF9"
            ),
        );
        rfc6979_vector::<Sha512>(
            concat!(
                "00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C",
                "AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83",
                "538"
            ),
            concat!(
                "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "FA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386",
                "409"
            ),
            521,
            concat!(
                "01DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F1019",
                "8B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBF",
                "FD3"
            ),
        );
    }

    #[test]
    fn canonical_scalar_check_rejects_zero_order_and_larger_values() {
        let order = [0x01, 0x00];
        assert!(is_canonical_nonzero_scalar(&[0x00, 0xff], &order));
        assert!(!is_canonical_nonzero_scalar(&[0x00, 0x00], &order));
        assert!(!is_canonical_nonzero_scalar(&order, &order));
        assert!(!is_canonical_nonzero_scalar(&[0x01, 0x01], &order));
        assert!(!is_canonical_nonzero_scalar(&[0xff], &order));
    }

    #[test]
    fn test_der_encoding() {
        let sig = SignatureComponents {
            r: vec![0x01, 0x23, 0x45, 0x67],
            s: vec![0x89, 0xAB, 0xCD, 0xEF],
        };

        let der = sig.to_der();
        let parsed = SignatureComponents::from_der(&der).unwrap();

        assert_eq!(sig.r, parsed.r);
        assert_eq!(sig.s, parsed.s);
    }

    #[test]
    fn test_der_with_high_bit() {
        // Test encoding when high bit is set (requires leading zero)
        let sig = SignatureComponents {
            r: vec![0xFF, 0x23, 0x45, 0x67],
            s: vec![0x79, 0xAB, 0xCD, 0xEF],
        };

        let der = sig.to_der();

        // Check that r has leading zero in DER
        assert_eq!(der[3], 5); // r length should be 5 (extra zero byte)
        assert_eq!(der[4], 0x00); // leading zero
        assert_eq!(der[5], 0xFF); // original first byte

        // Parse back and verify
        let parsed = SignatureComponents::from_der(&der).unwrap();
        assert_eq!(sig.r, parsed.r);
        assert_eq!(sig.s, parsed.s);
    }

    #[test]
    fn test_der_long_form_sequence_length_roundtrip() {
        let sig = SignatureComponents {
            r: vec![0x7F; 66],
            s: vec![0x80; 66],
        };

        let der = sig.to_der();
        assert_eq!(der[0], 0x30);
        assert_eq!(der[1], 0x81);

        let parsed = SignatureComponents::from_der(&der).unwrap();
        assert_eq!(sig.r, parsed.r);
        assert_eq!(sig.s, parsed.s);
    }

    #[test]
    fn test_der_rejects_truncated_lengths_without_panicking() {
        let malformed = [0x30, 0x06, 0x02, 0x02, 0x01];
        assert!(SignatureComponents::from_der(&malformed).is_err());
    }

    #[test]
    fn test_der_rejects_trailing_bytes() {
        let der = [0x30, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00];
        assert!(SignatureComponents::from_der(&der).is_err());
    }

    #[test]
    fn test_der_rejects_negative_integers() {
        let negative_r = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        let negative_s = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0xff];
        assert!(SignatureComponents::from_der(&negative_r).is_err());
        assert!(SignatureComponents::from_der(&negative_s).is_err());
    }
}
