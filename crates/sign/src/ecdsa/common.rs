//! Common utilities for ECDSA implementations

use dcrypt_api::{error::Error as ApiError, Result as ApiResult};

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

    fn parse_integer(der: &[u8], pos: &mut usize, name: &'static str) -> ApiResult<Vec<u8>> {
        let tag = *der.get(*pos).ok_or_else(|| ApiError::InvalidSignature {
            context: "ECDSA DER parsing",
            #[cfg(feature = "std")]
            message: format!("Missing DER INTEGER tag for {name}"),
        })?;
        if tag != 0x02 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("Invalid DER INTEGER tag for {name}"),
            });
        }
        *pos += 1;

        let (len, next_pos) = Self::parse_length(der, *pos)?;
        *pos = next_pos;
        if len == 0 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("DER INTEGER {name} cannot be empty"),
            });
        }

        let int_end = pos
            .checked_add(len)
            .ok_or_else(|| ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("DER INTEGER {name} length overflow"),
            })?;

        let value = der
            .get(*pos..int_end)
            .ok_or_else(|| ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("Truncated DER INTEGER {name}"),
            })?;

        if value.len() > 1 && value[0] == 0x00 && value[1] & 0x80 == 0 {
            return Err(ApiError::InvalidSignature {
                context: "ECDSA DER parsing",
                #[cfg(feature = "std")]
                message: format!("DER INTEGER {name} is not minimally encoded"),
            });
        }

        *pos = int_end;
        Ok(value.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
