//! Algorithm-specific ACVP handlers

pub mod aes_cbc;
pub mod aes_ctr;
pub mod aes_gcm;
pub mod ecdh;
pub mod ecdsa;
pub mod eddsa;
pub mod hkdf;
pub mod hmac;
pub mod ml_dsa;
pub mod ml_kem;
pub mod pbkdf2;
pub mod sha2;
pub mod sha3;
pub mod shake;

/// Compare two hexadecimal encodings by value rather than letter case.
/// Invalid encodings never compare equal, including two identical invalid
/// strings, so a malformed conformance vector cannot pass accidentally.
pub(super) fn hex_equal(left: &str, right: &str) -> bool {
    match (hex::decode(left), hex::decode(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::hex_equal;

    #[test]
    fn hexadecimal_comparison_is_case_insensitive_and_fail_closed() {
        assert!(hex_equal("A0b1", "a0B1"));
        assert!(!hex_equal("A0b1", "a0B2"));
        assert!(!hex_equal("not-hex", "not-hex"));
        assert!(!hex_equal("0", "0"));
    }
}
