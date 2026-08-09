//! Tests for ECDSA P-384 implementation

use super::*; // Imports items from the parent module (p384/mod.rs)
use crate::ecdsa::common::SignatureComponents; // For DER parsing tests
use dcrypt_algorithms::hash::sha2::Sha384;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_api::error::Error as ApiError; // Use the API error type
use dcrypt_api::Signature as SignatureTrait;
use dcrypt_internal::ChaCha20Rng;

fn test_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x42; 32])
}
use std::fs;
use std::path::PathBuf;

#[test]
fn rfc6979_sha384_sample_signature_matches() {
    let bytes: [u8; ec::P384_SCALAR_SIZE] = hex::decode(concat!(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8",
        "96D5724E4C70A825F872C9EA60D2EDF5"
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let secret = EcdsaP384SecretKey {
        raw: ec::Scalar::new(bytes).unwrap(),
        bytes,
    };
    let signature = EcdsaP384::sign(b"sample", &secret).unwrap();
    let components = SignatureComponents::from_der(signature.as_ref()).unwrap();

    assert_eq!(
        components.r,
        hex::decode(concat!(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C",
            "81A648152E44ACF96E36DD1E80FABE46"
        ))
        .unwrap()
    );
    let expected_rfc_s: [u8; ec::P384_SCALAR_SIZE] = hex::decode(concat!(
        "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F",
        "A329C145786E679E7B82C71A38628AC8"
    ))
    .unwrap()
    .try_into()
    .unwrap();
    let expected_rfc_s = ec::Scalar::new(expected_rfc_s).unwrap();
    let expected_low_s = expected_rfc_s.negate().serialize();
    assert_eq!(components.s, expected_low_s.to_vec());
}

#[test]
fn test_ecdsa_p384_signatures_are_low_s_and_high_s_is_rejected() {
    let (public_key, secret_key) = EcdsaP384::keypair(&mut test_rng()).unwrap();
    let message = b"canonical";
    let signature = EcdsaP384::sign(message, &secret_key).unwrap();
    let components = SignatureComponents::from_der(&signature.0).unwrap();
    let mut s = [0u8; ec::P384_SCALAR_SIZE];
    s[ec::P384_SCALAR_SIZE - components.s.len()..].copy_from_slice(&components.s);
    let s = ec::Scalar::new(s).unwrap();
    assert!(!is_high_s(&s.serialize(), &NIST_P384.n));

    let high_s = s.negate();
    assert!(is_high_s(&high_s.serialize(), &NIST_P384.n));
    let malleable = EcdsaP384Signature(
        SignatureComponents {
            r: components.r.clone(),
            s: high_s.serialize().to_vec(),
        }
        .to_der(),
    );
    assert!(EcdsaP384::verify(message, &malleable, &public_key).is_err());

    let out_of_range = EcdsaP384Signature(
        SignatureComponents {
            r: NIST_P384.n.to_vec(),
            s: s.serialize().to_vec(),
        }
        .to_der(),
    );
    assert!(EcdsaP384::verify(message, &out_of_range, &public_key).is_err());
}

/* ------------------------------------------------------------------------- */
/*                       Helper: canonicalise curve/hash                     */
/* ------------------------------------------------------------------------- */

fn canon(combo: &str) -> String {
    combo.to_ascii_uppercase().replace([' ', '-'], "")
}

// --- Start of Test Vector Parsing Utilities ---
// (KeyPairTestVector, PkvTestVector, SigGenVector structs and parsing functions remain the same)
#[derive(Debug, PartialEq, Clone)]
struct KeyPairTestVector {
    d: String,
    qx: String,
    qy: String,
}
#[derive(Debug, PartialEq, Clone)]
struct PkvTestVector {
    qx: String,
    qy: String,
    expected_result: String,
}
#[derive(Debug, PartialEq, Clone)]
struct SigGenVector {
    curve_sha_combo: String,
    msg: String,
    qx: String,
    qy: String,
    r_hex: String,
    s_hex: String,
}

// Helper structure for parsed SigVer.rsp data
#[derive(Debug, PartialEq, Clone)]
struct SigVerTestVector {
    curve_sha_combo: String, // e.g., "P-384,SHA384"
    msg: String,
    qx: String,
    qy: String,
    r_hex: String,
    s_hex: String,
    expected_result: String, // "P" or "F"
}

fn parse_key_pair_vectors(rsp_content: &str, curve_marker: &str) -> Vec<KeyPairTestVector> {
    let mut vectors = Vec::new();
    let mut in_section = false;
    let mut current_d: Option<String> = None;
    let mut current_qx: Option<String> = None;
    for line in rsp_content.lines() {
        let line = line.trim();
        if line.starts_with('#')
            || line.is_empty()
            || line.starts_with("N =")
            || line.starts_with("[B.4.2")
        {
            continue;
        }
        if line == curve_marker {
            in_section = true;
            current_d = None;
            current_qx = None;
            continue;
        }
        if in_section && line.starts_with('[') && line.ends_with(']') && line != curve_marker {
            break;
        }
        if !in_section {
            continue;
        }
        if line.starts_with("d = ") {
            current_d = Some(line.trim_start_matches("d = ").to_string());
            current_qx = None;
        } else if line.starts_with("Qx = ") {
            if current_d.is_some() {
                current_qx = Some(line.trim_start_matches("Qx = ").to_string());
            }
        } else if line.starts_with("Qy = ") {
            if let (Some(d_val), Some(qx_val)) = (current_d.take(), current_qx.take()) {
                let qy_val = line.trim_start_matches("Qy = ").to_string();
                vectors.push(KeyPairTestVector {
                    d: d_val,
                    qx: qx_val,
                    qy: qy_val,
                });
            }
        }
    }
    vectors
}
fn parse_pkv_vectors(rsp_content: &str, curve_marker: &str) -> Vec<PkvTestVector> {
    let mut vectors = Vec::new();
    let mut in_section = false;
    let mut current_qx: Option<String> = None;
    let mut current_qy: Option<String> = None;
    for line in rsp_content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line == curve_marker {
            in_section = true;
            current_qx = None;
            current_qy = None;
            continue;
        }
        if in_section && line.starts_with('[') && line.ends_with(']') && line != curve_marker {
            break;
        }
        if !in_section {
            continue;
        }
        if line.starts_with("Qx = ") {
            current_qx = Some(line.trim_start_matches("Qx = ").to_string());
        } else if line.starts_with("Qy = ") {
            current_qy = Some(line.trim_start_matches("Qy = ").to_string());
        } else if line.starts_with("Result = ") {
            if let (Some(qx_val), Some(qy_val)) = (current_qx.take(), current_qy.take()) {
                let result_str = line
                    .trim_start_matches("Result = ")
                    .chars()
                    .next()
                    .unwrap_or(' ')
                    .to_string();
                vectors.push(PkvTestVector {
                    qx: qx_val,
                    qy: qy_val,
                    expected_result: result_str,
                });
            }
        }
    }
    vectors
}
fn parse_sig_gen_truncated_sha_vectors(
    rsp_content: &str,
    target_curve_name: &str,
) -> Vec<SigGenVector> {
    let mut vectors = Vec::new();
    let mut current_section_curve_sha: Option<String> = None;
    let mut current_msg: Option<String> = None;
    let mut current_qx: Option<String> = None;
    let mut current_qy: Option<String> = None;
    let mut current_r: Option<String> = None;
    for line in rsp_content.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.starts_with('#') || line_trimmed.is_empty() {
            continue;
        }
        if line_trimmed.starts_with('[') && line_trimmed.ends_with(']') {
            let section_name = line_trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            if section_name.starts_with(target_curve_name) {
                current_section_curve_sha = Some(section_name);
            } else {
                current_section_curve_sha = None;
            }
            current_msg = None;
            continue;
        }
        if let Some(ref section_name) = current_section_curve_sha {
            if line_trimmed.starts_with("Msg = ") {
                current_msg = Some(line_trimmed.trim_start_matches("Msg = ").to_string());
            } else if line_trimmed.starts_with("Qx = ") {
                current_qx = Some(line_trimmed.trim_start_matches("Qx = ").to_string());
            } else if line_trimmed.starts_with("Qy = ") {
                current_qy = Some(line_trimmed.trim_start_matches("Qy = ").to_string());
            } else if line_trimmed.starts_with("R = ") {
                current_r = Some(line_trimmed.trim_start_matches("R = ").to_string());
            } else if line_trimmed.starts_with("S = ") {
                if let (Some(msg), Some(qx), Some(qy), Some(r_hex)) = (
                    current_msg.take(),
                    current_qx.take(),
                    current_qy.take(),
                    current_r.take(),
                ) {
                    let s_hex = line_trimmed.trim_start_matches("S = ").to_string();
                    vectors.push(SigGenVector {
                        curve_sha_combo: section_name.clone(),
                        msg,
                        qx,
                        qy,
                        r_hex,
                        s_hex,
                    });
                }
            }
        }
    }
    vectors
}

// Parser for SigVer.rsp
fn parse_sig_ver_vectors(rsp_content: &str, target_curve_name: &str) -> Vec<SigVerTestVector> {
    let mut vectors = Vec::new();
    let mut current_section_curve_sha: Option<String> = None;
    let mut current_msg: Option<String> = None;
    let mut current_qx: Option<String> = None;
    let mut current_qy: Option<String> = None;
    let mut current_r: Option<String> = None;
    let mut current_s: Option<String> = None;

    for line in rsp_content.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.starts_with('#') || line_trimmed.is_empty() {
            continue;
        }

        if line_trimmed.starts_with('[') && line_trimmed.ends_with(']') {
            let section_name = line_trimmed
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            if section_name.starts_with(target_curve_name) {
                // Normalize spaces, e.g., "[P-384, SHA384]" -> "P-384,SHA384"
                current_section_curve_sha = Some(section_name.replace(" ", ""));
            } else {
                current_section_curve_sha = None;
            }
            // Reset fields for new section or new vector
            current_msg = None;
            current_qx = None;
            current_qy = None;
            current_r = None;
            current_s = None;
            continue;
        }

        if let Some(ref section_name_val) = current_section_curve_sha {
            if line_trimmed.starts_with("Msg = ") {
                // Start of a new vector, clear previous partial data for safety
                current_qx = None;
                current_qy = None;
                current_r = None;
                current_s = None;
                current_msg = Some(line_trimmed.trim_start_matches("Msg = ").to_string());
            } else if line_trimmed.starts_with("Qx = ") {
                current_qx = Some(line_trimmed.trim_start_matches("Qx = ").to_string());
            } else if line_trimmed.starts_with("Qy = ") {
                current_qy = Some(line_trimmed.trim_start_matches("Qy = ").to_string());
            } else if line_trimmed.starts_with("R = ") {
                current_r = Some(line_trimmed.trim_start_matches("R = ").to_string());
            } else if line_trimmed.starts_with("S = ") {
                current_s = Some(line_trimmed.trim_start_matches("S = ").to_string());
            } else if line_trimmed.starts_with("Result = ") {
                if let (Some(msg), Some(qx), Some(qy), Some(r_hex), Some(s_hex)) = (
                    current_msg.take(),
                    current_qx.take(),
                    current_qy.take(),
                    current_r.take(),
                    current_s.take(),
                ) {
                    let result_char = line_trimmed
                        .trim_start_matches("Result = ")
                        .chars()
                        .next()
                        .unwrap_or('?');
                    vectors.push(SigVerTestVector {
                        curve_sha_combo: section_name_val.clone(),
                        msg,
                        qx,
                        qy,
                        r_hex,
                        s_hex,
                        expected_result: result_char.to_string(),
                    });
                }
                // Reset all fields for the next potential vector within the same section
                current_msg = None;
                current_qx = None;
                current_qy = None;
                current_r = None;
                current_s = None;
            }
        }
    }
    vectors
}

fn vectors_dir() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("tests");
    path.push("src");
    path.push("vectors");
    path.push("legacy_rsp");
    path.push("ecdsa");
    path
}
fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    if hex_str == "00" {
        // Special case for Msg = 00 (empty message)
        return Vec::new();
    }
    hex::decode(hex_str).expect("Failed to decode hex string")
}
// --- End of Test Vector Parsing Utilities ---

/* ------------------------------------------------------------------------- */
/*                          ORIGINAL BASIC TESTS                             */
/* ------------------------------------------------------------------------- */
#[test]
fn coordinate_reduction_preserves_zero() {
    // Coordinate/hash reduction is allowed to produce zero. Callers that
    // require a non-zero ECDSA scalar reject it at the protocol boundary.
    let zero_bytes = [0u8; 48];
    assert!(reduce_bytes_to_scalar(&zero_bytes).unwrap().is_zero());
}

#[test]
fn test_empty_message() {
    let mut rng = test_rng();
    let (public_key, secret_key) = EcdsaP384::keypair(&mut rng).unwrap();
    let message = b"";
    let signature = EcdsaP384::sign(message, &secret_key).unwrap();
    assert!(EcdsaP384::verify(message, &signature, &public_key).is_ok());
}

#[test]
fn test_large_message() {
    let mut rng = test_rng();
    let (public_key, secret_key) = EcdsaP384::keypair(&mut rng).unwrap();
    let message = vec![0xAB; 10000];
    let signature = EcdsaP384::sign(&message, &secret_key).unwrap();
    assert!(EcdsaP384::verify(&message, &signature, &public_key).is_ok());
}

#[test]
fn test_ecdsa_p384_sign_verify() {
    let mut rng = test_rng();
    let (public_key, secret_key) = EcdsaP384::keypair(&mut rng).unwrap();
    let message = b"Test message for ECDSA P-384";
    let signature = EcdsaP384::sign(message, &secret_key).unwrap();
    assert!(EcdsaP384::verify(message, &signature, &public_key).is_ok());
    let wrong_message = b"Wrong message";
    assert!(EcdsaP384::verify(wrong_message, &signature, &public_key).is_err());
}

#[test]
fn test_deterministic_verification() {
    let mut rng = test_rng();
    let (public_key, secret_key) = EcdsaP384::keypair(&mut rng).unwrap();
    let message = b"Test message";
    let signature = EcdsaP384::sign(message, &secret_key).unwrap();
    for _ in 0..10 {
        assert!(EcdsaP384::verify(message, &signature, &public_key).is_ok());
    }
}

#[test]
fn test_key_generation_details() {
    let mut rng = test_rng();
    for i in 0..5 {
        match EcdsaP384::keypair(&mut rng) {
            Ok((_, sec_key)) => {
                let sk_bytes = sec_key.as_ref();
                let is_zero = sk_bytes.iter().all(|&b| b == 0);
                assert!(!is_zero);
                ec::Scalar::new(sk_bytes.try_into().unwrap()).expect("recreate scalar");
            }
            Err(e) => panic!("Key generation failed on iteration {}: {:?}", i, e),
        }
    }
}

#[test]
fn test_multiple_signatures() {
    let mut rng = test_rng();
    let (public_key, secret_key) = EcdsaP384::keypair(&mut rng).unwrap();
    let message = b"Test message for multiple signatures";
    let sig1 = EcdsaP384::sign(message, &secret_key).unwrap();
    let sig2 = EcdsaP384::sign(message, &secret_key).unwrap();
    assert!(EcdsaP384::verify(message, &sig1, &public_key).is_ok());
    assert!(EcdsaP384::verify(message, &sig2, &public_key).is_ok());
    assert_eq!(sig1.as_ref(), sig2.as_ref());
}

#[test]
fn test_wrong_public_key() {
    let mut rng = test_rng();
    let (_, secret_key1) = EcdsaP384::keypair(&mut rng).unwrap();
    let (public_key2, _) = EcdsaP384::keypair(&mut rng).unwrap();
    let message = b"Test message";
    let signature = EcdsaP384::sign(message, &secret_key1).unwrap();
    assert!(EcdsaP384::verify(message, &signature, &public_key2).is_err());
}

#[test]
fn test_invalid_signature() {
    let mut rng = test_rng();
    let (public_key, _) = EcdsaP384::keypair(&mut rng).unwrap();
    let invalid_sig = EcdsaP384Signature(vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
    let message = b"Test message";
    assert!(EcdsaP384::verify(message, &invalid_sig, &public_key).is_err());
}

#[test]
fn test_der_malformed() {
    assert!(SignatureComponents::from_der(&[0x30, 0x00]).is_err());
    assert!(
        SignatureComponents::from_der(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]).is_err()
    );
    assert!(
        SignatureComponents::from_der(&[0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01]).is_err()
    );
    assert!(
        SignatureComponents::from_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01]).is_err()
    );
}

#[test]
fn test_signature_serialization() {
    let mut rng = test_rng();
    let (_, sec_key) = EcdsaP384::keypair(&mut rng).unwrap();
    let message = b"Test serialization";
    let signature = EcdsaP384::sign(message, &sec_key).unwrap();
    let sig_bytes = signature.as_ref();
    let sig2 = EcdsaP384Signature(sig_bytes.to_vec());
    assert_eq!(signature.as_ref(), sig2.as_ref());
}

#[test]
fn test_scalar_arithmetic_basic() {
    let a_bytes = [
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a,
        0xbc, 0xde, 0xf0,
    ];
    let b_bytes = [
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23,
        0x45, 0x67, 0x89,
    ];
    let a = ec::Scalar::new(a_bytes).unwrap();
    let b = ec::Scalar::new(b_bytes).unwrap();
    let b_inv = b.inv_mod_n().unwrap();
    let ab_inv = a.mul_mod_n(&b_inv).unwrap();
    let result = ab_inv.mul_mod_n(&b).unwrap();
    assert_eq!(result.serialize(), a.serialize());
    let a_plus_b = a.add_mod_n(&b).unwrap();
    let result2 = a_plus_b.sub_mod_n(&b).unwrap();
    assert_eq!(result2.serialize(), a.serialize());
}

#[test]
fn test_scalar_edge_cases() {
    let n_minus_1 = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37,
        0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC,
        0xC5, 0x29, 0x72,
    ];
    let max_scalar = ec::Scalar::new(n_minus_1).unwrap();
    let mut one_bytes = [0u8; 48];
    one_bytes[47] = 1;
    let one = ec::Scalar::new(one_bytes).unwrap();
    let zero_result = max_scalar.add_mod_n(&one).unwrap();
    assert!(zero_result.is_zero());
    let result = one.mul_mod_n(&max_scalar).unwrap();
    assert_eq!(result.serialize(), max_scalar.serialize());
}

#[test]
fn test_modular_inverse_comprehensive() {
    let mut rng = test_rng();
    let mut two_bytes = [0u8; 48];
    two_bytes[47] = 2;
    let two = ec::Scalar::new(two_bytes).unwrap();
    let two_inv = two.inv_mod_n().unwrap();
    let product = two.mul_mod_n(&two_inv).unwrap();
    let mut expected_one = [0u8; 48];
    expected_one[47] = 1;
    assert_eq!(product.serialize(), expected_one);
    for _ in 0..5 {
        let (scalar, _) = ec::generate_keypair(&mut rng).unwrap();
        let inv = scalar.inv_mod_n().unwrap();
        let product_rand = scalar.mul_mod_n(&inv).unwrap();
        assert_eq!(product_rand.serialize(), expected_one);
    }
    let n_minus_1 = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37,
        0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC,
        0xC5, 0x29, 0x72,
    ];
    let max_scalar = ec::Scalar::new(n_minus_1).unwrap();
    let max_inv = max_scalar.inv_mod_n().unwrap();
    let max_product = max_scalar.mul_mod_n(&max_inv).unwrap();
    assert_eq!(max_product.serialize(), expected_one);
    let n_minus_1_squared = max_scalar.mul_mod_n(&max_scalar).unwrap();
    assert_eq!(n_minus_1_squared.serialize(), expected_one);
    assert_eq!(max_inv.serialize(), max_scalar.serialize());
}

#[test]
fn test_scalar_endianness() {
    let test_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f, 0x30,
    ];
    let scalar = ec::Scalar::new(test_bytes).unwrap();
    assert_eq!(test_bytes, scalar.serialize());
    let mut one_bytes = [0u8; 48];
    one_bytes[47] = 1;
    let one = ec::Scalar::new(one_bytes).unwrap();
    let scalar_plus_one = scalar.add_mod_n(&one).unwrap();
    let mut expected = test_bytes;
    expected[47] += 1;
    assert_eq!(scalar_plus_one.serialize(), expected);
    let mut two_bytes = [0u8; 48];
    two_bytes[47] = 2;
    let two = ec::Scalar::new(two_bytes).unwrap();
    let scalar_times_two = scalar.mul_mod_n(&two).unwrap();
    let scalar_doubled = scalar.add_mod_n(&scalar).unwrap();
    assert_eq!(scalar_times_two.serialize(), scalar_doubled.serialize());
}

/* ------------------------------------------------------------------------- */
/*                 NEW: sanity-check Scalar::new rejects zero                */
/* ------------------------------------------------------------------------- */

#[test]
fn test_p384_scalar_zero_rejected() {
    let zero = [0u8; ec::P384_SCALAR_SIZE];
    assert!(
        ec::Scalar::new(zero).is_err(),
        "algorithms::ec::p384::Scalar::new should reject an all-zero input"
    );

    // sanity: 1 should succeed
    let mut one = [0u8; ec::P384_SCALAR_SIZE];
    one[ec::P384_SCALAR_SIZE - 1] = 1;
    assert!(ec::Scalar::new(one).is_ok());
}

#[test]
fn test_cofactor_validation() {
    let n_minus_1_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37,
        0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC,
        0xC5, 0x29, 0x72,
    ];
    let n_minus_1 = ec::Scalar::new(n_minus_1_bytes).unwrap();
    let n_minus_1_g = ec::scalar_mult_base_g(&n_minus_1).unwrap();
    let mut one_bytes = [0u8; 48];
    one_bytes[47] = 1;
    let one = ec::Scalar::new(one_bytes).unwrap();
    let g = ec::scalar_mult_base_g(&one).unwrap();
    let result = n_minus_1_g.add(&g);
    assert!(result.is_identity());
    let n_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37,
        0x2D, 0xDF, 0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC,
        0xC5, 0x29, 0x73,
    ];
    assert!(ec::Scalar::new(n_bytes).is_err());
}

#[test]
fn test_field_size_boundary() {
    let mut invalid_point = [0u8; ec::P384_POINT_UNCOMPRESSED_SIZE];
    invalid_point[0] = 0x04;
    let p_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
        0xFF, 0xFF, 0xFF,
    ];
    invalid_point[1..(1 + ec::P384_SCALAR_SIZE)].copy_from_slice(&p_bytes);
    invalid_point[(1 + ec::P384_SCALAR_SIZE)..].fill(0x42);
    let public_key = EcdsaP384PublicKey(invalid_point);
    let message = b"test";
    let dummy_sig = EcdsaP384Signature(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    assert!(EcdsaP384::verify(message, &dummy_sig, &public_key).is_err());
}

#[test]
fn test_mixed_size_der_integers() {
    let full_size_r = vec![0xFF; 48];
    let full_size_s = vec![0xAA; 48];
    let sig1 = SignatureComponents {
        r: full_size_r,
        s: full_size_s,
    };
    let der1 = sig1.to_der();
    let parsed1 = SignatureComponents::from_der(&der1).unwrap();
    assert_eq!(parsed1.r, sig1.r);
    assert_eq!(parsed1.s, sig1.s);
    let r_val = vec![0x12, 0x34, 0x56];
    let s_val = vec![0x78, 0x9A, 0xBC];
    let sig2 = SignatureComponents {
        r: r_val.clone(),
        s: s_val.clone(),
    };
    let der2 = sig2.to_der();
    let parsed2 = SignatureComponents::from_der(&der2).unwrap();
    assert_eq!(parsed2.r, r_val);
    assert_eq!(parsed2.s, s_val);
    let r_high_bit = vec![0x80, 0x01, 0x02, 0x03];
    let s_high_bit = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let sig3 = SignatureComponents {
        r: r_high_bit.clone(),
        s: s_high_bit.clone(),
    };
    let der3 = sig3.to_der();
    let parsed3 = SignatureComponents::from_der(&der3).unwrap();
    assert_eq!(parsed3.r, r_high_bit);
    assert_eq!(parsed3.s, s_high_bit);
}

#[test]
fn test_hash_edge_cases() {
    let mut hasher = Sha384::new();
    hasher.update(b"").unwrap();
    let hash = hasher.finalize().unwrap();
    let mut h_bytes = [0u8; 48];
    h_bytes.copy_from_slice(hash.as_ref());
    reduce_bytes_to_scalar(&h_bytes)
        .expect("Empty message hash should be reducible to a valid scalar");
}

#[test]
fn test_cross_validation() {
    let mut rng = test_rng();
    for _ in 0..3 {
        let (pk1, sk1) = EcdsaP384::keypair(&mut rng).unwrap();
        let (pk2, sk2) = EcdsaP384::keypair(&mut rng).unwrap();
        let msg1 = b"First test message";
        let msg2 = b"Second test message";
        let sig1_msg1 = EcdsaP384::sign(msg1, &sk1).unwrap();
        let sig1_msg2 = EcdsaP384::sign(msg2, &sk1).unwrap();
        let sig2_msg1 = EcdsaP384::sign(msg1, &sk2).unwrap();
        let sig2_msg2 = EcdsaP384::sign(msg2, &sk2).unwrap();
        assert!(EcdsaP384::verify(msg1, &sig1_msg1, &pk1).is_ok());
        assert!(EcdsaP384::verify(msg2, &sig1_msg2, &pk1).is_ok());
        assert!(EcdsaP384::verify(msg1, &sig2_msg1, &pk2).is_ok());
        assert!(EcdsaP384::verify(msg2, &sig2_msg2, &pk2).is_ok());
        assert!(EcdsaP384::verify(msg1, &sig1_msg1, &pk2).is_err());
        assert!(EcdsaP384::verify(msg2, &sig1_msg2, &pk2).is_err());
        assert!(EcdsaP384::verify(msg1, &sig2_msg1, &pk1).is_err());
        assert!(EcdsaP384::verify(msg2, &sig2_msg2, &pk1).is_err());
        assert!(EcdsaP384::verify(msg2, &sig1_msg1, &pk1).is_err());
        assert!(EcdsaP384::verify(msg1, &sig1_msg2, &pk1).is_err());
    }
}

#[test]
fn test_deterministic_k_properties() {
    let mut rng = test_rng();
    let (_, sk) = EcdsaP384::keypair(&mut rng).unwrap();
    let message = b"Test deterministic k";
    let mut signatures: Vec<EcdsaP384Signature> = Vec::new();
    for _ in 0..5 {
        let sig = EcdsaP384::sign(message, &sk).unwrap();
        for prev_sig in &signatures {
            assert_eq!(sig.as_ref(), prev_sig.as_ref());
        }
        signatures.push(sig);
    }
}

/* ------------------------------------------------------------------------- */
/*                       KEYPAIR.RSP PARSING TESTS                           */
/* ------------------------------------------------------------------------- */

#[test]
fn test_p384_keypair_rsp_parsing_and_validation() {
    let dir = vectors_dir();
    let keypair_rsp_path = dir.join("KeyPair.rsp");

    assert!(
        keypair_rsp_path.exists(),
        "Test vector file KeyPair.rsp not found at {}",
        keypair_rsp_path.display()
    );

    let rsp_content = fs::read_to_string(&keypair_rsp_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", keypair_rsp_path.display(), e));

    let p384_vectors = parse_key_pair_vectors(&rsp_content, "[P-384]");

    assert_eq!(
        p384_vectors.len(),
        10,
        "Should parse 10 P-384 test vectors from KeyPair.rsp"
    );

    for (i, vector) in p384_vectors.iter().enumerate() {
        let d_bytes_vec = hex_to_bytes(&vector.d);
        let qx_expected_bytes = hex_to_bytes(&vector.qx);
        let qy_expected_bytes = hex_to_bytes(&vector.qy);

        assert_eq!(
            d_bytes_vec.len(),
            ec::P384_SCALAR_SIZE,
            "P-384 d byte length for vector {}",
            i
        );
        assert_eq!(
            qx_expected_bytes.len(),
            ec::P384_SCALAR_SIZE,
            "P-384 Qx byte length for vector {}",
            i
        );
        assert_eq!(
            qy_expected_bytes.len(),
            ec::P384_SCALAR_SIZE,
            "P-384 Qy byte length for vector {}",
            i
        );

        let mut d_bytes_arr = [0u8; ec::P384_SCALAR_SIZE];
        d_bytes_arr.copy_from_slice(&d_bytes_vec);

        let d_scalar = ec::Scalar::new(d_bytes_arr).unwrap_or_else(|e| {
            panic!(
                "Vector {}: Failed to create scalar d from bytes {:?}: {:?}",
                i, d_bytes_vec, e
            )
        });

        let q_calculated = ec::scalar_mult_base_g(&d_scalar)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to compute Q=dG: {:?}", i, e));

        let qx_calculated_bytes = q_calculated.x_coordinate_bytes();
        let qy_calculated_bytes = q_calculated.y_coordinate_bytes();

        assert_eq!(
            qx_calculated_bytes.as_slice(),
            qx_expected_bytes.as_slice(),
            "Vector {}: Qx mismatch for d={}",
            i,
            vector.d
        );
        assert_eq!(
            qy_calculated_bytes.as_slice(),
            qy_expected_bytes.as_slice(),
            "Vector {}: Qy mismatch for d={}",
            i,
            vector.d
        );
    }
}

/* ------------------------------------------------------------------------- */
/*                         PKV.RSP PARSING TESTS                             */
/* ------------------------------------------------------------------------- */

#[test]
fn test_p384_pkv_rsp_parsing_and_validation() {
    let dir = vectors_dir();
    let pkv_rsp_path = dir.join("PKV.rsp");
    assert!(
        pkv_rsp_path.exists(),
        "PKV.rsp not found at {}",
        pkv_rsp_path.display()
    );
    let rsp_content = fs::read_to_string(&pkv_rsp_path).unwrap();
    let p384_pkv_vectors = parse_pkv_vectors(&rsp_content, "[P-384]");

    assert!(!p384_pkv_vectors.is_empty(), "No P-384 PKV vectors parsed");

    for (i, vector) in p384_pkv_vectors.iter().enumerate() {
        let qx_bytes_res = hex::decode(&vector.qx);
        let qy_bytes_res = hex::decode(&vector.qy);

        let mut pk_uncompressed = [0u8; ec::P384_POINT_UNCOMPRESSED_SIZE];
        pk_uncompressed[0] = 0x04;

        // Using the error type from your API or a common error type from algorithms
        let validation_attempt: Result<ec::Point, ApiError> = if let (Ok(qx_bytes), Ok(qy_bytes)) =
            (qx_bytes_res, qy_bytes_res)
        {
            if qx_bytes.len() == ec::P384_SCALAR_SIZE && qy_bytes.len() == ec::P384_SCALAR_SIZE {
                pk_uncompressed[1..(1 + ec::P384_SCALAR_SIZE)].copy_from_slice(&qx_bytes);
                pk_uncompressed[(1 + ec::P384_SCALAR_SIZE)..].copy_from_slice(&qy_bytes);
                let public_key_candidate = EcdsaP384PublicKey(pk_uncompressed);
                ec::Point::deserialize_uncompressed(&public_key_candidate.0).map_err(ApiError::from)
            } else {
                Err(ApiError::InvalidLength {
                    context: "P384 PKV Test - Qx/Qy hex length",
                    expected: ec::P384_SCALAR_SIZE * 2,
                    actual: qx_bytes.len() + qy_bytes.len(),
                })
            }
        } else {
            Err(ApiError::InvalidParameter {
                context: "P384 PKV Test - Hex decoding",
                #[cfg(feature = "std")]
                message: "Hex decoding failed for Qx or Qy".to_string(),
            })
        };

        if vector.expected_result == "P" {
            assert!(
                validation_attempt.is_ok(),
                "Vector {}: Expected PASS (P), got FAIL for Qx={}, Qy={}. Error: {:?}",
                i,
                vector.qx,
                vector.qy,
                validation_attempt.err()
            );
        } else {
            assert!(
                validation_attempt.is_err(),
                "Vector {}: Expected FAIL (F), got PASS for Qx={}, Qy={}",
                i,
                vector.qx,
                vector.qy
            );
        }
    }
}

/* ------------------------------------------------------------------------- */
/*            SIGGEN_TRUNCATEDSHAS.RSP (AS SIGVER) PARSING TESTS             */
/* ------------------------------------------------------------------------- */

#[test]
fn test_p384_siggen_truncated_shas_rsp_verify() {
    let dir = vectors_dir();
    let siggen_rsp_path = dir.join("SigGen_TruncatedSHAs.rsp");
    assert!(
        siggen_rsp_path.exists(),
        "SigGen_TruncatedSHAs.rsp not found at {}",
        siggen_rsp_path.display()
    );
    let rsp_content = fs::read_to_string(&siggen_rsp_path).unwrap();

    let p384_siggen_vectors = parse_sig_gen_truncated_sha_vectors(&rsp_content, "P-384");
    assert!(
        !p384_siggen_vectors.is_empty(),
        "No P-384 SigGen vectors parsed for truncated SHAs"
    );

    for (i, vector) in p384_siggen_vectors.iter().enumerate() {
        let msg_bytes = hex_to_bytes(&vector.msg);
        let qx_bytes = hex_to_bytes(&vector.qx);
        let qy_bytes = hex_to_bytes(&vector.qy);
        let r_bytes_vec = hex_to_bytes(&vector.r_hex);
        let s_bytes_vec = hex_to_bytes(&vector.s_hex);

        let mut pk_uncompressed = [0u8; ec::P384_POINT_UNCOMPRESSED_SIZE];
        pk_uncompressed[0] = 0x04;
        pk_uncompressed[1..(1 + ec::P384_SCALAR_SIZE)].copy_from_slice(&qx_bytes);
        pk_uncompressed[(1 + ec::P384_SCALAR_SIZE)..].copy_from_slice(&qy_bytes);
        let public_key = EcdsaP384PublicKey(pk_uncompressed);

        let sig_components = SignatureComponents {
            r: r_bytes_vec,
            s: s_bytes_vec,
        };
        let der_signature = EcdsaP384Signature(sig_components.to_der());

        let verification_result = EcdsaP384::verify(&msg_bytes, &der_signature, &public_key);

        // EcdsaP384::verify uses Sha384 internally.
        // These test vectors are generated with SHA-512/224 or SHA-512/256.
        // Thus, our current EcdsaP384::verify *should* fail these signatures due to hash mismatch.
        if vector.curve_sha_combo == "P-384,SHA-512224"
            || vector.curve_sha_combo == "P-384,SHA-512256"
        {
            assert!(verification_result.is_err(),
                "Vector {}: Expected FAIL for {} (due to hash mismatch with current EcdsaP384::verify, which uses Sha384), but it passed.\nMsg: {}",
                i, vector.curve_sha_combo, vector.msg);
        } else {
            eprintln!("Warning: Unexpected curve/SHA combo {} in SigGen_TruncatedSHAs.rsp for P-384 test vector {}", vector.curve_sha_combo, i);
        }
    }
}

/* ------------------------------------------------------------------------- */
/*                         SIGVER.RSP PARSING TESTS                          */
/* ------------------------------------------------------------------------- */

#[test]
fn test_p384_sigver_rsp_verify() {
    let dir = vectors_dir();
    let sigver_rsp_path = dir.join("SigVer.rsp");
    assert!(
        sigver_rsp_path.exists(),
        "SigVer.rsp not found at {}",
        sigver_rsp_path.display()
    );
    let rsp_content = fs::read_to_string(&sigver_rsp_path).unwrap();

    let p384_sigver_vectors = parse_sig_ver_vectors(&rsp_content, "P-384");
    assert!(
        !p384_sigver_vectors.is_empty(),
        "No P-384 SigVer vectors parsed from SigVer.rsp"
    );

    let mut correct_hash_pass = 0;
    let mut correct_hash_fail = 0;
    let mut mismatch_hash_correct_fail_originally_p = 0;
    let mismatch_hash_unexpected_pass = 0; // Should be 0
    let mut mismatch_hash_originally_fail_and_failed = 0;

    let combo_expected_by_impl = "P-384,SHA384"; // EcdsaP384 uses SHA384 internally

    for (i, vector) in p384_sigver_vectors.iter().enumerate() {
        let msg_bytes = hex_to_bytes(&vector.msg);
        let qx_bytes = hex_to_bytes(&vector.qx);
        let qy_bytes = hex_to_bytes(&vector.qy);
        let r_bytes_vec = hex_to_bytes(&vector.r_hex);
        let s_bytes_vec = hex_to_bytes(&vector.s_hex);

        let mut pk_uncompressed = [0u8; ec::P384_POINT_UNCOMPRESSED_SIZE];
        pk_uncompressed[0] = 0x04; // Uncompressed point marker

        // Ensure Qx and Qy have correct length before trying to use them
        if qx_bytes.len() != ec::P384_SCALAR_SIZE || qy_bytes.len() != ec::P384_SCALAR_SIZE {
            if vector.expected_result == "F" {
                mismatch_hash_originally_fail_and_failed += 1;
                continue;
            } else {
                panic!("Vector {}: Qx/Qy length invalid ({} / {}) for P-384 vector that expects PASS. Qx: {}, Qy: {}", 
                    i, qx_bytes.len(), qy_bytes.len(), vector.qx, vector.qy);
            }
        }

        pk_uncompressed[1..(1 + ec::P384_SCALAR_SIZE)].copy_from_slice(&qx_bytes);
        pk_uncompressed[(1 + ec::P384_SCALAR_SIZE)..].copy_from_slice(&qy_bytes);
        let public_key = EcdsaP384PublicKey(pk_uncompressed);

        let mut canonical_s = s_bytes_vec.clone();
        if vector.expected_result == "P" && s_bytes_vec.len() <= ec::P384_SCALAR_SIZE {
            let mut padded = [0u8; ec::P384_SCALAR_SIZE];
            padded[ec::P384_SCALAR_SIZE - s_bytes_vec.len()..].copy_from_slice(&s_bytes_vec);
            if is_high_s(&padded, &NIST_P384.n) {
                let original = EcdsaP384Signature(
                    SignatureComponents {
                        r: r_bytes_vec.clone(),
                        s: s_bytes_vec.clone(),
                    }
                    .to_der(),
                );
                assert!(EcdsaP384::verify(&msg_bytes, &original, &public_key).is_err());
                canonical_s = ec::Scalar::new(padded)
                    .unwrap()
                    .negate()
                    .serialize()
                    .to_vec();
            }
        }
        let sig_components = SignatureComponents {
            r: r_bytes_vec.clone(),
            s: canonical_s,
        };
        let der_signature = EcdsaP384Signature(sig_components.to_der());

        let verification_result = EcdsaP384::verify(&msg_bytes, &der_signature, &public_key);

        if canon(&vector.curve_sha_combo) == canon(combo_expected_by_impl) {
            // Hashes match: the test vector was generated with the same hash our implementation uses.
            if vector.expected_result == "P" {
                assert!(verification_result.is_ok(),
                    "Vector {} ({}): Expected PASS (matching hash), got FAIL: {:?}\nMsg: {}\nR: {}\nS: {}",
                    i, vector.curve_sha_combo, verification_result.err(), vector.msg, vector.r_hex, vector.s_hex);
                correct_hash_pass += 1;
            } else {
                // Expected "F"
                assert!(verification_result.is_err(),
                    "Vector {} ({}): Expected FAIL (matching hash), got PASS\nMsg: {}\nR: {}\nS: {}",
                    i, vector.curve_sha_combo, vector.msg, vector.r_hex, vector.s_hex);
                correct_hash_fail += 1;
            }
        } else if vector.expected_result == "P" {
            // Signature is valid for its *original* hash (from RSP), but should FAIL with our implementation's hash.
            assert!(verification_result.is_err(),
                "Vector {} ({}): Expected FAIL (due to hash mismatch with EcdsaP384 internal SHA384, original was P), but got PASS.\nMsg: {}\nR: {}\nS: {}",
                i, vector.curve_sha_combo, vector.msg, vector.r_hex, vector.s_hex);
            mismatch_hash_correct_fail_originally_p += 1;
        } else if verification_result.is_ok() {
            // vector.expected_result == "F"
            // Signature was ALREADY INVALID for its original hash. It should still be invalid with our hash.
            panic!(
                "Vector {} ({}): Originally FAILED, but PASSED with EcdsaP384 internal SHA384. This is unexpected.\nMsg: {}\nR: {}\nS: {}",
                i, vector.curve_sha_combo, vector.msg, vector.r_hex, vector.s_hex
            );
        } else {
            mismatch_hash_originally_fail_and_failed += 1;
        }
    }
    println!("\n--- P-384 SigVer.rsp Test Summary ---");
    println!(
        "Total P-384 vectors processed: {}",
        p384_sigver_vectors.len()
    );
    println!("  Vectors with matching hash ({}):", combo_expected_by_impl);
    println!("    Correct PASS: {}", correct_hash_pass);
    println!("    Correct FAIL: {}", correct_hash_fail);
    println!(
        "  Vectors with mismatched hash (implementation uses {}):",
        combo_expected_by_impl.split(',').nth(1).unwrap_or("?")
    );
    println!(
        "    Correctly FAILED (where original vector was P): {}",
        mismatch_hash_correct_fail_originally_p
    );
    println!(
        "    Correctly FAILED (where original vector was F): {}",
        mismatch_hash_originally_fail_and_failed
    );
    if mismatch_hash_unexpected_pass > 0 {
        println!(
            "    WARNING: UNEXPECTED PASS with mismatched hash: {}",
            mismatch_hash_unexpected_pass
        );
    }
    assert!(
        correct_hash_pass > 0,
        "No P-384,SHA384 PASS vectors were successfully tested from SigVer.rsp."
    );
    assert_eq!(
        mismatch_hash_unexpected_pass, 0,
        "There were unexpected passes with mismatched hashes for P-384."
    );
}
