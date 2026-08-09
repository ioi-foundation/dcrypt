//! Tests for ECDSA P-521 implementation

use super::*;
use crate::ecdsa::common::SignatureComponents;
use dcrypt_algorithms::hash::sha2::Sha512;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_api::error::Error as ApiError;
use dcrypt_api::Signature as SignatureTrait;
use rand::rngs::OsRng;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_ecdsa_p521_signatures_are_low_s_and_high_s_is_rejected() {
    let (public_key, secret_key) = EcdsaP521::keypair(&mut OsRng).unwrap();
    let message = b"canonical";
    let signature = EcdsaP521::sign(message, &secret_key).unwrap();
    let components = SignatureComponents::from_der(&signature.0).unwrap();
    let mut s = [0u8; ec::P521_SCALAR_SIZE];
    s[ec::P521_SCALAR_SIZE - components.s.len()..].copy_from_slice(&components.s);
    let s = ec::Scalar::new(s).unwrap();
    assert!(!is_high_s(&s.serialize(), &NIST_P521.n));

    let high_s = s.negate();
    assert!(is_high_s(&high_s.serialize(), &NIST_P521.n));
    let malleable = EcdsaP521Signature(
        SignatureComponents {
            r: components.r.clone(),
            s: high_s.serialize().to_vec(),
        }
        .to_der(),
    );
    assert!(EcdsaP521::verify(message, &malleable, &public_key).is_err());

    let out_of_range = EcdsaP521Signature(
        SignatureComponents {
            r: NIST_P521.n.to_vec(),
            s: s.serialize().to_vec(),
        }
        .to_der(),
    );
    assert!(EcdsaP521::verify(message, &out_of_range, &public_key).is_err());
}

/* ------------------------------------------------------------------------- */
/*                       Helper: canonicalise curve/hash                     */
/* ------------------------------------------------------------------------- */

fn canon(combo: &str) -> String {
    combo.to_ascii_uppercase().replace([' ', '-'], "")
}

// --- Start of Test Vector Parsing Utilities ---

// New helper function for parsing hex strings into fixed-size byte arrays (e.g., for P-521 scalars/coordinates)
fn hex_to_fixed_size_bytes<const N: usize>(hex_str: &str) -> Result<[u8; N], String> {
    let mut corrected_hex_str = hex_str.to_string();
    if corrected_hex_str.len() % 2 != 0 {
        // Prepend '0' to make length even, common for some test vector formats
        corrected_hex_str.insert(0, '0');
    }

    let bytes_vec = hex::decode(&corrected_hex_str).map_err(|e| {
        format!(
            "Failed to decode hex string '{}' (corrected: '{}'): {}",
            hex_str, corrected_hex_str, e
        )
    })?;

    if bytes_vec.len() > N {
        return Err(format!(
            "Hex string '{}' decodes to {} bytes, which is more than the expected {} bytes.",
            hex_str,
            bytes_vec.len(),
            N
        ));
    }

    let mut arr = [0u8; N];
    let padding_len = N.saturating_sub(bytes_vec.len()); // Ensure N is not less than bytes_vec.len()

    // Check if bytes_vec can fit into arr starting from padding_len
    if bytes_vec.len() > N - padding_len {
        return Err(format!(
            "Decoded hex string '{}' ({} bytes) is too large to fit into the target array of {} bytes after padding.",
            hex_str,
            bytes_vec.len(),
            N
        ));
    }
    arr[padding_len..].copy_from_slice(&bytes_vec);
    Ok(arr)
}

// Modified helper for parsing hex strings into Vec<u8> (e.g., for messages, or R/S in DER components)
fn hex_to_vec_tolerant(hex_str: &str) -> Result<Vec<u8>, String> {
    if hex_str == "00" {
        // NIST CAVS specific: "00" often means empty message
        return Ok(Vec::new());
    }
    let mut corrected_hex_str = hex_str.to_string();
    if corrected_hex_str.len() % 2 != 0 {
        corrected_hex_str.insert(0, '0');
    }
    hex::decode(&corrected_hex_str).map_err(|e| {
        format!(
            "Failed to decode hex string '{}' (corrected: '{}'): {}",
            hex_str, corrected_hex_str, e
        )
    })
}

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
struct SigVerTestVector {
    curve_sha_combo: String,
    msg: String,
    qx: String,
    qy: String,
    r_hex: String,
    s_hex: String,
    expected_result: String,
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
                current_section_curve_sha = Some(section_name.replace(" ", ""));
            } else {
                current_section_curve_sha = None;
            }
            current_msg = None;
            current_qx = None;
            current_qy = None;
            current_r = None;
            current_s = None;
            continue;
        }

        if let Some(ref section_name_val) = current_section_curve_sha {
            if line_trimmed.starts_with("Msg = ") {
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

/* ------------------------------------------------------------------------- */
/*                          BASIC FUNCTIONALITY TESTS                        */
/* ------------------------------------------------------------------------- */

#[test]
fn test_ecdsa_p521_sign_verify() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP521::keypair(&mut rng).unwrap();
    let message = b"Test message for ECDSA P-521";
    let signature = EcdsaP521::sign(message, &secret_key).unwrap();
    assert!(EcdsaP521::verify(message, &signature, &public_key).is_ok());
    let wrong_message = b"Wrong message";
    assert!(EcdsaP521::verify(wrong_message, &signature, &public_key).is_err());
}

#[test]
fn test_deterministic_verification() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP521::keypair(&mut rng).unwrap();
    let message = b"Test message";
    let signature = EcdsaP521::sign(message, &secret_key).unwrap();
    for _ in 0..10 {
        assert!(EcdsaP521::verify(message, &signature, &public_key).is_ok());
    }
}

#[test]
fn test_empty_message() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP521::keypair(&mut rng).unwrap();
    let message = b"";
    let signature = EcdsaP521::sign(message, &secret_key).unwrap();
    assert!(EcdsaP521::verify(message, &signature, &public_key).is_ok());
}

#[test]
fn test_large_message() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP521::keypair(&mut rng).unwrap();
    let message = vec![0xAB; 10000];
    let signature = EcdsaP521::sign(&message, &secret_key).unwrap();
    assert!(EcdsaP521::verify(&message, &signature, &public_key).is_ok());
}

#[test]
fn test_multiple_signatures() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP521::keypair(&mut rng).unwrap();
    let message = b"Test message for multiple signatures";
    let sig1 = EcdsaP521::sign(message, &secret_key).unwrap();
    let sig2 = EcdsaP521::sign(message, &secret_key).unwrap();
    assert!(EcdsaP521::verify(message, &sig1, &public_key).is_ok());
    assert!(EcdsaP521::verify(message, &sig2, &public_key).is_ok());
    // Signatures should be different due to hedged nonce generation
    assert_ne!(sig1.as_ref(), sig2.as_ref());
}

#[test]
fn test_wrong_public_key() {
    let mut rng = OsRng;
    let (_, secret_key1) = EcdsaP521::keypair(&mut rng).unwrap();
    let (public_key2, _) = EcdsaP521::keypair(&mut rng).unwrap();
    let message = b"Test message";
    let signature = EcdsaP521::sign(message, &secret_key1).unwrap();
    assert!(EcdsaP521::verify(message, &signature, &public_key2).is_err());
}

#[test]
fn test_invalid_signature() {
    let mut rng = OsRng;
    let (public_key, _) = EcdsaP521::keypair(&mut rng).unwrap();
    let invalid_sig = EcdsaP521Signature(vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
    let message = b"Test message";
    assert!(EcdsaP521::verify(message, &invalid_sig, &public_key).is_err());
}

#[test]
fn test_key_generation_details() {
    let mut rng = OsRng;
    for i in 0..5 {
        match EcdsaP521::keypair(&mut rng) {
            Ok((_, sec_key)) => {
                let sk_bytes = sec_key.as_ref();
                let is_zero = sk_bytes.iter().all(|&b| b == 0);
                assert!(!is_zero, "Generated secret key should not be zero");
                ec::Scalar::new(sk_bytes.try_into().unwrap())
                    .expect("Should be able to recreate scalar from secret key");
            }
            Err(e) => panic!("Key generation failed on iteration {}: {:?}", i, e),
        }
    }
}

#[test]
fn test_signature_serialization() {
    let mut rng = OsRng;
    let (_, sec_key) = EcdsaP521::keypair(&mut rng).unwrap();
    let message = b"Test serialization";
    let signature = EcdsaP521::sign(message, &sec_key).unwrap();
    let sig_bytes = signature.as_ref();
    let sig2 = EcdsaP521Signature(sig_bytes.to_vec());
    assert_eq!(signature.as_ref(), sig2.as_ref());
}

#[test]
fn test_hash_edge_cases() {
    let mut hasher = Sha512::new();
    hasher.update(b"").unwrap();
    let hash = hasher.finalize().unwrap();
    let mut h_bytes = [0u8; 66]; // P-521 scalar size
    h_bytes[2..].copy_from_slice(hash.as_ref()); // Right-align in 66 bytes (SHA512 is 64 bytes)
    reduce_bytes_to_scalar(&h_bytes) // Using the function from mod.rs
        .expect("Empty message hash should create valid scalar");
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

/* ------------------------------------------------------------------------- */
/*                          SCALAR ARITHMETIC TESTS                          */
/* ------------------------------------------------------------------------- */

#[test]
fn test_scalar_arithmetic_basic() {
    let a_bytes = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
        0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
        0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
    ];

    let b_bytes = [
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
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
    // P-521 order n - 1
    let n_minus_1 = [
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01,
        0x48, 0xF7, 0x09, 0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F,
        0xB7, 0x1E, 0x91, 0x38, 0x64, 0x08,
    ];

    let max_scalar = ec::Scalar::new(n_minus_1).unwrap();
    let mut one_bytes = [0u8; 66];
    one_bytes[65] = 1;
    let one = ec::Scalar::new(one_bytes).unwrap();

    let zero_result = max_scalar.add_mod_n(&one).unwrap();
    assert!(zero_result.is_zero());

    let result = one.mul_mod_n(&max_scalar).unwrap();
    assert_eq!(result.serialize(), max_scalar.serialize());
}

#[test]
fn test_p521_scalar_zero_rejected() {
    let zero = [0u8; ec::P521_SCALAR_SIZE];
    assert!(
        ec::Scalar::new(zero).is_err(),
        "algorithms::ec::p521::Scalar::new should reject an all-zero input"
    );

    // Sanity check: 1 should succeed
    let mut one = [0u8; ec::P521_SCALAR_SIZE];
    one[ec::P521_SCALAR_SIZE - 1] = 1;
    assert!(ec::Scalar::new(one).is_ok());
}

#[test]
fn test_modular_inverse_comprehensive() {
    let mut rng = OsRng;
    let mut two_bytes = [0u8; 66];
    two_bytes[65] = 2; // P-521 scalar is 66 bytes
    let two = ec::Scalar::new(two_bytes).unwrap();
    let two_inv = two.inv_mod_n().unwrap();
    let product = two.mul_mod_n(&two_inv).unwrap();
    let mut expected_one = [0u8; 66];
    expected_one[65] = 1;
    assert_eq!(product.serialize(), expected_one, "2 * 2_inv should be 1");

    for _ in 0..5 {
        // Reduced iterations for faster CI, increase for thorough local testing
        let (scalar, _) = ec::generate_keypair(&mut rng).unwrap();
        let inv = scalar.inv_mod_n().unwrap();
        let product_rand = scalar.mul_mod_n(&inv).unwrap();
        assert_eq!(
            product_rand.serialize(),
            expected_one,
            "random_scalar * random_scalar_inv should be 1"
        );
    }
}

/* ------------------------------------------------------------------------- */
/*                          CURVE VALIDATION TESTS                           */
/* ------------------------------------------------------------------------- */

#[test]
fn test_cofactor_validation() {
    // Test that n * G = O (point at infinity)
    let n_minus_1_bytes = [
        0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F, 0x96, 0x6B, 0x7F, 0xCC, 0x01,
        0x48, 0xF7, 0x09, 0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C, 0x47, 0xAE, 0xBB, 0x6F,
        0xB7, 0x1E, 0x91, 0x38, 0x64, 0x08,
    ];

    let n_minus_1 = ec::Scalar::new(n_minus_1_bytes).unwrap();
    let n_minus_1_g = ec::scalar_mult_base_g(&n_minus_1).unwrap();

    let mut one_bytes = [0u8; 66];
    one_bytes[65] = 1;
    let one = ec::Scalar::new(one_bytes).unwrap();
    let g = ec::scalar_mult_base_g(&one).unwrap();

    let result = n_minus_1_g.add(&g);
    assert!(result.is_identity());
}

#[test]
fn test_cross_validation() {
    let mut rng = OsRng;
    for _ in 0..3 {
        let (pk1, sk1) = EcdsaP521::keypair(&mut rng).unwrap();
        let (pk2, sk2) = EcdsaP521::keypair(&mut rng).unwrap();

        let msg1 = b"First test message";
        let msg2 = b"Second test message";

        let sig1_msg1 = EcdsaP521::sign(msg1, &sk1).unwrap();
        let sig1_msg2 = EcdsaP521::sign(msg2, &sk1).unwrap();
        let sig2_msg1 = EcdsaP521::sign(msg1, &sk2).unwrap();
        let sig2_msg2 = EcdsaP521::sign(msg2, &sk2).unwrap();

        // Correct key/message pairs should verify
        assert!(EcdsaP521::verify(msg1, &sig1_msg1, &pk1).is_ok());
        assert!(EcdsaP521::verify(msg2, &sig1_msg2, &pk1).is_ok());
        assert!(EcdsaP521::verify(msg1, &sig2_msg1, &pk2).is_ok());
        assert!(EcdsaP521::verify(msg2, &sig2_msg2, &pk2).is_ok());

        // Wrong key should fail
        assert!(EcdsaP521::verify(msg1, &sig1_msg1, &pk2).is_err());
        assert!(EcdsaP521::verify(msg2, &sig1_msg2, &pk2).is_err());
        assert!(EcdsaP521::verify(msg1, &sig2_msg1, &pk1).is_err());
        assert!(EcdsaP521::verify(msg2, &sig2_msg2, &pk1).is_err());

        // Wrong message should fail
        assert!(EcdsaP521::verify(msg2, &sig1_msg1, &pk1).is_err());
        assert!(EcdsaP521::verify(msg1, &sig1_msg2, &pk1).is_err());
    }
}

#[test]
fn test_deterministic_k_properties() {
    let mut rng = OsRng;
    let (_, sk) = EcdsaP521::keypair(&mut rng).unwrap();
    let message = b"Test deterministic k";

    // Generate multiple signatures to ensure they're different (due to hedging)
    let mut signatures: Vec<EcdsaP521Signature> = Vec::new();
    for _ in 0..5 {
        let sig = EcdsaP521::sign(message, &sk).unwrap();
        for prev_sig in &signatures {
            assert_ne!(sig.as_ref(), prev_sig.as_ref());
        }
        signatures.push(sig);
    }
}

/* ------------------------------------------------------------------------- */
/*                         TEST VECTOR TESTS (IF AVAILABLE)                  */
/* ------------------------------------------------------------------------- */

#[test]
fn test_p521_keypair_rsp_parsing_and_validation() {
    let dir = vectors_dir();
    let keypair_rsp_path = dir.join("KeyPair.rsp");

    if !keypair_rsp_path.exists() {
        eprintln!("KeyPair.rsp not found, skipping P-521 test vector validation");
        return;
    }

    let rsp_content = fs::read_to_string(&keypair_rsp_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", keypair_rsp_path.display(), e));

    let p521_vectors = parse_key_pair_vectors(&rsp_content, "[P-521]");

    if p521_vectors.is_empty() {
        eprintln!("No P-521 test vectors found in KeyPair.rsp");
        return;
    }

    for (i, vector) in p521_vectors.iter().enumerate() {
        let d_bytes_arr = hex_to_fixed_size_bytes::<{ ec::P521_SCALAR_SIZE }>(&vector.d)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse d: {}", i, e));
        let qx_expected_bytes_arr = hex_to_fixed_size_bytes::<{ ec::P521_SCALAR_SIZE }>(&vector.qx)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse Qx: {}", i, e));
        let qy_expected_bytes_arr = hex_to_fixed_size_bytes::<{ ec::P521_SCALAR_SIZE }>(&vector.qy)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse Qy: {}", i, e));

        let d_scalar = ec::Scalar::new(d_bytes_arr).unwrap_or_else(|e| {
            panic!(
                "Vector {}: Failed to create scalar d from bytes {:?}: {:?}",
                i, d_bytes_arr, e
            )
        });

        let q_calculated = ec::scalar_mult_base_g(&d_scalar)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to compute Q=dG: {:?}", i, e));

        let qx_calculated_bytes_arr = q_calculated.x_coordinate_bytes();
        let qy_calculated_bytes_arr = q_calculated.y_coordinate_bytes();

        assert_eq!(
            qx_calculated_bytes_arr, qx_expected_bytes_arr,
            "Vector {}: Qx mismatch for d={}",
            i, vector.d
        );
        assert_eq!(
            qy_calculated_bytes_arr, qy_expected_bytes_arr,
            "Vector {}: Qy mismatch for d={}",
            i, vector.d
        );
    }
}

#[test]
fn test_p521_pkv_rsp_parsing_and_validation() {
    let dir = vectors_dir();
    let pkv_rsp_path = dir.join("PKV.rsp");

    if !pkv_rsp_path.exists() {
        eprintln!("PKV.rsp not found, skipping P-521 PKV test");
        return;
    }

    let rsp_content = fs::read_to_string(&pkv_rsp_path).unwrap();
    let p521_pkv_vectors = parse_pkv_vectors(&rsp_content, "[P-521]");

    if p521_pkv_vectors.is_empty() {
        eprintln!("No P-521 PKV vectors found");
        return;
    }

    for (i, vector) in p521_pkv_vectors.iter().enumerate() {
        let qx_bytes_arr_res = hex_to_fixed_size_bytes::<{ ec::P521_SCALAR_SIZE }>(&vector.qx);
        let qy_bytes_arr_res = hex_to_fixed_size_bytes::<{ ec::P521_SCALAR_SIZE }>(&vector.qy);

        let mut pk_uncompressed = [0u8; ec::P521_POINT_UNCOMPRESSED_SIZE];
        pk_uncompressed[0] = 0x04;

        let validation_attempt: Result<ec::Point, ApiError> =
            match (qx_bytes_arr_res, qy_bytes_arr_res) {
                (Ok(qx_bytes_arr), Ok(qy_bytes_arr)) => {
                    pk_uncompressed[1..(1 + ec::P521_SCALAR_SIZE)].copy_from_slice(&qx_bytes_arr);
                    pk_uncompressed[(1 + ec::P521_SCALAR_SIZE)..].copy_from_slice(&qy_bytes_arr);
                    let public_key_candidate = EcdsaP521PublicKey(pk_uncompressed);
                    ec::Point::deserialize_uncompressed(&public_key_candidate.0)
                        .map_err(ApiError::from)
                }
                (Err(e_qx), _) => Err(ApiError::InvalidParameter {
                    context: "P521 PKV Test - Hex decoding Qx",
                    #[cfg(feature = "std")]
                    message: e_qx,
                }),
                (_, Err(e_qy)) => Err(ApiError::InvalidParameter {
                    context: "P521 PKV Test - Hex decoding Qy",
                    #[cfg(feature = "std")]
                    message: e_qy,
                }),
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

#[test]
fn test_p521_sigver_rsp_verify() {
    let dir = vectors_dir();
    let sigver_rsp_path = dir.join("SigVer.rsp");

    if !sigver_rsp_path.exists() {
        eprintln!("SigVer.rsp not found, skipping P-521 SigVer test");
        return;
    }

    let rsp_content = fs::read_to_string(&sigver_rsp_path).unwrap();
    let p521_sigver_vectors = parse_sig_ver_vectors(&rsp_content, "P-521");

    if p521_sigver_vectors.is_empty() {
        eprintln!("No P-521 SigVer vectors found");
        return;
    }

    let mut correct_hash_pass = 0;
    let mut correct_hash_fail = 0;
    let mut mismatch_hash_correct_fail_originally_p = 0;
    let mut mismatch_hash_unexpected_pass = 0;
    let mut mismatch_hash_originally_fail_and_failed = 0;

    let combo_expected_by_impl = "P-521,SHA512"; // EcdsaP521 uses SHA512 internally

    for (i, vector) in p521_sigver_vectors.iter().enumerate() {
        let msg_bytes = hex_to_vec_tolerant(&vector.msg)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse Msg: {}", i, e));
        let qx_bytes_arr = hex_to_fixed_size_bytes::<{ ec::P521_SCALAR_SIZE }>(&vector.qx)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse Qx: {}", i, e));
        let qy_bytes_arr = hex_to_fixed_size_bytes::<{ ec::P521_SCALAR_SIZE }>(&vector.qy)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse Qy: {}", i, e));
        let r_bytes_vec = hex_to_vec_tolerant(&vector.r_hex)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse R: {}", i, e));
        let s_bytes_vec = hex_to_vec_tolerant(&vector.s_hex)
            .unwrap_or_else(|e| panic!("Vector {}: Failed to parse S: {}", i, e));

        let mut pk_uncompressed = [0u8; ec::P521_POINT_UNCOMPRESSED_SIZE];
        pk_uncompressed[0] = 0x04;

        pk_uncompressed[1..(1 + ec::P521_SCALAR_SIZE)].copy_from_slice(&qx_bytes_arr);
        pk_uncompressed[(1 + ec::P521_SCALAR_SIZE)..].copy_from_slice(&qy_bytes_arr);
        let public_key = EcdsaP521PublicKey(pk_uncompressed);

        let mut canonical_s = s_bytes_vec.clone();
        if vector.expected_result == "P" && s_bytes_vec.len() <= ec::P521_SCALAR_SIZE {
            let mut padded = [0u8; ec::P521_SCALAR_SIZE];
            padded[ec::P521_SCALAR_SIZE - s_bytes_vec.len()..].copy_from_slice(&s_bytes_vec);
            if is_high_s(&padded, &NIST_P521.n) {
                let original = EcdsaP521Signature(
                    SignatureComponents {
                        r: r_bytes_vec.clone(),
                        s: s_bytes_vec.clone(),
                    }
                    .to_der(),
                );
                assert!(EcdsaP521::verify(&msg_bytes, &original, &public_key).is_err());
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
        let der_signature = EcdsaP521Signature(sig_components.to_der());

        let verification_result = EcdsaP521::verify(&msg_bytes, &der_signature, &public_key);

        if canon(&vector.curve_sha_combo) == canon(combo_expected_by_impl) {
            if vector.expected_result == "P" {
                assert!(verification_result.is_ok(),
                    "Vector {} ({}): Expected PASS (matching hash), got FAIL: {:?}\nMsg: {}\nR: {}\nS: {}",
                    i, vector.curve_sha_combo, verification_result.err(), vector.msg, vector.r_hex, vector.s_hex);
                correct_hash_pass += 1;
            } else {
                assert!(verification_result.is_err(),
                    "Vector {} ({}): Expected FAIL (matching hash), got PASS\nMsg: {}\nR: {}\nS: {}",
                    i, vector.curve_sha_combo, vector.msg, vector.r_hex, vector.s_hex);
                correct_hash_fail += 1;
            }
        } else if vector.expected_result == "P" {
            assert!(verification_result.is_err(),
                "Vector {} ({}): Expected FAIL (due to hash mismatch with EcdsaP521 internal SHA512, original was P), but got PASS.\nMsg: {}\nR: {}\nS: {}",
                i, vector.curve_sha_combo, vector.msg, vector.r_hex, vector.s_hex);
            mismatch_hash_correct_fail_originally_p += 1;
        } else if verification_result.is_ok() {
            mismatch_hash_unexpected_pass += 1;
            eprintln!(
                "ERROR: Vector {} ({}): Originally FAILED, but PASSED with EcdsaP521 internal SHA512. This is unexpected.\nMsg: {}\nR: {}\nS: {}",
                i, vector.curve_sha_combo, vector.msg, vector.r_hex, vector.s_hex
            );
        } else {
            mismatch_hash_originally_fail_and_failed += 1;
        }
    }

    println!("\n--- P-521 SigVer.rsp Test Summary ---");
    println!(
        "Total P-521 vectors processed: {}",
        p521_sigver_vectors.len()
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

    if correct_hash_pass == 0 && correct_hash_fail == 0 && !p521_sigver_vectors.is_empty() {
        let found_matching_combo = p521_sigver_vectors
            .iter()
            .any(|v| canon(&v.curve_sha_combo) == canon(combo_expected_by_impl));
        if !found_matching_combo {
            eprintln!(
                "Warning: No P-521,SHA512 test vectors were found in the parsed SigVer.rsp data."
            );
        } else {
            eprintln!("Warning: P-521,SHA512 test vectors were found, but none resulted in a PASS or FAIL count. Check test logic.");
        }
    }

    // Add assertion to fail the test if there were unexpected passes
    assert_eq!(
        mismatch_hash_unexpected_pass, 0,
        "There were {} unexpected passes with mismatched hashes for P-521.",
        mismatch_hash_unexpected_pass
    );
}
