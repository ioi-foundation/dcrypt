//! ACVP handlers for AES-GCM mode

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use arrayref::array_ref;
use dcrypt_algorithms::aead::gcm::Gcm;
use dcrypt_algorithms::block::aes::{Aes128, Aes192, Aes256};
use dcrypt_algorithms::block::BlockCipher;
use dcrypt_algorithms::types::{Nonce, SecretBytes};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};
use super::super::runner::SKIP_MARKER;

fn skip_unsupported_tag(case: &TestCase, tag_len: usize) -> Result<bool> {
    if tag_len < 12 {
        case.outputs.borrow_mut().insert(
            SKIP_MARKER.into(),
            format!(
                "{}-bit GCM tags are intentionally unsupported; minimum is 96 bits",
                tag_len * 8
            ),
        );
        return Ok(true);
    }
    if tag_len > 16 {
        return Err(EngineError::InvalidData(format!(
            "GCM tag length exceeds 128 bits: {}",
            tag_len * 8
        )));
    }
    Ok(false)
}

/// Extract tag length from test case (ACVP provides it in bits)
fn get_tag_length(case: &TestCase, group: &TestGroup) -> Result<usize> {
    // Look for tagLen in case inputs first, then group defaults
    let tag_len_bits = case
        .inputs
        .get("tagLen")
        .or_else(|| group.defaults.get("tagLen"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("tagLen"))?
        .parse::<usize>()
        .map_err(|_| EngineError::InvalidData("Invalid tagLen".into()))?;

    // Convert from bits to bytes
    if tag_len_bits % 8 != 0 {
        return Err(EngineError::InvalidData(format!(
            "Tag length must be a multiple of 8 bits, got {}",
            tag_len_bits
        )));
    }

    let tag_len_bytes = tag_len_bits / 8;
    if tag_len_bytes < 1 || tag_len_bytes > 16 {
        return Err(EngineError::InvalidData(format!(
            "Tag length must be between 8 and 128 bits, got {}",
            tag_len_bits
        )));
    }

    Ok(tag_len_bytes)
}

/// Standard AES-GCM AFT encrypt
pub(crate) fn aes_gcm_encrypt(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get inputs
    let key_hex = case
        .inputs
        .get("key")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("key"))?;
    let iv_hex = case
        .inputs
        .get("iv")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("iv"))?;
    let plaintext_hex = case
        .inputs
        .get("pt")
        .or_else(|| case.inputs.get("plainText"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("pt"))?;

    // AAD is optional
    let aad_hex = case.inputs.get("aad").map(|v| v.as_string());

    // Expected outputs (optional for generation)
    let expected_ct_hex = case
        .inputs
        .get("ct")
        .or_else(|| case.inputs.get("cipherText"))
        .map(|v| v.as_string());
    let expected_tag_hex = case.inputs.get("tag").map(|v| v.as_string());

    // Decode hex values
    let mut key_bytes = hex::decode(&key_hex)?;
    let iv_bytes = hex::decode(&iv_hex)?;
    let plaintext = hex::decode(&plaintext_hex)?;
    let aad = if let Some(aad_hex) = aad_hex {
        hex::decode(&aad_hex)?
    } else {
        Vec::new()
    };

    // Get tag length
    let tag_len = get_tag_length(case, group)?;
    if skip_unsupported_tag(case, tag_len)? {
        key_bytes.zeroize();
        return Ok(());
    }

    // Perform encryption based on key size AND IV length
    let result = match (key_bytes.len(), iv_bytes.len()) {
        // 128-bit key with 96-bit IV
        (16, 12) => {
            let key = SecretBytes::<16>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes128::new(&key);
            let nonce = Nonce::<12>::new(*array_ref![iv_bytes, 0, 12]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_encrypt(&nonce, &plaintext, Some(&aad))?
        }
        // 128-bit key with 120-bit IV
        (16, 15) => {
            let key = SecretBytes::<16>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes128::new(&key);
            let nonce = Nonce::<15>::new(*array_ref![iv_bytes, 0, 15]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_encrypt(&nonce, &plaintext, Some(&aad))?
        }
        // 192-bit key with 96-bit IV
        (24, 12) => {
            let key = SecretBytes::<24>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes192::new(&key);
            let nonce = Nonce::<12>::new(*array_ref![iv_bytes, 0, 12]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_encrypt(&nonce, &plaintext, Some(&aad))?
        }
        // 192-bit key with 120-bit IV
        (24, 15) => {
            let key = SecretBytes::<24>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes192::new(&key);
            let nonce = Nonce::<15>::new(*array_ref![iv_bytes, 0, 15]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_encrypt(&nonce, &plaintext, Some(&aad))?
        }
        // 256-bit key with 96-bit IV
        (32, 12) => {
            let key = SecretBytes::<32>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes256::new(&key);
            let nonce = Nonce::<12>::new(*array_ref![iv_bytes, 0, 12]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_encrypt(&nonce, &plaintext, Some(&aad))?
        }
        // 256-bit key with 120-bit IV
        (32, 15) => {
            let key = SecretBytes::<32>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes256::new(&key);
            let nonce = Nonce::<15>::new(*array_ref![iv_bytes, 0, 15]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_encrypt(&nonce, &plaintext, Some(&aad))?
        }
        (_, iv_len) => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported IV length for GCM: {} bytes",
                iv_len
            )))
        }
    };

    // Zeroize sensitive data
    key_bytes.zeroize();

    // Split result into ciphertext and tag
    let (ciphertext, tag) = result.split_at(result.len() - tag_len);

    // Check results if expected values were provided
    if let Some(exp_ct_hex) = expected_ct_hex {
        let expected_ct = hex::decode(&exp_ct_hex)?;
        if ciphertext.ct_eq(&expected_ct).unwrap_u8() != 1 {
            return Err(EngineError::Mismatch {
                expected: exp_ct_hex,
                actual: hex::encode(ciphertext),
            });
        }
    } else {
        // Store ciphertext for response generation
        case.outputs
            .borrow_mut()
            .insert("ct".into(), hex::encode(ciphertext));
    }

    if let Some(exp_tag_hex) = expected_tag_hex {
        let expected_tag = hex::decode(&exp_tag_hex)?;
        if tag.ct_eq(&expected_tag).unwrap_u8() != 1 {
            return Err(EngineError::Mismatch {
                expected: exp_tag_hex,
                actual: hex::encode(tag),
            });
        }
    } else {
        // Store tag for response generation
        case.outputs
            .borrow_mut()
            .insert("tag".into(), hex::encode(tag));
    }

    Ok(())
}

/// Standard AES-GCM AFT decrypt
pub(crate) fn aes_gcm_decrypt(_group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get inputs
    let key_hex = case
        .inputs
        .get("key")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("key"))?;
    let iv_hex = case
        .inputs
        .get("iv")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("iv"))?;
    let ciphertext_hex = case
        .inputs
        .get("ct")
        .or_else(|| case.inputs.get("cipherText"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("ct"))?;
    let tag_hex = case
        .inputs
        .get("tag")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("tag"))?;

    // AAD is optional
    let aad_hex = case.inputs.get("aad").map(|v| v.as_string());

    // Expected plaintext (optional)
    let expected_pt_hex = case
        .inputs
        .get("pt")
        .or_else(|| case.inputs.get("plainText"))
        .map(|v| v.as_string());

    // For decryption tests, ACVP might include a "fail" flag
    let should_fail = case
        .inputs
        .get("fail")
        .map(|v| v.as_string() == "true")
        .unwrap_or(false);

    // Decode hex values
    let mut key_bytes = hex::decode(&key_hex)?;
    let iv_bytes = hex::decode(&iv_hex)?;
    let ciphertext = hex::decode(&ciphertext_hex)?;
    let tag = hex::decode(&tag_hex)?;
    let aad = if let Some(aad_hex) = aad_hex {
        hex::decode(&aad_hex)?
    } else {
        Vec::new()
    };

    // Get tag length from the tag itself
    let tag_len = tag.len();
    if skip_unsupported_tag(case, tag_len)? {
        key_bytes.zeroize();
        return Ok(());
    }

    // Combine ciphertext and tag for decryption
    let mut combined = ciphertext.clone();
    combined.extend_from_slice(&tag);

    // Perform decryption based on key size AND IV length
    let decrypt_result = match (key_bytes.len(), iv_bytes.len()) {
        // 128-bit key with 96-bit IV
        (16, 12) => {
            let key = SecretBytes::<16>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes128::new(&key);
            let nonce = Nonce::<12>::new(*array_ref![iv_bytes, 0, 12]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_decrypt(&nonce, &combined, Some(&aad))
        }
        // 128-bit key with 120-bit IV
        (16, 15) => {
            let key = SecretBytes::<16>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes128::new(&key);
            let nonce = Nonce::<15>::new(*array_ref![iv_bytes, 0, 15]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_decrypt(&nonce, &combined, Some(&aad))
        }
        // 192-bit key with 96-bit IV
        (24, 12) => {
            let key = SecretBytes::<24>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes192::new(&key);
            let nonce = Nonce::<12>::new(*array_ref![iv_bytes, 0, 12]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_decrypt(&nonce, &combined, Some(&aad))
        }
        // 192-bit key with 120-bit IV
        (24, 15) => {
            let key = SecretBytes::<24>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes192::new(&key);
            let nonce = Nonce::<15>::new(*array_ref![iv_bytes, 0, 15]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_decrypt(&nonce, &combined, Some(&aad))
        }
        // 256-bit key with 96-bit IV
        (32, 12) => {
            let key = SecretBytes::<32>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes256::new(&key);
            let nonce = Nonce::<12>::new(*array_ref![iv_bytes, 0, 12]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_decrypt(&nonce, &combined, Some(&aad))
        }
        // 256-bit key with 120-bit IV
        (32, 15) => {
            let key = SecretBytes::<32>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes256::new(&key);
            let nonce = Nonce::<15>::new(*array_ref![iv_bytes, 0, 15]);
            let gcm = Gcm::new_with_tag_len(cipher, tag_len)?;
            gcm.internal_decrypt(&nonce, &combined, Some(&aad))
        }
        (_, iv_len) => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported IV length for GCM: {} bytes",
                iv_len
            )))
        }
    };

    // Zeroize sensitive data
    key_bytes.zeroize();

    // Handle the result based on whether we expect failure
    match (decrypt_result, should_fail) {
        (Ok(plaintext), false) => {
            // Successful decryption when expected
            if let Some(exp_pt_hex) = expected_pt_hex {
                let expected_pt = hex::decode(&exp_pt_hex)?;
                if plaintext.ct_eq(&expected_pt).unwrap_u8() != 1 {
                    return Err(EngineError::Mismatch {
                        expected: exp_pt_hex,
                        actual: hex::encode(&plaintext),
                    });
                }
            } else {
                // Store plaintext for response generation
                case.outputs
                    .borrow_mut()
                    .insert("pt".into(), hex::encode(&plaintext));
            }
            Ok(())
        }
        (Err(_), true) => {
            // Failed decryption when expected (authentication failure)
            // This is a pass - the implementation correctly rejected invalid data
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "true".into());
            Ok(())
        }
        (Ok(_), true) => {
            // Successful decryption when failure was expected
            Err(EngineError::Mismatch {
                expected: "authentication failure".into(),
                actual: "successful decryption".into(),
            })
        }
        (Err(_), false) => {
            // Failed decryption when success was expected
            // For ACVP, some test cases are expected to fail authentication
            // These should be marked as testPassed = false, not errors
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "false".into());
            Ok(())
        }
    }
}

/// Register AES-GCM handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "AES-GCM", "encrypt", "AFT", aes_gcm_encrypt);
    insert(map, "AES-GCM", "decrypt", "AFT", aes_gcm_decrypt);
    // Note: GCM doesn't typically have MCT (Monte Carlo Test) mode
}
