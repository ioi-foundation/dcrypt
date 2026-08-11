//! ACVP handlers for AES-GCM mode

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use arrayref::array_ref;
use dcrypt_algorithms::aead::gcm::Gcm;
use dcrypt_algorithms::block::aes::{Aes128, Aes192, Aes256};
use dcrypt_algorithms::block::BlockCipher;
use dcrypt_algorithms::types::{Nonce, SecretBytes};
use zeroize::Zeroize;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};
fn skip_unsupported_tag(case: &TestCase, tag_len: usize) -> Result<bool> {
    if tag_len < 12 {
        case.mark_skipped(format!(
            "{}-bit GCM tags are intentionally unsupported; minimum is 96 bits",
            tag_len * 8
        ));
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

    // Emit computed values only.  The runner owns all comparison with the
    // separately loaded expected-results namespace.
    case.outputs
        .borrow_mut()
        .insert("ct".into(), hex::encode(ciphertext));
    case.outputs
        .borrow_mut()
        .insert("tag".into(), hex::encode(tag));
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

    // The expected validity bit is evidence, never an input.  Only the typed
    // authentication rejection is a computed negative verdict; every other
    // operational error remains a harness failure.
    match decrypt_result {
        Ok(plaintext) => {
            case.outputs
                .borrow_mut()
                .insert("pt".into(), hex::encode(plaintext));
            Ok(())
        }
        Err(dcrypt_algorithms::error::Error::Authentication { .. }) => {
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "false".into());
            Ok(())
        }
        Err(error) => Err(EngineError::from(error)),
    }
}

/// Register AES-GCM handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "AES-GCM", "encrypt", "AFT", aes_gcm_encrypt);
    insert(map, "AES-GCM", "decrypt", "AFT", aes_gcm_decrypt);
    // Note: GCM doesn't typically have MCT (Monte Carlo Test) mode
}
