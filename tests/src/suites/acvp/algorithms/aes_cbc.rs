//! ACVP handlers for AES-CBC mode

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use arrayref::array_ref;
use dcrypt_algorithms::block::BlockCipher;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

/// Helper to safely create a Nonce from a slice
fn make_nonce(iv: &[u8]) -> Result<dcrypt_algorithms::types::Nonce<16>> {
    if iv.len() != 16 {
        return Err(EngineError::InvalidData(format!(
            "Invalid IV length: {}",
            iv.len()
        )));
    }
    Ok(dcrypt_algorithms::types::Nonce::<16>::new(*array_ref![
        iv, 0, 16
    ]))
}

/// Standard AES-CBC AFT encrypt
pub(crate) fn aes_cbc_encrypt(_group: &TestGroup, case: &TestCase) -> Result<()> {
    use dcrypt_algorithms::block::aes::{Aes128, Aes192, Aes256};
    use dcrypt_algorithms::block::modes::cbc::Cbc;
    use dcrypt_algorithms::types::SecretBytes;

    // Get inputs - ACVP uses short field names
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

    // Expected ciphertext is OPTIONAL
    let expected_hex = case
        .inputs
        .get("ct")
        .or_else(|| case.inputs.get("cipherText"))
        .map(|v| v.as_string());

    // Decode hex values
    let mut key_bytes = hex::decode(&key_hex)?;
    let iv_bytes = hex::decode(&iv_hex)?;
    let plaintext = hex::decode(&plaintext_hex)?;

    // Create IV nonce
    let iv = make_nonce(&iv_bytes)?;

    // Perform encryption based on key size
    let result = match key_bytes.len() {
        16 => {
            let key = SecretBytes::<16>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes128::new(&key);
            let cbc = Cbc::new(cipher, &iv)?;
            cbc.encrypt(&plaintext)?
        }
        24 => {
            let key = SecretBytes::<24>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes192::new(&key);
            let cbc = Cbc::new(cipher, &iv)?;
            cbc.encrypt(&plaintext)?
        }
        32 => {
            let key = SecretBytes::<32>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes256::new(&key);
            let cbc = Cbc::new(cipher, &iv)?;
            cbc.encrypt(&plaintext)?
        }
        n => return Err(EngineError::KeySize(n)),
    };

    // Zeroize sensitive data
    key_bytes.zeroize();

    // Check result if expected value was provided
    if let Some(exp_hex) = expected_hex {
        let expected = hex::decode(&exp_hex)?;
        // Use constant-time comparison for the actual ciphertext bytes
        if result.ct_eq(&expected).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(EngineError::Mismatch {
                expected: exp_hex,
                actual: hex::encode(&result),
            })
        }
    } else {
        // Store result for response generation
        case.outputs
            .borrow_mut()
            .insert("ct".into(), hex::encode(&result));
        Ok(())
    }
}

/// Standard AES-CBC AFT decrypt
pub(crate) fn aes_cbc_decrypt(_group: &TestGroup, case: &TestCase) -> Result<()> {
    use dcrypt_algorithms::block::aes::{Aes128, Aes192, Aes256};
    use dcrypt_algorithms::block::modes::cbc::Cbc;
    use dcrypt_algorithms::types::SecretBytes;

    // Get inputs - ACVP uses short field names
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

    // Expected plaintext is OPTIONAL
    let expected_hex = case
        .inputs
        .get("pt")
        .or_else(|| case.inputs.get("plainText"))
        .map(|v| v.as_string());

    // Decode hex values
    let mut key_bytes = hex::decode(&key_hex)?;
    let iv_bytes = hex::decode(&iv_hex)?;
    let ciphertext = hex::decode(&ciphertext_hex)?;

    // Create IV nonce
    let iv = make_nonce(&iv_bytes)?;

    // Perform decryption based on key size
    let result = match key_bytes.len() {
        16 => {
            let key = SecretBytes::<16>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes128::new(&key);
            let cbc = Cbc::new(cipher, &iv)?;
            cbc.decrypt(&ciphertext)?
        }
        24 => {
            let key = SecretBytes::<24>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes192::new(&key);
            let cbc = Cbc::new(cipher, &iv)?;
            cbc.decrypt(&ciphertext)?
        }
        32 => {
            let key = SecretBytes::<32>::from_slice(&key_bytes)
                .map_err(|_| EngineError::InvalidData("Failed to create key".into()))?;
            let cipher = Aes256::new(&key);
            let cbc = Cbc::new(cipher, &iv)?;
            cbc.decrypt(&ciphertext)?
        }
        n => return Err(EngineError::KeySize(n)),
    };

    // Zeroize sensitive data
    key_bytes.zeroize();

    // Check result if expected value was provided
    if let Some(exp_hex) = expected_hex {
        let expected = hex::decode(&exp_hex)?;
        // Use constant-time comparison for the actual plaintext bytes
        if result.ct_eq(&expected).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(EngineError::Mismatch {
                expected: exp_hex,
                actual: hex::encode(&result),
            })
        }
    } else {
        // Store result for response generation
        case.outputs
            .borrow_mut()
            .insert("pt".into(), hex::encode(&result));
        Ok(())
    }
}

/// Optimized AES-CBC MCT encryption with key schedule reuse
pub(crate) fn aes_cbc_mct_encrypt_optimized(_group: &TestGroup, case: &TestCase) -> Result<()> {
    use dcrypt_algorithms::block::aes::{Aes128, Aes192, Aes256};
    use dcrypt_algorithms::block::modes::cbc::Cbc;
    use dcrypt_algorithms::types::SecretBytes;

    // Parse inputs with proper error handling
    let mut key = hex::decode(
        &case
            .inputs
            .get("key")
            .map(|v| v.as_string())
            .ok_or(EngineError::MissingField("key"))?,
    )?;
    let mut iv = hex::decode(
        &case
            .inputs
            .get("iv")
            .map(|v| v.as_string())
            .ok_or(EngineError::MissingField("iv"))?,
    )?;
    let mut pt = hex::decode(
        &case
            .inputs
            .get("pt")
            .map(|v| v.as_string())
            .ok_or(EngineError::MissingField("pt"))?,
    )?;

    // Build cipher once (key schedule reuse)
    enum CipherVariant {
        Aes128(Aes128),
        Aes192(Aes192),
        Aes256(Aes256),
    }

    let cipher = match key.len() {
        16 => {
            let key_array = array_ref![key, 0, 16];
            let secret_key = SecretBytes::<16>::new(*key_array);
            CipherVariant::Aes128(Aes128::new(&secret_key))
        }
        24 => {
            let key_array = array_ref![key, 0, 24];
            let secret_key = SecretBytes::<24>::new(*key_array);
            CipherVariant::Aes192(Aes192::new(&secret_key))
        }
        32 => {
            let key_array = array_ref![key, 0, 32];
            let secret_key = SecretBytes::<32>::new(*key_array);
            CipherVariant::Aes256(Aes256::new(&secret_key))
        }
        n => return Err(EngineError::KeySize(n)),
    };

    // Monte Carlo loop - 1000 iterations
    for _ in 0..1000 {
        let iv_nonce = make_nonce(&iv)?;

        // Only recreate CBC wrapper (cheap, IV-only change)
        let ct = match &cipher {
            CipherVariant::Aes128(c) => {
                let cbc = Cbc::new(c.clone(), &iv_nonce)?;
                cbc.encrypt(&pt)?
            }
            CipherVariant::Aes192(c) => {
                let cbc = Cbc::new(c.clone(), &iv_nonce)?;
                cbc.encrypt(&pt)?
            }
            CipherVariant::Aes256(c) => {
                let cbc = Cbc::new(c.clone(), &iv_nonce)?;
                cbc.encrypt(&pt)?
            }
        };

        // Update for next iteration
        if ct.len() >= 16 {
            iv.clear();
            iv.extend_from_slice(&ct[ct.len() - 16..]);
        } else {
            return Err(EngineError::InvalidData("Ciphertext too short".into()));
        }
        pt = ct;
    }

    // Zeroize sensitive data
    key.zeroize();
    iv.zeroize();

    // Check or store result - pt now contains final ciphertext (CT999)
    if let Some(expected_hex) = case.inputs.get("ct").map(|v| v.as_string()) {
        // For test vectors, regular comparison is acceptable
        let result_hex = hex::encode(&pt);
        if result_hex == expected_hex {
            Ok(())
        } else {
            Err(EngineError::Mismatch {
                expected: expected_hex,
                actual: result_hex,
            })
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert("ct".into(), hex::encode(&pt));
        Ok(())
    }
}

/// Optimized AES-CBC MCT decryption with key schedule reuse
pub(crate) fn aes_cbc_mct_decrypt_optimized(_group: &TestGroup, case: &TestCase) -> Result<()> {
    use dcrypt_algorithms::block::aes::{Aes128, Aes192, Aes256};
    use dcrypt_algorithms::block::modes::cbc::Cbc;
    use dcrypt_algorithms::types::SecretBytes;

    // Parse inputs with proper error handling
    let mut key = hex::decode(
        &case
            .inputs
            .get("key")
            .map(|v| v.as_string())
            .ok_or(EngineError::MissingField("key"))?,
    )?;
    let mut iv = hex::decode(
        &case
            .inputs
            .get("iv")
            .map(|v| v.as_string())
            .ok_or(EngineError::MissingField("iv"))?,
    )?;
    let mut ct = hex::decode(
        &case
            .inputs
            .get("ct")
            .map(|v| v.as_string())
            .ok_or(EngineError::MissingField("ct"))?,
    )?;

    // Build cipher once (key schedule reuse)
    enum CipherVariant {
        Aes128(Aes128),
        Aes192(Aes192),
        Aes256(Aes256),
    }

    let cipher = match key.len() {
        16 => {
            let key_array = array_ref![key, 0, 16];
            let secret_key = SecretBytes::<16>::new(*key_array);
            CipherVariant::Aes128(Aes128::new(&secret_key))
        }
        24 => {
            let key_array = array_ref![key, 0, 24];
            let secret_key = SecretBytes::<24>::new(*key_array);
            CipherVariant::Aes192(Aes192::new(&secret_key))
        }
        32 => {
            let key_array = array_ref![key, 0, 32];
            let secret_key = SecretBytes::<32>::new(*key_array);
            CipherVariant::Aes256(Aes256::new(&secret_key))
        }
        n => return Err(EngineError::KeySize(n)),
    };

    // Monte Carlo loop - 1000 iterations
    for _ in 0..1000 {
        let iv_nonce = make_nonce(&iv)?;

        // Store current ciphertext for next IV
        let current_ct = ct.clone();

        // Only recreate CBC wrapper (cheap, IV-only change)
        let pt = match &cipher {
            CipherVariant::Aes128(c) => {
                let cbc = Cbc::new(c.clone(), &iv_nonce)?;
                cbc.decrypt(&current_ct)?
            }
            CipherVariant::Aes192(c) => {
                let cbc = Cbc::new(c.clone(), &iv_nonce)?;
                cbc.decrypt(&current_ct)?
            }
            CipherVariant::Aes256(c) => {
                let cbc = Cbc::new(c.clone(), &iv_nonce)?;
                cbc.decrypt(&current_ct)?
            }
        };

        // Update for next iteration
        if current_ct.len() >= 16 {
            iv.clear();
            iv.extend_from_slice(&current_ct[current_ct.len() - 16..]);
        } else {
            return Err(EngineError::InvalidData("Ciphertext too short".into()));
        }
        ct = pt;
    }

    // Zeroize sensitive data
    key.zeroize();
    iv.zeroize();

    // After 1000 iterations, ct holds PT999
    if let Some(expected_hex) = case.inputs.get("pt").map(|v| v.as_string()) {
        // For test vectors, regular comparison is acceptable
        let result_hex = hex::encode(&ct);
        if result_hex == expected_hex {
            Ok(())
        } else {
            Err(EngineError::Mismatch {
                expected: expected_hex,
                actual: result_hex,
            })
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert("pt".into(), hex::encode(&ct));
        Ok(())
    }
}

/// Register AES-CBC handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "AES-CBC", "encrypt", "AFT", aes_cbc_encrypt);
    insert(map, "AES-CBC", "decrypt", "AFT", aes_cbc_decrypt);
    insert(
        map,
        "AES-CBC",
        "encrypt",
        "MCT",
        aes_cbc_mct_encrypt_optimized,
    );
    insert(
        map,
        "AES-CBC",
        "decrypt",
        "MCT",
        aes_cbc_mct_decrypt_optimized,
    );
}
