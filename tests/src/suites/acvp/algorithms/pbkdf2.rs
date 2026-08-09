//! ACVP handlers for PBKDF2 (Password-Based Key Derivation Function 2)

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use dcrypt_algorithms::hash::sha1::Sha1;
use dcrypt_algorithms::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use dcrypt_algorithms::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use dcrypt_algorithms::kdf::pbkdf2::{Pbkdf2, Pbkdf2Params};
use dcrypt_algorithms::kdf::{KeyDerivationFunction, ParamProvider};
use dcrypt_algorithms::types::Salt;
use hex;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

/// Helper to look for a value in the test case first, then the group defaults
fn lookup<'a>(case: &'a TestCase, group: &'a TestGroup, names: &[&str]) -> Option<String> {
    for &name in names {
        if let Some(v) = case.inputs.get(name) {
            return Some(v.as_string());
        }
        if let Some(v) = group.defaults.get(name) {
            return Some(v.as_string());
        }
    }
    None
}

/// PBKDF2 Algorithm Functional Test (AFT) handler
pub(crate) fn pbkdf2_aft(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get inputs - ACVP uses these field names for PBKDF2
    let password_str = lookup(case, group, &["password", "pass", "p"])
        .ok_or(EngineError::MissingField("password"))?;

    let salt_str = lookup(case, group, &["salt", "s"]).ok_or(EngineError::MissingField("salt"))?;

    // Get iteration count
    let iterations_str = lookup(case, group, &["iterationCount", "iterations", "c"])
        .ok_or(EngineError::MissingField("iterationCount"))?;
    let iterations = iterations_str.parse::<u32>().map_err(|_| {
        EngineError::InvalidData(format!("Invalid iteration count: {}", iterations_str))
    })?;

    // Get key length - ACVP provides this in BITS
    let key_len_str = lookup(case, group, &["keyLen", "dkLen", "keyLength"])
        .ok_or(EngineError::MissingField("keyLen"))?;
    let key_len_bits = key_len_str
        .parse::<usize>()
        .map_err(|_| EngineError::InvalidData(format!("Invalid key length: {}", key_len_str)))?;

    if key_len_bits % 8 != 0 {
        return Err(EngineError::InvalidData(
            "Key length must be a multiple of 8 bits".into(),
        ));
    }
    let key_len_bytes = key_len_bits / 8;

    // Get expected derived key if provided (this is typically hex encoded)
    let expected_dk = lookup(case, group, &["derivedKey", "dk", "dkm"]);

    // ACVP PBKDF encodes passwords as literal strings and salts as hexadecimal.
    // Guessing encodings is not safe here: many ordinary ASCII passwords are also
    // syntactically valid Base64 and would silently derive a different key.
    let password = password_str.as_bytes();
    let salt_bytes = hex::decode(&salt_str)?;

    // Get the HMAC algorithm
    let hmac_alg = lookup(case, group, &["hmacAlg"])
        .or_else(|| {
            // Try to extract from the algorithm name
            let algo = &group.algorithm;
            if algo.contains("SHA1") || algo.contains("SHA-1") {
                Some("SHA-1".to_string())
            } else if algo.contains("SHA224")
                || algo.contains("SHA-224")
                || algo.contains("SHA2-224")
            {
                Some("SHA2-224".to_string())
            } else if algo.contains("SHA256")
                || algo.contains("SHA-256")
                || algo.contains("SHA2-256")
            {
                Some("SHA2-256".to_string())
            } else if algo.contains("SHA384")
                || algo.contains("SHA-384")
                || algo.contains("SHA2-384")
            {
                Some("SHA2-384".to_string())
            } else if algo.contains("SHA512")
                || algo.contains("SHA-512")
                || algo.contains("SHA2-512")
            {
                Some("SHA2-512".to_string())
            } else if algo.contains("SHA3-224") {
                Some("SHA3-224".to_string())
            } else if algo.contains("SHA3-256") {
                Some("SHA3-256".to_string())
            } else if algo.contains("SHA3-384") {
                Some("SHA3-384".to_string())
            } else if algo.contains("SHA3-512") {
                Some("SHA3-512".to_string())
            } else {
                None
            }
        })
        .ok_or(EngineError::MissingField("hmacAlg"))?;

    // Create parameters with the specified iteration count
    let params = Pbkdf2Params {
        salt: Salt::<16>::zeroed(), // Will be overridden by derive_key
        iterations,
        key_length: key_len_bytes,
    };

    // Perform PBKDF2 based on the HMAC algorithm
    let dk_hex = match hmac_alg.as_str() {
        "SHA-1" | "SHA1" => {
            let pbkdf2 = Pbkdf2::<Sha1, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        "SHA-224" | "SHA224" | "SHA2-224" => {
            let pbkdf2 = Pbkdf2::<Sha224, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        "SHA-256" | "SHA256" | "SHA2-256" => {
            let pbkdf2 = Pbkdf2::<Sha256, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        "SHA-384" | "SHA384" | "SHA2-384" => {
            let pbkdf2 = Pbkdf2::<Sha384, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        "SHA-512" | "SHA512" | "SHA2-512" => {
            let pbkdf2 = Pbkdf2::<Sha512, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        "SHA3-224" | "SHA-3-224" => {
            let pbkdf2 = Pbkdf2::<Sha3_224, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        "SHA3-256" | "SHA-3-256" => {
            let pbkdf2 = Pbkdf2::<Sha3_256, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        "SHA3-384" | "SHA-3-384" => {
            let pbkdf2 = Pbkdf2::<Sha3_384, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        "SHA3-512" | "SHA-3-512" => {
            let pbkdf2 = Pbkdf2::<Sha3_512, 16>::with_params(params);
            let dk = pbkdf2.derive_key(password, Some(&salt_bytes), None, key_len_bytes)?;
            hex::encode(&dk)
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported HMAC algorithm: {}",
                hmac_alg
            )))
        }
    };

    // Check result if expected value was provided
    if let Some(expected) = expected_dk {
        if !super::hex_equal(&dk_hex, &expected) {
            return Err(EngineError::Mismatch {
                expected,
                actual: dk_hex,
            });
        }
    } else {
        // Store result for response generation
        case.outputs
            .borrow_mut()
            .insert("derivedKey".into(), dk_hex);
    }

    Ok(())
}

/// Register PBKDF2 handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // Register AFT handlers for PBKDF2 with various hash functions
    let pbkdf2_variants = &[
        "PBKDF",
        "PBKDF2",
        "PBKDF-SHA-1",
        "PBKDF2-SHA-1",
        "PBKDF-SHA1",
        "PBKDF2-SHA1",
        "PBKDF-SHA-224",
        "PBKDF2-SHA-224",
        "PBKDF-SHA224",
        "PBKDF2-SHA224",
        "PBKDF-SHA-256",
        "PBKDF2-SHA-256",
        "PBKDF-SHA256",
        "PBKDF2-SHA256",
        "PBKDF-SHA-384",
        "PBKDF2-SHA-384",
        "PBKDF-SHA384",
        "PBKDF2-SHA384",
        "PBKDF-SHA-512",
        "PBKDF2-SHA-512",
        "PBKDF-SHA512",
        "PBKDF2-SHA512",
        "PBKDF-SHA3-224",
        "PBKDF2-SHA3-224",
        "PBKDF-SHA3-256",
        "PBKDF2-SHA3-256",
        "PBKDF-SHA3-384",
        "PBKDF2-SHA3-384",
        "PBKDF-SHA3-512",
        "PBKDF2-SHA3-512",
    ];

    for algo in pbkdf2_variants {
        // AFT tests
        insert(map, algo, "AFT", "AFT", pbkdf2_aft);

        // Some ACVP vectors might not have a specific direction
        insert(map, algo, "", "AFT", pbkdf2_aft);
    }
}
