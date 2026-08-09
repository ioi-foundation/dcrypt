//! ACVP handlers for HMAC (Hash-based Message Authentication Code)

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use dcrypt_algorithms::hash::sha1::Sha1;
use dcrypt_algorithms::hash::sha2::{Sha224, Sha256, Sha384, Sha512};
use dcrypt_algorithms::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use dcrypt_algorithms::mac::hmac::Hmac;
use hex;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

fn lookup<'a>(case: &'a TestCase, group: &'a TestGroup, name: &str) -> Option<String> {
    case.inputs
        .get(name)
        .or_else(|| group.defaults.get(name))
        .map(|value| value.as_string())
}

/// HMAC Algorithm Functional Test (AFT) handler
pub(crate) fn hmac_aft(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get inputs
    let key_hex = case
        .inputs
        .get("key")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("key"))?;

    let msg_hex = case
        .inputs
        .get("msg")
        .or_else(|| case.inputs.get("message"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("msg"))?;

    // Get expected MAC if provided
    let expected_mac = case
        .inputs
        .get("mac")
        .or_else(|| case.inputs.get("tag"))
        .map(|v| v.as_string());

    // Decode inputs
    let key = hex::decode(&key_hex)?;
    let msg = hex::decode(&msg_hex)?;

    // Determine which HMAC variant to use based on algorithm name
    let algorithm = &group.algorithm;

    let mac = match algorithm.as_str() {
        "HMAC-SHA-1" | "HMAC-SHA1" => Hmac::<Sha1>::mac(&key, &msg)?,
        "HMAC-SHA2-224" | "HMAC-SHA-224" | "HMAC-SHA224" => Hmac::<Sha224>::mac(&key, &msg)?,
        "HMAC-SHA2-256" | "HMAC-SHA-256" | "HMAC-SHA256" => Hmac::<Sha256>::mac(&key, &msg)?,
        "HMAC-SHA2-384" | "HMAC-SHA-384" | "HMAC-SHA384" => Hmac::<Sha384>::mac(&key, &msg)?,
        "HMAC-SHA2-512" | "HMAC-SHA-512" | "HMAC-SHA512" => Hmac::<Sha512>::mac(&key, &msg)?,
        "HMAC-SHA3-224" => Hmac::<Sha3_224>::mac(&key, &msg)?,
        "HMAC-SHA3-256" => Hmac::<Sha3_256>::mac(&key, &msg)?,
        "HMAC-SHA3-384" => Hmac::<Sha3_384>::mac(&key, &msg)?,
        "HMAC-SHA3-512" => Hmac::<Sha3_512>::mac(&key, &msg)?,
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported HMAC variant: {}",
                algorithm
            )))
        }
    };

    let mac_len_bits = lookup(case, group, "macLen")
        .ok_or(EngineError::MissingField("macLen"))?
        .parse::<usize>()
        .map_err(|_| EngineError::InvalidData("macLen must be an integer".into()))?;
    if mac_len_bits % 8 != 0 {
        return Err(EngineError::InvalidData(
            "macLen must be a multiple of 8 bits".into(),
        ));
    }
    let mac_len_bytes = mac_len_bits / 8;
    if mac_len_bytes > mac.len() {
        return Err(EngineError::InvalidData(format!(
            "macLen {mac_len_bits} exceeds the {}-bit HMAC output",
            mac.len() * 8
        )));
    }
    let mac_hex = hex::encode(&mac[..mac_len_bytes]);

    // Check result if expected value was provided
    if let Some(expected) = expected_mac {
        if !super::hex_equal(&mac_hex, &expected) {
            return Err(EngineError::Mismatch {
                expected,
                actual: mac_hex,
            });
        }
    } else {
        // Store result for response generation
        case.outputs.borrow_mut().insert("mac".into(), mac_hex);
    }

    Ok(())
}

/// HMAC Verification Test handler
pub(crate) fn hmac_verify(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get inputs
    let key_hex = case
        .inputs
        .get("key")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("key"))?;

    let msg_hex = case
        .inputs
        .get("msg")
        .or_else(|| case.inputs.get("message"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("msg"))?;

    let mac_hex = case
        .inputs
        .get("mac")
        .or_else(|| case.inputs.get("tag"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("mac"))?;

    // Decode inputs
    let key = hex::decode(&key_hex)?;
    let msg = hex::decode(&msg_hex)?;
    let mac = hex::decode(&mac_hex)?;

    // Determine which HMAC variant to use
    let algorithm = &group.algorithm;

    let is_valid = match algorithm.as_str() {
        "HMAC-SHA-1" | "HMAC-SHA1" => Hmac::<Sha1>::verify(&key, &msg, &mac)?,
        "HMAC-SHA2-224" | "HMAC-SHA-224" | "HMAC-SHA224" => {
            Hmac::<Sha224>::verify(&key, &msg, &mac)?
        }
        "HMAC-SHA2-256" | "HMAC-SHA-256" | "HMAC-SHA256" => {
            Hmac::<Sha256>::verify(&key, &msg, &mac)?
        }
        "HMAC-SHA2-384" | "HMAC-SHA-384" | "HMAC-SHA384" => {
            Hmac::<Sha384>::verify(&key, &msg, &mac)?
        }
        "HMAC-SHA2-512" | "HMAC-SHA-512" | "HMAC-SHA512" => {
            Hmac::<Sha512>::verify(&key, &msg, &mac)?
        }
        "HMAC-SHA3-224" => Hmac::<Sha3_224>::verify(&key, &msg, &mac)?,
        "HMAC-SHA3-256" => Hmac::<Sha3_256>::verify(&key, &msg, &mac)?,
        "HMAC-SHA3-384" => Hmac::<Sha3_384>::verify(&key, &msg, &mac)?,
        "HMAC-SHA3-512" => Hmac::<Sha3_512>::verify(&key, &msg, &mac)?,
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported HMAC variant: {}",
                algorithm
            )))
        }
    };

    // For verification tests, store whether the MAC was valid
    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), is_valid.to_string());

    Ok(())
}

/// Register HMAC handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // Register AFT handlers for all HMAC variants
    let hmac_variants = &[
        "HMAC-SHA-1",
        "HMAC-SHA1",
        "HMAC-SHA2-224",
        "HMAC-SHA-224",
        "HMAC-SHA224",
        "HMAC-SHA2-256",
        "HMAC-SHA-256",
        "HMAC-SHA256",
        "HMAC-SHA2-384",
        "HMAC-SHA-384",
        "HMAC-SHA384",
        "HMAC-SHA2-512",
        "HMAC-SHA-512",
        "HMAC-SHA512",
        "HMAC-SHA3-224",
        "HMAC-SHA3-256",
        "HMAC-SHA3-384",
        "HMAC-SHA3-512",
    ];

    for algo in hmac_variants {
        // AFT generation tests
        insert(map, algo, "gen", "AFT", hmac_aft);
        insert(map, algo, "generate", "AFT", hmac_aft);

        // AFT verification tests
        insert(map, algo, "ver", "AFT", hmac_verify);
        insert(map, algo, "verify", "AFT", hmac_verify);

        // Add a fallback for when ACVP test vectors lack a specific "function" or "direction",
        // causing the dispatcher to use the "testType" ("AFT") as the direction.
        insert(map, algo, "AFT", "AFT", hmac_aft);
    }
}
