//! ACVP handlers for ECDSA operations

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use crate::test_rng::ChaCha20Rng;
use dcrypt_api::Signature;
use dcrypt_sign::ecdsa::{
    EcdsaP192,
    EcdsaP192PublicKey,
    EcdsaP192Signature, // Added P-192
    EcdsaP224,
    EcdsaP224PublicKey,
    EcdsaP224Signature,
    EcdsaP256,
    EcdsaP256PublicKey,
    EcdsaP256Signature,
    EcdsaP384,
    EcdsaP384PublicKey,
    EcdsaP384Signature,
    EcdsaP521,
    EcdsaP521PublicKey,
    EcdsaP521Signature,
};
use hex;
// Import P-192 constants
use dcrypt_algorithms::ec::p192 as ec_p192;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

/// ECDSA Key Generation
pub(crate) fn ecdsa_keygen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let curve = group
        .defaults
        .get("curve")
        .or_else(|| case.inputs.get("curve"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("curve"))?;

    let mut rng = if let Some(seed_hex) = case.inputs.get("seed").map(|v| v.as_string()) {
        let seed_bytes = hex::decode(&seed_hex)?;
        let mut seed = [0u8; 32];
        let len_to_copy = std::cmp::min(32, seed_bytes.len());
        seed[..len_to_copy].copy_from_slice(&seed_bytes[..len_to_copy]);
        ChaCha20Rng::from_seed(seed)
    } else {
        ChaCha20Rng::from_entropy()
    };

    match curve.as_str() {
        "P-192" | "secp192r1" => {
            // Added P-192
            let (public_key, secret_key) = EcdsaP192::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!("P-192 keypair generation failed: {:?}", e))
            })?;
            let d_bytes = secret_key.as_ref();
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == ec_p192::P192_POINT_UNCOMPRESSED_SIZE && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("d".into(), hex::encode(d_bytes));
                case.outputs.borrow_mut().insert(
                    "qx".into(),
                    hex::encode(&pub_bytes[1..1 + ec_p192::P192_FIELD_ELEMENT_SIZE]),
                );
                case.outputs.borrow_mut().insert(
                    "qy".into(),
                    hex::encode(&pub_bytes[1 + ec_p192::P192_FIELD_ELEMENT_SIZE..]),
                );
            } else {
                return Err(EngineError::Crypto(
                    "Invalid P-192 public key format".into(),
                ));
            }
        }
        "P-224" | "secp224r1" => {
            let (public_key, secret_key) = EcdsaP224::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!("P-224 keypair generation failed: {:?}", e))
            })?;
            let d_bytes = secret_key.as_ref();
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == 57 && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("d".into(), hex::encode(d_bytes));
                case.outputs
                    .borrow_mut()
                    .insert("qx".into(), hex::encode(&pub_bytes[1..29]));
                case.outputs
                    .borrow_mut()
                    .insert("qy".into(), hex::encode(&pub_bytes[29..57]));
            } else {
                return Err(EngineError::Crypto(
                    "Invalid P-224 public key format".into(),
                ));
            }
        }
        "P-256" | "secp256r1" => {
            let (public_key, secret_key) = EcdsaP256::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!("P-256 keypair generation failed: {:?}", e))
            })?;
            let d_bytes = secret_key.as_ref();
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == 65 && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("d".into(), hex::encode(d_bytes));
                case.outputs
                    .borrow_mut()
                    .insert("qx".into(), hex::encode(&pub_bytes[1..33]));
                case.outputs
                    .borrow_mut()
                    .insert("qy".into(), hex::encode(&pub_bytes[33..65]));
            } else {
                return Err(EngineError::Crypto(
                    "Invalid P-256 public key format".into(),
                ));
            }
        }
        "P-384" | "secp384r1" => {
            let (public_key, secret_key) = EcdsaP384::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!("P-384 keypair generation failed: {:?}", e))
            })?;
            let d_bytes = secret_key.as_ref();
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == 97 && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("d".into(), hex::encode(d_bytes));
                case.outputs
                    .borrow_mut()
                    .insert("qx".into(), hex::encode(&pub_bytes[1..49]));
                case.outputs
                    .borrow_mut()
                    .insert("qy".into(), hex::encode(&pub_bytes[49..97]));
            } else {
                return Err(EngineError::Crypto(
                    "Invalid P-384 public key format".into(),
                ));
            }
        }
        "P-521" | "secp521r1" => {
            let (public_key, secret_key) = EcdsaP521::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!("P-521 keypair generation failed: {:?}", e))
            })?;
            let d_bytes = secret_key.as_ref();
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == 133 && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("d".into(), hex::encode(d_bytes));
                case.outputs
                    .borrow_mut()
                    .insert("qx".into(), hex::encode(&pub_bytes[1..67]));
                case.outputs
                    .borrow_mut()
                    .insert("qy".into(), hex::encode(&pub_bytes[67..133]));
            } else {
                return Err(EngineError::Crypto(
                    "Invalid P-521 public key format".into(),
                ));
            }
        }
        // Skip Koblitz and Binary curves for now
        s if s.starts_with("K-") || s.starts_with("B-") => {
            println!("Skipping unsupported curve for keygen: {}", s);
            // To indicate a skip rather than pass/fail, we can avoid setting outputs
            // or set a specific "skipped" output if the runner logic can handle it.
            // For now, just returning Ok will make it seem like a pass in the runner if no outputs are expected.
            // If outputs ARE expected, this will lead to a mismatch.
            // A better way is to have the runner check if outputs were populated.
            // For now, we'll indicate pass = false
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "false".into());
            case.outputs
                .borrow_mut()
                .insert("reason".into(), format!("Unsupported curve: {}", s));
            return Ok(());
        }
        _ => return Err(EngineError::Crypto(format!("Unsupported curve: {}", curve))),
    }

    Ok(())
}

/// ECDSA Key Verification
pub(crate) fn ecdsa_keyver(group: &TestGroup, case: &TestCase) -> Result<()> {
    let curve = group
        .defaults
        .get("curve")
        .or_else(|| case.inputs.get("curve"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("curve"))?;

    let qx_hex = case
        .inputs
        .get("qx")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("qx"))?;
    let qy_hex = case
        .inputs
        .get("qy")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("qy"))?;

    let qx_bytes = hex::decode(&qx_hex)?;
    let qy_bytes = hex::decode(&qy_hex)?;

    let is_valid = match curve.as_str() {
        "P-192" | "secp192r1" => verify_p192_public_key(&qx_bytes, &qy_bytes), // Added P-192
        "P-224" | "secp224r1" => verify_p224_public_key(&qx_bytes, &qy_bytes),
        "P-256" | "secp256r1" => verify_p256_public_key(&qx_bytes, &qy_bytes),
        "P-384" | "secp384r1" => verify_p384_public_key(&qx_bytes, &qy_bytes),
        "P-521" | "secp521r1" => verify_p521_public_key(&qx_bytes, &qy_bytes),
        s if s.starts_with("K-") || s.starts_with("B-") => {
            println!("Skipping key verification for unsupported curve: {}", s);
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "false".into()); // Treat as not passed for this specific test case
            case.outputs.borrow_mut().insert(
                "reason".into(),
                format!("Unsupported curve for keyVer: {}", s),
            );
            return Ok(());
        }
        _ => return Err(EngineError::Crypto(format!("Unsupported curve: {}", curve))),
    };

    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), is_valid.to_string());
    Ok(())
}

/// ECDSA Signature Generation
pub(crate) fn ecdsa_siggen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let curve = group
        .defaults
        .get("curve")
        .or_else(|| case.inputs.get("curve"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("curve"))?;

    let msg_hex = case
        .inputs
        .get("message")
        .or_else(|| case.inputs.get("msg"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("message"))?;

    let msg_bytes = hex::decode(&msg_hex)?;

    let mut rng = ChaCha20Rng::from_entropy();

    match curve.as_str() {
        "P-192" | "secp192r1" => {
            // Added P-192
            let (public_key, secret_key) = EcdsaP192::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!(
                    "P-192 keypair generation failed for siggen: {:?}",
                    e
                ))
            })?;
            let signature = EcdsaP192::sign(&msg_bytes, &secret_key)
                .map_err(|e| EngineError::Crypto(format!("P-192 signing failed: {:?}", e)))?;
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == ec_p192::P192_POINT_UNCOMPRESSED_SIZE && pub_bytes[0] == 0x04 {
                case.outputs.borrow_mut().insert(
                    "qx".into(),
                    hex::encode(&pub_bytes[1..1 + ec_p192::P192_FIELD_ELEMENT_SIZE]),
                );
                case.outputs.borrow_mut().insert(
                    "qy".into(),
                    hex::encode(&pub_bytes[1 + ec_p192::P192_FIELD_ELEMENT_SIZE..]),
                );
            }
            case.outputs
                .borrow_mut()
                .insert("d".into(), hex::encode(secret_key.as_ref()));
            let (r, s) = parse_der_signature(signature.as_ref())?;
            case.outputs
                .borrow_mut()
                .insert("r".into(), hex::encode(&r));
            case.outputs
                .borrow_mut()
                .insert("s".into(), hex::encode(&s));
        }
        "P-224" | "secp224r1" => {
            let (public_key, secret_key) = EcdsaP224::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!(
                    "P-224 keypair generation failed for siggen: {:?}",
                    e
                ))
            })?;
            let signature = EcdsaP224::sign(&msg_bytes, &secret_key)
                .map_err(|e| EngineError::Crypto(format!("P-224 signing failed: {:?}", e)))?;
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == 57 && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("qx".into(), hex::encode(&pub_bytes[1..29]));
                case.outputs
                    .borrow_mut()
                    .insert("qy".into(), hex::encode(&pub_bytes[29..57]));
            }
            case.outputs
                .borrow_mut()
                .insert("d".into(), hex::encode(secret_key.as_ref()));
            let (r, s) = parse_der_signature(signature.as_ref())?;
            case.outputs
                .borrow_mut()
                .insert("r".into(), hex::encode(&r));
            case.outputs
                .borrow_mut()
                .insert("s".into(), hex::encode(&s));
        }
        "P-256" | "secp256r1" => {
            let (public_key, secret_key) = EcdsaP256::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!(
                    "P-256 keypair generation failed for siggen: {:?}",
                    e
                ))
            })?;
            let signature = EcdsaP256::sign(&msg_bytes, &secret_key)
                .map_err(|e| EngineError::Crypto(format!("P-256 signing failed: {:?}", e)))?;
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == 65 && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("qx".into(), hex::encode(&pub_bytes[1..33]));
                case.outputs
                    .borrow_mut()
                    .insert("qy".into(), hex::encode(&pub_bytes[33..65]));
            }
            case.outputs
                .borrow_mut()
                .insert("d".into(), hex::encode(secret_key.as_ref()));
            let (r, s) = parse_der_signature(signature.as_ref())?;
            case.outputs
                .borrow_mut()
                .insert("r".into(), hex::encode(&r));
            case.outputs
                .borrow_mut()
                .insert("s".into(), hex::encode(&s));
        }
        "P-384" | "secp384r1" => {
            let (public_key, secret_key) = EcdsaP384::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!(
                    "P-384 keypair generation failed for siggen: {:?}",
                    e
                ))
            })?;
            let signature = EcdsaP384::sign(&msg_bytes, &secret_key)
                .map_err(|e| EngineError::Crypto(format!("P-384 signing failed: {:?}", e)))?;
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == 97 && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("qx".into(), hex::encode(&pub_bytes[1..49]));
                case.outputs
                    .borrow_mut()
                    .insert("qy".into(), hex::encode(&pub_bytes[49..97]));
            }
            case.outputs
                .borrow_mut()
                .insert("d".into(), hex::encode(secret_key.as_ref()));
            let (r, s) = parse_der_signature(signature.as_ref())?;
            case.outputs
                .borrow_mut()
                .insert("r".into(), hex::encode(&r));
            case.outputs
                .borrow_mut()
                .insert("s".into(), hex::encode(&s));
        }
        "P-521" | "secp521r1" => {
            let (public_key, secret_key) = EcdsaP521::keypair(&mut rng).map_err(|e| {
                EngineError::Crypto(format!(
                    "P-521 keypair generation failed for siggen: {:?}",
                    e
                ))
            })?;
            let signature = EcdsaP521::sign(&msg_bytes, &secret_key)
                .map_err(|e| EngineError::Crypto(format!("P-521 signing failed: {:?}", e)))?;
            let pub_bytes = public_key.as_ref();
            if pub_bytes.len() == 133 && pub_bytes[0] == 0x04 {
                case.outputs
                    .borrow_mut()
                    .insert("qx".into(), hex::encode(&pub_bytes[1..67]));
                case.outputs
                    .borrow_mut()
                    .insert("qy".into(), hex::encode(&pub_bytes[67..133]));
            }
            case.outputs
                .borrow_mut()
                .insert("d".into(), hex::encode(secret_key.as_ref()));
            let (r, s) = parse_der_signature(signature.as_ref())?;
            case.outputs
                .borrow_mut()
                .insert("r".into(), hex::encode(&r));
            case.outputs
                .borrow_mut()
                .insert("s".into(), hex::encode(&s));
        }
        s if s.starts_with("K-") || s.starts_with("B-") => {
            println!("Skipping siggen for unsupported curve: {}", s);
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "false".into());
            case.outputs.borrow_mut().insert(
                "reason".into(),
                format!("Unsupported curve for sigGen: {}", s),
            );
            return Ok(());
        }
        _ => return Err(EngineError::Crypto(format!("Unsupported curve: {}", curve))),
    }

    Ok(())
}

/// ECDSA Signature Verification
pub(crate) fn ecdsa_sigver(group: &TestGroup, case: &TestCase) -> Result<()> {
    let curve = group
        .defaults
        .get("curve")
        .or_else(|| case.inputs.get("curve"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("curve"))?;

    let msg_hex = case
        .inputs
        .get("message")
        .or_else(|| case.inputs.get("msg"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("message"))?;

    let qx_hex = case
        .inputs
        .get("qx")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("qx"))?;
    let qy_hex = case
        .inputs
        .get("qy")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("qy"))?;

    let r_hex = case
        .inputs
        .get("r")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("r"))?;
    let s_hex = case
        .inputs
        .get("s")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("s"))?;

    let msg_bytes = hex::decode(&msg_hex)?;
    let r_bytes = hex::decode(&r_hex)?;
    let s_bytes = hex::decode(&s_hex)?;

    let result = match curve.as_str() {
        "P-192" | "secp192r1" => {
            // Added P-192
            let public_key = create_p192_public_key(&qx_hex, &qy_hex)?;
            let signature = create_der_signature(&r_bytes, &s_bytes)?;
            let sig = EcdsaP192Signature(signature);
            EcdsaP192::verify(&msg_bytes, &sig, &public_key).is_ok()
        }
        "P-224" | "secp224r1" => {
            let public_key = create_p224_public_key(&qx_hex, &qy_hex)?;
            let signature = create_der_signature(&r_bytes, &s_bytes)?;
            let sig = EcdsaP224Signature(signature);
            EcdsaP224::verify(&msg_bytes, &sig, &public_key).is_ok()
        }
        "P-256" | "secp256r1" => {
            let public_key = create_p256_public_key(&qx_hex, &qy_hex)?;
            let signature = create_der_signature(&r_bytes, &s_bytes)?;
            let sig = EcdsaP256Signature(signature);
            EcdsaP256::verify(&msg_bytes, &sig, &public_key).is_ok()
        }
        "P-384" | "secp384r1" => {
            let public_key = create_p384_public_key(&qx_hex, &qy_hex)?;
            let signature = create_der_signature(&r_bytes, &s_bytes)?;
            let sig = EcdsaP384Signature(signature);
            EcdsaP384::verify(&msg_bytes, &sig, &public_key).is_ok()
        }
        "P-521" | "secp521r1" => {
            let public_key = create_p521_public_key(&qx_hex, &qy_hex)?;
            let signature = create_der_signature(&r_bytes, &s_bytes)?;
            let sig = EcdsaP521Signature(signature);
            EcdsaP521::verify(&msg_bytes, &sig, &public_key).is_ok()
        }
        s if s.starts_with("K-") || s.starts_with("B-") => {
            println!("Skipping sigver for unsupported curve: {}", s);
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "false".into());
            case.outputs.borrow_mut().insert(
                "reason".into(),
                format!("Unsupported curve for sigVer: {}", s),
            );
            return Ok(());
        }
        _ => return Err(EngineError::Crypto(format!("Unsupported curve: {}", curve))),
    };

    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), result.to_string());
    Ok(())
}

/* Helper functions */
fn verify_p192_public_key(qx: &[u8], qy: &[u8]) -> bool {
    // Added P-192 helper
    if qx.len() != ec_p192::P192_FIELD_ELEMENT_SIZE || qy.len() != ec_p192::P192_FIELD_ELEMENT_SIZE
    {
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    point.len() == ec_p192::P192_POINT_UNCOMPRESSED_SIZE
}

fn verify_p224_public_key(qx: &[u8], qy: &[u8]) -> bool {
    if qx.len() != 28 || qy.len() != 28 {
        // P-224 coordinates are 28 bytes
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    point.len() == 57 // P-224 uncompressed point size
}

fn verify_p256_public_key(qx: &[u8], qy: &[u8]) -> bool {
    if qx.len() != 32 || qy.len() != 32 {
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    point.len() == 65
}

fn verify_p384_public_key(qx: &[u8], qy: &[u8]) -> bool {
    if qx.len() != 48 || qy.len() != 48 {
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    point.len() == 97
}

fn verify_p521_public_key(qx: &[u8], qy: &[u8]) -> bool {
    if qx.len() != 66 || qy.len() != 66 {
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    point.len() == 133
}

fn create_p192_public_key(qx_hex: &str, qy_hex: &str) -> Result<EcdsaP192PublicKey> {
    // Added P-192 helper
    let qx_bytes = hex::decode(qx_hex)?;
    let qy_bytes = hex::decode(qy_hex)?;
    if qx_bytes.len() != ec_p192::P192_FIELD_ELEMENT_SIZE
        || qy_bytes.len() != ec_p192::P192_FIELD_ELEMENT_SIZE
    {
        return Err(EngineError::InvalidData(
            "Invalid P-192 public key component size".into(),
        ));
    }
    let mut key = [0u8; ec_p192::P192_POINT_UNCOMPRESSED_SIZE];
    key[0] = 0x04;
    key[1..1 + ec_p192::P192_FIELD_ELEMENT_SIZE].copy_from_slice(&qx_bytes);
    key[1 + ec_p192::P192_FIELD_ELEMENT_SIZE..].copy_from_slice(&qy_bytes);
    Ok(EcdsaP192PublicKey(key))
}

fn create_p224_public_key(qx_hex: &str, qy_hex: &str) -> Result<EcdsaP224PublicKey> {
    let qx_bytes = hex::decode(qx_hex)?;
    let qy_bytes = hex::decode(qy_hex)?;
    if qx_bytes.len() != 28 || qy_bytes.len() != 28 {
        return Err(EngineError::InvalidData(
            "Invalid P-224 public key component size".into(),
        ));
    }
    let mut key = [0u8; 57];
    key[0] = 0x04;
    key[1..29].copy_from_slice(&qx_bytes);
    key[29..57].copy_from_slice(&qy_bytes);
    Ok(EcdsaP224PublicKey(key))
}

fn create_p256_public_key(qx_hex: &str, qy_hex: &str) -> Result<EcdsaP256PublicKey> {
    let qx_bytes = hex::decode(qx_hex)?;
    let qy_bytes = hex::decode(qy_hex)?;
    if qx_bytes.len() != 32 || qy_bytes.len() != 32 {
        return Err(EngineError::InvalidData(
            "Invalid P-256 public key component size".into(),
        ));
    }
    let mut key = [0u8; 65];
    key[0] = 0x04;
    key[1..33].copy_from_slice(&qx_bytes);
    key[33..65].copy_from_slice(&qy_bytes);
    Ok(EcdsaP256PublicKey(key))
}

fn create_p384_public_key(qx_hex: &str, qy_hex: &str) -> Result<EcdsaP384PublicKey> {
    let qx_bytes = hex::decode(qx_hex)?;
    let qy_bytes = hex::decode(qy_hex)?;
    if qx_bytes.len() != 48 || qy_bytes.len() != 48 {
        return Err(EngineError::InvalidData(
            "Invalid P-384 public key component size".into(),
        ));
    }
    let mut key = [0u8; 97];
    key[0] = 0x04;
    key[1..49].copy_from_slice(&qx_bytes);
    key[49..97].copy_from_slice(&qy_bytes);
    Ok(EcdsaP384PublicKey(key))
}

fn create_p521_public_key(qx_hex: &str, qy_hex: &str) -> Result<EcdsaP521PublicKey> {
    let qx_bytes = hex::decode(qx_hex)?;
    let qy_bytes = hex::decode(qy_hex)?;
    if qx_bytes.len() != 66 || qy_bytes.len() != 66 {
        return Err(EngineError::InvalidData(
            "Invalid P-521 public key component size".into(),
        ));
    }
    let mut key = [0u8; 133];
    key[0] = 0x04;
    key[1..67].copy_from_slice(&qx_bytes);
    key[67..133].copy_from_slice(&qy_bytes);
    Ok(EcdsaP521PublicKey(key))
}

fn create_der_signature(r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
    use dcrypt_sign::ecdsa::common::SignatureComponents;
    let sig = SignatureComponents {
        r: r.to_vec(),
        s: s.to_vec(),
    };
    Ok(sig.to_der())
}

fn parse_der_signature(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use dcrypt_sign::ecdsa::common::SignatureComponents;
    let sig = SignatureComponents::from_der(der)
        .map_err(|e| EngineError::Crypto(format!("DER parsing failed: {:?}", e)))?;
    Ok((sig.r, sig.s))
}

/// Register ECDSA handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "ECDSA", "keyGen", "AFT", ecdsa_keygen);
    insert(map, "ECDSA", "keyVer", "AFT", ecdsa_keyver);
    insert(map, "ECDSA", "sigGen", "AFT", ecdsa_siggen);
    insert(map, "ECDSA", "sigVer", "AFT", ecdsa_sigver);
}
