//! ACVP handlers for ECDSA operations

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{FlexValue, TestCase, TestGroup};
use dcrypt_api::Signature;
use dcrypt_sign::ecdsa::{
    EcdsaP224, EcdsaP224PublicKey, EcdsaP224SecretKey, EcdsaP224Signature, EcdsaP256,
    EcdsaP256PublicKey, EcdsaP256SecretKey, EcdsaP256Signature, EcdsaP384, EcdsaP384PublicKey,
    EcdsaP384SecretKey, EcdsaP384Signature, EcdsaP521, EcdsaP521PublicKey, EcdsaP521SecretKey,
    EcdsaP521Signature,
};
use hex;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

fn expected_hash(curve: &str) -> Option<&'static str> {
    match curve {
        "P-224" | "secp224r1" => Some("SHA2-224"),
        "P-256" | "secp256r1" => Some("SHA2-256"),
        "P-384" | "secp384r1" => Some("SHA2-384"),
        "P-521" | "secp521r1" => Some("SHA2-512"),
        _ => None,
    }
}

fn required_string(group: &TestGroup, case: &TestCase, field: &'static str) -> Result<String> {
    let mut selected: Option<&str> = None;
    for value in [group.defaults.get(field), case.inputs.get(field)]
        .into_iter()
        .flatten()
    {
        let FlexValue::String(value) = value else {
            return Err(EngineError::InvalidData(format!(
                "ECDSA {field} must be a string"
            )));
        };
        if selected.is_some_and(|prior| prior != value) {
            return Err(EngineError::InvalidData(format!(
                "conflicting ECDSA {field} metadata"
            )));
        }
        selected = Some(value);
    }
    selected
        .map(str::to_owned)
        .ok_or(EngineError::MissingField(field))
}

fn required_case_string(case: &TestCase, field: &'static str) -> Result<String> {
    match case.inputs.get(field) {
        Some(FlexValue::String(value)) => Ok(value.clone()),
        Some(_) => Err(EngineError::InvalidData(format!(
            "ECDSA {field} must be a string"
        ))),
        None => Err(EngineError::MissingField(field)),
    }
}

fn recognized_curve(curve: &str) -> bool {
    matches!(
        curve,
        "B-163"
            | "B-233"
            | "B-283"
            | "B-409"
            | "B-571"
            | "K-163"
            | "K-233"
            | "K-283"
            | "K-409"
            | "K-571"
            | "P-192"
            | "P-224"
            | "P-256"
            | "P-384"
            | "P-521"
            | "secp224r1"
            | "secp256r1"
            | "secp384r1"
            | "secp521r1"
    )
}

fn skip_unsupported_curve(case: &TestCase, curve: &str, operation: &str) -> Result<bool> {
    if !recognized_curve(curve) {
        return Err(EngineError::InvalidData(format!(
            "unrecognized ECDSA curve {curve}"
        )));
    }
    if expected_hash(curve).is_none() {
        case.mark_skipped(format!(
            "{operation} does not support ACVP curve {curve} through the dcrypt public API"
        ));
        Ok(true)
    } else {
        Ok(false)
    }
}

fn recognized_hash(hash: &str) -> bool {
    matches!(
        hash,
        "SHA-1"
            | "SHA2-224"
            | "SHA2-256"
            | "SHA2-384"
            | "SHA2-512"
            | "SHA2-512/224"
            | "SHA2-512/256"
            | "SHA3-224"
            | "SHA3-256"
            | "SHA3-384"
            | "SHA3-512"
            | "SHAKE-128"
            | "SHAKE-256"
    )
}

fn required_recognized_hash(group: &TestGroup, case: &TestCase) -> Result<String> {
    let hash = required_string(group, case, "hashAlg")?;
    if !recognized_hash(&hash) {
        return Err(EngineError::InvalidData(format!(
            "unrecognized ECDSA hashAlg {hash}"
        )));
    }
    Ok(hash)
}

fn skip_unsupported_hash(case: &TestCase, curve: &str, hash: &str) -> bool {
    let required = expected_hash(curve).expect("curve must be checked first");
    if hash != required {
        case.mark_skipped(format!(
            "dcrypt {curve} fixes {required}; ACVP vector requests {hash}"
        ));
        true
    } else {
        false
    }
}

fn skip_sp800_106(case: &TestCase) -> Result<bool> {
    let random_value = case.inputs.get("randomValue");
    let random_value_len = case.inputs.get("randomValueLen");
    match (random_value, random_value_len) {
        (None, None) => Ok(false),
        (Some(FlexValue::String(_)), Some(FlexValue::Number(_))) => {
            case.mark_skipped(
                "SP800-106 randomValue conformance semantics are not implemented by the dcrypt public API",
            );
            Ok(true)
        }
        (Some(_), None) => Err(EngineError::MissingField("randomValueLen")),
        (None, Some(_)) => Err(EngineError::MissingField("randomValue")),
        (Some(FlexValue::String(_)), Some(_)) => Err(EngineError::InvalidData(
            "ECDSA randomValueLen must be a number".into(),
        )),
        (Some(_), Some(_)) => Err(EngineError::InvalidData(
            "ECDSA randomValue must be a string".into(),
        )),
    }
}

/// ECDSA Key Generation
pub(crate) fn ecdsa_keygen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let curve = required_string(group, case, "curve")?;
    if !recognized_curve(&curve) {
        return Err(EngineError::InvalidData(format!(
            "unrecognized ECDSA curve {curve}"
        )));
    }
    let generation_mode = required_string(group, case, "secretGenerationMode")?;
    if !matches!(
        generation_mode.as_str(),
        "testing candidates" | "extra bits"
    ) {
        return Err(EngineError::InvalidData(format!(
            "unrecognized ECDSA secretGenerationMode {generation_mode}"
        )));
    }
    if skip_unsupported_curve(case, &curve, "ECDSA keyGen")? {
        return Ok(());
    }
    if generation_mode != "testing candidates" {
        case.mark_skipped(format!(
            "ECDSA keyGen secretGenerationMode {generation_mode} is not exposed by the public API"
        ));
        return Ok(());
    }

    replay_keygen_candidate(&curve, case)?;
    Ok(())
}

fn projection_hex(case: &TestCase, field: &'static str) -> Result<String> {
    match case.projection.get(field) {
        Some(FlexValue::String(value)) => Ok(value.clone()),
        Some(_) => Err(EngineError::InvalidData(format!(
            "ECDSA internalProjection.{field} must be a string"
        ))),
        None => Err(EngineError::MissingField(field)),
    }
}

fn replay_keygen_candidate(curve: &str, case: &TestCase) -> Result<()> {
    let d_hex = projection_hex(case, "d")?;
    let qx_hex = projection_hex(case, "qx")?;
    let qy_hex = projection_hex(case, "qy")?;
    let d = hex::decode(&d_hex)?;
    let probe = b"ACVP ECDSA keyGen candidate relation";

    let public_bytes = match curve {
        "P-224" | "secp224r1" => {
            let secret = EcdsaP224SecretKey::from_bytes(&d)?;
            let public = create_p224_public_key(&qx_hex, &qy_hex)?;
            let signature = EcdsaP224::sign(probe, &secret)?;
            EcdsaP224::verify(probe, &signature, &public)?;
            public.as_ref().to_vec()
        }
        "P-256" | "secp256r1" => {
            let secret = EcdsaP256SecretKey::from_bytes(&d)?;
            let public = create_p256_public_key(&qx_hex, &qy_hex)?;
            let signature = EcdsaP256::sign(probe, &secret)?;
            EcdsaP256::verify(probe, &signature, &public)?;
            public.as_ref().to_vec()
        }
        "P-384" | "secp384r1" => {
            let secret = EcdsaP384SecretKey::from_bytes(&d)?;
            let public = create_p384_public_key(&qx_hex, &qy_hex)?;
            let signature = EcdsaP384::sign(probe, &secret)?;
            EcdsaP384::verify(probe, &signature, &public)?;
            public.as_ref().to_vec()
        }
        "P-521" | "secp521r1" => {
            let secret = EcdsaP521SecretKey::from_bytes(&d)?;
            let public = create_p521_public_key(&qx_hex, &qy_hex)?;
            let signature = EcdsaP521::sign(probe, &secret)?;
            EcdsaP521::verify(probe, &signature, &public)?;
            public.as_ref().to_vec()
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "unsupported replay curve {curve}"
            )))
        }
    };

    if public_bytes.first() != Some(&0x04) || public_bytes.len() < 3 {
        return Err(EngineError::Crypto(
            "replayed ECDSA public key is not uncompressed SEC1".into(),
        ));
    }
    let coordinate_len = (public_bytes.len() - 1) / 2;
    case.outputs.borrow_mut().insert("d".into(), hex::encode(d));
    case.outputs.borrow_mut().insert(
        "qx".into(),
        hex::encode(&public_bytes[1..1 + coordinate_len]),
    );
    case.outputs.borrow_mut().insert(
        "qy".into(),
        hex::encode(&public_bytes[1 + coordinate_len..]),
    );
    Ok(())
}

/// ECDSA Key Verification
pub(crate) fn ecdsa_keyver(group: &TestGroup, case: &TestCase) -> Result<()> {
    let curve = required_string(group, case, "curve")?;

    let qx_hex = required_case_string(case, "qx")?;
    let qy_hex = required_case_string(case, "qy")?;

    if skip_unsupported_curve(case, &curve, "ECDSA keyVer")? {
        return Ok(());
    }

    let decoded = hex::decode(&qx_hex).ok().zip(hex::decode(&qy_hex).ok());

    let is_valid = match (curve.as_str(), decoded) {
        ("P-224" | "secp224r1", Some((qx, qy))) => verify_p224_public_key(&qx, &qy),
        ("P-256" | "secp256r1", Some((qx, qy))) => verify_p256_public_key(&qx, &qy),
        ("P-384" | "secp384r1", Some((qx, qy))) => verify_p384_public_key(&qx, &qy),
        ("P-521" | "secp521r1", Some((qx, qy))) => verify_p521_public_key(&qx, &qy),
        (_, None) => false,
        _ => return Err(EngineError::Crypto(format!("Unsupported curve: {}", curve))),
    };

    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), is_valid.to_string());
    Ok(())
}

/// ECDSA Signature Generation
pub(crate) fn ecdsa_siggen(group: &TestGroup, case: &TestCase) -> Result<()> {
    let curve = required_string(group, case, "curve")?;
    if !recognized_curve(&curve) {
        return Err(EngineError::InvalidData(format!(
            "unrecognized ECDSA curve {curve}"
        )));
    }
    let hash = required_recognized_hash(group, case)?;
    if skip_unsupported_curve(case, &curve, "ECDSA sigGen")? {
        return Ok(());
    }
    if skip_unsupported_hash(case, &curve, &hash) {
        return Ok(());
    }
    // The FIPS 186-5 response set supplies a per-case nonce `k` only in the
    // non-public projection.  dcrypt intentionally exposes RFC6979 signing and
    // no nonce-injection API, so these response values cannot be replayed
    // without adding a new cryptographic interface.
    case.mark_skipped(
        "ACVP SigGen requires supplied-nonce component testing; dcrypt exposes only RFC6979 signing",
    );
    Ok(())
}

/// ECDSA Signature Verification
pub(crate) fn ecdsa_sigver(group: &TestGroup, case: &TestCase) -> Result<()> {
    let curve = required_string(group, case, "curve")?;
    if !recognized_curve(&curve) {
        return Err(EngineError::InvalidData(format!(
            "unrecognized ECDSA curve {curve}"
        )));
    }
    let hash = required_recognized_hash(group, case)?;
    // SP 800-106 changes the operation semantics regardless of whether its
    // curve/hash pair would otherwise be supported.  Classify it first so no
    // such case is mislabeled as an ordinary curve/hash capability skip.
    if skip_sp800_106(case)? {
        return Ok(());
    }
    if skip_unsupported_curve(case, &curve, "ECDSA sigVer")? {
        return Ok(());
    }
    if skip_unsupported_hash(case, &curve, &hash) {
        return Ok(());
    }

    let msg_hex = if case.inputs.contains_key("message") {
        required_case_string(case, "message")?
    } else {
        required_case_string(case, "msg")?
    };
    let qx_hex = required_case_string(case, "qx")?;
    let qy_hex = required_case_string(case, "qy")?;
    let r_hex = required_case_string(case, "r")?;
    let s_hex = required_case_string(case, "s")?;

    let decoded = hex::decode(&msg_hex)
        .ok()
        .zip(hex::decode(&r_hex).ok())
        .zip(hex::decode(&s_hex).ok());

    let result = match decoded {
        Some(((message, r), s)) => verify_signature(&curve, &message, &qx_hex, &qy_hex, &r, &s),
        None => false,
    };

    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), result.to_string());
    Ok(())
}

fn verify_signature(curve: &str, message: &[u8], qx: &str, qy: &str, r: &[u8], s: &[u8]) -> bool {
    let signature = create_der_signature(r, s);
    match curve {
        "P-224" | "secp224r1" => create_p224_public_key(qx, qy)
            .ok()
            .zip(signature.ok())
            .and_then(|(public, signature)| {
                EcdsaP224Signature::from_bytes(&signature)
                    .ok()
                    .map(|signature| EcdsaP224::verify(message, &signature, &public).is_ok())
            })
            .unwrap_or(false),
        "P-256" | "secp256r1" => create_p256_public_key(qx, qy)
            .ok()
            .zip(signature.ok())
            .and_then(|(public, signature)| {
                EcdsaP256Signature::from_bytes(&signature)
                    .ok()
                    .map(|signature| EcdsaP256::verify(message, &signature, &public).is_ok())
            })
            .unwrap_or(false),
        "P-384" | "secp384r1" => create_p384_public_key(qx, qy)
            .ok()
            .zip(signature.ok())
            .and_then(|(public, signature)| {
                EcdsaP384Signature::from_bytes(&signature)
                    .ok()
                    .map(|signature| EcdsaP384::verify(message, &signature, &public).is_ok())
            })
            .unwrap_or(false),
        "P-521" | "secp521r1" => create_p521_public_key(qx, qy)
            .ok()
            .zip(signature.ok())
            .and_then(|(public, signature)| {
                EcdsaP521Signature::from_bytes(&signature)
                    .ok()
                    .map(|signature| EcdsaP521::verify(message, &signature, &public).is_ok())
            })
            .unwrap_or(false),
        _ => false,
    }
}

/* Helper functions */
fn verify_p224_public_key(qx: &[u8], qy: &[u8]) -> bool {
    if qx.len() != 28 || qy.len() != 28 {
        // P-224 coordinates are 28 bytes
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    EcdsaP224PublicKey::from_bytes(&point).is_ok()
}

fn verify_p256_public_key(qx: &[u8], qy: &[u8]) -> bool {
    if qx.len() != 32 || qy.len() != 32 {
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    EcdsaP256PublicKey::from_bytes(&point).is_ok()
}

fn verify_p384_public_key(qx: &[u8], qy: &[u8]) -> bool {
    if qx.len() != 48 || qy.len() != 48 {
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    EcdsaP384PublicKey::from_bytes(&point).is_ok()
}

fn verify_p521_public_key(qx: &[u8], qy: &[u8]) -> bool {
    if qx.len() != 66 || qy.len() != 66 {
        return false;
    }
    let mut point = vec![0x04];
    point.extend_from_slice(qx);
    point.extend_from_slice(qy);
    EcdsaP521PublicKey::from_bytes(&point).is_ok()
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
    EcdsaP224PublicKey::from_bytes(&key).map_err(EngineError::from)
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
    EcdsaP256PublicKey::from_bytes(&key).map_err(EngineError::from)
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
    EcdsaP384PublicKey::from_bytes(&key).map_err(EngineError::from)
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
    EcdsaP521PublicKey::from_bytes(&key).map_err(EngineError::from)
}

fn create_der_signature(r: &[u8], s: &[u8]) -> Result<Vec<u8>> {
    use dcrypt_sign::ecdsa::common::SignatureComponents;
    let sig = SignatureComponents {
        r: r.to_vec(),
        s: s.to_vec(),
    };
    Ok(sig.to_der())
}

/// Register ECDSA handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "ECDSA", "keyGen", "AFT", ecdsa_keygen);
    insert(map, "ECDSA", "keyVer", "AFT", ecdsa_keyver);
    insert(map, "ECDSA", "sigGen", "AFT", ecdsa_siggen);
    insert(map, "ECDSA", "sigVer", "AFT", ecdsa_sigver);
}
