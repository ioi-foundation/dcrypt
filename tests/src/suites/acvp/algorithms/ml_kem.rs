//! Official FIPS 203 ML-KEM ACVP handlers.
//!
//! Deterministic vectors call the standard's internal interfaces directly:
//! key generation consumes `(d, z)` in that order and encapsulation consumes
//! `m`. Expected results are joined by `(tgId, tcId)` in the loader.

use crate::suites::acvp::dispatcher::{insert, DispatchKey, HandlerFn};
use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};

use dcrypt_api::Kem;
use dcrypt_internal::constant_time::ConstantTimeEq;
use dcrypt_kem::ml_kem::{
    MlKem, MlKem1024Params, MlKem512Params, MlKem768Params, MlKemCiphertext, MlKemDecapsulationKey,
    MlKemEncapsulationKey, MlKemParameterSet,
};

fn parameter_set(group: &TestGroup) -> Result<String> {
    group
        .defaults
        .get("parameterSet")
        .map(|value| value.as_string())
        .ok_or(EngineError::MissingField("parameterSet"))
}

fn hex_field(case: &TestCase, name: &'static str) -> Result<Vec<u8>> {
    let value = case
        .inputs
        .get(name)
        .ok_or(EngineError::MissingField(name))?
        .as_string();
    Ok(hex::decode(value)?)
}

fn array_32(case: &TestCase, name: &'static str) -> Result<[u8; 32]> {
    let bytes = hex_field(case, name)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        EngineError::InvalidData(format!("{} must be 32 bytes, got {}", name, bytes.len()))
    })
}

fn verify_hex(case: &TestCase, name: &'static str, actual: &[u8]) -> Result<()> {
    if let Some(expected) = case.inputs.get(name) {
        let expected_string = expected.as_string();
        let expected_bytes = hex::decode(&expected_string)?;
        if expected_bytes.as_slice().ct_eq(actual).unwrap_u8() != 1 {
            return Err(EngineError::Mismatch {
                expected: expected_string,
                actual: hex::encode_upper(actual),
            });
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert(name.into(), hex::encode_upper(actual));
    }
    Ok(())
}

fn verify_bool(case: &TestCase, actual: bool) -> Result<()> {
    if let Some(expected) = case.inputs.get("testPassed") {
        let expected = expected.as_string();
        if expected.parse::<bool>().ok() != Some(actual) {
            return Err(EngineError::Mismatch {
                expected,
                actual: actual.to_string(),
            });
        }
    } else {
        case.outputs
            .borrow_mut()
            .insert("testPassed".into(), actual.to_string());
    }
    Ok(())
}

fn keygen_for<P: MlKemParameterSet>(case: &TestCase) -> Result<()> {
    let d = array_32(case, "d")?;
    let z = array_32(case, "z")?;
    let keypair = MlKem::<P>::keypair_deterministic(&d, &z)?;
    let encapsulation_key = MlKem::<P>::public_key(&keypair);
    let decapsulation_key = MlKem::<P>::secret_key(&keypair);
    verify_hex(case, "ek", encapsulation_key.as_bytes())?;
    let secret_bytes = decapsulation_key.to_bytes_zeroizing();
    verify_hex(case, "dk", &secret_bytes[..])
}

fn encapsulate_for<P: MlKemParameterSet>(case: &TestCase) -> Result<()> {
    let public_bytes = hex_field(case, "ek")?;
    let public_key = MlKemEncapsulationKey::<P>::from_bytes(&public_bytes)?;
    let message = array_32(case, "m")?;
    let (ciphertext, shared_secret) = MlKem::<P>::encapsulate_deterministic(&public_key, &message)?;
    verify_hex(case, "c", ciphertext.as_bytes())?;
    let secret_bytes = shared_secret.to_bytes_zeroizing();
    verify_hex(case, "k", &secret_bytes[..])
}

fn decapsulate_for<P: MlKemParameterSet>(case: &TestCase) -> Result<()> {
    let secret_bytes = hex_field(case, "dk")?;
    let ciphertext_bytes = hex_field(case, "c")?;
    let secret_key = MlKemDecapsulationKey::<P>::from_bytes(&secret_bytes)?;
    let ciphertext = MlKemCiphertext::<P>::from_bytes(&ciphertext_bytes)?;
    let shared_secret = MlKem::<P>::decapsulate(&secret_key, &ciphertext)?;
    let actual = shared_secret.to_bytes_zeroizing();
    verify_hex(case, "k", &actual[..])
}

fn encapsulation_key_check_for<P: MlKemParameterSet>(case: &TestCase) -> Result<()> {
    let bytes = hex_field(case, "ek")?;
    verify_bool(case, MlKemEncapsulationKey::<P>::from_bytes(&bytes).is_ok())
}

fn decapsulation_key_check_for<P: MlKemParameterSet>(case: &TestCase) -> Result<()> {
    let bytes = hex_field(case, "dk")?;
    verify_bool(case, MlKemDecapsulationKey::<P>::from_bytes(&bytes).is_ok())
}

macro_rules! dispatch_parameter_set {
    ($group:expr, $case:expr, $operation:ident) => {{
        match parameter_set($group)?.as_str() {
            "ML-KEM-512" => $operation::<MlKem512Params>($case),
            "ML-KEM-768" => $operation::<MlKem768Params>($case),
            "ML-KEM-1024" => $operation::<MlKem1024Params>($case),
            other => Err(EngineError::InvalidData(format!(
                "unknown ML-KEM parameterSet: {}",
                other
            ))),
        }
    }};
}

fn ml_kem_keygen(group: &TestGroup, case: &TestCase) -> Result<()> {
    dispatch_parameter_set!(group, case, keygen_for)
}

fn ml_kem_encapsulate(group: &TestGroup, case: &TestCase) -> Result<()> {
    dispatch_parameter_set!(group, case, encapsulate_for)
}

fn ml_kem_decapsulate(group: &TestGroup, case: &TestCase) -> Result<()> {
    dispatch_parameter_set!(group, case, decapsulate_for)
}

fn ml_kem_encapsulation_key_check(group: &TestGroup, case: &TestCase) -> Result<()> {
    dispatch_parameter_set!(group, case, encapsulation_key_check_for)
}

fn ml_kem_decapsulation_key_check(group: &TestGroup, case: &TestCase) -> Result<()> {
    dispatch_parameter_set!(group, case, decapsulation_key_check_for)
}

/// Register every ML-KEM operation present in the official ACVP files.
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "ML-KEM-keyGen", "AFT", "AFT", ml_kem_keygen);
    insert(
        map,
        "ML-KEM-encapDecap",
        "encapsulation",
        "AFT",
        ml_kem_encapsulate,
    );
    insert(
        map,
        "ML-KEM-encapDecap",
        "decapsulation",
        "VAL",
        ml_kem_decapsulate,
    );
    insert(
        map,
        "ML-KEM-encapDecap",
        "encapsulationKeyCheck",
        "VAL",
        ml_kem_encapsulation_key_check,
    );
    insert(
        map,
        "ML-KEM-encapDecap",
        "decapsulationKeyCheck",
        "VAL",
        ml_kem_decapsulation_key_check,
    );
}
