//! ACVP handlers for ECDH (Elliptic Curve Diffie-Hellman) key agreement

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use crate::test_rng::OsRng;
use dcrypt_algorithms::ec::{k256, p224, p256, p384, p521};
use dcrypt_common::security::SecretBuffer;
use hex;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

/// Helper to look for a value in the test case first, then the group defaults.
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

/// Check if a curve is supported by the implementation
fn is_curve_supported(curve: &str) -> bool {
    matches!(
        curve,
        "P-224"
            | "secp224r1"
            | "P-256"
            | "secp256r1"
            | "P-384"
            | "secp384r1"
            | "P-521"
            | "secp521r1"
            | "K-256"
            | "secp256k1"
    )
}

/// ECDH shared secret computation (Component mode - just x-coordinate)
pub(crate) fn ecdh_component(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get the curve from group defaults or test case
    let curve = lookup(case, group, &["curve"]).ok_or(EngineError::MissingField("curve"))?;

    // Check if curve is supported
    if !is_curve_supported(&curve) {
        // For unsupported curves, mark as skipped rather than failing
        println!("Skipping unsupported curve: {}", curve);
        case.outputs
            .borrow_mut()
            .insert("testPassed".into(), "false".into());
        case.outputs
            .borrow_mut()
            .insert("reason".into(), format!("Unsupported curve: {}", curve));
        return Ok(());
    }

    // Check if the private key is provided. Its presence distinguishes VAL from AFT tests.
    let d_iut_hex_opt = lookup(
        case,
        group,
        &[
            "dIUT",
            "dIut",
            "privateKeyIut",
            "d",
            "dEphemIut",
            "dStaticIut",
            "privateKey",
        ],
    );

    // Get peer's public key coordinates (qx, qy).
    let qx_hex = lookup(
        case,
        group,
        &[
            "qxPublicKeyPeer",
            "qxPeer",
            "qx",
            "qxEphemPeer",
            "qxStaticPeer",
            "publicServerX",
            "qxServer",
            "ephemeralPublicServerX",
            "staticPublicServerX",
        ],
    )
    .ok_or(EngineError::MissingField("qxPublicKeyPeer"))?;

    let qy_hex = lookup(
        case,
        group,
        &[
            "qyPublicKeyPeer",
            "qyPeer",
            "qy",
            "qyEphemPeer",
            "qyStaticPeer",
            "publicServerY",
            "qyServer",
            "ephemeralPublicServerY",
            "staticPublicServerY",
        ],
    )
    .ok_or(EngineError::MissingField("qyPublicKeyPeer"))?;

    let qx_bytes = hex::decode(&qx_hex)?;
    let qy_bytes = hex::decode(&qy_hex)?;

    if let Some(d_iut_hex) = d_iut_hex_opt {
        // --- VALIDATION LOGIC (for VAL tests) ---
        // This path is taken for VAL tests where dIUT is provided.
        let d_bytes = hex::decode(&d_iut_hex)?;

        let z_hex = match curve.as_str() {
            "P-224" | "secp224r1" => compute_ecdh_p224(&d_bytes, &qx_bytes, &qy_bytes)?,
            "P-256" | "secp256r1" => compute_ecdh_p256(&d_bytes, &qx_bytes, &qy_bytes)?,
            "P-384" | "secp384r1" => compute_ecdh_p384(&d_bytes, &qx_bytes, &qy_bytes)?,
            "P-521" | "secp521r1" => compute_ecdh_p521(&d_bytes, &qx_bytes, &qy_bytes)?,
            "K-256" | "secp256k1" => compute_ecdh_k256(&d_bytes, &qx_bytes, &qy_bytes)?,
            _ => return Err(EngineError::Crypto(format!("Unsupported curve: {}", curve))),
        };

        if let Some(expected_z) = lookup(case, group, &["z", "sharedSecret"]) {
            if !super::hex_equal(&z_hex, &expected_z) {
                return Err(EngineError::Mismatch {
                    expected: expected_z,
                    actual: z_hex,
                });
            }
        } else {
            // In validation tests, we expect 'z' to be present for comparison.
            return Err(EngineError::MissingField("z"));
        }
    } else {
        // --- GENERATION LOGIC (for AFT tests) ---
        // This path is taken when dIUT is missing. The IUT must generate a keypair.
        let (qx_iut_hex, qy_iut_hex, z_hex) = match curve.as_str() {
            "P-224" | "secp224r1" => {
                let (d_iut, q_iut) = p224::generate_keypair(&mut OsRng)?;
                let peer_point = p224::Point::new_uncompressed(
                    qx_bytes.as_slice().try_into().unwrap(),
                    qy_bytes.as_slice().try_into().unwrap(),
                )?;
                let shared_point = p224::scalar_mult(&d_iut, &peer_point)?;
                (
                    hex::encode(q_iut.x_coordinate_bytes()),
                    hex::encode(q_iut.y_coordinate_bytes()),
                    hex::encode(shared_point.x_coordinate_bytes()),
                )
            }
            "P-256" | "secp256r1" => {
                let (d_iut, q_iut) = p256::generate_keypair(&mut OsRng)?;
                let peer_point = p256::Point::new_uncompressed(
                    qx_bytes.as_slice().try_into().unwrap(),
                    qy_bytes.as_slice().try_into().unwrap(),
                )?;
                let shared_point = p256::scalar_mult(&d_iut, &peer_point)?;
                (
                    hex::encode(q_iut.x_coordinate_bytes()),
                    hex::encode(q_iut.y_coordinate_bytes()),
                    hex::encode(shared_point.x_coordinate_bytes()),
                )
            }
            "P-384" | "secp384r1" => {
                let (d_iut, q_iut) = p384::generate_keypair(&mut OsRng)?;
                let peer_point = p384::Point::new_uncompressed(
                    qx_bytes.as_slice().try_into().unwrap(),
                    qy_bytes.as_slice().try_into().unwrap(),
                )?;
                let shared_point = p384::scalar_mult(&d_iut, &peer_point)?;
                (
                    hex::encode(q_iut.x_coordinate_bytes()),
                    hex::encode(q_iut.y_coordinate_bytes()),
                    hex::encode(shared_point.x_coordinate_bytes()),
                )
            }
            "P-521" | "secp521r1" => {
                let (d_iut, q_iut) = p521::generate_keypair(&mut OsRng)?;
                let peer_point = p521::Point::new_uncompressed(
                    qx_bytes.as_slice().try_into().unwrap(),
                    qy_bytes.as_slice().try_into().unwrap(),
                )?;
                let shared_point = p521::scalar_mult(&d_iut, &peer_point)?;
                (
                    hex::encode(q_iut.x_coordinate_bytes()),
                    hex::encode(q_iut.y_coordinate_bytes()),
                    hex::encode(shared_point.x_coordinate_bytes()),
                )
            }
            "K-256" | "secp256k1" => {
                let (d_iut, q_iut) = k256::generate_keypair(&mut OsRng)?;
                let peer_point = k256::Point::new_uncompressed(
                    qx_bytes.as_slice().try_into().map_err(|_| {
                        EngineError::InvalidData("Invalid qx size for K-256".into())
                    })?,
                    qy_bytes.as_slice().try_into().map_err(|_| {
                        EngineError::InvalidData("Invalid qy size for K-256".into())
                    })?,
                )?;
                let shared_point = k256::scalar_mult(&d_iut, &peer_point)?;
                (
                    hex::encode(q_iut.x_coordinate_bytes()),
                    hex::encode(q_iut.y_coordinate_bytes()),
                    hex::encode(shared_point.x_coordinate_bytes()),
                )
            }
            _ => return Err(EngineError::Crypto(format!("Unsupported curve: {}", curve))),
        };

        // Store the generated ephemeral public key and shared secret for the response.
        case.outputs.borrow_mut().insert("qxIUT".into(), qx_iut_hex);
        case.outputs.borrow_mut().insert("qyIUT".into(), qy_iut_hex);
        case.outputs.borrow_mut().insert("z".into(), z_hex);
    }

    Ok(())
}

/// ECDH validity test - checks if the computation would fail
pub(crate) fn ecdh_validity(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get the curve first to check if it's supported
    let curve = lookup(case, group, &["curve"]).ok_or(EngineError::MissingField("curve"))?;

    // Check if curve is supported
    if !is_curve_supported(&curve) {
        // For unsupported curves in validity tests, mark as skipped
        println!("Skipping validity test for unsupported curve: {}", curve);
        case.outputs
            .borrow_mut()
            .insert("testPassed".into(), "false".into());
        case.outputs
            .borrow_mut()
            .insert("reason".into(), format!("Unsupported curve: {}", curve));
        return Ok(());
    }

    // Similar to component test but expects some to fail
    let result = ecdh_component(group, case);

    // For validity tests, we need to check if the test should pass or fail
    let should_pass = case
        .inputs
        .get("testPassed")
        .map(|v| v.as_string() == "true")
        .unwrap_or(true);

    match (result, should_pass) {
        (Ok(_), true) | (Err(_), false) => {
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "true".into());
            Ok(())
        }
        (Ok(_), false) => {
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "false".into());
            case.outputs
                .borrow_mut()
                .insert("reason".into(), "Expected failure but succeeded".into());
            Ok(())
        }
        (Err(e), true) => {
            case.outputs
                .borrow_mut()
                .insert("testPassed".into(), "false".into());
            case.outputs.borrow_mut().insert(
                "reason".into(),
                format!("Expected success but failed: {}", e),
            );
            Ok(())
        }
    }
}

// Helper functions for each curve (for VAL tests)

fn compute_ecdh_p224(d: &[u8], qx: &[u8], qy: &[u8]) -> Result<String> {
    use p224::{Point, Scalar};

    let mut d_bytes = [0u8; p224::P224_SCALAR_SIZE];
    if d.len() > p224::P224_SCALAR_SIZE {
        return Err(EngineError::InvalidData(
            "Invalid P-224 private key size".into(),
        ));
    }
    d_bytes[p224::P224_SCALAR_SIZE - d.len()..].copy_from_slice(d);
    let scalar = Scalar::from_secret_buffer(SecretBuffer::new(d_bytes))
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    let peer_point = Point::new_uncompressed(qx.try_into().unwrap(), qy.try_into().unwrap())
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    if peer_point.is_identity() {
        return Err(EngineError::Crypto(
            "Peer public key is point at infinity".into(),
        ));
    }

    let shared_point =
        p224::scalar_mult(&scalar, &peer_point).map_err(|e| EngineError::Crypto(e.to_string()))?;

    if shared_point.is_identity() {
        return Err(EngineError::Crypto(
            "Shared secret is point at infinity".into(),
        ));
    }

    Ok(hex::encode(shared_point.x_coordinate_bytes()))
}

fn compute_ecdh_p256(d: &[u8], qx: &[u8], qy: &[u8]) -> Result<String> {
    use p256::{Point, Scalar};

    let mut d_bytes = [0u8; p256::P256_SCALAR_SIZE];
    if d.len() > p256::P256_SCALAR_SIZE {
        return Err(EngineError::InvalidData(
            "Invalid P-256 private key size".into(),
        ));
    }
    d_bytes[p256::P256_SCALAR_SIZE - d.len()..].copy_from_slice(d);
    let scalar = Scalar::from_secret_buffer(SecretBuffer::new(d_bytes))
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    let peer_point = Point::new_uncompressed(qx.try_into().unwrap(), qy.try_into().unwrap())
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    if peer_point.is_identity() {
        return Err(EngineError::Crypto(
            "Peer public key is point at infinity".into(),
        ));
    }

    let shared_point =
        p256::scalar_mult(&scalar, &peer_point).map_err(|e| EngineError::Crypto(e.to_string()))?;

    if shared_point.is_identity() {
        return Err(EngineError::Crypto(
            "Shared secret is point at infinity".into(),
        ));
    }

    Ok(hex::encode(shared_point.x_coordinate_bytes()))
}

fn compute_ecdh_p384(d: &[u8], qx: &[u8], qy: &[u8]) -> Result<String> {
    use p384::{Point, Scalar};

    let mut d_bytes = [0u8; p384::P384_SCALAR_SIZE];
    if d.len() > p384::P384_SCALAR_SIZE {
        return Err(EngineError::InvalidData(
            "Invalid P-384 private key size".into(),
        ));
    }
    d_bytes[p384::P384_SCALAR_SIZE - d.len()..].copy_from_slice(d);
    let scalar = Scalar::from_secret_buffer(SecretBuffer::new(d_bytes))
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    let peer_point = Point::new_uncompressed(qx.try_into().unwrap(), qy.try_into().unwrap())
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    if peer_point.is_identity() {
        return Err(EngineError::Crypto(
            "Peer public key is point at infinity".into(),
        ));
    }

    let shared_point =
        p384::scalar_mult(&scalar, &peer_point).map_err(|e| EngineError::Crypto(e.to_string()))?;

    if shared_point.is_identity() {
        return Err(EngineError::Crypto(
            "Shared secret is point at infinity".into(),
        ));
    }

    Ok(hex::encode(shared_point.x_coordinate_bytes()))
}

fn compute_ecdh_p521(d: &[u8], qx: &[u8], qy: &[u8]) -> Result<String> {
    use p521::{Point, Scalar};

    let mut d_bytes = [0u8; p521::P521_SCALAR_SIZE];
    if d.len() > p521::P521_SCALAR_SIZE {
        return Err(EngineError::InvalidData(
            "Invalid P-521 private key size".into(),
        ));
    }
    d_bytes[p521::P521_SCALAR_SIZE - d.len()..].copy_from_slice(d);
    let scalar = Scalar::from_secret_buffer(SecretBuffer::new(d_bytes))
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    let peer_point = Point::new_uncompressed(qx.try_into().unwrap(), qy.try_into().unwrap())
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    if peer_point.is_identity() {
        return Err(EngineError::Crypto(
            "Peer public key is point at infinity".into(),
        ));
    }

    let shared_point =
        p521::scalar_mult(&scalar, &peer_point).map_err(|e| EngineError::Crypto(e.to_string()))?;

    if shared_point.is_identity() {
        return Err(EngineError::Crypto(
            "Shared secret is point at infinity".into(),
        ));
    }

    Ok(hex::encode(shared_point.x_coordinate_bytes()))
}

fn compute_ecdh_k256(d: &[u8], qx: &[u8], qy: &[u8]) -> Result<String> {
    use k256::{Point, Scalar};

    let mut d_bytes = [0u8; k256::K256_SCALAR_SIZE];
    if d.len() > k256::K256_SCALAR_SIZE {
        return Err(EngineError::InvalidData(
            "Invalid K-256 private key size".into(),
        ));
    }
    d_bytes[k256::K256_SCALAR_SIZE - d.len()..].copy_from_slice(d);
    let scalar = Scalar::from_secret_buffer(SecretBuffer::new(d_bytes))
        .map_err(|e| EngineError::Crypto(e.to_string()))?;

    let peer_point = Point::new_uncompressed(
        qx.try_into()
            .map_err(|_| EngineError::InvalidData("Invalid qx for K-256".into()))?,
        qy.try_into()
            .map_err(|_| EngineError::InvalidData("Invalid qy for K-256".into()))?,
    )
    .map_err(|e| EngineError::Crypto(e.to_string()))?;

    let shared_point =
        k256::scalar_mult(&scalar, &peer_point).map_err(|e| EngineError::Crypto(e.to_string()))?;

    Ok(hex::encode(shared_point.x_coordinate_bytes()))
}

/// Register ECDH handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // KAS-ECC-CDH-Component tests
    insert(map, "KAS-ECC-CDH-Component", "AFT", "AFT", ecdh_component);
    insert(map, "KAS-ECC-CDH-Component", "VAL", "VAL", ecdh_validity);

    // Also register with alternative names that might be used
    insert(map, "KAS-ECC", "CDH-Component", "AFT", ecdh_component);
    insert(map, "KAS-ECC", "CDH-Component", "VAL", ecdh_validity);

    // Add handlers for the general "KAS-ECC" algorithm which ACVP uses
    // for some component tests, mapping them to the existing component handlers.
    insert(map, "KAS-ECC", "AFT", "AFT", ecdh_component);
    insert(map, "KAS-ECC", "VAL", "VAL", ecdh_validity);

    // Register handlers for specific curve variants if needed
    for curve in &["P-224", "P-256", "P-384", "P-521", "K-256"] {
        let algo = format!("ECDH-{}", curve);
        insert(map, &algo, "AFT", "AFT", ecdh_component);
        insert(map, &algo, "VAL", "VAL", ecdh_validity);
    }
}
