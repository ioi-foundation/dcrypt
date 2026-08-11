//! ACVP handlers for the Ed25519 subset exposed by dcrypt.

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{FlexValue, TestCase, TestGroup};
use dcrypt_api::Signature;
use dcrypt_sign::eddsa::{Ed25519, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

#[derive(Clone, Copy)]
enum OperationKind {
    Key,
    Signature,
}

enum OperationSupport {
    Supported,
    Unsupported(String),
}

fn strict_string_values<'a>(
    field: &'static str,
    values: impl IntoIterator<Item = Option<&'a FlexValue>>,
) -> Result<Option<String>> {
    let mut selected = None;
    for value in values.into_iter().flatten() {
        let FlexValue::String(value) = value else {
            return Err(EngineError::InvalidData(format!(
                "EdDSA {field} must be a JSON string"
            )));
        };
        if selected.as_ref().is_some_and(|prior| prior != value) {
            return Err(EngineError::InvalidData(format!(
                "conflicting EdDSA {field} metadata"
            )));
        }
        selected = Some(value.clone());
    }
    Ok(selected)
}

fn strict_bool_values<'a>(
    field: &'static str,
    values: impl IntoIterator<Item = Option<&'a FlexValue>>,
) -> Result<Option<bool>> {
    let mut selected = None;
    for value in values.into_iter().flatten() {
        let FlexValue::Bool(value) = value else {
            return Err(EngineError::InvalidData(format!(
                "EdDSA {field} must be a JSON boolean"
            )));
        };
        if selected.is_some_and(|prior| prior != *value) {
            return Err(EngineError::InvalidData(format!(
                "conflicting EdDSA {field} metadata"
            )));
        }
        selected = Some(*value);
    }
    Ok(selected)
}

fn strict_usize_values<'a>(
    field: &'static str,
    values: impl IntoIterator<Item = Option<&'a FlexValue>>,
) -> Result<Option<usize>> {
    let mut selected = None;
    for value in values.into_iter().flatten() {
        let FlexValue::Number(value) = value else {
            return Err(EngineError::InvalidData(format!(
                "EdDSA {field} must be a non-negative JSON integer"
            )));
        };
        let value = value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| {
                EngineError::InvalidData(format!(
                    "EdDSA {field} must be a non-negative JSON integer"
                ))
            })?;
        if selected.is_some_and(|prior| prior != value) {
            return Err(EngineError::InvalidData(format!(
                "conflicting EdDSA {field} metadata"
            )));
        }
        selected = Some(value);
    }
    Ok(selected)
}

fn get_curve(group: &TestGroup, case: &TestCase) -> Result<String> {
    let mut curve = strict_string_values(
        "curve",
        [group.defaults.get("curve"), case.inputs.get("curve")],
    )?;

    if let Some(params) = &group.params {
        let params = params
            .as_object()
            .ok_or_else(|| EngineError::InvalidData("EdDSA params must be a JSON object".into()))?;
        if let Some(value) = params.get("curve") {
            let value = value.as_str().ok_or_else(|| {
                EngineError::InvalidData("EdDSA params.curve must be a JSON string".into())
            })?;
            if curve.as_ref().is_some_and(|prior| prior != value) {
                return Err(EngineError::InvalidData(
                    "conflicting EdDSA curve metadata".into(),
                ));
            }
            curve = Some(value.to_owned());
        }
    }

    curve.ok_or(EngineError::MissingField("curve"))
}

fn is_ed25519(curve: &str) -> bool {
    matches!(curve, "Ed25519" | "ed25519" | "ED-25519" | "ed-25519")
}

fn is_ed448(curve: &str) -> bool {
    matches!(curve, "Ed448" | "ed448" | "ED-448" | "ed-448")
}

fn get_prehash(group: &TestGroup, case: &TestCase, required: bool) -> Result<Option<bool>> {
    let prehash = group.defaults.get("preHash");
    let prehash = strict_bool_values(
        "preHash",
        [
            prehash,
            case.inputs.get("preHash"),
            group.projection.get("preHash"),
            case.projection.get("preHash"),
        ],
    )?;
    if required && prehash.is_none() {
        return Err(EngineError::MissingField("preHash"));
    }
    Ok(prehash)
}

fn get_context(group: &TestGroup, case: &TestCase) -> Result<Option<String>> {
    // The prompt declares the requested operation.  Internal projection files
    // also carry an empty context and zero length for pure Ed25519; those
    // replay defaults must be validated but must not silently select ctx mode.
    let prompt_context = strict_string_values(
        "context",
        [case.inputs.get("context"), group.defaults.get("context")],
    )?;
    let projected_context = strict_string_values(
        "internalProjection.context",
        [
            case.projection.get("context"),
            group.projection.get("context"),
        ],
    )?;
    let context_length = strict_usize_values(
        "contextLength",
        [
            case.inputs.get("contextLength"),
            case.projection.get("contextLength"),
            group.defaults.get("contextLength"),
        ],
    )?;

    if prompt_context.is_none()
        && projected_context
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    {
        return Err(EngineError::InvalidData(
            "internalProjection.context cannot introduce Ed25519ctx when the prompt omits context"
                .into(),
        ));
    }
    if let (Some(prompt), Some(projected)) = (&prompt_context, &projected_context) {
        if prompt != projected {
            return Err(EngineError::InvalidData(
                "prompt/internalProjection EdDSA context mismatch".into(),
            ));
        }
    }

    let effective_context = prompt_context
        .as_ref()
        .or(projected_context.as_ref())
        .map(String::as_str);
    match (effective_context, context_length) {
        (None, Some(_)) => return Err(EngineError::MissingField("context")),
        (Some(context), declared_length) => {
            let decoded = hex::decode(context).map_err(|_| {
                EngineError::InvalidData("EdDSA context must be hexadecimal".into())
            })?;
            if let Some(length) = declared_length {
                if length != decoded.len() {
                    return Err(EngineError::InvalidData(format!(
                        "EdDSA contextLength does not match context: declared {length}, decoded {}",
                        decoded.len()
                    )));
                }
            }
        }
        (None, None) => {}
    }

    Ok(prompt_context)
}

fn operation_support(
    group: &TestGroup,
    case: &TestCase,
    operation: OperationKind,
) -> Result<OperationSupport> {
    let curve = get_curve(group, case)?;
    let prehash = get_prehash(group, case, matches!(operation, OperationKind::Signature))?;
    let context = get_context(group, case)?;

    if is_ed448(&curve) {
        return Ok(OperationSupport::Unsupported(format!(
            "unsupported EdDSA curve {curve}"
        )));
    }
    if !is_ed25519(&curve) {
        return Err(EngineError::InvalidData(format!(
            "unrecognized EdDSA curve {curve}"
        )));
    }
    if prehash == Some(true) {
        return Ok(OperationSupport::Unsupported(
            "Ed25519ph is not exposed by the dcrypt Ed25519 API".into(),
        ));
    }
    // Presence, rather than non-emptiness, selects Ed25519ctx.  The empty
    // Ed25519ctx domain is not the same operation as pure Ed25519.
    if context.is_some() {
        return Ok(OperationSupport::Unsupported(
            "Ed25519ctx is not exposed by the dcrypt Ed25519 API".into(),
        ));
    }
    Ok(OperationSupport::Supported)
}

fn skip_if_unsupported(
    group: &TestGroup,
    case: &TestCase,
    operation: OperationKind,
) -> Result<bool> {
    match operation_support(group, case, operation)? {
        OperationSupport::Supported => Ok(false),
        OperationSupport::Unsupported(reason) => {
            debug_assert!(!reason.trim().is_empty());
            case.mark_skipped(reason);
            Ok(true)
        }
    }
}

fn message(case: &TestCase) -> Result<Vec<u8>> {
    let encoded = case
        .inputs
        .get("message")
        .or_else(|| case.inputs.get("msg"))
        .map(FlexValue::as_string)
        .ok_or(EngineError::MissingField("message"))?;
    Ok(hex::decode(encoded)?)
}

fn seed_from_projection(group: &TestGroup, case: &TestCase) -> Result<[u8; 32]> {
    let encoded = case
        .projection
        .get("d")
        .or_else(|| group.projection.get("d"))
        .map(FlexValue::as_string)
        .ok_or(EngineError::MissingField("internalProjection.d"))?;
    let seed = hex::decode(encoded)?;
    seed.try_into().map_err(|seed: Vec<u8>| {
        EngineError::InvalidData(format!(
            "Ed25519 internalProjection.d must be 32 bytes, got {}",
            seed.len()
        ))
    })
}

fn verify_generated_keypair(secret: &Ed25519SecretKey, public: &Ed25519PublicKey) -> Result<()> {
    let derived = secret
        .public_key()
        .map_err(|error| EngineError::Crypto(format!("public-key derivation failed: {error:?}")))?;
    if derived.0 != public.0 {
        return Err(EngineError::Crypto(
            "generated Ed25519 public key does not match its seed".into(),
        ));
    }
    let signature = Ed25519::sign(b"ACVP keyGen postcondition", secret)
        .map_err(|error| EngineError::Crypto(format!("postcondition signing failed: {error:?}")))?;
    Ed25519::verify(b"ACVP keyGen postcondition", &signature, public).map_err(|error| {
        EngineError::Crypto(format!("postcondition verification failed: {error:?}"))
    })
}

pub(crate) fn eddsa_keygen(group: &TestGroup, case: &TestCase) -> Result<()> {
    if skip_if_unsupported(group, case, OperationKind::Key)? {
        return Ok(());
    }

    // The projection carries the exact RFC 8032 seed used to produce the
    // response.  Import it directly: seeding a PRNG with `d` changes the
    // operation and cannot reproduce the ACVP result.
    let seed = seed_from_projection(group, case)?;
    let secret = Ed25519SecretKey::from_seed(&seed)
        .map_err(|error| EngineError::Crypto(format!("invalid projected seed: {error:?}")))?;
    let public = secret
        .public_key()
        .map_err(|error| EngineError::Crypto(format!("public-key derivation failed: {error:?}")))?;
    verify_generated_keypair(&secret, &public)?;

    case.outputs
        .borrow_mut()
        .insert("d".into(), hex::encode(secret.seed()));
    case.outputs
        .borrow_mut()
        .insert("q".into(), hex::encode(public.0));
    Ok(())
}

pub(crate) fn eddsa_keyver(group: &TestGroup, case: &TestCase) -> Result<()> {
    if skip_if_unsupported(group, case, OperationKind::Key)? {
        return Ok(());
    }
    let encoded = case
        .inputs
        .get("q")
        .map(FlexValue::as_string)
        .ok_or(EngineError::MissingField("q"))?;
    let valid = hex::decode(encoded)
        .ok()
        .and_then(|bytes| Ed25519PublicKey::from_bytes(&bytes).ok())
        .is_some();
    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), valid.to_string());
    Ok(())
}

pub(crate) fn eddsa_siggen(group: &TestGroup, case: &TestCase) -> Result<()> {
    if skip_if_unsupported(group, case, OperationKind::Signature)? {
        return Ok(());
    }

    let seed = seed_from_projection(group, case)?;
    let secret = Ed25519SecretKey::from_seed(&seed)
        .map_err(|error| EngineError::Crypto(format!("invalid projected seed: {error:?}")))?;
    let public = secret
        .public_key()
        .map_err(|error| EngineError::Crypto(format!("public-key derivation failed: {error:?}")))?;
    let message = message(case)?;
    let signature = Ed25519::sign(&message, &secret)
        .map_err(|error| EngineError::Crypto(format!("Ed25519 signing failed: {error:?}")))?;
    Ed25519::verify(&message, &signature, &public)
        .map_err(|error| EngineError::Crypto(format!("self-verification failed: {error:?}")))?;

    group
        .outputs
        .borrow_mut()
        .insert("q".into(), hex::encode(public.0));
    case.outputs
        .borrow_mut()
        .insert("signature".into(), hex::encode(signature.0));
    Ok(())
}

pub(crate) fn eddsa_sigver(group: &TestGroup, case: &TestCase) -> Result<()> {
    if skip_if_unsupported(group, case, OperationKind::Signature)? {
        return Ok(());
    }

    let message = message(case)?;
    let q = case
        .inputs
        .get("q")
        .map(FlexValue::as_string)
        .ok_or(EngineError::MissingField("q"))?;
    let signature = case
        .inputs
        .get("signature")
        .map(FlexValue::as_string)
        .ok_or(EngineError::MissingField("signature"))?;

    // Both constructors enforce canonical encodings.  Public-key decoding also
    // rejects the identity and non-prime-order/small-order points.
    let valid = match (hex::decode(q), hex::decode(signature)) {
        (Ok(q), Ok(signature)) => match (
            Ed25519PublicKey::from_bytes(&q),
            Ed25519Signature::from_bytes(&signature),
        ) {
            (Ok(public), Ok(signature)) => Ed25519::verify(&message, &signature, &public).is_ok(),
            _ => false,
        },
        _ => false,
    };
    case.outputs
        .borrow_mut()
        .insert("testPassed".into(), valid.to_string());
    Ok(())
}

pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    insert(map, "EDDSA-keyGen", "AFT", "AFT", eddsa_keygen);
    insert(map, "EDDSA-keyVer", "AFT", "AFT", eddsa_keyver);
    insert(map, "EDDSA-sigGen", "AFT", "AFT", eddsa_siggen);
    insert(map, "EDDSA-sigGen", "BFT", "BFT", eddsa_siggen);
    insert(map, "EDDSA-sigVer", "AFT", "AFT", eddsa_sigver);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suites::acvp::model::TestSuite;
    use crate::suites::acvp::runner::{AcvpEngine, CaseStatus, Runner, SKIP_MARKER};

    const MESSAGE: &[u8] = b"ACVP Ed25519 handler boundary";
    const MIXED_TORSION_POINT: [u8; 32] = [
        0x52, 0x52, 0xcc, 0x0a, 0x7f, 0x20, 0x81, 0x33, 0xb6, 0x20, 0xac, 0xbd, 0x45, 0x37, 0xeb,
        0xa2, 0xa4, 0x12, 0x3b, 0xf0, 0xa8, 0xc2, 0xe4, 0xf9, 0x80, 0xc3, 0xb3, 0x1b, 0xb6, 0x97,
        0x65, 0xea,
    ];
    const GROUP_ORDER: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    struct SigVerEngine;

    impl AcvpEngine for SigVerEngine {
        fn run(&self, group: &TestGroup, case: &TestCase) -> std::result::Result<(), String> {
            eddsa_sigver(group, case).map_err(|error| error.to_string())
        }
    }

    fn valid_material(message: &[u8]) -> (String, String) {
        let secret = Ed25519SecretKey::from_seed(&[0x42; 32]).expect("fixed seed is valid");
        let public = secret.public_key().expect("public-key derivation succeeds");
        let signature = Ed25519::sign(message, &secret).expect("fixed-message signing succeeds");
        (hex::encode(public.0), hex::encode(signature.0))
    }

    fn sigver_group() -> TestGroup {
        let (q, signature) = valid_material(MESSAGE);
        serde_json::from_value(serde_json::json!({
            "tgId": 1,
            "testType": "AFT",
            "algorithm": "EDDSA-sigVer",
            "curve": "ED-25519",
            "preHash": false,
            "tests": [{
                "tcId": 1,
                "message": hex::encode(MESSAGE),
                "q": q,
                "signature": signature
            }]
        }))
        .expect("valid Ed25519 SigVer fixture")
    }

    fn keyver_group() -> TestGroup {
        let (q, _) = valid_material(MESSAGE);
        serde_json::from_value(serde_json::json!({
            "tgId": 1,
            "testType": "AFT",
            "algorithm": "EDDSA-keyVer",
            "curve": "ED-25519",
            "tests": [{"tcId": 1, "q": q}]
        }))
        .expect("valid Ed25519 KeyVer fixture")
    }

    fn set_case_string(group: &mut TestGroup, field: &str, value: impl Into<String>) {
        group.tests[0]
            .inputs
            .insert(field.into(), FlexValue::String(value.into()));
    }

    fn assert_sigver_false(group: TestGroup, label: &str) {
        eddsa_sigver(&group, &group.tests[0])
            .unwrap_or_else(|error| panic!("{label} returned an error instead of false: {error}"));
        let outputs = group.tests[0].outputs.borrow();
        assert_eq!(
            outputs.get("testPassed").map(String::as_str),
            Some("false"),
            "{label}"
        );
        assert!(!outputs.contains_key(SKIP_MARKER), "{label} was skipped");
        assert_eq!(outputs.len(), 1, "{label} emitted unexpected evidence");
    }

    fn assert_metadata_error(group: TestGroup, expected: &str) {
        let error = eddsa_sigver(&group, &group.tests[0])
            .expect_err("malformed metadata must fail instead of skip");
        assert!(
            error.to_string().contains(expected),
            "unexpected error: {error}"
        );
        assert!(!group.tests[0].outputs.borrow().contains_key(SKIP_MARKER));
    }

    fn assert_nonblank_skip(group: TestGroup, expected: &str) {
        eddsa_sigver(&group, &group.tests[0]).expect("recognized unsupported mode must skip");
        let outputs = group.tests[0].outputs.borrow();
        let reason = outputs
            .get(SKIP_MARKER)
            .expect("recognized unsupported mode lacks a skip marker");
        assert!(!reason.trim().is_empty());
        assert!(
            reason.contains(expected),
            "unexpected skip reason: {reason}"
        );
        assert!(!outputs.contains_key("testPassed"));
    }

    #[test]
    fn malformed_capability_metadata_fails_instead_of_skipping() {
        let mut group = sigver_group();
        group.defaults.remove("curve");
        assert_metadata_error(group, "missing required field: curve");

        let mut group = sigver_group();
        group.defaults.insert("curve".into(), FlexValue::Bool(true));
        assert_metadata_error(group, "curve must be a JSON string");

        let mut group = sigver_group();
        group
            .defaults
            .insert("curve".into(), FlexValue::String("P-256".into()));
        assert_metadata_error(group, "unrecognized EdDSA curve");

        let mut group = sigver_group();
        group.defaults.remove("preHash");
        assert_metadata_error(group, "missing required field: preHash");

        let mut group = sigver_group();
        group
            .defaults
            .insert("preHash".into(), FlexValue::String("false".into()));
        assert_metadata_error(group, "preHash must be a JSON boolean");

        let mut group = sigver_group();
        group.tests[0]
            .inputs
            .insert("context".into(), FlexValue::Bool(false));
        assert_metadata_error(group, "context must be a JSON string");

        let mut group = sigver_group();
        set_case_string(&mut group, "context", "not-hex");
        assert_metadata_error(group, "context must be hexadecimal");

        let mut group = sigver_group();
        group.tests[0]
            .inputs
            .insert("contextLength".into(), FlexValue::Number(1u64.into()));
        assert_metadata_error(group, "missing required field: context");

        let mut group = sigver_group();
        set_case_string(&mut group, "context", "00");
        group.tests[0]
            .inputs
            .insert("contextLength".into(), FlexValue::Number(2u64.into()));
        assert_metadata_error(group, "contextLength does not match context");
    }

    #[test]
    fn only_recognized_unsupported_capabilities_are_skipped() {
        let mut group = sigver_group();
        group
            .defaults
            .insert("curve".into(), FlexValue::String("ED-448".into()));
        assert_nonblank_skip(group, "unsupported EdDSA curve ED-448");

        let mut group = sigver_group();
        group
            .defaults
            .insert("preHash".into(), FlexValue::Bool(true));
        assert_nonblank_skip(group, "Ed25519ph");

        let mut group = sigver_group();
        set_case_string(&mut group, "context", "");
        assert_nonblank_skip(group, "Ed25519ctx");

        let mut group = sigver_group();
        set_case_string(&mut group, "context", "00");
        group.tests[0]
            .inputs
            .insert("contextLength".into(), FlexValue::Number(1u64.into()));
        assert_nonblank_skip(group, "Ed25519ctx");

        let group = keyver_group();
        eddsa_keyver(&group, &group.tests[0]).expect("key operations do not require preHash");
        assert_eq!(
            group.tests[0]
                .outputs
                .borrow()
                .get("testPassed")
                .map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn key_and_signature_handlers_reject_malformed_and_noncanonical_encodings() {
        let valid = sigver_group();
        let valid_q = valid.tests[0].inputs["q"].as_string();
        let valid_signature = valid.tests[0].inputs["signature"].as_string();
        let q_bytes = hex::decode(&valid_q).expect("fixture public key is hex");
        let signature_bytes = hex::decode(&valid_signature).expect("fixture signature is hex");

        let mut identity = [0u8; 32];
        identity[0] = 1;
        let invalid_public_keys = [
            ("non-hex public key", "not-hex".into()),
            ("truncated public key", hex::encode(&q_bytes[..31])),
            (
                "overlong public key",
                hex::encode([q_bytes.as_slice(), &[0]].concat()),
            ),
            ("identity public key", hex::encode(identity)),
            ("small-order public key", hex::encode([0u8; 32])),
            ("mixed-torsion public key", hex::encode(MIXED_TORSION_POINT)),
            ("noncanonical public key", hex::encode([0xff; 32])),
        ];
        for (label, q) in invalid_public_keys {
            let mut group = sigver_group();
            set_case_string(&mut group, "q", q.clone());
            assert_sigver_false(group, label);

            let mut key_group = keyver_group();
            set_case_string(&mut key_group, "q", q);
            eddsa_keyver(&key_group, &key_group.tests[0])
                .unwrap_or_else(|error| panic!("{label} KeyVer returned an error: {error}"));
            assert_eq!(
                key_group.tests[0]
                    .outputs
                    .borrow()
                    .get("testPassed")
                    .map(String::as_str),
                Some("false"),
                "{label}"
            );
        }

        let mut identity_r = signature_bytes.clone();
        identity_r[..32].copy_from_slice(&identity);
        let mut small_order_r = signature_bytes.clone();
        small_order_r[..32].fill(0);
        let mut mixed_torsion_r = signature_bytes.clone();
        mixed_torsion_r[..32].copy_from_slice(&MIXED_TORSION_POINT);
        let mut noncanonical_r = signature_bytes.clone();
        noncanonical_r[..32].fill(0xff);
        let mut noncanonical_s = signature_bytes.clone();
        noncanonical_s[32..].copy_from_slice(&GROUP_ORDER);
        let invalid_signatures = [
            ("non-hex signature", "not-hex".into()),
            ("truncated signature", hex::encode(&signature_bytes[..63])),
            (
                "overlong signature",
                hex::encode([signature_bytes.as_slice(), &[0]].concat()),
            ),
            ("identity R", hex::encode(identity_r)),
            ("small-order R", hex::encode(small_order_r)),
            ("mixed-torsion R", hex::encode(mixed_torsion_r)),
            ("noncanonical R", hex::encode(noncanonical_r)),
            ("S equal to the group order", hex::encode(noncanonical_s)),
        ];
        for (label, signature) in invalid_signatures {
            let mut group = sigver_group();
            set_case_string(&mut group, "signature", signature);
            assert_sigver_false(group, label);
        }

        let mut wrong_message = sigver_group();
        set_case_string(
            &mut wrong_message,
            "message",
            hex::encode(b"different message"),
        );
        assert_sigver_false(wrong_message, "wrong message");

        let (_, signature_for_other_message) = valid_material(b"different message");
        let mut wrong_signature = sigver_group();
        set_case_string(
            &mut wrong_signature,
            "signature",
            signature_for_other_message,
        );
        assert_sigver_false(wrong_signature, "wrong signature");
    }

    #[test]
    fn missing_verification_fields_fail_instead_of_skipping() {
        for (field, expected) in [
            ("message", "missing required field: message"),
            ("q", "missing required field: q"),
            ("signature", "missing required field: signature"),
        ] {
            let mut group = sigver_group();
            group.tests[0].inputs.remove(field);
            let error = eddsa_sigver(&group, &group.tests[0])
                .expect_err("missing verification input must fail");
            assert!(
                error.to_string().contains(expected),
                "unexpected error: {error}"
            );
            assert!(!group.tests[0].outputs.borrow().contains_key(SKIP_MARKER));
        }
    }

    fn expected_invalid_suite(expected: bool) -> TestSuite {
        let mut group = sigver_group();
        set_case_string(&mut group, "q", hex::encode([0u8; 32]));
        group.tests[0].insert_expected_output("testPassed".into(), FlexValue::Bool(expected));
        TestSuite {
            suite_name: 1,
            algorithm: "EDDSA-sigVer".into(),
            mode: Some("sigVer".into()),
            revision: Some("fixture".into()),
            is_sample: Some(true),
            groups: vec![group],
        }
    }

    #[test]
    fn expected_invalid_verdict_is_compared_and_mutation_fails() {
        let report = Runner::new(&SigVerEngine).run_suite_report(&expected_invalid_suite(false));
        assert_eq!(report.summary.passed, 1, "{:?}", report.failures);
        assert_eq!(report.summary.failed, 0, "{:?}", report.failures);
        assert_eq!(report.summary.skipped, 0);
        assert_eq!(report.cases[0].status, CaseStatus::Passed);

        let report = Runner::new(&SigVerEngine).run_suite_report(&expected_invalid_suite(true));
        assert_eq!(report.summary.passed, 0);
        assert_eq!(report.summary.failed, 1);
        assert_eq!(report.summary.skipped, 0);
        assert_eq!(report.cases[0].status, CaseStatus::Failed);
    }
}
