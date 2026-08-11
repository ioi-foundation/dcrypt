//! Loads ACVP test vectors from JSON files.

use crate::suites::acvp::model::{FlexValue, TestGroup, TestSuite};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Join NIST's separate expected-results file onto prompt cases by `(tgId,
/// tcId)`. ACVP files do not guarantee matching array order, so positional
/// joins can silently compare a result with the wrong test case.
fn merge_expected_results(suite_dir: &Path, suite: &mut TestSuite) -> Result<(), String> {
    let expected_file = suite_dir.join("expectedResults.json");
    if !expected_file.exists() {
        return Err(format!(
            "ACVP validation requires {}",
            expected_file.display()
        ));
    }
    let json = fs::read_to_string(&expected_file)
        .map_err(|error| format!("Failed to read {}: {}", expected_file.display(), error))?;
    let expected: serde_json::Value = serde_json::from_str(&json)
        .map_err(|error| format!("Failed to parse {}: {}", expected_file.display(), error))?;
    merge_expected_value(&expected, suite)
}

/// Load NIST's non-public replay material without merging it into either the
/// prompt or expected-output namespace.  Projection data is optional because
/// validation-only suites do not always publish it.
fn merge_internal_projection(suite_dir: &Path, suite: &mut TestSuite) -> Result<(), String> {
    let projection_file = suite_dir.join("internalProjection.json");
    if !projection_file.exists() {
        return Ok(());
    }
    let json = fs::read_to_string(&projection_file)
        .map_err(|error| format!("Failed to read {}: {}", projection_file.display(), error))?;
    let projection: serde_json::Value = serde_json::from_str(&json)
        .map_err(|error| format!("Failed to parse {}: {}", projection_file.display(), error))?;
    merge_projection_value(&projection, suite)
}

fn prompt_case_ids(suite: &TestSuite) -> Result<BTreeMap<u64, BTreeSet<u64>>, String> {
    let mut groups = BTreeMap::new();
    for group in &suite.groups {
        let mut cases = BTreeSet::new();
        for case in &group.tests {
            if !cases.insert(case.test_id) {
                return Err(format!(
                    "prompt.json contains duplicate tgId {}/tcId {}",
                    group.group_name, case.test_id
                ));
            }
        }
        if groups.insert(group.group_name, cases).is_some() {
            return Err(format!(
                "prompt.json contains duplicate tgId {}",
                group.group_name
            ));
        }
    }
    Ok(groups)
}

fn expected_case_ids(expected: &serde_json::Value) -> Result<BTreeMap<u64, BTreeSet<u64>>, String> {
    let groups = expected
        .get("testGroups")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "expectedResults.json is missing testGroups".to_string())?;

    let mut ids = BTreeMap::new();
    for expected_group in groups {
        let group_id = expected_group
            .get("tgId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "expected result group is missing tgId".to_string())?;
        let cases = expected_group
            .get("tests")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("expected result tgId {} is missing tests", group_id))?;
        let mut case_ids = BTreeSet::new();
        for expected_case in cases {
            let case_id = expected_case
                .get("tcId")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| format!("expected result tgId {} is missing tcId", group_id))?;
            if !case_ids.insert(case_id) {
                return Err(format!(
                    "expectedResults.json contains duplicate tgId {}/tcId {}",
                    group_id, case_id
                ));
            }
        }
        if ids.insert(group_id, case_ids).is_some() {
            return Err(format!(
                "expectedResults.json contains duplicate tgId {}",
                group_id
            ));
        }
    }
    Ok(ids)
}

fn merge_expected_value(expected: &serde_json::Value, suite: &mut TestSuite) -> Result<(), String> {
    merge_companion_value(expected, suite, CompanionKind::Expected)
}

fn merge_projection_value(
    projection: &serde_json::Value,
    suite: &mut TestSuite,
) -> Result<(), String> {
    merge_companion_value(projection, suite, CompanionKind::Projection)
}

#[derive(Clone, Copy)]
enum CompanionKind {
    Expected,
    Projection,
}

impl CompanionKind {
    fn label(self) -> &'static str {
        match self {
            Self::Expected => "expectedResults.json",
            Self::Projection => "internalProjection.json",
        }
    }
}

fn merge_companion_value(
    companion: &serde_json::Value,
    suite: &mut TestSuite,
    kind: CompanionKind,
) -> Result<(), String> {
    validate_companion_metadata(companion, suite, kind)?;
    let prompt_ids = prompt_case_ids(suite)?;
    let expected_ids = expected_case_ids(companion)?;
    let prompt_groups: BTreeSet<_> = prompt_ids.keys().copied().collect();
    let expected_groups: BTreeSet<_> = expected_ids.keys().copied().collect();
    if prompt_groups != expected_groups {
        return Err(format!(
            "prompt/{} tgId sets differ: missing companion {:?}, unexpected companion {:?}",
            kind.label(),
            prompt_groups
                .difference(&expected_groups)
                .collect::<Vec<_>>(),
            expected_groups
                .difference(&prompt_groups)
                .collect::<Vec<_>>()
        ));
    }
    for (group_id, prompt_cases) in &prompt_ids {
        let expected_cases = expected_ids
            .get(group_id)
            .ok_or_else(|| format!("expected result is missing tgId {}", group_id))?;
        if prompt_cases != expected_cases {
            return Err(format!(
                "prompt/{} tcId sets differ for tgId {}: missing companion {:?}, unexpected companion {:?}",
                kind.label(),
                group_id,
                prompt_cases.difference(expected_cases).collect::<Vec<_>>(),
                expected_cases.difference(prompt_cases).collect::<Vec<_>>()
            ));
        }
    }

    let groups = companion
        .get("testGroups")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "expectedResults.json is missing testGroups".to_string())?;
    for expected_group in groups {
        let group_id = expected_group
            .get("tgId")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "expected result group is missing tgId".to_string())?;
        let group = suite
            .groups
            .iter_mut()
            .find(|group| group.group_name == group_id)
            .ok_or_else(|| format!("expected result references unknown tgId {}", group_id))?;
        let group_fields = expected_group
            .as_object()
            .ok_or_else(|| format!("{} tgId {} is not an object", kind.label(), group_id))?;
        for (name, value) in group_fields {
            if matches!(name.as_str(), "tgId" | "tests") {
                continue;
            }
            let value: FlexValue = serde_json::from_value(value.clone()).map_err(|error| {
                format!(
                    "invalid {} group field {} for tgId {}: {}",
                    kind.label(),
                    name,
                    group_id,
                    error
                )
            })?;
            match kind {
                CompanionKind::Expected => {
                    group.insert_expected_output(name.clone(), value);
                }
                CompanionKind::Projection => {
                    if let Some(prompt_value) = prompt_group_value(group, name)? {
                        if prompt_value != value {
                            return Err(format!(
                                "prompt/internalProjection.json group field mismatch for tgId {group_id}/{name}"
                            ));
                        }
                    } else {
                        group.projection.insert(name.clone(), value);
                    }
                }
            }
        }
        let cases = expected_group
            .get("tests")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("expected result tgId {} is missing tests", group_id))?;
        for expected_case in cases {
            let case_id = expected_case
                .get("tcId")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| format!("expected result tgId {} is missing tcId", group_id))?;
            let case = group
                .tests
                .iter_mut()
                .find(|case| case.test_id == case_id)
                .ok_or_else(|| {
                    format!(
                        "expected result references unknown tgId {}/tcId {}",
                        group_id, case_id
                    )
                })?;
            let fields = expected_case.as_object().ok_or_else(|| {
                format!(
                    "expected result tgId {}/tcId {} is not an object",
                    group_id, case_id
                )
            })?;
            for (name, value) in fields {
                if name == "tcId" {
                    continue;
                }
                let value: FlexValue = serde_json::from_value(value.clone()).map_err(|error| {
                    format!(
                        "invalid expected field {} for tgId {}/tcId {}: {}",
                        name, group_id, case_id, error
                    )
                })?;
                match kind {
                    CompanionKind::Expected => {
                        case.insert_expected_output(name.clone(), value);
                    }
                    CompanionKind::Projection => {
                        if let Some(prompt_value) = prompt_case_value(case, name) {
                            if prompt_value != value {
                                return Err(format!(
                                    "prompt/internalProjection.json case field mismatch for tgId {group_id}/tcId {case_id}/{name}"
                                ));
                            }
                        } else {
                            case.projection.insert(name.clone(), value);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn prompt_group_value(group: &TestGroup, name: &str) -> Result<Option<FlexValue>, String> {
    let value = match name {
        "testType" => Some(FlexValue::String(group.test_type.clone())),
        "algorithm" => Some(FlexValue::String(group.algorithm.clone())),
        "direction" => group.direction.clone().map(FlexValue::String),
        "keyLen" => group
            .key_len
            .map(|value| FlexValue::Number(serde_json::Number::from(value))),
        "params" => group
            .params
            .as_ref()
            .map(|value| {
                serde_json::from_value(value.clone())
                    .map_err(|error| format!("invalid prompt params: {error}"))
            })
            .transpose()?,
        _ => group.defaults.get(name).cloned(),
    };
    Ok(value)
}

fn prompt_case_value(case: &crate::suites::acvp::model::TestCase, name: &str) -> Option<FlexValue> {
    match name {
        "description" => case.description.clone().map(FlexValue::String),
        _ => case.inputs.get(name).cloned(),
    }
}

fn optional_string_metadata<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
    kind: CompanionKind,
) -> Result<Option<&'a str>, String> {
    match object.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(format!("{} {name} must be a string or null", kind.label())),
    }
}

fn optional_bool_metadata(
    object: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    kind: CompanionKind,
) -> Result<Option<bool>, String> {
    match object.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(format!("{} {name} must be a boolean or null", kind.label())),
    }
}

fn validate_companion_metadata(
    companion: &serde_json::Value,
    suite: &TestSuite,
    kind: CompanionKind,
) -> Result<(), String> {
    let object = companion
        .as_object()
        .ok_or_else(|| format!("{} root is not an object", kind.label()))?;
    let vector_set_id = object
        .get("vsId")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{} is missing numeric vsId", kind.label()))?;
    if vector_set_id != suite.suite_name {
        return Err(format!(
            "prompt/{} vsId mismatch: {} != {}",
            kind.label(),
            suite.suite_name,
            vector_set_id
        ));
    }
    let algorithm = object
        .get("algorithm")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{} is missing string algorithm", kind.label()))?;
    if algorithm != suite.algorithm {
        return Err(format!(
            "prompt/{} algorithm mismatch: {:?} != {:?}",
            kind.label(),
            suite.algorithm,
            algorithm
        ));
    }

    let companion_mode = optional_string_metadata(object, "mode", kind)?;
    if companion_mode != suite.mode.as_deref() {
        return Err(format!(
            "prompt/{} mode mismatch: {:?} != {:?}",
            kind.label(),
            suite.mode,
            companion_mode
        ));
    }
    let companion_revision = optional_string_metadata(object, "revision", kind)?;
    if companion_revision != suite.revision.as_deref() {
        return Err(format!(
            "prompt/{} revision mismatch: {:?} != {:?}",
            kind.label(),
            suite.revision,
            companion_revision
        ));
    }
    let companion_sample = optional_bool_metadata(object, "isSample", kind)?;
    if companion_sample != suite.is_sample {
        return Err(format!(
            "prompt/{} isSample mismatch: {:?} != {:?}",
            kind.label(),
            suite.is_sample,
            companion_sample
        ));
    }
    Ok(())
}

/// ----------------------------------------------------------------
/// Get the path to ACVP JSON test vectors
/// ----------------------------------------------------------------
fn acvp_json_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("vectors")
        .join("acvp_json")
}

/// ----------------------------------------------------------------
/// Helper to normalize algorithm names from ACVP format to canonical format
/// Strips "ACVP-" prefix and any leading/trailing hyphens
/// ----------------------------------------------------------------
fn normalize_algorithm(raw: &str) -> String {
    let without_prefix = raw.trim().strip_prefix("ACVP-").unwrap_or(raw);
    without_prefix.trim_matches('-').to_string()
}

/// ----------------------------------------------------------------
/// Normalise individual test-case field names so the crypto backend
/// sees all of the canonical keys it understands (`iv`, `pt`, `ct`, ...)
/// ----------------------------------------------------------------
fn canonicalise_inputs(inputs: &mut HashMap<String, FlexValue>) {
    // --------- IV -------------------------------------------------
    if !inputs.contains_key("iv") {
        if let Some(v) = inputs
            .get("ctr")
            .cloned()
            .or_else(|| inputs.get("nonce").cloned())
        {
            inputs.insert("iv".into(), v);
        }
    }

    // --------- PT / CT --------------------------------------------
    if !inputs.contains_key("pt") {
        if let Some(v) = inputs.get("plaintext").cloned() {
            inputs.insert("pt".into(), v);
        }
    }

    if !inputs.contains_key("ct") {
        if let Some(v) = inputs.get("ciphertext").cloned() {
            inputs.insert("ct".into(), v);
        }
    }

    // --------- Expansion Technique --------------------------------
    // Normalize expansion technique to lowercase for consistent handling
    if let Some(exp_tech) = inputs.get("expansionTechnique") {
        let normalized = exp_tech.as_string().to_lowercase();
        inputs.insert("expansionTechnique".into(), FlexValue::String(normalized));
    }
}

/// ----------------------------------------------------------------
/// Public helper to load a specific suite by name
/// ----------------------------------------------------------------
pub fn load_suite_by_name(suite_name: &str) -> Result<TestSuite, String> {
    let suite_dir = acvp_json_dir().join(suite_name);

    if !suite_dir.exists() {
        return Err(format!(
            "Suite directory not found: {}",
            suite_dir.display()
        ));
    }

    // Load the prompt.json file which contains the test cases
    let prompt_file = suite_dir.join("prompt.json");
    let json = fs::read_to_string(&prompt_file)
        .map_err(|e| format!("Failed to read {}: {}", prompt_file.display(), e))?;

    let mut suite: TestSuite =
        serde_json::from_str(&json).map_err(|e| format!("Failed to parse JSON: {}", e))?;
    merge_expected_results(&suite_dir, &mut suite)?;
    merge_internal_projection(&suite_dir, &mut suite)?;

    // Normalize the suite-level algorithm (strip ACVP- prefix, trailing hyphens)
    let base_alg = normalize_algorithm(&suite.algorithm);
    let mode_part = suite.mode.as_ref().map(|m| normalize_algorithm(m));

    // For algorithms where the *mode* is really the operation (ECDSA, DSA, RSA…)
    // we keep `algorithm` == "ECDSA" and store the mode in `direction`.
    let asymmetric = matches!(base_alg.as_str(), "ECDSA" | "DSA" | "RSA" | "EdDSA");

    let full_algorithm = if asymmetric || mode_part.is_none() {
        base_alg.clone()
    } else {
        let mode = mode_part.as_ref().unwrap();
        // Prevent duplication like "AES-CTR" + "CTR" → "AES-CTR-CTR"
        if base_alg.to_uppercase().ends_with(&mode.to_uppercase()) {
            base_alg.clone()
        } else {
            format!("{}-{}", base_alg, mode)
        }
    };

    // Propagate to groups and normalize all algorithm names
    for group in &mut suite.groups {
        // 1. If the group still has the default placeholder, inject the suite value
        if group.algorithm == "AES-CBC" {
            group.algorithm = full_algorithm.clone();
        }
        // 2. Whatever is there, canonicalize it so the dispatcher sees
        //    "AES-CBC", "AES-CTR", etc. without ACVP- prefix or trailing hyphens
        group.algorithm = normalize_algorithm(&group.algorithm);

        // If this is an asymmetric suite, copy the mode into `direction`
        if asymmetric {
            if let Some(m) = &mode_part {
                // Only overwrite if the JSON didn't already specify a direction
                if group.direction.is_none() || group.direction.as_deref() == Some("") {
                    group.direction = Some(m.clone());
                }
            }
        }

        // 3. Canonicalize the group-level defaults FIRST
        //    This ensures "ctr" → "iv" happens before we copy to test cases
        canonicalise_inputs(&mut group.defaults);

        // 4. Copy canonicalized defaults down to each test case
        //    This handles ACVP's pattern of storing common values (iv, key, etc.) at group level
        for tc in &mut group.tests {
            for (k, v) in &group.defaults {
                tc.inputs.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }

        // 5. Canonicalize the test case inputs (for any case-specific fields)
        for tc in &mut group.tests {
            canonicalise_inputs(&mut tc.inputs);
        }
    }

    Ok(suite)
}

/// ----------------------------------------------------------------
/// Public helper to load all suites (for compatibility)
/// ----------------------------------------------------------------
pub fn load_all_suites() -> Vec<TestSuite> {
    // For now, just load AES-CBC as an example
    vec![load_suite_by_name("ACVP-AES-CBC-1.0").unwrap_or_else(|e| {
        panic!("Failed to load ACVP-AES-CBC-1.0: {}", e);
    })]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn suite(groups: serde_json::Value) -> TestSuite {
        serde_json::from_value(json!({
            "vsId": 1,
            "algorithm": "SHA2-256",
            "testGroups": groups,
        }))
        .expect("test prompt should deserialize")
    }

    fn prompt_group(group_id: u64, case_ids: &[u64]) -> serde_json::Value {
        json!({
            "tgId": group_id,
            "testType": "AFT",
            "tests": case_ids
                .iter()
                .map(|case_id| json!({ "tcId": case_id, "msg": "" }))
                .collect::<Vec<_>>(),
        })
    }

    fn expected_group(group_id: u64, case_ids: &[u64]) -> serde_json::Value {
        json!({
            "tgId": group_id,
            "tests": case_ids
                .iter()
                .map(|case_id| json!({ "tcId": case_id, "md": "00" }))
                .collect::<Vec<_>>(),
        })
    }

    fn companion(groups: serde_json::Value) -> serde_json::Value {
        json!({
            "vsId": 1,
            "algorithm": "SHA2-256",
            "isSample": null,
            "testGroups": groups,
        })
    }

    fn merge_error(prompt_groups: serde_json::Value, expected_groups: serde_json::Value) -> String {
        let mut prompt = suite(prompt_groups);
        merge_expected_value(&companion(expected_groups), &mut prompt)
            .expect_err("malformed identifier sets must be rejected")
    }

    #[test]
    fn expected_results_require_an_exact_unique_group_and_case_join() {
        let mut exact = suite(json!([prompt_group(1, &[1, 2]), prompt_group(2, &[3])]));
        merge_expected_value(
            &companion(json!([expected_group(2, &[3]), expected_group(1, &[2, 1])])),
            &mut exact,
        )
        .expect("array order must not affect the identifier join");
        assert_eq!(
            exact.groups[0].tests[0]
                .expected_output_for_test("md")
                .expect("expected md")
                .as_string(),
            "00"
        );
        assert!(!exact.groups[0].tests[0].inputs.contains_key("md"));

        assert!(merge_error(
            json!([prompt_group(1, &[1]), prompt_group(1, &[2])]),
            json!([expected_group(1, &[1, 2])]),
        )
        .contains("prompt.json contains duplicate tgId 1"));
        assert!(merge_error(
            json!([prompt_group(1, &[1, 1])]),
            json!([expected_group(1, &[1])]),
        )
        .contains("prompt.json contains duplicate tgId 1/tcId 1"));
        assert!(merge_error(
            json!([prompt_group(1, &[1])]),
            json!([expected_group(1, &[1]), expected_group(1, &[1])]),
        )
        .contains("expectedResults.json contains duplicate tgId 1"));
        assert!(merge_error(
            json!([prompt_group(1, &[1])]),
            json!([expected_group(1, &[1, 1])]),
        )
        .contains("expectedResults.json contains duplicate tgId 1/tcId 1"));

        let missing_case = merge_error(
            json!([prompt_group(1, &[1, 2])]),
            json!([expected_group(1, &[1])]),
        );
        assert!(
            missing_case.contains("missing companion [2]"),
            "{missing_case}"
        );
        let unexpected_case = merge_error(
            json!([prompt_group(1, &[1])]),
            json!([expected_group(1, &[1, 2])]),
        );
        assert!(
            unexpected_case.contains("unexpected companion [2]"),
            "{unexpected_case}"
        );
        let missing_group = merge_error(
            json!([prompt_group(1, &[1]), prompt_group(2, &[2])]),
            json!([expected_group(1, &[1])]),
        );
        assert!(
            missing_group.contains("missing companion [2]"),
            "{missing_group}"
        );
    }

    #[test]
    fn companion_root_metadata_is_typed_and_exact() {
        for (field, value, diagnostic) in [
            ("vsId", json!(2), "vsId mismatch"),
            ("algorithm", json!("SHA2-384"), "algorithm mismatch"),
            ("mode", json!(7), "mode must be a string or null"),
            (
                "revision",
                json!(false),
                "revision must be a string or null",
            ),
            (
                "isSample",
                json!("false"),
                "isSample must be a boolean or null",
            ),
        ] {
            let mut expected = companion(json!([expected_group(1, &[1])]));
            expected[field] = value;
            let error = merge_expected_value(&expected, &mut suite(json!([prompt_group(1, &[1])])))
                .expect_err("metadata mutation must fail");
            assert!(error.contains(diagnostic), "{field}: {error}");
        }
    }

    #[test]
    fn projection_cannot_override_prompt_group_or_case_data() {
        let prompt = json!([{
            "tgId": 1,
            "testType": "AFT",
            "curve": "P-256",
            "tests": [{"tcId": 1, "msg": "00"}],
        }]);

        let mut exact = suite(prompt.clone());
        merge_projection_value(
            &companion(json!([{
                "tgId": 1,
                "testType": "AFT",
                "curve": "P-256",
                "replaySecret": "01",
                "tests": [{"tcId": 1, "msg": "00", "nonce": "02"}],
            }])),
            &mut exact,
        )
        .expect("identical duplicated metadata and replay-only values should load");
        assert!(!exact.groups[0].projection.contains_key("curve"));
        assert_eq!(exact.groups[0].projection["replaySecret"].as_string(), "01");
        assert!(!exact.groups[0].tests[0].projection.contains_key("msg"));
        assert_eq!(
            exact.groups[0].tests[0].projection["nonce"].as_string(),
            "02"
        );

        let mut wrong_group = suite(prompt.clone());
        let error = merge_projection_value(
            &companion(json!([{
                "tgId": 1,
                "testType": "AFT",
                "curve": "P-384",
                "tests": [{"tcId": 1, "msg": "00"}],
            }])),
            &mut wrong_group,
        )
        .expect_err("projection group metadata drift must fail");
        assert!(error.contains("tgId 1/curve"), "{error}");

        let mut wrong_case = suite(prompt);
        let error = merge_projection_value(
            &companion(json!([{
                "tgId": 1,
                "testType": "AFT",
                "curve": "P-256",
                "tests": [{"tcId": 1, "msg": "01"}],
            }])),
            &mut wrong_case,
        )
        .expect_err("projection case input drift must fail");
        assert!(error.contains("tgId 1/tcId 1/msg"), "{error}");
    }

    #[test]
    fn validation_requires_an_expected_results_file() {
        let error = merge_expected_results(
            Path::new("/dcrypt-acvp-fixture-that-does-not-exist"),
            &mut suite(json!([prompt_group(1, &[1])])),
        )
        .expect_err("validation without expectedResults.json must fail");
        assert!(error.contains("ACVP validation requires"), "{error}");
    }
}
