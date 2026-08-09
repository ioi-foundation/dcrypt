//! Loads ACVP test vectors from JSON files.

use crate::suites::acvp::model::{FlexValue, TestSuite};
use std::collections::HashMap;
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
        return Ok(());
    }
    let json = fs::read_to_string(&expected_file)
        .map_err(|error| format!("Failed to read {}: {}", expected_file.display(), error))?;
    let expected: serde_json::Value = serde_json::from_str(&json)
        .map_err(|error| format!("Failed to parse {}: {}", expected_file.display(), error))?;
    let groups = expected
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
                case.inputs.insert(name.clone(), value);
            }
        }
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
