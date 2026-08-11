//! Pure data model for ACVP-style test vectors.
//! No dependency on the rest of the framework.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;

/// Flexible value that can be either string, number, bool, array, object, or null
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum FlexValue {
    String(String),
    Number(serde_json::Number),
    Bool(bool),
    Array(Vec<FlexValue>),
    Object(HashMap<String, FlexValue>),
    Null,
}

impl FlexValue {
    pub fn as_string(&self) -> String {
        match self {
            FlexValue::String(s) => s.clone(),
            FlexValue::Number(n) => n.to_string(),
            FlexValue::Bool(b) => b.to_string(),
            FlexValue::Array(arr) => {
                serde_json::to_string(arr).unwrap_or_else(|_| format!("{:?}", arr))
            }
            FlexValue::Object(obj) => {
                serde_json::to_string(obj).unwrap_or_else(|_| format!("{:?}", obj))
            }
            FlexValue::Null => String::new(),
        }
    }
}

/// ----------------------------------------------------------------
/// 1. Leaf-level test case
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestCase {
    #[serde(rename = "tcId")]
    pub test_id: u64,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(flatten)]
    pub inputs: HashMap<String, FlexValue>,
    /// Fields from `expectedResults.json`.  These deliberately do not share a
    /// namespace with prompt inputs: an expected value must never become an
    /// input merely because it has the same field name.
    #[serde(skip)]
    expected_outputs: HashMap<String, FlexValue>,
    /// Non-public replay material from `internalProjection.json`.
    #[serde(skip)]
    pub projection: HashMap<String, FlexValue>,
    #[serde(skip)]
    pub outputs: RefCell<HashMap<String, String>>,
}

impl TestCase {
    pub(crate) fn insert_expected_output(&mut self, name: String, value: FlexValue) {
        self.expected_outputs.insert(name, value);
    }

    pub(crate) fn validate_outputs(&self) -> Result<(), String> {
        validate_expected_fields(&self.expected_outputs, &self.outputs.borrow(), true)
    }

    /// Deliberately corrupt one oracle field for integration-level fail-closed
    /// tests without exposing oracle values to algorithm handlers.
    #[doc(hidden)]
    pub fn corrupt_expected_for_test(&mut self, name: &str) -> Result<(), String> {
        let value = self
            .expected_outputs
            .get_mut(name)
            .ok_or_else(|| format!("missing expected field {name}"))?;
        corrupt_value(value);
        Ok(())
    }

    #[doc(hidden)]
    pub fn remove_expected_for_test(&mut self, name: &str) -> bool {
        self.expected_outputs.remove(name).is_some()
    }

    #[doc(hidden)]
    pub fn add_expected_for_test(&mut self, name: &str) -> bool {
        self.expected_outputs
            .insert(name.into(), FlexValue::Null)
            .is_none()
    }

    #[cfg(test)]
    pub(crate) fn expected_output_for_test(&self, name: &str) -> Option<&FlexValue> {
        self.expected_outputs.get(name)
    }

    pub fn mark_skipped(&self, reason: impl Into<String>) {
        self.outputs
            .borrow_mut()
            .insert("__acvp_skip".into(), reason.into());
    }

    pub fn reset_evidence(&self) {
        self.outputs.borrow_mut().clear();
    }
}

/// ----------------------------------------------------------------
/// 2. Groups (ACVP terminology) – often share parameters
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestGroup {
    #[serde(rename = "tgId")]
    pub group_name: u64,
    #[serde(rename = "testType")]
    pub test_type: String, // AFT / MCT / ...
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub direction: Option<String>, // encrypt / decrypt
    #[serde(default)]
    pub key_len: Option<u32>,
    #[serde(default)]
    pub params: Option<serde_json::Value>,

    /// Any other ACVP fields (iv, ctr, nonce, key, payloadLen, ...)
    /// These are group-level defaults that apply to all test cases
    #[serde(flatten)]
    pub defaults: HashMap<String, FlexValue>,

    /// Group-level response fields from `expectedResults.json`.
    #[serde(skip)]
    expected_outputs: HashMap<String, FlexValue>,
    /// Group-level replay material from `internalProjection.json`.
    #[serde(skip)]
    pub projection: HashMap<String, FlexValue>,
    #[serde(skip)]
    pub outputs: RefCell<HashMap<String, String>>,

    pub tests: Vec<TestCase>,
}

impl TestGroup {
    pub(crate) fn insert_expected_output(&mut self, name: String, value: FlexValue) {
        self.expected_outputs.insert(name, value);
    }

    pub(crate) fn validate_outputs(&self) -> Result<(), String> {
        validate_expected_fields(&self.expected_outputs, &self.outputs.borrow(), false)
    }

    #[doc(hidden)]
    pub fn corrupt_expected_for_test(&mut self, name: &str) -> Result<(), String> {
        let value = self
            .expected_outputs
            .get_mut(name)
            .ok_or_else(|| format!("missing expected group field {name}"))?;
        corrupt_value(value);
        Ok(())
    }

    #[doc(hidden)]
    pub fn remove_expected_for_test(&mut self, name: &str) -> bool {
        self.expected_outputs.remove(name).is_some()
    }

    #[doc(hidden)]
    pub fn add_expected_for_test(&mut self, name: &str) -> bool {
        self.expected_outputs
            .insert(name.into(), FlexValue::Null)
            .is_none()
    }

    pub fn reset_evidence(&self) {
        self.outputs.borrow_mut().clear();
    }
}

fn validate_expected_fields(
    expected: &HashMap<String, FlexValue>,
    actual: &HashMap<String, String>,
    require_nonempty: bool,
) -> Result<(), String> {
    if require_nonempty && expected.is_empty() {
        return Err("handler returned success without any expected result fields".into());
    }

    for name in actual.keys() {
        if !expected.contains_key(name) {
            return Err(format!("handler produced unexpected field {name}"));
        }
    }
    for (name, wanted) in expected {
        let got = actual
            .get(name)
            .ok_or_else(|| format!("expected field {name} was not compared"))?;
        if !expected_matches(wanted, got) {
            return Err(format!(
                "expected field {name} mismatch: expected {}, got {got}",
                wanted.as_string()
            ));
        }
    }
    Ok(())
}

pub(crate) fn expected_matches(expected: &FlexValue, actual: &str) -> bool {
    match expected {
        FlexValue::String(wanted) => {
            if is_hex(wanted) && is_hex(actual) {
                wanted.eq_ignore_ascii_case(actual)
            } else {
                wanted == actual
            }
        }
        FlexValue::Number(wanted) => wanted.to_string() == actual,
        FlexValue::Bool(wanted) => actual.parse::<bool>().ok() == Some(*wanted),
        FlexValue::Array(_) | FlexValue::Object(_) => {
            let Ok(actual) = serde_json::from_str::<serde_json::Value>(actual) else {
                return false;
            };
            serde_json::to_value(expected).ok().as_ref() == Some(&actual)
        }
        FlexValue::Null => actual.is_empty() || actual == "null",
    }
}

fn is_hex(value: &str) -> bool {
    !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn corrupt_value(value: &mut FlexValue) {
    match value {
        FlexValue::String(value) => {
            if value.is_empty() {
                value.push_str("00");
            } else {
                let replacement = if value.as_bytes()[0] == b'0' {
                    '1'
                } else {
                    '0'
                };
                value.replace_range(..1, &replacement.to_string());
            }
        }
        FlexValue::Number(value) => {
            *value = value.as_u64().unwrap_or_default().saturating_add(1).into();
        }
        FlexValue::Bool(value) => *value = !*value,
        FlexValue::Array(values) => {
            if let Some(first) = values.first_mut() {
                corrupt_value(first);
            } else {
                values.push(FlexValue::Null);
            }
        }
        FlexValue::Object(values) => {
            if let Some(key) = values.keys().min().cloned() {
                corrupt_value(values.get_mut(&key).expect("selected object key exists"));
            } else {
                values.insert("mutated".into(), FlexValue::Null);
            }
        }
        FlexValue::Null => *value = FlexValue::String("not-null".into()),
    }
}

fn default_algorithm() -> String {
    "AES-CBC".into()
}

/// ----------------------------------------------------------------
/// 3. Vector set info
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorSetInfo {
    pub vector_set_id: u64,
    pub algorithm: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub revision: Option<String>,
}

/// ----------------------------------------------------------------
/// 4. Whole suite (file) – ACVP JSON format
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestSuite {
    #[serde(rename = "vsId")]
    pub suite_name: u64,
    #[serde(default = "default_suite_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub mode: Option<String>, // Added mode field to capture ACVP mode
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default)]
    pub is_sample: Option<bool>,
    #[serde(rename = "testGroups")]
    pub groups: Vec<TestGroup>,
}

fn default_suite_algorithm() -> String {
    "AES-CBC".into()
}

/// ----------------------------------------------------------------
/// 5. Build-time stub emitted by build.rs (not used for now)
/// ----------------------------------------------------------------
#[derive(Debug, Deserialize)]
pub struct SuiteMeta {
    pub algorithm: String,
    pub operation: String,
    pub manifest: String,   // directory that holds JSON files
    pub files: Vec<String>, // typically 4 JSON files
}
