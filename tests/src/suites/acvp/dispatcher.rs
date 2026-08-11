//! Extensible dispatcher for ACVP algorithm handlers

use once_cell::sync::Lazy;
use std::collections::HashMap;

use super::error::Result;
use super::model::{TestCase, TestGroup};

/// Registry key for looking up handlers
#[derive(Hash, Eq, PartialEq, Debug, Clone)]
pub struct DispatchKey {
    pub algo: String,
    pub dir: String, // "function" from ACVP JSON (e.g., "encapsulation", "decapsulation")
    pub kind: String, // "testType" from ACVP JSON (e.g., "AFT")
}

/// Handler function type
pub type HandlerFn = fn(&TestGroup, &TestCase) -> Result<()>;

/// Global registry of algorithm handlers
pub static REGISTRY: Lazy<HashMap<DispatchKey, HandlerFn>> = Lazy::new(|| {
    let mut m = HashMap::<DispatchKey, HandlerFn>::new();

    // Register all algorithm modules
    super::algorithms::aes_cbc::register(&mut m);
    super::algorithms::aes_ctr::register(&mut m);
    super::algorithms::aes_gcm::register(&mut m);
    super::algorithms::ecdsa::register(&mut m);
    super::algorithms::ml_kem::register(&mut m);
    super::algorithms::ml_dsa::register(&mut m);
    super::algorithms::eddsa::register(&mut m);
    super::algorithms::sha2::register(&mut m);
    super::algorithms::sha3::register(&mut m);
    super::algorithms::shake::register(&mut m);
    super::algorithms::hmac::register(&mut m);
    super::algorithms::hkdf::register(&mut m);
    super::algorithms::pbkdf2::register(&mut m);
    super::algorithms::ecdh::register(&mut m);
    m
});

/// Helper function for registering handlers
pub fn insert(
    map: &mut HashMap<DispatchKey, HandlerFn>,
    algo: &str, // e.g., "ML-KEM", "AES-CBC"
    dir: &str,  // Corresponds to "function" or "direction"
    kind: &str, // Corresponds to "testType" like "AFT", "MCT"
    handler: HandlerFn,
) {
    let key = DispatchKey {
        algo: algo.to_string(),
        dir: dir.to_string(),
        kind: kind.to_string(),
    };
    assert!(
        map.insert(key.clone(), handler).is_none(),
        "duplicate ACVP handler registration for {key:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(_group: &TestGroup, _case: &TestCase) -> Result<()> {
        Ok(())
    }

    #[test]
    #[should_panic(expected = "duplicate ACVP handler registration")]
    fn duplicate_registration_is_fatal() {
        let mut handlers = HashMap::new();
        insert(&mut handlers, "fixture", "verify", "AFT", fixture);
        insert(&mut handlers, "fixture", "verify", "AFT", fixture);
    }
}
