//! Generic driver that executes a `TestSuite` using a pluggable engine.

use crate::suites::acvp::model::{TestCase, TestGroup, TestSuite};
use std::collections::HashMap;

/// Internal output marker used by handlers for vector groups that the safe
/// public API intentionally does not support.
pub(crate) const SKIP_MARKER: &str = "__acvp_skip";

/// Trait every crypto back-end must implement.
pub trait AcvpEngine {
    /// Execute one test case and return `Ok(())` on success.
    fn run(&self, group: &TestGroup, case: &TestCase) -> Result<(), String>;
}

/// Thin wrapper that walks suites and tallies results.
pub struct Runner<'e, E: AcvpEngine> {
    engine: &'e E,
}

impl<'e, E: AcvpEngine> Runner<'e, E> {
    pub fn new(engine: &'e E) -> Self {
        Self { engine }
    }

    pub fn run_suite(&self, suite: &TestSuite) -> Result<(), String> {
        let mut passed = 0;
        let mut failed = 0;
        let mut skipped = 0;
        let mut results = HashMap::new(); // Collect results for response generation

        for group in &suite.groups {
            println!(
                "Running group {}: {} - {} ({})",
                group.group_name,
                group.algorithm,
                group.direction.as_deref().unwrap_or(&group.test_type),
                group.test_type
            );

            let mut group_results = Vec::new();

            for case in &group.tests {
                let res = self.engine.run(group, case);
                let expected = case.expected_result.as_str();

                if let Some(reason) = case.outputs.borrow_mut().remove(SKIP_MARKER) {
                    skipped += 1;
                    println!("Case {} skipped: {}", case.test_id, reason);
                    continue;
                }

                match (res, expected) {
                    (Ok(()), "valid") => {
                        passed += 1;

                        // Collect any generated outputs
                        if !case.outputs.borrow().is_empty() {
                            group_results.push((case.test_id, case.outputs.borrow().clone()));
                        }
                    }
                    (Err(_), "invalid") => {
                        passed += 1;
                    }
                    (Err(_), "fail") => {
                        passed += 1;
                    }
                    (Ok(()), _) => {
                        failed += 1;
                        eprintln!("Case {} succeeded but expected {}", case.test_id, expected);
                    }
                    (Err(e), _) => {
                        failed += 1;
                        eprintln!("Case {} failed: {}", case.test_id, e);
                    }
                }
            }

            if !group_results.is_empty() {
                results.insert(group.group_name, group_results);
            }
        }

        println!(
            "Test results: {} passed, {} skipped, {} failed",
            passed, skipped, failed
        );

        // If we collected results, we could serialize them here for ACVP response
        if !results.is_empty() {
            println!(
                "Collected {} groups of results for response generation",
                results.len()
            );
            // In a real implementation, serialize to ACVP response format
        }

        if failed > 0 {
            Err(format!("{} tests failed", failed))
        } else {
            Ok(())
        }
    }
}
