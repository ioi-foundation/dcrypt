//! Generic driver that executes a `TestSuite` using a pluggable engine.

use crate::suites::acvp::model::{TestCase, TestGroup, TestSuite};
use std::collections::{BTreeMap, HashMap};

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

/// Machine-readable outcome counts.  In particular, unsupported cases never
/// share the `passed` bucket and every skip reason is retained with a count.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct RunSummary {
    pub total: usize,
    pub passed: usize,
    pub generated: usize,
    pub skipped: usize,
    pub failed: usize,
    pub skip_reasons: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct RunReport {
    pub summary: RunSummary,
    pub cases: Vec<CaseOutcome>,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CaseStatus {
    Passed,
    Skipped,
    Failed,
}

/// Stable per-case evidence.  Aggregate counts alone cannot show that a skip
/// moved from one parameter set or operation to another.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CaseOutcome {
    pub group_id: u64,
    pub case_id: u64,
    pub algorithm: String,
    pub direction: String,
    pub test_type: String,
    pub status: CaseStatus,
    pub detail: Option<String>,
}

impl RunReport {
    pub fn require_success(self) -> Result<(), String> {
        if self.summary.total == 0 {
            Err("ACVP suite contains no test cases".into())
        } else if self.summary.passed == 0
            && self.summary.generated == 0
            && self.summary.failed == 0
        {
            Err("ACVP suite executed no supported or response-generation cases".into())
        } else if self.summary.failed > 0 {
            Err(format!("{} tests failed", self.summary.failed))
        } else {
            Ok(())
        }
    }
}

impl<'e, E: AcvpEngine> Runner<'e, E> {
    pub fn new(engine: &'e E) -> Self {
        Self { engine }
    }

    pub fn run_suite(&self, suite: &TestSuite) -> Result<(), String> {
        self.run_suite_report(suite).require_success()
    }

    pub fn run_suite_report(&self, suite: &TestSuite) -> RunReport {
        let mut report = RunReport::default();
        let mut results = HashMap::new(); // Collect results for response generation

        for group in &suite.groups {
            group.reset_evidence();
            println!(
                "Running group {}: {} - {} ({})",
                group.group_name,
                group.algorithm,
                group.direction.as_deref().unwrap_or(&group.test_type),
                group.test_type
            );

            let mut group_results = Vec::new();
            let mut group_executed = 0usize;

            for case in &group.tests {
                report.summary.total += 1;
                case.reset_evidence();
                let res = self.engine.run(group, case);
                let skip_reason = case.outputs.borrow_mut().remove(SKIP_MARKER);

                match res {
                    Ok(()) => {
                        if let Some(reason) = skip_reason {
                            if reason.trim().is_empty() {
                                let detail =
                                    "handler supplied an empty ACVP skip reason".to_string();
                                report.summary.failed += 1;
                                report.failures.push(format!(
                                    "tgId {}/tcId {} handler failure: {detail}",
                                    group.group_name, case.test_id
                                ));
                                report.cases.push(case_outcome(
                                    group,
                                    case,
                                    CaseStatus::Failed,
                                    Some(detail.clone()),
                                ));
                                eprintln!("Case {} failed: {}", case.test_id, detail);
                                continue;
                            }
                            report.summary.skipped += 1;
                            *report
                                .summary
                                .skip_reasons
                                .entry(reason.clone())
                                .or_default() += 1;
                            println!("Case {} skipped: {}", case.test_id, reason);
                            report.cases.push(case_outcome(
                                group,
                                case,
                                CaseStatus::Skipped,
                                Some(reason),
                            ));
                            continue;
                        }
                        group_executed += 1;
                        match case.validate_outputs() {
                            Ok(()) => {
                                report.summary.passed += 1;
                                report.cases.push(case_outcome(
                                    group,
                                    case,
                                    CaseStatus::Passed,
                                    None,
                                ));
                                if !case.outputs.borrow().is_empty() {
                                    group_results
                                        .push((case.test_id, case.outputs.borrow().clone()));
                                }
                            }
                            Err(error) => {
                                report.summary.failed += 1;
                                report.cases.push(case_outcome(
                                    group,
                                    case,
                                    CaseStatus::Failed,
                                    Some(error.clone()),
                                ));
                                report.failures.push(format!(
                                    "tgId {}/tcId {}: {error}",
                                    group.group_name, case.test_id
                                ));
                                eprintln!("Case {} evidence failure: {}", case.test_id, error);
                            }
                        }
                    }
                    Err(e) => {
                        report.summary.failed += 1;
                        let detail = if let Some(reason) = skip_reason {
                            format!("{e} (handler also attempted to skip: {reason})")
                        } else {
                            e
                        };
                        report.failures.push(format!(
                            "tgId {}/tcId {} handler failure: {detail}",
                            group.group_name, case.test_id
                        ));
                        report.cases.push(case_outcome(
                            group,
                            case,
                            CaseStatus::Failed,
                            Some(detail.clone()),
                        ));
                        eprintln!("Case {} failed: {}", case.test_id, detail);
                    }
                }
            }

            if group_executed > 0 {
                if let Err(error) = group.validate_outputs() {
                    report.summary.failed += 1;
                    report
                        .failures
                        .push(format!("tgId {} group evidence: {error}", group.group_name));
                    eprintln!("Group {} evidence failure: {}", group.group_name, error);
                }
            }

            if !group_results.is_empty() {
                results.insert(group.group_name, group_results);
            }
        }

        println!(
            "Test results: {} passed, {} generated, {} skipped, {} failed",
            report.summary.passed,
            report.summary.generated,
            report.summary.skipped,
            report.summary.failed
        );

        // If we collected results, we could serialize them here for ACVP response
        if !results.is_empty() {
            println!(
                "Collected {} groups of results for response generation",
                results.len()
            );
            // In a real implementation, serialize to ACVP response format
        }

        report
    }
}

fn case_outcome(
    group: &TestGroup,
    case: &TestCase,
    status: CaseStatus,
    detail: Option<String>,
) -> CaseOutcome {
    CaseOutcome {
        group_id: group.group_name,
        case_id: case.test_id,
        algorithm: group.algorithm.clone(),
        direction: group
            .direction
            .clone()
            .unwrap_or_else(|| group.test_type.clone()),
        test_type: group.test_type.clone(),
        status,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoEvidence;

    impl AcvpEngine for NoEvidence {
        fn run(&self, _group: &TestGroup, _case: &TestCase) -> Result<(), String> {
            Ok(())
        }
    }

    struct Unsupported;

    impl AcvpEngine for Unsupported {
        fn run(&self, _group: &TestGroup, case: &TestCase) -> Result<(), String> {
            case.mark_skipped("fixture capability is unsupported");
            Ok(())
        }
    }

    struct SkipThenError;

    impl AcvpEngine for SkipThenError {
        fn run(&self, _group: &TestGroup, case: &TestCase) -> Result<(), String> {
            case.mark_skipped("must not mask error");
            Err("fixture internal failure".into())
        }
    }

    struct EmptySkip;

    impl AcvpEngine for EmptySkip {
        fn run(&self, _group: &TestGroup, case: &TestCase) -> Result<(), String> {
            case.mark_skipped("  ");
            Ok(())
        }
    }

    fn one_case_suite() -> TestSuite {
        serde_json::from_value(serde_json::json!({
            "vsId": 1,
            "algorithm": "fixture",
            "testGroups": [{
                "tgId": 1,
                "testType": "AFT",
                "tests": [{"tcId": 1, "input": "00"}]
            }]
        }))
        .expect("fixture should deserialize")
    }

    #[test]
    fn ok_without_comparison_is_not_a_pass() {
        let mut suite = one_case_suite();
        suite.groups[0].tests[0].insert_expected_output(
            "output".into(),
            crate::suites::acvp::model::FlexValue::String("00".into()),
        );

        let error = Runner::new(&NoEvidence)
            .run_suite(&suite)
            .expect_err("Ok alone must not pass");
        assert!(error.contains("1 tests failed"));
    }

    #[test]
    fn unsupported_is_counted_and_explained_separately() {
        let report = Runner::new(&Unsupported).run_suite_report(&one_case_suite());
        assert_eq!(report.summary.passed, 0);
        assert_eq!(report.summary.skipped, 1);
        assert_eq!(
            report.summary.skip_reasons["fixture capability is unsupported"],
            1
        );
        assert_eq!(
            report.require_success().unwrap_err(),
            "ACVP suite executed no supported or response-generation cases"
        );
    }

    #[test]
    fn an_error_cannot_be_masked_by_a_skip_marker() {
        let report = Runner::new(&SkipThenError).run_suite_report(&one_case_suite());
        assert_eq!(report.summary.skipped, 0);
        assert_eq!(report.summary.failed, 1);
        assert!(report.failures[0].contains("fixture internal failure"));
        assert!(report.failures[0].contains("attempted to skip"));
    }

    #[test]
    fn an_empty_skip_reason_is_a_failure() {
        let report = Runner::new(&EmptySkip).run_suite_report(&one_case_suite());
        assert_eq!(report.summary.skipped, 0);
        assert_eq!(report.summary.failed, 1);
        assert!(report.failures[0].contains("empty ACVP skip reason"));
    }

    #[test]
    fn every_supported_expected_value_kind_is_fail_closed() {
        use crate::suites::acvp::model::{expected_matches, FlexValue};
        assert!(expected_matches(&FlexValue::String("A0ff".into()), "a0FF"));
        assert!(!expected_matches(&FlexValue::String("A0ff".into()), "a0FE"));
        assert!(expected_matches(&FlexValue::Bool(false), "false"));
        assert!(!expected_matches(&FlexValue::Bool(false), "true"));
        assert!(expected_matches(
            &FlexValue::Array(vec![FlexValue::Number(1.into())]),
            "[1]"
        ));
    }
}
