// tests/acvp_tests.rs
use dcrypt_tests::suites::acvp::{
    engine::DcryptEngine,
    loader,
    model::{FlexValue, TestSuite},
    runner::{CaseStatus, RunReport, Runner},
};
use std::collections::BTreeMap;

fn run_report(suite: &TestSuite) -> RunReport {
    Runner::new(&DcryptEngine).run_suite_report(suite)
}

fn assert_counts(
    report: &RunReport,
    total: usize,
    passed: usize,
    skipped: usize,
    skip_reason_total: usize,
) {
    assert_eq!(report.summary.total, total);
    assert_eq!(report.summary.passed, passed);
    assert_eq!(report.summary.generated, 0);
    assert_eq!(report.summary.skipped, skipped);
    assert_eq!(report.summary.failed, 0, "{:?}", report.failures);
    assert_eq!(report.cases.len(), total);
    assert!(report.cases.iter().all(|case| {
        case.status != CaseStatus::Skipped
            || case
                .detail
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty())
    }));
    assert_eq!(
        report.summary.skip_reasons.values().sum::<usize>(),
        skip_reason_total
    );
}

fn assert_group_counts(report: &RunReport, expected: &[(u64, usize, usize)]) {
    let mut actual = BTreeMap::<u64, (usize, usize)>::new();
    for case in &report.cases {
        let counts = actual.entry(case.group_id).or_default();
        match case.status {
            CaseStatus::Passed => counts.0 += 1,
            CaseStatus::Skipped => counts.1 += 1,
            CaseStatus::Failed => panic!("unexpected failed case: {case:?}"),
        }
    }
    assert_eq!(
        actual,
        expected
            .iter()
            .copied()
            .map(|(g, p, s)| (g, (p, s)))
            .collect()
    );
}

fn assert_all_groups_skipped(report: &RunReport, first: u64, last: u64) {
    let mut groups = BTreeMap::<u64, usize>::new();
    for case in &report.cases {
        assert_eq!(case.status, CaseStatus::Skipped, "{case:?}");
        *groups.entry(case.group_id).or_default() += 1;
    }
    assert_eq!(
        groups.keys().copied().collect::<Vec<_>>(),
        (first..=last).collect::<Vec<_>>()
    );
    assert!(groups.values().all(|count| *count > 0));
}

fn isolate_case(suite: &mut TestSuite, group_id: u64, case_id: u64) {
    suite.groups.retain(|group| group.group_name == group_id);
    assert_eq!(suite.groups.len(), 1, "missing tgId {group_id}");
    suite.groups[0].tests.retain(|case| case.test_id == case_id);
    assert_eq!(
        suite.groups[0].tests.len(),
        1,
        "missing tgId {group_id}/tcId {case_id}"
    );
}

fn assert_case_mutation_fails(suite_name: &str, group_id: u64, case_id: u64, field: &str) {
    let mut suite = loader::load_suite_by_name(suite_name)
        .unwrap_or_else(|error| panic!("failed to load {suite_name}: {error}"));
    isolate_case(&mut suite, group_id, case_id);
    suite.groups[0].tests[0]
        .corrupt_expected_for_test(field)
        .unwrap_or_else(|_| panic!("{suite_name} tgId {group_id}/tcId {case_id} lacks {field}"));
    let report = run_report(&suite);
    assert_eq!(report.summary.passed, 0);
    assert!(
        report.summary.failed > 0,
        "mutated {suite_name} tgId {group_id}/tcId {case_id}/{field} did not fail"
    );
}

fn assert_case_deletion_fails(suite_name: &str, group_id: u64, case_id: u64, field: &str) {
    let mut suite = loader::load_suite_by_name(suite_name)
        .unwrap_or_else(|error| panic!("failed to load {suite_name}: {error}"));
    isolate_case(&mut suite, group_id, case_id);
    assert!(
        suite.groups[0].tests[0].remove_expected_for_test(field),
        "{suite_name} tgId {group_id}/tcId {case_id} lacks {field}"
    );
    let report = run_report(&suite);
    assert_eq!(report.summary.passed, 0);
    assert!(
        report.summary.failed > 0,
        "deleted {suite_name} tgId {group_id}/tcId {case_id}/{field} did not fail"
    );
}

fn assert_group_mutation_fails(suite_name: &str, group_id: u64, case_id: u64, field: &str) {
    let mut suite = loader::load_suite_by_name(suite_name)
        .unwrap_or_else(|error| panic!("failed to load {suite_name}: {error}"));
    isolate_case(&mut suite, group_id, case_id);
    suite.groups[0]
        .corrupt_expected_for_test(field)
        .unwrap_or_else(|_| panic!("{suite_name} tgId {group_id} lacks {field}"));
    let report = run_report(&suite);
    assert!(
        report.summary.failed > 0,
        "mutated {suite_name} tgId {group_id}/{field} did not fail"
    );
}

fn assert_group_deletion_fails(suite_name: &str, group_id: u64, case_id: u64, field: &str) {
    let mut suite = loader::load_suite_by_name(suite_name)
        .unwrap_or_else(|error| panic!("failed to load {suite_name}: {error}"));
    isolate_case(&mut suite, group_id, case_id);
    assert!(suite.groups[0].remove_expected_for_test(field));
    let report = run_report(&suite);
    assert!(
        report.summary.failed > 0,
        "deleted {suite_name} tgId {group_id}/{field} did not fail"
    );
}

#[test]
fn test_aes_cbc_acvp() {
    let suite = loader::load_suite_by_name("ACVP-AES-CBC-1.0")
        .expect("Failed to load ACVP-AES-CBC-1.0 suite");

    println!("Running ACVP test suite: {}", suite.suite_name);
    let report = run_report(&suite);
    assert_counts(&report, 2_156, 2_150, 6, 6);
    let mut groups = Vec::new();
    for group in &suite.groups {
        let count = group.tests.len();
        groups.push(if group.group_name >= 37 {
            (group.group_name, 0, count)
        } else {
            (group.group_name, count, 0)
        });
    }
    assert_group_counts(&report, &groups);
    report.require_success().expect("ACVP tests failed");
}

#[test]
fn test_aes_ctr_acvp() {
    let suite = loader::load_suite_by_name("ACVP-AES-CTR-1.0")
        .expect("Failed to load ACVP-AES-CTR-1.0 suite");

    // DEBUG: Print what's actually in the group defaults
    // println!("DEBUG ▶ first-group defaults = {:#?}", suite.groups[0].defaults);

    // DEBUG: Print what's in the first test case
    // println!("DEBUG ▶ first test raw = {:#?}", suite.groups[0].tests[0].inputs);

    println!("Running ACVP test suite: {}", suite.suite_name);
    let report = run_report(&suite);
    assert_counts(&report, 150, 150, 0, 0);
    report.require_success().expect("ACVP tests failed");
}

#[test]
fn test_aes_gcm_acvp() {
    let suite = loader::load_suite_by_name("ACVP-AES-GCM-1.0")
        .expect("Failed to load ACVP-AES-GCM-1.0 suite");

    println!("Running ACVP test suite: {}", suite.suite_name);
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     if let Some(direction) = &first_group.direction {
    //         println!("First group direction: {}", direction);
    //     }

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    // Run the test suite
    let report = run_report(&suite);
    assert_counts(&report, 60, 30, 30, 30);
    assert_group_counts(&report, &[(1, 15, 0), (2, 0, 15), (3, 15, 0), (4, 0, 15)]);
    report.require_success().expect("ACVP GCM tests failed");
}

#[test]
fn test_sha256_acvp() {
    let suite =
        loader::load_suite_by_name("SHA2-256-1.0").expect("Failed to load SHA2-256-1.0 suite");

    println!("Running ACVP test suite: {}", suite.suite_name);
    let report = run_report(&suite);
    assert_counts(&report, 517, 516, 1, 1);
    assert_group_counts(&report, &[(1, 512, 0), (2, 0, 1), (3, 4, 0)]);
    report.require_success().expect("SHA-256 ACVP tests failed");
}

#[test]
fn test_sha224_acvp() {
    let suite =
        loader::load_suite_by_name("SHA2-224-1.0").expect("Failed to load SHA2-224-1.0 suite");

    println!("Running ACVP test suite: {}", suite.suite_name);
    let report = run_report(&suite);
    assert_counts(&report, 517, 516, 1, 1);
    assert_group_counts(&report, &[(1, 512, 0), (2, 0, 1), (3, 4, 0)]);
    report.require_success().expect("SHA-224 ACVP tests failed");
}

#[test]
fn test_sha384_acvp() {
    let suite =
        loader::load_suite_by_name("SHA2-384-1.0").expect("Failed to load SHA2-384-1.0 suite");

    println!("Running ACVP test suite: {}", suite.suite_name);
    let report = run_report(&suite);
    assert_counts(&report, 1_029, 1_028, 1, 1);
    assert_group_counts(&report, &[(1, 1_024, 0), (2, 0, 1), (3, 4, 0)]);
    report.require_success().expect("SHA-384 ACVP tests failed");
}

#[test]
fn test_sha512_acvp() {
    let suite =
        loader::load_suite_by_name("SHA2-512-1.0").expect("Failed to load SHA2-512-1.0 suite");

    println!("Running ACVP test suite: {}", suite.suite_name);
    let report = run_report(&suite);
    assert_counts(&report, 1_029, 1_028, 1, 1);
    assert_group_counts(&report, &[(1, 1_024, 0), (2, 0, 1), (3, 4, 0)]);
    report.require_success().expect("SHA-512 ACVP tests failed");
}

#[test]
fn test_sha512_224_acvp() {
    let suite = loader::load_suite_by_name("SHA2-512-224-1.0")
        .expect("Failed to load SHA2-512-224-1.0 suite");

    println!("Running ACVP test suite: {}", suite.suite_name);
    let report = run_report(&suite);
    assert_counts(&report, 1_029, 1_028, 1, 1);
    assert_group_counts(&report, &[(1, 1_024, 0), (2, 0, 1), (3, 4, 0)]);
    report
        .require_success()
        .expect("SHA-512/224 ACVP tests failed");
}

#[test]
fn test_sha512_256_acvp() {
    let suite = loader::load_suite_by_name("SHA2-512-256-1.0")
        .expect("Failed to load SHA2-512-256-1.0 suite");

    println!("Running ACVP test suite: {}", suite.suite_name);
    let report = run_report(&suite);
    assert_counts(&report, 1_029, 1_028, 1, 1);
    assert_group_counts(&report, &[(1, 1_024, 0), (2, 0, 1), (3, 4, 0)]);
    report
        .require_success()
        .expect("SHA-512/256 ACVP tests failed");
}

// Add these test functions to tests/tests/acvp_tests.rs

#[test]
fn test_sha3_224_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHA3-224-2.0").expect("Failed to load SHA3-224-2.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA3-224 ACVP tests failed");
}

#[test]
fn test_sha3_256_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHA3-256-2.0").expect("Failed to load SHA3-256-2.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA3-256 ACVP tests failed");
}

// Note: SHA3-384 and SHA3-512 ACVP test vectors are not available in the test vector directory.
// The SHA3-384 and SHA3-512 implementations are tested via the NIST test vectors in the unit tests.
// If ACVP test vectors for these variants become available, uncomment the tests below:

// #[test]
// #[ignore = "ACVP test vectors not available"]
// fn test_sha3_384_acvp() {
//     let engine = DcryptEngine;
//     let suite = loader::load_suite_by_name("SHA3-384-2.0")
//         .expect("Failed to load SHA3-384-2.0 suite");
//
//     let r = Runner::new(&engine);
//
//     println!("Running ACVP test suite: {}", suite.suite_name);
//     r.run_suite(&suite).expect("SHA3-384 ACVP tests failed");
// }

// #[test]
// #[ignore = "ACVP test vectors not available"]
// fn test_sha3_512_acvp() {
//     let engine = DcryptEngine;
//     let suite = loader::load_suite_by_name("SHA3-512-2.0")
//         .expect("Failed to load SHA3-512-2.0 suite");
//
//     let r = Runner::new(&engine);
//
//     println!("Running ACVP test suite: {}", suite.suite_name);
//     r.run_suite(&suite).expect("SHA3-512 ACVP tests failed");
// }

#[test]
fn test_shake128_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHAKE-128-1.0").expect("Failed to load SHAKE-128-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHAKE-128 ACVP tests failed");
}

#[test]
fn test_shake256_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHAKE-256-1.0").expect("Failed to load SHAKE-256-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHAKE-256 ACVP tests failed");
}

#[test]
fn test_hmac_sha256_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HMAC-SHA2-256-1.0")
        .expect("Failed to load HMAC-SHA2-256-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HMAC-SHA2-256");
    r.run_suite(&suite)
        .expect("HMAC-SHA2-256 ACVP tests failed");
}

#[test]
fn test_hmac_sha384_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HMAC-SHA2-384-1.0")
        .expect("Failed to load HMAC-SHA2-384-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HMAC-SHA2-384");
    r.run_suite(&suite)
        .expect("HMAC-SHA2-384 ACVP tests failed");
}

#[test]
fn test_hmac_sha512_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HMAC-SHA2-512-1.0")
        .expect("Failed to load HMAC-SHA2-512-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HMAC-SHA2-512");
    r.run_suite(&suite)
        .expect("HMAC-SHA2-512 ACVP tests failed");
}

#[test]
fn test_hmac_sha3_256_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HMAC-SHA3-256-1.0")
        .expect("Failed to load HMAC-SHA3-256-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HMAC-SHA3-256");
    r.run_suite(&suite)
        .expect("HMAC-SHA3-256 ACVP tests failed");
}

#[test]
fn test_hkdf_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HKDF-1.0").expect("Failed to load HKDF-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HKDF-1.0");
    r.run_suite(&suite).expect("HKDF ACVP tests failed");
}

#[test]
fn test_pbkdf2_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("PBKDF-1.0").expect("Failed to load PBKDF-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: PBKDF-1.0");
    r.run_suite(&suite).expect("PBKDF2 ACVP tests failed");
}

#[test]
fn test_ecdh_component_acvp() {
    let suite = loader::load_suite_by_name("KAS-ECC-CDH-Component-1.0")
        .expect("Failed to load KAS-ECC-CDH-Component-1.0 suite");

    println!("Running ACVP test suite: KAS-ECC-CDH-Component-1.0");
    let report = run_report(&suite);
    assert_counts(&report, 75, 0, 75, 75);
    assert_group_counts(&report, &[(1, 0, 25), (2, 0, 25), (3, 0, 25)]);
    assert_eq!(
        report
            .require_success()
            .expect_err("unsupported P-192/K-163/B-163 component suite must not pass"),
        "ACVP suite executed no supported or response-generation cases"
    );
}

#[test]
fn test_ecdh_kas_ecc_acvp() {
    let suite =
        loader::load_suite_by_name("KAS-ECC-1.0").expect("Failed to load KAS-ECC-1.0 suite");

    println!("Running ACVP test suite: KAS-ECC-1.0");
    let report = run_report(&suite);
    assert_counts(&report, 5_670, 0, 5_670, 5_670);
    assert_all_groups_skipped(&report, 1, 324);
    assert_eq!(
        report
            .require_success()
            .expect_err("unimplemented KAS-ECC protocol profiles must not pass"),
        "ACVP suite executed no supported or response-generation cases"
    );
}

#[test]
fn test_ecdsa_keygen_acvp() {
    let suite = loader::load_suite_by_name("ECDSA-KeyGen-FIPS186-5")
        .expect("Failed to load ECDSA-KeyGen-FIPS186-5 suite");

    println!("Running ACVP test suite: ECDSA-KeyGen-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    let report = run_report(&suite);
    assert_counts(&report, 72, 12, 60, 60);
    let groups: Vec<_> = (1..=24)
        .map(|group| {
            if matches!(group, 1 | 3 | 5 | 7) {
                (group, 3, 0)
            } else {
                (group, 0, 3)
            }
        })
        .collect();
    assert_group_counts(&report, &groups);
    report
        .require_success()
        .expect("ACVP ECDSA KeyGen tests failed");
}

#[test]
fn test_ecdsa_keyver_acvp() {
    let suite = loader::load_suite_by_name("ECDSA-KeyVer-FIPS186-5")
        .expect("Failed to load ECDSA-KeyVer-FIPS186-5 suite");

    println!("Running ACVP test suite: ECDSA-KeyVer-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    let report = run_report(&suite);
    assert_counts(&report, 36, 12, 24, 24);
    let groups: Vec<_> = (1..=12)
        .map(|group| {
            if group <= 4 {
                (group, 3, 0)
            } else {
                (group, 0, 3)
            }
        })
        .collect();
    assert_group_counts(&report, &groups);
    report
        .require_success()
        .expect("ACVP ECDSA KeyVer tests failed");
}

#[test]
fn test_ecdsa_siggen_acvp() {
    let suite = loader::load_suite_by_name("ECDSA-SigGen-FIPS186-5")
        .expect("Failed to load ECDSA-SigGen-FIPS186-5 suite");

    println!("Running ACVP test suite: ECDSA-SigGen-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    let report = run_report(&suite);
    assert_counts(&report, 2_880, 0, 2_880, 2_880);
    assert_all_groups_skipped(&report, 1, 288);
    let error = report
        .require_success()
        .expect_err("ACVP supplied-nonce SigGen must not be reported as supported");
    assert_eq!(
        error,
        "ACVP suite executed no supported or response-generation cases"
    );
}

#[test]
fn test_ecdsa_sigver_acvp() {
    let suite = loader::load_suite_by_name("ECDSA-SigVer-FIPS186-5")
        .expect("Failed to load ECDSA-SigVer-FIPS186-5 suite");

    println!("Running ACVP test suite: ECDSA-SigVer-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    let report = run_report(&suite);
    assert_counts(&report, 196, 14, 182, 182);
    let groups: Vec<_> = (1..=28)
        .map(|group| {
            if matches!(group, 8 | 23) {
                (group, 7, 0)
            } else {
                (group, 0, 7)
            }
        })
        .collect();
    assert_group_counts(&report, &groups);
    report
        .require_success()
        .expect("ACVP ECDSA SigVer tests failed");
}

#[test]
fn test_ecdsa_sigver_all_supported_public_curve_hash_pairs() {
    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");

    // These legacy ACVP groups exercise the three public fixed-hash pairs not
    // all present in the FIPS 186-5 sample: P-224/SHA2-224,
    // P-256/SHA2-256, and P-384/SHA2-384.  P-521 remains covered by FIPS
    // 186-5 tgId 23 because legacy tgId 49 includes an expected-valid high-S
    // signature that dcrypt intentionally rejects under its stricter policy.
    suite
        .groups
        .retain(|group| matches!(group.group_name, 13 | 25 | 37));
    let report = run_report(&suite);
    assert_counts(&report, 21, 21, 0, 0);
    assert_group_counts(&report, &[(13, 7, 0), (25, 7, 0), (37, 7, 0)]);
    report
        .require_success()
        .expect("supported public ECDSA curve/hash pairs must verify fail closed");
}

#[test]
fn test_ecdsa_sp800_106_groups_are_explicitly_unsupported() {
    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    suite.groups.retain(|group| {
        group
            .tests
            .iter()
            .any(|case| case.inputs.contains_key("randomValue"))
    });
    assert_eq!(
        suite
            .groups
            .iter()
            .map(|group| group.group_name)
            .collect::<Vec<_>>(),
        (166..=330).collect::<Vec<_>>()
    );
    let report = run_report(&suite);
    assert_counts(&report, 1_155, 0, 1_155, 1_155);
    let groups = (166..=330).map(|group| (group, 0, 7)).collect::<Vec<_>>();
    assert_group_counts(&report, &groups);
    assert_eq!(report.summary.skip_reasons.len(), 1);
    assert!(report
        .summary
        .skip_reasons
        .keys()
        .next()
        .is_some_and(|reason| reason.contains("SP800-106")));
    assert!(report.require_success().is_err());
}

fn assert_ecdsa_invalid_input_is_compared(field: &str, value: String) {
    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 25, 174);
    suite.groups[0].tests[0]
        .corrupt_expected_for_test("testPassed")
        .expect("tcId 174 must be expected-valid before mutation");
    suite.groups[0].tests[0]
        .inputs
        .insert(field.into(), FlexValue::String(value));
    let report = run_report(&suite);
    assert_counts(&report, 1, 1, 0, 0);
    report
        .require_success()
        .unwrap_or_else(|error| panic!("invalid {field} was not compared as false: {error}"));
}

#[test]
fn ecdsa_sigver_handler_boundary_rejects_malformed_keys_signatures_and_messages() {
    let zero32 = "00".repeat(32);
    let ff32 = "ff".repeat(32);
    let overlong = "01".repeat(33);
    for (field, value) in [
        ("qx", "not-hex".into()),
        ("qx", "00".into()),
        ("qx", overlong.clone()),
        ("qx", ff32.clone()),
        ("qy", zero32.clone()),
        ("r", "not-hex".into()),
        ("r", "00".into()),
        ("r", overlong.clone()),
        ("r", zero32.clone()),
        ("r", ff32.clone()),
        ("s", "not-hex".into()),
        ("s", "00".into()),
        ("s", overlong),
        ("s", zero32),
        ("s", ff32),
        ("message", "00".into()),
    ] {
        assert_ecdsa_invalid_input_is_compared(field, value);
    }

    for missing in ["message", "qx", "qy", "r", "s"] {
        let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
            .expect("Failed to load ECDSA-SigVer-1.0 suite");
        isolate_case(&mut suite, 25, 174);
        assert!(suite.groups[0].tests[0].inputs.remove(missing).is_some());
        let report = run_report(&suite);
        assert_eq!(report.summary.passed, 0);
        assert_eq!(report.summary.skipped, 0);
        assert_eq!(report.summary.failed, 1);
    }
}

#[test]
fn malformed_ecdsa_capability_metadata_fails_instead_of_skipping() {
    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 25, 174);
    assert!(suite.groups[0].defaults.remove("hashAlg").is_some());
    assert!(suite.groups[0].tests[0].inputs.remove("hashAlg").is_some());
    let report = run_report(&suite);
    assert_eq!(
        (
            report.summary.passed,
            report.summary.skipped,
            report.summary.failed
        ),
        (0, 0, 1)
    );

    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 25, 174);
    suite.groups[0].tests[0]
        .inputs
        .insert("hashAlg".into(), FlexValue::String("SHA2-384".into()));
    let report = run_report(&suite);
    assert_eq!(
        (
            report.summary.passed,
            report.summary.skipped,
            report.summary.failed
        ),
        (0, 0, 1)
    );

    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 25, 174);
    suite.groups[0].tests[0]
        .inputs
        .insert("curve".into(), FlexValue::String("P-384".into()));
    let report = run_report(&suite);
    assert_eq!(
        (
            report.summary.passed,
            report.summary.skipped,
            report.summary.failed
        ),
        (0, 0, 1)
    );

    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 25, 174);
    assert!(suite.groups[0].defaults.remove("curve").is_some());
    assert!(suite.groups[0].tests[0].inputs.remove("curve").is_some());
    let report = run_report(&suite);
    assert_eq!(
        (
            report.summary.passed,
            report.summary.skipped,
            report.summary.failed
        ),
        (0, 0, 1)
    );

    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 25, 174);
    suite.groups[0]
        .defaults
        .insert("curve".into(), FlexValue::Bool(true));
    let report = run_report(&suite);
    assert_eq!(
        (
            report.summary.passed,
            report.summary.skipped,
            report.summary.failed
        ),
        (0, 0, 1)
    );

    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 25, 174);
    suite.groups[0]
        .defaults
        .insert("hashAlg".into(), FlexValue::Bool(true));
    let report = run_report(&suite);
    assert_eq!(
        (
            report.summary.passed,
            report.summary.skipped,
            report.summary.failed
        ),
        (0, 0, 1)
    );

    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 25, 174);
    suite.groups[0]
        .defaults
        .insert("curve".into(), FlexValue::String("P-999".into()));
    let report = run_report(&suite);
    assert_eq!(
        (
            report.summary.passed,
            report.summary.skipped,
            report.summary.failed
        ),
        (0, 0, 1)
    );

    let mut suite = loader::load_suite_by_name("ECDSA-SigVer-1.0")
        .expect("Failed to load ECDSA-SigVer-1.0 suite");
    isolate_case(&mut suite, 190, 1324);
    suite.groups[0].tests[0]
        .inputs
        .insert("randomValue".into(), FlexValue::Bool(true));
    let report = run_report(&suite);
    assert_eq!(
        (
            report.summary.passed,
            report.summary.skipped,
            report.summary.failed
        ),
        (0, 0, 1)
    );
}

#[test]
fn test_eddsa_keygen_acvp() {
    let suite = loader::load_suite_by_name("EDDSA-KeyGen-1.0")
        .expect("Failed to load EDDSA-KeyGen-1.0 suite");

    println!("Running ACVP test suite: EDDSA-KeyGen-1.0");
    let report = run_report(&suite);
    assert_counts(&report, 6, 3, 3, 3);
    assert_group_counts(&report, &[(1, 3, 0), (2, 0, 3)]);
    report
        .require_success()
        .expect("ACVP EdDSA KeyGen tests failed");
}

#[test]
fn test_eddsa_keyver_acvp() {
    let suite = loader::load_suite_by_name("EDDSA-KeyVer-1.0")
        .expect("Failed to load EDDSA-KeyVer-1.0 suite");

    println!("Running ACVP test suite: EDDSA-KeyVer-1.0");
    let report = run_report(&suite);
    assert_counts(&report, 8, 4, 4, 4);
    assert_group_counts(&report, &[(1, 4, 0), (2, 0, 4)]);
    report
        .require_success()
        .expect("ACVP EdDSA KeyVer tests failed");
}

#[test]
fn test_eddsa_siggen_acvp() {
    let suite = loader::load_suite_by_name("EDDSA-SigGen-1.0")
        .expect("Failed to load EDDSA-SigGen-1.0 suite");

    println!("Running ACVP test suite: EDDSA-SigGen-1.0");
    let report = run_report(&suite);
    assert_counts(&report, 168, 42, 126, 126);
    assert_group_counts(
        &report,
        &[
            (1, 10, 0),
            (2, 0, 10),
            (3, 0, 10),
            (4, 0, 10),
            (5, 32, 0),
            (6, 0, 32),
            (7, 0, 32),
            (8, 0, 32),
        ],
    );
    report
        .require_success()
        .expect("ACVP EdDSA SigGen tests failed");
}

#[test]
fn test_eddsa_sigver_acvp() {
    let suite = loader::load_suite_by_name("EDDSA-SigVer-1.0")
        .expect("Failed to load EDDSA-SigVer-1.0 suite");

    println!("Running ACVP test suite: EDDSA-SigVer-1.0");
    let report = run_report(&suite);
    assert_counts(&report, 20, 5, 15, 15);
    assert_group_counts(&report, &[(1, 5, 0), (2, 0, 5), (3, 0, 5), (4, 0, 5)]);
    report
        .require_success()
        .expect("ACVP EdDSA SigVer tests failed");
}

#[test]
fn test_ml_kem_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-KEM-encapDecap-FIPS203")
        .expect("Failed to load ML-KEM-encapDecap-FIPS203 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-KEM-encapDecap-FIPS203");
    // println!("Number of test groups: {}", suite.groups.len());

    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type); // Should be "AFT"
    //     // For KEMs, the "direction" is more like a "function"
    //     if let Some(function) = first_group.defaults.get("function").map(|v| v.as_string()) {
    //          println!("First group function: {}", function);
    //     } else if let Some(function) = first_group.direction.as_ref() {
    //         println!("First group function (from direction): {}", function);
    //     }
    //      println!("First group parameterSet: {:?}", first_group.defaults.get("parameterSet").map(|v| v.as_string()));

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    r.run_suite(&suite).expect("ACVP ML-KEM tests failed");
}

#[test]
fn test_ml_kem_keygen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-KEM-keyGen-FIPS203")
        .expect("Failed to load ML-KEM-keyGen-FIPS203 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-KEM-keyGen-FIPS203");
    r.run_suite(&suite)
        .expect("ACVP ML-KEM keyGen tests failed");
}

#[test]
fn test_ml_dsa_keygen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-DSA-keyGen-FIPS204")
        .expect("Failed to load ML-DSA-keyGen-FIPS204 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-DSA-keyGen-FIPS204");
    r.run_suite(&suite)
        .expect("ACVP ML-DSA KeyGen tests failed");
}

#[test]
fn test_ml_dsa_siggen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-DSA-sigGen-FIPS204")
        .expect("Failed to load ML-DSA-sigGen-FIPS204 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-DSA-sigGen-FIPS204");
    r.run_suite(&suite)
        .expect("ACVP ML-DSA SigGen tests failed");
}

#[test]
fn test_ml_dsa_sigver_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-DSA-sigVer-FIPS204")
        .expect("Failed to load ML-DSA-sigVer-FIPS204 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-DSA-sigVer-FIPS204");
    r.run_suite(&suite)
        .expect("ACVP ML-DSA SigVer tests failed");
}

/// Each supported expected-output class is corrupted independently.  A
/// handler that merely returns `Ok(())`, or that forgets to emit one of these
/// values, therefore cannot turn altered oracle data into a passing case.
#[test]
fn expected_output_mutations_fail_closed() {
    let case_fields = [
        ("ACVP-AES-CBC-1.0", 1, 1, "ct"),
        ("ACVP-AES-CBC-1.0", 13, 1040, "pt"),
        ("ACVP-AES-CTR-1.0", 1, 1, "ct"),
        ("ACVP-AES-CTR-1.0", 1, 1, "iv"),
        ("ACVP-AES-CTR-1.0", 4, 76, "pt"),
        ("ACVP-AES-GCM-1.0", 1, 1, "ct"),
        ("ACVP-AES-GCM-1.0", 1, 1, "tag"),
        ("ACVP-AES-GCM-1.0", 3, 31, "pt"),
        ("ACVP-AES-GCM-1.0", 3, 33, "testPassed"),
        ("SHA2-256-1.0", 1, 1, "md"),
        ("SHA3-224-2.0", 1, 1, "md"),
        ("SHA3-224-2.0", 2, 1254, "resultsArray"),
        ("SHAKE-128-1.0", 1, 1, "md"),
        ("SHAKE-128-1.0", 1, 1, "outLen"),
        ("SHAKE-128-1.0", 2, 1392, "resultsArray"),
        ("HMAC-SHA2-256-1.0", 1, 1, "mac"),
        ("HKDF-1.0", 1, 1, "derivedKey"),
        ("PBKDF-1.0", 1, 1, "derivedKey"),
        ("ECDSA-KeyGen-FIPS186-5", 1, 1, "d"),
        ("ECDSA-KeyGen-FIPS186-5", 1, 1, "qx"),
        ("ECDSA-KeyGen-FIPS186-5", 1, 1, "qy"),
        ("ECDSA-KeyVer-FIPS186-5", 1, 1, "testPassed"),
        ("ECDSA-SigVer-FIPS186-5", 8, 50, "testPassed"),
        ("EDDSA-KeyGen-1.0", 1, 1, "d"),
        ("EDDSA-KeyGen-1.0", 1, 1, "q"),
        ("EDDSA-KeyVer-1.0", 1, 1, "testPassed"),
        ("EDDSA-SigGen-1.0", 1, 1, "signature"),
        ("EDDSA-SigVer-1.0", 1, 1, "testPassed"),
        ("ML-KEM-keyGen-FIPS203", 1, 1, "ek"),
        ("ML-KEM-keyGen-FIPS203", 1, 1, "dk"),
        ("ML-KEM-encapDecap-FIPS203", 1, 1, "c"),
        ("ML-KEM-encapDecap-FIPS203", 1, 1, "k"),
        ("ML-KEM-encapDecap-FIPS203", 7, 106, "testPassed"),
        ("ML-KEM-encapDecap-FIPS203", 8, 116, "testPassed"),
        ("ML-DSA-keyGen-FIPS204", 1, 1, "pk"),
        ("ML-DSA-keyGen-FIPS204", 1, 1, "sk"),
        ("ML-DSA-sigGen-FIPS204", 1, 1, "signature"),
        ("ML-DSA-sigVer-FIPS204", 1, 1, "testPassed"),
    ];

    for (suite, group, case, field) in case_fields {
        assert_case_mutation_fails(suite, group, case, field);
        assert_case_deletion_fails(suite, group, case, field);
    }
    assert_group_mutation_fails("EDDSA-SigGen-1.0", 1, 1, "q");
    assert_group_deletion_fails("EDDSA-SigGen-1.0", 1, 1, "q");

    let mut suite = loader::load_suite_by_name("SHA2-256-1.0").expect("load SHA2 fixture");
    isolate_case(&mut suite, 1, 1);
    assert!(suite.groups[0].tests[0].add_expected_for_test("unexpected"));
    let report = run_report(&suite);
    assert_eq!(report.summary.passed, 0);
    assert!(report.summary.failed > 0, "added oracle field did not fail");
}

#[test]
fn full_stack_sha256_suite() {
    // SHA-256 tests would need to be loaded separately
    // For now, this test is disabled as we're focusing on AES-CBC

    /*
    let sha256 = suites.iter()
        .find(|s| s.suite_name.contains("SHA2-256"))
        .expect("suite not found");

    r.run_suite(sha256).unwrap();
    */
}
