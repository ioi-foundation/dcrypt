// tests/tests/constant_time/mod.rs
mod aead_tests;
mod block_cipher_tests;
mod bls;
mod ecdh;
mod hash_tests;
mod hybrid;
mod kdf;
mod mac_tests;
mod ml_dsa;
mod ml_kem;
mod stream_tests;
mod xof_tests;

use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    analyze_blocking_family, generate_familywise_insights, generate_test_insights, TimingAnalysis,
    EXPECTED_BLOCKING_CASES,
};

const BLOCKING_CASE_NAMES: [&str; EXPECTED_BLOCKING_CASES] = [
    "AES-128",
    "SHA-256",
    "SHA3-256",
    "HMAC-SHA256",
    "ChaCha20",
    "SHAKE-256",
    "BLAKE3-XOF",
    "HKDF",
    "PBKDF2",
    "Argon2id Verify",
    "Argon2 Comparison",
    "GCM Success Path",
    "GCM Invalid Ciphertext Data",
    "GCM First-vs-Last Tag Mismatch",
    "ChaChaPoly Success Path",
    "ChaChaPoly Invalid Ciphertext Data",
    "ChaChaPoly First-vs-Last Tag Mismatch",
    "BLS12-381 G1 secret scalar multiplication",
    "BLS12-381 G2 secret scalar multiplication",
    "ECDH P-224 Scalar Mult",
    "ECDH P-256 Scalar Mult",
    "ECDH K-256 Scalar Mult",
    "ECDH P-384 Scalar Mult",
    "ECDH P-521 Scalar Mult",
    "Hybrid KEM Decapsulate Success",
    "Hybrid KEM Decapsulate Reject",
    "MlKem768 Decapsulate Success",
    "MlKem768 Decapsulate Reject",
    "ML-DSA-65 Verify Reject",
];

fn collect_case(
    expected_name: &str,
    measurement: fn() -> Result<TimingAnalysis, String>,
    cases: &mut Vec<TimingAnalysis>,
    errors: &mut Vec<String>,
) {
    match measurement() {
        Ok(analysis) => {
            if analysis.name != expected_name {
                errors.push(format!(
                    "{expected_name}: measurement returned mismatched name {:?}",
                    analysis.name
                ));
            }
            println!(
                "{}",
                generate_test_insights(&analysis, &TestConfig::default(), expected_name)
            );
            cases.push(analysis);
        }
        Err(error) => errors.push(format!("{expected_name}: {error}")),
    }
}

#[test]
fn repository_constant_time_suite() {
    let mut cases = Vec::with_capacity(EXPECTED_BLOCKING_CASES);
    let mut errors = Vec::new();

    let measurements: [fn() -> Result<TimingAnalysis, String>; EXPECTED_BLOCKING_CASES] = [
        block_cipher_tests::measure_aes_constant_time,
        hash_tests::measure_sha256_constant_time,
        hash_tests::measure_sha3_256_constant_time,
        mac_tests::measure_hmac_sha256_constant_time,
        stream_tests::measure_chacha20_constant_time,
        xof_tests::measure_shake256_constant_time,
        xof_tests::measure_blake3_xof_constant_time,
        kdf::measure_hkdf_constant_time,
        kdf::measure_pbkdf2_constant_time,
        kdf::measure_argon2id_verify_constant_time,
        kdf::measure_argon2_constant_time_compare,
        aead_tests::measure_gcm_success_path,
        aead_tests::measure_gcm_invalid_ciphertext_data,
        aead_tests::measure_gcm_first_vs_last_tag_mismatch,
        aead_tests::measure_chacha_poly_success_path,
        aead_tests::measure_chacha_poly_invalid_ciphertext_data,
        aead_tests::measure_chacha_poly_first_vs_last_tag_mismatch,
        bls::measure_bls_g1_secret_scalar_multiplication,
        bls::measure_bls_g2_secret_scalar_multiplication,
        ecdh::measure_p224_scalar_mult,
        ecdh::measure_p256_scalar_mult,
        ecdh::measure_k256_scalar_mult,
        ecdh::measure_p384_scalar_mult,
        ecdh::measure_p521_scalar_mult,
        hybrid::measure_hybrid_kem_decapsulate_success_path,
        hybrid::measure_hybrid_kem_decapsulate_rejection_path,
        ml_kem::measure_ml_kem768_decapsulate_success_path,
        ml_kem::measure_ml_kem768_decapsulate_rejection_path,
        ml_dsa::measure_ml_dsa_65_verify_rejection_path,
    ];

    for (&name, measurement) in BLOCKING_CASE_NAMES.iter().zip(measurements) {
        collect_case(name, measurement, &mut cases, &mut errors);
    }

    if !errors.is_empty() {
        panic!(
            "blocking timing collection failed after attempting every case:\n{}",
            errors.join("\n")
        );
    }

    let family = analyze_blocking_family(&cases, &BLOCKING_CASE_NAMES)
        .unwrap_or_else(|error| panic!("blocking timing family evidence is invalid: {error}"));
    println!("{}", generate_familywise_insights(&family));
    if !family.passes() {
        let blockers: Vec<_> = family
            .blocking_cases()
            .map(|decision| decision.name.as_str())
            .collect();
        panic!(
            "suite-wide Holm rejected and the paired mean exceeded its unchanged practical threshold for: {blockers:?}"
        );
    }
}

#[test]
fn timing_harness_contract_guard() {
    const CASE_SOURCES: [(&str, &str); 15] = [
        ("aead_tests.rs", include_str!("aead_tests.rs")),
        (
            "block_cipher_tests.rs",
            include_str!("block_cipher_tests.rs"),
        ),
        ("bls.rs", include_str!("bls.rs")),
        ("ecdh.rs", include_str!("ecdh.rs")),
        ("hash_tests.rs", include_str!("hash_tests.rs")),
        ("hybrid.rs", include_str!("hybrid.rs")),
        ("mac_tests.rs", include_str!("mac_tests.rs")),
        ("ml_dsa.rs", include_str!("ml_dsa.rs")),
        ("ml_kem.rs", include_str!("ml_kem.rs")),
        ("stream_tests.rs", include_str!("stream_tests.rs")),
        ("xof_tests.rs", include_str!("xof_tests.rs")),
        ("kdf/mod.rs", include_str!("kdf/mod.rs")),
        ("kdf/argon2/mod.rs", include_str!("kdf/argon2/mod.rs")),
        ("kdf/hkdf/mod.rs", include_str!("kdf/hkdf/mod.rs")),
        ("kdf/pbkdf2/mod.rs", include_str!("kdf/pbkdf2/mod.rs")),
    ];
    const FORBIDDEN_CASE_PATTERNS: [&str; 7] = [
        ".calibrate_and_measure(",
        "FnMut(bool)",
        ".is_constant_time",
        "assert!(analysis",
        "match class",
        "if class",
        "|use_b",
    ];

    let mut prepared_call_sites = 0usize;
    let mut child_tests = 0usize;
    for (path, source) in CASE_SOURCES {
        for forbidden in FORBIDDEN_CASE_PATTERNS {
            assert!(
                !source.contains(forbidden),
                "{path} contains forbidden timing-harness pattern {forbidden:?}"
            );
        }
        let calls = source.matches("calibrate_and_measure_prepared").count();
        if calls != 0 {
            assert!(
                source.contains("prepare_bytes"),
                "{path} has a prepared timing call without the shared read-both selector"
            );
        }
        prepared_call_sites += calls;
        child_tests += source.matches("#[test]").count();
    }
    assert_eq!(prepared_call_sites, 24);
    assert_eq!(
        child_tests, 2,
        "only ML-DSA correctness/diagnostic tests stay separate"
    );

    let tester = include_str!("../../src/suites/constant_time/tester.rs");
    assert!(!tester.contains("pub fn calibrate_and_measure("));
    let prepared_start = tester
        .find("pub fn calibrate_and_measure_prepared")
        .expect("prepared API must exist");
    let prepared_end = tester[prepared_start..]
        .find("#[allow(clippy::too_many_arguments)]")
        .map(|offset| prepared_start + offset)
        .expect("prepared API body boundary must exist");
    let prepared_body = &tester[prepared_start..prepared_end];
    assert!(!prepared_body.contains("if class_a_first"));
    assert!(!prepared_body.contains("match class"));
    assert!(prepared_body.contains(
        "let measurement_schedule = measurement_schedule(self.num_samples, schedule_seed)?;"
    ));
    assert!(
        prepared_body.contains("let (first_class, second_class) = load_measurement_pair(pair);")
    );
    assert!(prepared_body.contains("for pair in &measurement_schedule"));
    assert!(tester.contains("let class_b_mask = 0u8.wrapping_sub(class as u8);"));
    assert!(tester
        .contains("for ((destination, &a), &b) in current.iter_mut().zip(class_a).zip(class_b)"));
}
