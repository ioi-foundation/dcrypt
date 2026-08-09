// tests/tests/constant_time/hybrid.rs

use dcrypt_api::{Kem, Serialize};
use dcrypt_hybrid::kem::EcdhP256MlKem768;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use dcrypt_tests::test_rng::ChaCha20Rng;

fn create_hybrid_config() -> TestConfig {
    let mut config = TestConfig::for_pqc_kem();
    config.num_samples = 50;
    config.num_iterations = 5;
    config
}

#[test]
fn test_hybrid_kem_decapsulate_success_path_constant_time() {
    let config = create_hybrid_config();
    let mut rng = ChaCha20Rng::from_seed([77u8; 32]);

    let (pk, sk) = EcdhP256MlKem768::keypair(&mut rng).expect("Hybrid Keygen failed");
    let (valid_ct_a, _valid_ss_a) =
        EcdhP256MlKem768::encapsulate(&mut rng, &pk).expect("Encapsulation failed");
    let (valid_ct_b, _valid_ss_b) =
        EcdhP256MlKem768::encapsulate(&mut rng, &pk).expect("Encapsulation failed");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = EcdhP256MlKem768::decapsulate(&sk, &valid_ct_a);
    };

    let measurement_op = |use_b: bool| {
        if use_b {
            let _ = EcdhP256MlKem768::decapsulate(&sk, &valid_ct_b);
        } else {
            let _ = EcdhP256MlKem768::decapsulate(&sk, &valid_ct_a);
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "Hybrid KEM Decapsulate Success",
        )
        .expect("Calibration failed");

    println!("Hybrid KEM Success-Path Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "Hybrid KEM Decapsulate Success")
        );
    }

    assert!(analysis.is_constant_time);
}

#[test]
fn test_hybrid_kem_decapsulate_rejection_path_constant_time() {
    let config = create_hybrid_config();
    let mut rng = ChaCha20Rng::from_seed([77u8; 32]);

    let (pk, sk) = EcdhP256MlKem768::keypair(&mut rng).expect("Hybrid Keygen failed");
    let (valid_ct, _valid_ss) =
        EcdhP256MlKem768::encapsulate(&mut rng, &pk).expect("Encapsulation failed");

    let mut ct_bytes = valid_ct.to_bytes();
    if let Some(last) = ct_bytes.last_mut() {
        *last ^= 0xFF;
    }
    let invalid_ct = <EcdhP256MlKem768 as Kem>::Ciphertext::from_bytes(&ct_bytes)
        .expect("Failed to deserialize modified ciphertext");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = EcdhP256MlKem768::decapsulate(&sk, &valid_ct);
    };

    let measurement_op = |use_invalid: bool| {
        if use_invalid {
            let _ = EcdhP256MlKem768::decapsulate(&sk, &invalid_ct);
        } else {
            let _ = EcdhP256MlKem768::decapsulate(&sk, &valid_ct);
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "Hybrid KEM Decapsulate Reject",
        )
        .expect("Calibration failed");

    println!("Hybrid KEM Rejection-Path Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "Hybrid KEM Decapsulate Reject")
        );
    }

    assert!(analysis.is_constant_time);
}
