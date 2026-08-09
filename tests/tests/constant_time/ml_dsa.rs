// tests/tests/constant_time/ml_dsa.rs
use dcrypt_api::Signature;
use dcrypt_sign::mldsa::{MlDsa65, MlDsaSignature};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use dcrypt_tests::test_rng::ChaCha20Rng;

fn create_ml_dsa_config() -> TestConfig {
    let mut config = TestConfig::for_pqc_sign();
    config.num_warmup = 30;
    config.num_samples = 80;
    config.num_iterations = 3;
    config
}

#[test]
fn test_ml_dsa_65_verify_success_path_constant_time() {
    let config = create_ml_dsa_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message_a = b"Constant time test message for ML-DSA-65";
    let message_b = b"Another constant time test message for ML-DSA-65";

    let (pk, sk) = MlDsa65::keypair(&mut rng).expect("Keygen failed");
    let valid_sig_a = MlDsa65::sign(message_a, &sk).expect("Signing failed");
    let valid_sig_b = MlDsa65::sign(message_b, &sk).expect("Signing failed");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = MlDsa65::verify(message_a, &valid_sig_a, &pk);
    };

    let measurement_op = |use_b: bool| {
        if use_b {
            let _ = MlDsa65::verify(message_b, &valid_sig_b, &pk);
        } else {
            let _ = MlDsa65::verify(message_a, &valid_sig_a, &pk);
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "ML-DSA-65 Verify Success",
        )
        .expect("Calibration failed");

    println!("ML-DSA-65 Verify Success Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "ML-DSA-65 Verify Success")
        );
    }

    assert!(analysis.is_constant_time);
}

#[test]
fn test_ml_dsa_65_verify_rejection_path_constant_time() {
    let config = create_ml_dsa_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message = b"Constant time test message for ML-DSA-65";

    let (pk, sk) = MlDsa65::keypair(&mut rng).expect("Keygen failed");
    let valid_sig = MlDsa65::sign(message, &sk).expect("Signing failed");

    let mut invalid_sig_bytes = valid_sig.to_bytes().to_vec();
    if let Some(z_byte) = invalid_sig_bytes.get_mut(64) {
        *z_byte ^= 0x01;
    }
    let invalid_sig = MlDsaSignature::from_bytes(&invalid_sig_bytes)
        .expect("Failed to deserialize modified signature");
    assert!(MlDsa65::verify(message, &invalid_sig, &pk).is_err());

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = MlDsa65::verify(message, &valid_sig, &pk);
    };

    let measurement_op = |use_invalid: bool| {
        if use_invalid {
            let _ = MlDsa65::verify(message, &invalid_sig, &pk);
        } else {
            let _ = MlDsa65::verify(message, &valid_sig, &pk);
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "ML-DSA-65 Verify Reject",
        )
        .expect("Calibration failed");

    println!("ML-DSA-65 Verify Rejection Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "ML-DSA-65 Verify Reject")
        );
    }

    assert!(analysis.is_constant_time);
}
