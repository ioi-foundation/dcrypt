// tests/tests/constant_time/dilithium.rs
use dcrypt_api::Signature;
use dcrypt_sign::dilithium::{Dilithium3, DilithiumSignatureData};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use dcrypt_tests::test_rng::ChaCha20Rng;

fn create_dilithium_config() -> TestConfig {
    let mut config = TestConfig::for_pqc_sign();
    config.num_warmup = 30;
    config.num_samples = 80;
    config.num_iterations = 3;
    config
}

#[test]
fn test_dilithium3_verify_success_path_constant_time() {
    let config = create_dilithium_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message_a = b"Constant time test message for Dilithium3";
    let message_b = b"Another constant time test message for Dilithium3";

    let (pk, sk) = Dilithium3::keypair(&mut rng).expect("Keygen failed");
    let valid_sig_a = Dilithium3::sign(message_a, &sk).expect("Signing failed");
    let valid_sig_b = Dilithium3::sign(message_b, &sk).expect("Signing failed");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = Dilithium3::verify(message_a, &valid_sig_a, &pk);
    };

    let measurement_op = |use_b: bool| {
        if use_b {
            let _ = Dilithium3::verify(message_b, &valid_sig_b, &pk);
        } else {
            let _ = Dilithium3::verify(message_a, &valid_sig_a, &pk);
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "Dilithium3 Verify Success",
        )
        .expect("Calibration failed");

    println!("Dilithium3 Verify Success Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "Dilithium3 Verify Success")
        );
    }

    assert!(analysis.is_constant_time);
}

#[test]
fn test_dilithium3_verify_rejection_path_constant_time() {
    let config = create_dilithium_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message = b"Constant time test message for Dilithium3";

    let (pk, sk) = Dilithium3::keypair(&mut rng).expect("Keygen failed");
    let valid_sig = Dilithium3::sign(message, &sk).expect("Signing failed");

    let mut invalid_sig_bytes = valid_sig.to_bytes().to_vec();
    if let Some(z_byte) = invalid_sig_bytes.get_mut(64) {
        *z_byte ^= 0x01;
    }
    let invalid_sig = DilithiumSignatureData::from_bytes(&invalid_sig_bytes)
        .expect("Failed to deserialize modified signature");
    assert!(Dilithium3::verify(message, &invalid_sig, &pk).is_err());

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = Dilithium3::verify(message, &valid_sig, &pk);
    };

    let measurement_op = |use_invalid: bool| {
        if use_invalid {
            let _ = Dilithium3::verify(message, &invalid_sig, &pk);
        } else {
            let _ = Dilithium3::verify(message, &valid_sig, &pk);
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "Dilithium3 Verify Reject",
        )
        .expect("Calibration failed");

    println!("Dilithium3 Verify Rejection Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "Dilithium3 Verify Reject")
        );
    }

    assert!(analysis.is_constant_time);
}
