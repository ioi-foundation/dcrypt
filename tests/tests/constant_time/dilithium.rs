// tests/tests/constant_time/dilithium.rs
use dcrypt_api::Signature;
use dcrypt_sign::dilithium::{Dilithium3, DilithiumSignatureData};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn create_dilithium_config() -> TestConfig {
    let mut config = TestConfig::for_pqc_sign();
    config.num_warmup = 50;
    config.num_samples = 100;
    config.num_iterations = 5;
    config.practical_significance_threshold = 5.0; // High threshold due to complexity
    config
}

#[test]
fn test_dilithium3_verify_constant_time() {
    let config = create_dilithium_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message = b"Constant time test message for Dilithium3";

    let (pk, sk) = Dilithium3::keypair(&mut rng).expect("Keygen failed");
    let valid_sig = Dilithium3::sign(message, &sk).expect("Signing failed");

    let mut invalid_sig_bytes = valid_sig.to_bytes().to_vec();
    if let Some(first) = invalid_sig_bytes.first_mut() {
        *first ^= 0xFF;
    }
    let invalid_sig = DilithiumSignatureData::from_bytes(&invalid_sig_bytes)
        .expect("Failed to deserialize modified signature");

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

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "Dilithium3 Verify"
    ).expect("Calibration failed");

    println!("Dilithium3 Verify Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "Dilithium3 Verify"));
    }

    assert!(analysis.is_constant_time);
}