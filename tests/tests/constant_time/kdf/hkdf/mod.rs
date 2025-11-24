// tests/tests/constant_time/kdf/hkdf/mod.rs
use dcrypt_algorithms::hash::Sha256;
use dcrypt_algorithms::kdf::hkdf::Hkdf;
use dcrypt_algorithms::kdf::KeyDerivationFunction;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

fn create_hkdf_config() -> TestConfig {
    TestConfig::for_hkdf()
}

#[test]
fn test_hkdf_constant_time() {
    let config = create_hkdf_config();
    let secret1 = [0x0bu8; 32];
    let secret2 = [0x0cu8; 32];
    let salt = Some(&[0x0au8; 16][..]);
    let info = Some(&[0x01u8; 8][..]);
    let output_len = 32;
    
    let hkdf = Hkdf::<Sha256>::new();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = hkdf.derive_key(&secret1, salt, info, output_len);
    };

    let measurement_op = |use_sec2: bool| {
        if use_sec2 {
            let _ = hkdf.derive_key(&secret2, salt, info, output_len);
        } else {
            let _ = hkdf.derive_key(&secret1, salt, info, output_len);
        }
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "HKDF"
    ).expect("Calibration failed");

    println!("HKDF Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "HKDF"));
    }

    assert!(analysis.is_constant_time);
}