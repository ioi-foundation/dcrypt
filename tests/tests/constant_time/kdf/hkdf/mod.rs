// tests/tests/constant_time/kdf/hkdf/mod.rs

use dcrypt_algorithms::hash::Sha256;
use dcrypt_algorithms::kdf::hkdf::Hkdf;
use dcrypt_algorithms::kdf::KeyDerivationFunction;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

fn create_hkdf_config() -> TestConfig {
    TestConfig {
        num_warmup: 5,
        num_samples: 30,
        num_iterations: 3,
        mean_ratio_max: 1.4,
        mean_ratio_min: 0.6,
        t_stat_threshold: 5.0,
        std_dev_threshold: 0.25,
        combined_score_threshold: 3.0,

        // DTS Config
        enable_dynamic_scaling: true,
        noise_scale_factor: 1.0,
        noise_sensitivity: 20.0,
        noise_soft_floor: 0.02,
        noise_hard_floor: 0.20,
    }
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
        &config
    ).expect("Calibration failed");

    println!("HKDF Timing Analysis:");
    println!("  Combined score: {:.3}", analysis.combined_score);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "HKDF"));
    }

    assert!(analysis.is_constant_time);
}