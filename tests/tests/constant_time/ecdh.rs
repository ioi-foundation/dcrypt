// tests/tests/constant_time/ecdh.rs

use dcrypt_algorithms::ec::p256::{self, Scalar, P256_SCALAR_SIZE};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

fn create_ecdh_config() -> TestConfig {
    TestConfig {
        num_warmup: 50,
        num_samples: 40,
        num_iterations: 5,
        mean_ratio_max: 1.2,
        mean_ratio_min: 0.8,
        t_stat_threshold: 6.0,
        std_dev_threshold: 0.25,
        combined_score_threshold: 3.0,

        enable_dynamic_scaling: true,
        noise_scale_factor: 1.0,
        noise_sensitivity: 15.0,
        noise_soft_floor: 0.01,
        noise_hard_floor: 0.20,
    }
}

#[test]
fn test_p256_scalar_mult_constant_time() {
    let config = create_ecdh_config();
    
    // 1. Setup
    let base_point = p256::base_point_g();

    // Construct Low-Hamming Weight Scalar
    let mut low_weight_bytes = [0u8; P256_SCALAR_SIZE];
    low_weight_bytes[P256_SCALAR_SIZE - 1] = 1;
    let scalar_low = Scalar::new(low_weight_bytes).expect("Invalid scalar");

    // Construct High-Hamming Weight Scalar
    let mut high_weight_bytes = [0xFFu8; P256_SCALAR_SIZE];
    high_weight_bytes[0] = 0x00; // Ensure < n
    let scalar_high = Scalar::new(high_weight_bytes).expect("Invalid scalar");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    // 2. Define Operations
    
    // Warmup: Use low weight scalar
    let warmup_op = || {
        let _ = base_point.mul(&scalar_low);
    };

    // Measurement: Toggle High (true) / Low (false)
    let measurement_op = |high_weight: bool| {
        if high_weight {
            let _ = base_point.mul(&scalar_high);
        } else {
            let _ = base_point.mul(&scalar_low);
        }
    };

    // 3. Run Calibrated Test
    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config
    ).expect("Calibration failed");

    // 4. Reporting
    println!("ECDH P-256 Scalar Mult Timing Analysis:");
    println!(
        "  Mean times: {:.2} ns (Low) vs {:.2} ns (High)",
        analysis.mean_a, analysis.mean_b
    );
    println!("  Mean ratio: {:.4}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  Combined score: {:.3}", analysis.combined_score);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "ECDH P-256");
        println!("\n{}", insights);
    }

    // 5. Assertion
    assert!(
        analysis.is_constant_time,
        "ECDH P-256 scalar multiplication is not constant-time: combined_score={:.3}",
        analysis.combined_score
    );
}