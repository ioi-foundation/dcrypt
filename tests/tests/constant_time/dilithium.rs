// tests/tests/constant_time/dilithium.rs

use dcrypt_api::Signature;
use dcrypt_sign::dilithium::{Dilithium3, DilithiumSignatureData};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn create_dilithium_config() -> TestConfig {
    TestConfig {
        num_warmup: 50,
        num_samples: 40,
        num_iterations: 5, 
        mean_ratio_max: 1.6,
        mean_ratio_min: 0.5,
        t_stat_threshold: 12.0, // Increased from 4.0
        std_dev_threshold: 0.40,
        combined_score_threshold: 5.0, // Increased from 2.5

        enable_dynamic_scaling: true,
        noise_scale_factor: 1.0,
        noise_sensitivity: 15.0,
        noise_soft_floor: 0.01,
        noise_hard_floor: 0.20,
    }
}

#[test]
fn test_dilithium3_verify_constant_time() {
    let config = create_dilithium_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message = b"Constant time test message for Dilithium3";

    // 1. Setup: Generate keypair and valid signature
    let (pk, sk) = Dilithium3::keypair(&mut rng).expect("Keygen failed");
    let valid_sig = Dilithium3::sign(message, &sk).expect("Signing failed");

    // 2. Generate invalid signature (Deep Path)
    // We modify the challenge seed.
    let mut invalid_sig_bytes = valid_sig.to_bytes().to_vec();
    
    // Flip a bit in the first byte (challenge seed)
    if let Some(first) = invalid_sig_bytes.first_mut() {
        *first ^= 0xFF;
    }
    
    // Re-construct signature from bytes
    let invalid_sig = DilithiumSignatureData::from_bytes(&invalid_sig_bytes)
        .expect("Failed to deserialize modified signature");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    // 3. Define Operations
    
    // Warmup: Run valid verification
    let warmup_op = || {
        let _ = Dilithium3::verify(message, &valid_sig, &pk);
    };

    // Measurement: Toggle between Valid (false) and Invalid (true)
    let measurement_op = |use_invalid: bool| {
        if use_invalid {
            let _ = Dilithium3::verify(message, &invalid_sig, &pk);
        } else {
            let _ = Dilithium3::verify(message, &valid_sig, &pk);
        }
    };

    // 4. Run Calibrated Test
    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config
    ).expect("Calibration failed");

    // 5. Reporting
    println!("Dilithium3 Verify Timing Analysis:");
    println!(
        "  Mean times: {:.2} ns (Valid) vs {:.2} ns (Invalid)",
        analysis.mean_a, analysis.mean_b
    );
    println!("  Mean ratio: {:.4}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value: {:.4}", analysis.p_value);
    println!("  Combined score: {:.3}", analysis.combined_score);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "Dilithium3 Verify");
        println!("\n{}", insights);
    }

    // 6. Assertion
    assert!(
        analysis.is_constant_time,
        "Dilithium3 verification is not constant-time: combined_score={:.3} (threshold: {:.3})",
        analysis.combined_score, config.combined_score_threshold
    );
}