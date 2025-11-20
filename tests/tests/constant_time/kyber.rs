// tests/tests/constant_time/kyber.rs

use dcrypt_api::Kem;
use dcrypt_kem::kyber::Kyber768;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn create_kyber_config() -> TestConfig {
    TestConfig {
        num_warmup: 100,
        num_samples: 50,
        num_iterations: 10,
        
        // Kyber involves complex lattice operations which can have slight jitter
        // even in constant-time implementations due to cache/memory bus effects.
        // We set thresholds to catch algorithmic branches while ignoring noise.
        mean_ratio_max: 1.10,
        mean_ratio_min: 0.90,
        t_stat_threshold: 3.5,
        std_dev_threshold: 0.25,
        combined_score_threshold: 2.0,

        // --- Dynamic Threshold Scaling (DTS) Configuration ---
        enable_dynamic_scaling: true,
        // Allow thresholds to double in worst-case valid noise (1.0 = +100%)
        noise_scale_factor: 1.0,
        // Sensitivity to noise. 15.0 makes the scaling curve moderately steep.
        noise_sensitivity: 15.0,
        // Below 1% RCV, assume clean environment (multiplier = 1.0)
        noise_soft_floor: 0.01,
        // Above 5% RCV, assume environment is broken/overloaded and abort test
        noise_hard_floor: 0.05,
    }
}

#[test]
fn test_kyber768_decapsulate_constant_time() {
    let config = create_kyber_config();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // 1. Setup Inputs
    let (pk, sk) = Kyber768::keypair(&mut rng).expect("Keygen failed");
    
    // Generate a valid ciphertext (C, SS)
    let (valid_ct, _valid_ss) = Kyber768::encapsulate(&mut rng, &pk).expect("Encapsulation failed");

    // Create invalid ciphertext (flip last byte) for implicit rejection check.
    // This forces the Kyber decapsulation routine into the "re-encryption check failed" path.
    // Constant-time security requires that this path takes indistinguishable time from the success path.
    let mut ct_bytes = valid_ct.to_bytes();
    if let Some(last) = ct_bytes.last_mut() {
        *last ^= 0xFF; 
    }
    let invalid_ct = <Kyber768 as Kem>::Ciphertext::from_bytes(&ct_bytes)
        .expect("Failed to deserialize manipulated ciphertext");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    // 2. Define Operations
    
    // Warmup: Just run valid decapsulation repeatedly to gauge system noise.
    // This establishes the Noise Floor (J).
    let warmup_op = || {
        let _ = Kyber768::decapsulate(&sk, &valid_ct);
    };

    // Measurement: Toggle between Valid (false) and Invalid (true) inputs.
    let measurement_op = |use_invalid: bool| {
        if use_invalid {
            let _ = Kyber768::decapsulate(&sk, &invalid_ct);
        } else {
            let _ = Kyber768::decapsulate(&sk, &valid_ct);
        }
    };

    // 3. Run Calibrated Test
    // This will internally calculate J, scale thresholds if 0.01 < J <= 0.05,
    // or panic with an error message if J > 0.05.
    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config
    ).expect("Calibration failed: Environment too noisy for reliable timing analysis");

    // 4. Reporting
    println!("Kyber768 Decapsulation Timing Analysis:");
    println!(
        "  Mean times: {:.2} ns (Valid) vs {:.2} ns (Invalid)",
        analysis.mean_a, analysis.mean_b
    );
    println!("  Mean ratio: {:.4}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!("  p-value (Student's t): {:.4}", analysis.p_value);
    println!("  Bootstrap p-value: {:.4}", analysis.bootstrap_p_value);
    println!("  KS-statistic: {:.4}", analysis.ks_statistic);
    println!("  Combined score: {:.3}", analysis.combined_score);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "Kyber768 Decapsulate");
        println!("\n{}", insights);
    }

    // 5. Assertion
    // A failure here indicates that the implicit rejection mechanism (re-encryption + comparison)
    // takes a statistically different amount of time than the normal path, which would be a
    // severe side-channel vulnerability in a KEM.
    assert!(
        analysis.is_constant_time,
        "Kyber768 decapsulation is not constant-time: combined_score={:.3} (threshold: {:.3})",
        analysis.combined_score, config.combined_score_threshold
    );
}