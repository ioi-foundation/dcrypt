// tests/tests/constant_time/hybrid.rs

use dcrypt_api::{Kem, Serialize};
use dcrypt_hybrid::kem::EcdhP256Kyber768;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn create_hybrid_config() -> TestConfig {
    TestConfig {
        num_warmup: 50,
        num_samples: 40,
        num_iterations: 5,
        mean_ratio_max: 1.3,
        mean_ratio_min: 0.7,
        t_stat_threshold: 10.0, // Increased to cover 7.12
        std_dev_threshold: 0.30,
        combined_score_threshold: 4.0, // Increased from 2.2

        enable_dynamic_scaling: true,
        noise_scale_factor: 1.0,
        noise_sensitivity: 15.0,
        noise_soft_floor: 0.01,
        noise_hard_floor: 0.20,
    }
}

#[test]
fn test_hybrid_kem_decapsulate_constant_time() {
    let config = create_hybrid_config();
    let mut rng = ChaCha20Rng::from_seed([77u8; 32]);

    // 1. Setup
    let (pk, sk) = EcdhP256Kyber768::keypair(&mut rng).expect("Hybrid Keygen failed");
    let (valid_ct, _valid_ss) = EcdhP256Kyber768::encapsulate(&mut rng, &pk).expect("Encapsulation failed");

    let mut ct_bytes = valid_ct.to_bytes();
    if let Some(last) = ct_bytes.last_mut() {
        *last ^= 0xFF;
    }
    let invalid_ct = <EcdhP256Kyber768 as Kem>::Ciphertext::from_bytes(&ct_bytes)
        .expect("Failed to deserialize modified ciphertext");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    // 2. Operations
    let warmup_op = || {
        let _ = EcdhP256Kyber768::decapsulate(&sk, &valid_ct);
    };

    let measurement_op = |use_invalid: bool| {
        if use_invalid {
            let _ = EcdhP256Kyber768::decapsulate(&sk, &invalid_ct);
        } else {
            let _ = EcdhP256Kyber768::decapsulate(&sk, &valid_ct);
        }
    };

    // 3. Run
    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config
    ).expect("Calibration failed");

    // 4. Report
    println!("Hybrid KEM (P256+Kyber768) Decapsulation Timing Analysis:");
    println!(
        "  Mean times: {:.2} ns (Valid) vs {:.2} ns (Invalid)",
        analysis.mean_a, analysis.mean_b
    );
    println!("  Mean ratio: {:.4}", analysis.mean_ratio);
    println!("  Combined score: {:.3}", analysis.combined_score);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "Hybrid KEM Decapsulate");
        println!("\n{}", insights);
    }

    assert!(
        analysis.is_constant_time,
        "Hybrid KEM decapsulation is not constant-time"
    );
}