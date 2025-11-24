// tests/tests/constant_time/kyber.rs
use dcrypt_api::Kem;
use dcrypt_kem::kyber::Kyber768;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn create_kyber_config() -> TestConfig {
    let mut config = TestConfig::for_pqc_kem();
    config.num_samples = 50;
    config.num_iterations = 10;
    config
}

#[test]
fn test_kyber768_decapsulate_constant_time() {
    let config = create_kyber_config();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    let (pk, sk) = Kyber768::keypair(&mut rng).expect("Keygen failed");
    let (valid_ct, _valid_ss) = Kyber768::encapsulate(&mut rng, &pk).expect("Encapsulation failed");

    let mut ct_bytes = valid_ct.to_bytes();
    if let Some(last) = ct_bytes.last_mut() {
        *last ^= 0xFF; 
    }
    let invalid_ct = <Kyber768 as Kem>::Ciphertext::from_bytes(&ct_bytes)
        .expect("Failed to deserialize manipulated ciphertext");

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = Kyber768::decapsulate(&sk, &valid_ct);
    };

    let measurement_op = |use_invalid: bool| {
        if use_invalid {
            let _ = Kyber768::decapsulate(&sk, &invalid_ct);
        } else {
            let _ = Kyber768::decapsulate(&sk, &valid_ct);
        }
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "Kyber768 Decapsulate"
    ).expect("Calibration failed");

    println!("Kyber768 Decapsulation Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "Kyber768 Decapsulate"));
    }

    assert!(analysis.is_constant_time);
}