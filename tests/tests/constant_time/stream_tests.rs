// tests/constant_time/stream_tests.rs
use dcrypt_algorithms::stream::chacha::chacha20::{
    ChaCha20, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE,
};
use dcrypt_algorithms::types::Nonce;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

#[test]
fn test_chacha20_constant_time() {
    let config = TestConfig::for_chacha_poly(); // Reusing ChaChaPoly config
    let key = [0x42u8; CHACHA20_KEY_SIZE];
    let nonce_bytes = [0x24u8; CHACHA20_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20_NONCE_SIZE>::new(nonce_bytes);

    let data_zeros = [0u8; 64];
    let data_ones = [1u8; 64];

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let mut chacha = ChaCha20::new(&key, &nonce);
        let mut buf = data_zeros.clone();
        chacha.encrypt(&mut buf);
    };

    let measurement_op = |use_ones: bool| {
        let mut buf = if use_ones { data_ones } else { data_zeros };
        let mut chacha = ChaCha20::new(&key, &nonce);
        chacha.encrypt(&mut buf);
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "ChaCha20"
    ).expect("Calibration failed");

    println!("ChaCha20 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "ChaCha20"));
    }

    assert!(analysis.is_constant_time);
}