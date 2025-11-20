// tests/constant_time/block_cipher_tests.rs
// Constant-time tests for block ciphers

use dcrypt_algorithms::block::aes::Aes128;
use dcrypt_algorithms::block::BlockCipher;
use dcrypt_api::types::SecretBytes;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

#[test]
fn test_aes_constant_time() {
    let config = TestConfig::for_block_cipher();
    // Convert raw key bytes to SecretBytes
    let key_bytes = [0u8; 16];
    let key = SecretBytes::<16>::new(key_bytes);
    let cipher = Aes128::new(&key);

    // Use non-zero patterns to avoid CPU zero-optimizations
    // Previous [0u8; 16] vs [1u8; 16] caused artifacts due to hardware-level 
    // optimizations for zero buffers.
    let plain_a = [0x55u8; 16];
    let plain_b = [0xAAu8; 16];

    // Warm-up phase
    for _ in 0..config.num_warmup {
        let mut b0 = plain_a;
        let mut b1 = plain_b;
        cipher.encrypt_block(&mut b0).unwrap();
        cipher.encrypt_block(&mut b1).unwrap();
    }

    // Use configured sample/iteration counts
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    // Measure encrypting pattern A
    let times0 = tester.measure(|| {
        let mut buf = plain_a;
        cipher.encrypt_block(&mut buf).unwrap();
    });

    // Measure encrypting pattern B
    let times1 = tester.measure(|| {
        let mut buf = plain_b;
        cipher.encrypt_block(&mut buf).unwrap();
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &times0,
        &times1,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold,
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("AES Timing Analysis:");
    println!(
        "  Mean times: {:.2} ns vs {:.2} ns",
        analysis.mean_a, analysis.mean_b
    );
    println!("  Mean ratio: {:.3}", analysis.mean_ratio);
    println!("  t-statistic: {:.3}", analysis.t_statistic);
    println!(
        "  p-value: {:.4} (calculated from t-distribution)",
        analysis.p_value
    );
    println!(
        "  Effect size (Cohen's d): {:.3} - {}",
        analysis.cohens_d, analysis.effect_size_interpretation
    );
    println!(
        "  95% CI for mean difference: ({:.2}, {:.2}) ns",
        analysis.confidence_interval.0, analysis.confidence_interval.1
    );
    println!("  Combined score: {:.3}", analysis.combined_score);
    println!(
        "  Relative std dev A: {:.3}",
        analysis.std_dev_a / analysis.mean_a
    );
    println!(
        "  Relative std dev B: {:.3}",
        analysis.std_dev_b / analysis.mean_b
    );

    // Generate insights for failed tests or in verbose mode
    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        let insights = generate_test_insights(&analysis, &config, "AES");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "AES implementation is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}