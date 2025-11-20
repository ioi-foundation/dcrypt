// tests/constant_time/xof_tests.rs
// Constant-time tests for XOF (Extendable Output Function) algorithms

use dcrypt_algorithms::xof::{Blake3Xof, ExtendableOutputFunction, ShakeXof256};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

#[test]
fn test_shake256_constant_time() {
    let config = TestConfig::for_xof();
    
    // Use non-zero patterns to avoid CPU zero-optimization artifacts
    // 0x55 = 01010101, 0xAA = 10101010 (alternating bits)
    let data_a = [0x55u8; 136]; // SHAKE-256 rate block size
    let data_b = [0xAAu8; 136];
    let output_len = 64;

    for _ in 0..config.num_warmup {
        let _ = ShakeXof256::generate(&data_a, output_len);
        let _ = ShakeXof256::generate(&data_b, output_len);
    }

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let t1 = tester.measure(|| {
        let _ = ShakeXof256::generate(&data_a, output_len);
    });
    let t2 = tester.measure(|| {
        let _ = ShakeXof256::generate(&data_b, output_len);
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1,
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold,
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("SHAKE-256 Timing Analysis:");
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
        let insights = generate_test_insights(&analysis, &config, "SHAKE-256");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "SHAKE-256 is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}

#[test]
fn test_blake3_xof_constant_time() {
    let config = TestConfig::for_blake3_xof();
    
    // Use non-zero patterns to avoid CPU zero-optimization artifacts
    let data_a = [0x55u8; 64];
    let data_b = [0xAAu8; 64];
    let output_len = 64;

    let mut output = vec![0u8; output_len];
    let mut xof = Blake3Xof::new();

    // Warm-up phase
    for _ in 0..config.num_warmup {
        xof.update(&data_a).unwrap();
        xof.squeeze(&mut output).unwrap();
        xof.reset().unwrap();
        xof.update(&data_b).unwrap();
        xof.squeeze(&mut output).unwrap();
        xof.reset().unwrap();
    }

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    // Measure timing for pattern A
    let t1 = tester.measure(|| {
        xof.update(&data_a).unwrap();
        xof.squeeze(&mut output).unwrap();
        xof.reset().unwrap();
    });

    // Measure timing for pattern B
    let t2 = tester.measure(|| {
        xof.update(&data_b).unwrap();
        xof.squeeze(&mut output).unwrap();
        xof.reset().unwrap();
    });

    // Use instance method instead of associated function
    let analysis = match tester.analyze_constant_time(
        &t1,
        &t2,
        config.mean_ratio_max,
        config.t_stat_threshold,
        config.combined_score_threshold,
    ) {
        Ok(result) => result,
        Err(e) => panic!("Analysis error: {}", e),
    };

    // Output detailed diagnostics with new metrics
    println!("BLAKE3-XOF Timing Analysis:");
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
        let insights = generate_test_insights(&analysis, &config, "BLAKE3-XOF");
        println!("\n{}", insights);
    }

    // Assert that the implementation is constant-time
    assert!(
        analysis.is_constant_time,
        "BLAKE3-XOF is not constant-time: combined_score={:.3} (threshold: {:.3})\nUse VERBOSE=1 for detailed insights",
        analysis.combined_score, config.combined_score_threshold
    );
}