// tests/constant_time/hash_tests.rs
use dcrypt_algorithms::hash::{HashFunction, Sha256, Sha3_256};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    generate_test_insights, prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};

struct PreparedInput<const N: usize> {
    current: [u8; N],
    class_a: [u8; N],
    class_b: [u8; N],
}

impl<const N: usize> PreparedInput<N> {
    fn prepare(&mut self, class: TimingClass) {
        prepare_bytes(&mut self.current, &self.class_a, &self.class_b, class);
    }
}

pub(super) fn measure_sha256_constant_time() -> Result<TimingAnalysis, String> {
    let config = TestConfig::for_hash();
    let data_a = [0x55u8; 64];
    let data_b = [0xAAu8; 64];
    let mut state = PreparedInput {
        current: data_a,
        class_a: data_a,
        class_b: data_b,
    };

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedInput<64>| {
        let _ = std::hint::black_box(Sha256::digest(&prepared.current));
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedInput::prepare,
        measurement_op,
        &config,
        "SHA-256",
    )?;

    println!("SHA-256 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "SHA-256")
        );
    }

    Ok(analysis)
}

pub(super) fn measure_sha3_256_constant_time() -> Result<TimingAnalysis, String> {
    let config = TestConfig::for_hash();
    let data_a = [0x55u8; 136];
    let data_b = [0xAAu8; 136];
    let mut state = PreparedInput {
        current: data_a,
        class_a: data_a,
        class_b: data_b,
    };

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedInput<136>| {
        let _ = std::hint::black_box(Sha3_256::digest(&prepared.current));
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedInput::prepare,
        measurement_op,
        &config,
        "SHA3-256",
    )?;

    println!("SHA3-256 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "SHA3-256")
        );
    }

    Ok(analysis)
}
