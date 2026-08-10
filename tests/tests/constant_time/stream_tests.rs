// tests/constant_time/stream_tests.rs
use dcrypt_algorithms::stream::chacha::chacha20::{
    ChaCha20, CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE,
};
use dcrypt_algorithms::types::Nonce;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    generate_test_insights, prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};

struct PreparedStreamInput {
    current: [u8; 64],
    class_a: [u8; 64],
    class_b: [u8; 64],
}

impl PreparedStreamInput {
    fn prepare(&mut self, class: TimingClass) {
        prepare_bytes(&mut self.current, &self.class_a, &self.class_b, class);
    }
}

pub(super) fn measure_chacha20_constant_time() -> Result<TimingAnalysis, String> {
    let config = TestConfig::for_chacha_poly(); // Reusing ChaChaPoly config
    let key = [0x42u8; CHACHA20_KEY_SIZE];
    let nonce_bytes = [0x24u8; CHACHA20_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20_NONCE_SIZE>::new(nonce_bytes);

    let data_zeros = [0u8; 64];
    let data_ones = [1u8; 64];
    let mut state = PreparedStreamInput {
        current: data_zeros,
        class_a: data_zeros,
        class_b: data_ones,
    };

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedStreamInput| {
        let mut buf = prepared.current;
        let mut chacha = ChaCha20::new(&key, &nonce);
        chacha.encrypt(&mut buf).unwrap();
        std::hint::black_box(buf);
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedStreamInput::prepare,
        measurement_op,
        &config,
        "ChaCha20",
    )?;

    println!("ChaCha20 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "ChaCha20")
        );
    }

    Ok(analysis)
}
