// tests/constant_time/mac_tests.rs
use dcrypt_algorithms::hash::Sha256;
use dcrypt_algorithms::mac::hmac::Hmac;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    generate_test_insights, prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};

struct PreparedMessage {
    current: [u8; 64],
    class_a: [u8; 64],
    class_b: [u8; 64],
}

impl PreparedMessage {
    fn prepare(&mut self, class: TimingClass) {
        prepare_bytes(&mut self.current, &self.class_a, &self.class_b, class);
    }
}

pub(super) fn measure_hmac_sha256_constant_time() -> Result<TimingAnalysis, String> {
    let config = TestConfig::for_mac();
    let key = [0x0bu8; 32];
    let data_zeros = [0u8; 64];
    let data_ones = [1u8; 64];
    let mut state = PreparedMessage {
        current: data_zeros,
        class_a: data_zeros,
        class_b: data_ones,
    };

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedMessage| {
        std::hint::black_box(Hmac::<Sha256>::mac(&key, &prepared.current));
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedMessage::prepare,
        measurement_op,
        &config,
        "HMAC-SHA256",
    )?;

    println!("HMAC-SHA256 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "HMAC-SHA256")
        );
    }

    Ok(analysis)
}
