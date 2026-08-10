// tests/tests/constant_time/kdf/pbkdf2/mod.rs
use dcrypt_algorithms::hash::Sha256;
use dcrypt_algorithms::kdf::pbkdf2::Pbkdf2;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    generate_test_insights, prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};

struct PreparedPassword {
    current: [u8; 32],
    class_a: [u8; 32],
    class_b: [u8; 32],
}

impl PreparedPassword {
    fn prepare(&mut self, class: TimingClass) {
        prepare_bytes(&mut self.current, &self.class_a, &self.class_b, class);
    }
}

fn create_pbkdf2_config() -> TestConfig {
    TestConfig::for_pbkdf2()
}

pub(super) fn measure_pbkdf2_constant_time() -> Result<TimingAnalysis, String> {
    let config = create_pbkdf2_config();
    let iterations = 50;
    // Password length is public to this slice-based API and affects ordinary
    // allocation, copying, and hash-input work. Keep it fixed so this A/B test
    // isolates secret contents rather than comparing 28-byte and 11-byte jobs.
    let password1_bytes = [0x00; 32];
    let password2_bytes = [0xff; 32];
    let salt = &[0x73, 0x61, 0x6c, 0x74];
    let output_len = 32;

    assert_eq!(
        password1_bytes.len(),
        password2_bytes.len(),
        "timing classes must use equal public password lengths"
    );
    let mut state = PreparedPassword {
        current: password1_bytes,
        class_a: password1_bytes,
        class_b: password2_bytes,
    };

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedPassword| {
        let _ = std::hint::black_box(Pbkdf2::<Sha256>::pbkdf2(
            &prepared.current,
            salt,
            iterations,
            output_len,
        ));
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedPassword::prepare,
        measurement_op,
        &config,
        "PBKDF2",
    )?;

    println!("PBKDF2 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "PBKDF2"));
    }

    Ok(analysis)
}
