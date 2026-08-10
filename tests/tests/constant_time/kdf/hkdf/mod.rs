// tests/tests/constant_time/kdf/hkdf/mod.rs
use dcrypt_algorithms::hash::Sha256;
use dcrypt_algorithms::kdf::hkdf::Hkdf;
use dcrypt_algorithms::kdf::KeyDerivationFunction;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    generate_test_insights, prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};

struct PreparedSecret {
    current: [u8; 32],
    class_a: [u8; 32],
    class_b: [u8; 32],
}

impl PreparedSecret {
    fn prepare(&mut self, class: TimingClass) {
        prepare_bytes(&mut self.current, &self.class_a, &self.class_b, class);
    }
}

fn create_hkdf_config() -> TestConfig {
    TestConfig::for_hkdf()
}

pub(super) fn measure_hkdf_constant_time() -> Result<TimingAnalysis, String> {
    let config = create_hkdf_config();
    let secret1 = [0x0bu8; 32];
    let secret2 = [0x0cu8; 32];
    let salt = Some(&[0x0au8; 16][..]);
    let info = Some(&[0x01u8; 8][..]);
    let output_len = 32;
    let mut state = PreparedSecret {
        current: secret1,
        class_a: secret1,
        class_b: secret2,
    };

    let hkdf = Hkdf::<Sha256>::new();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedSecret| {
        std::hint::black_box(hkdf.derive_key(&prepared.current, salt, info, output_len));
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedSecret::prepare,
        measurement_op,
        &config,
        "HKDF",
    )?;

    println!("HKDF Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "HKDF"));
    }

    Ok(analysis)
}
