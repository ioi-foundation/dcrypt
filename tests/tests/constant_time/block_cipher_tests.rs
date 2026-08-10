// tests/constant_time/block_cipher_tests.rs
use dcrypt_algorithms::block::aes::Aes128;
use dcrypt_algorithms::block::BlockCipher;
use dcrypt_api::types::SecretBytes;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    generate_test_insights, prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};

struct PreparedBlock {
    current: [u8; 16],
    class_a: [u8; 16],
    class_b: [u8; 16],
}

impl PreparedBlock {
    fn prepare(&mut self, class: TimingClass) {
        prepare_bytes(&mut self.current, &self.class_a, &self.class_b, class);
    }
}

pub(super) fn measure_aes_constant_time() -> Result<TimingAnalysis, String> {
    let config = TestConfig::for_block_cipher();
    let key_bytes = [0u8; 16];
    let key = SecretBytes::<16>::new(key_bytes);
    let cipher = Aes128::new(&key);

    let plain_a = [0x55u8; 16];
    let plain_b = [0xAAu8; 16];
    let mut state = PreparedBlock {
        current: plain_a,
        class_a: plain_a,
        class_b: plain_b,
    };

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedBlock| {
        let mut buf = prepared.current;
        cipher.encrypt_block(&mut buf).unwrap();
        std::hint::black_box(buf);
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedBlock::prepare,
        measurement_op,
        &config,
        "AES-128",
    )?;

    println!("AES-128 Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );
    println!("  Cohen's d: {:.3}", analysis.cohens_d);

    if std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "AES-128")
        );
    }

    Ok(analysis)
}
