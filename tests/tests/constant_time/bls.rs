use dcrypt_algorithms::ec::bls12_381::{G1Projective, G2Projective};
use dcrypt_internal::Zeroize;
use dcrypt_sign::bls::BLS_POP_G2_DST;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};
use std::hint::black_box;

const LOW_WEIGHT_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const HIGH_WEIGHT_SCALAR: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
];

struct PreparedBlsScalar {
    current: [u8; 32],
    input_a: [u8; 32],
    input_b: [u8; 32],
    current_address: Option<usize>,
}

impl PreparedBlsScalar {
    fn new() -> Self {
        Self {
            current: LOW_WEIGHT_SCALAR,
            input_a: LOW_WEIGHT_SCALAR,
            input_b: HIGH_WEIGHT_SCALAR,
            current_address: None,
        }
    }

    fn prepare(&mut self, class: TimingClass) {
        self.enforce_stable_current_address();
        prepare_bytes(&mut self.current, &self.input_a, &self.input_b, class);
        self.enforce_stable_current_address();
    }

    fn enforce_stable_current_address(&mut self) {
        let address = std::ptr::from_ref(&self.current).addr();
        if let Some(expected) = self.current_address {
            assert_eq!(address, expected);
        } else {
            self.current_address = Some(address);
        }
    }
}

fn bls_config() -> TestConfig {
    let mut config = TestConfig::default();
    config.num_warmup = 100;
    config.num_samples = 200;
    config.num_iterations = 2;
    // BLS12-381 group arithmetic is a comparatively long operation, so ordinary
    // host scheduling noise is substantially larger than for a block cipher.
    config.practical_significance_threshold = 5_000.0;
    config
}

pub(super) fn measure_bls_g1_secret_scalar_multiplication() -> Result<TimingAnalysis, String> {
    let config = bls_config();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    let point = G1Projective::generator();
    let mut state = PreparedBlsScalar::new();

    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedBlsScalar::prepare,
        |state| {
            let mut result = point
                .multiply_secret_be_bytes(black_box(&state.current))
                .expect("fixed BLS G1 timing scalar must be valid");
            black_box(&result);
            result.zeroize();
        },
        &config,
        "BLS12-381 G1 secret scalar multiplication",
    )
}

pub(super) fn measure_bls_g2_secret_scalar_multiplication() -> Result<TimingAnalysis, String> {
    let config = bls_config();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    let point = G2Projective::hash_to_curve(b"fixed timing message", BLS_POP_G2_DST)
        .map_err(|error| format!("fixed BLS G2 timing point is invalid: {error}"))?;
    let mut state = PreparedBlsScalar::new();

    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedBlsScalar::prepare,
        |state| {
            let mut result = point
                .multiply_secret_be_bytes(black_box(&state.current))
                .expect("fixed BLS G2 timing scalar must be valid");
            black_box(&result);
            result.zeroize();
        },
        &config,
        "BLS12-381 G2 secret scalar multiplication",
    )
}
