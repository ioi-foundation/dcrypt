// Timing regressions for secret-scalar multiplication.

use dcrypt_algorithms::ec::{
    k256::{self, Scalar as K256Scalar, K256_SCALAR_SIZE},
    p224::{self, Scalar as P224Scalar, P224_SCALAR_SIZE},
    p256::{self, Scalar as P256Scalar, P256_SCALAR_SIZE},
    p384::{self, Scalar as P384Scalar, P384_SCALAR_SIZE},
    p521::{self, Scalar as P521Scalar, P521_SCALAR_SIZE},
};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};
use std::hint::black_box;

struct PreparedScalar<S, const N: usize> {
    current: S,
    input_a: [u8; N],
    input_b: [u8; N],
    current_address: Option<usize>,
}

impl<S, const N: usize> PreparedScalar<S, N> {
    fn new(current: S, input_a: [u8; N], input_b: [u8; N]) -> Self {
        Self {
            current,
            input_a,
            input_b,
            current_address: None,
        }
    }

    fn enforce_stable_current_address(&mut self) {
        let address = std::ptr::from_ref(&self.current).addr();
        if let Some(expected) = self.current_address {
            assert_eq!(address, expected);
        } else {
            self.current_address = Some(address);
        }
    }

    fn selected_bytes(&self, class: TimingClass) -> [u8; N] {
        let mut selected = [0u8; N];
        prepare_bytes(&mut selected, &self.input_a, &self.input_b, class);
        selected
    }
}

fn scalar_inputs<const N: usize>() -> Result<([u8; N], [u8; N]), String> {
    if N == 0 {
        return Err("scalar timing fixture cannot use an empty encoding".to_string());
    }

    let mut low_weight = [0u8; N];
    low_weight[N - 1] = 1;
    let mut high_weight = [0xffu8; N];
    high_weight[0] = 0;
    Ok((low_weight, high_weight))
}

fn ecdh_config() -> TestConfig {
    let mut config = TestConfig::default();
    config.num_warmup = 100;
    config.num_samples = 50;
    config.num_iterations = 20;
    config.practical_significance_threshold = 2.0;
    config
}

macro_rules! define_scalar_timing_case {
    ($function:ident, $base_point:expr, $scalar:ty, $size:expr, $name:literal) => {
        pub(super) fn $function() -> Result<TimingAnalysis, String> {
            let config = ecdh_config();
            let tester = TimingTester::new(config.num_samples, config.num_iterations);
            let base_point = $base_point;
            let (input_a, input_b) = scalar_inputs::<$size>()?;
            let current = <$scalar>::new(input_a)
                .map_err(|error| format!("{} class A scalar is invalid: {error}", $name))?;
            drop(
                <$scalar>::new(input_b)
                    .map_err(|error| format!("{} class B scalar is invalid: {error}", $name))?,
            );
            let mut state = PreparedScalar::new(current, input_a, input_b);

            tester.calibrate_and_measure_prepared(
                &mut state,
                |state, class| {
                    state.enforce_stable_current_address();
                    let selected = state.selected_bytes(class);
                    state.current = <$scalar>::new(selected)
                        .expect("prevalidated scalar timing class must remain valid");
                    state.enforce_stable_current_address();
                },
                |state| {
                    drop(black_box(base_point.mul(black_box(&state.current))));
                },
                &config,
                $name,
            )
        }
    };
}

define_scalar_timing_case!(
    measure_p224_scalar_mult,
    p224::base_point_g(),
    P224Scalar,
    P224_SCALAR_SIZE,
    "ECDH P-224 Scalar Mult"
);

define_scalar_timing_case!(
    measure_p256_scalar_mult,
    p256::base_point_g(),
    P256Scalar,
    P256_SCALAR_SIZE,
    "ECDH P-256 Scalar Mult"
);

define_scalar_timing_case!(
    measure_k256_scalar_mult,
    k256::base_point_g(),
    K256Scalar,
    K256_SCALAR_SIZE,
    "ECDH K-256 Scalar Mult"
);

define_scalar_timing_case!(
    measure_p384_scalar_mult,
    p384::base_point_g(),
    P384Scalar,
    P384_SCALAR_SIZE,
    "ECDH P-384 Scalar Mult"
);

define_scalar_timing_case!(
    measure_p521_scalar_mult,
    p521::base_point_g(),
    P521Scalar,
    P521_SCALAR_SIZE,
    "ECDH P-521 Scalar Mult"
);
