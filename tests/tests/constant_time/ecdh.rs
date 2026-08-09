// tests/tests/constant_time/ecdh.rs
use dcrypt_algorithms::ec::{
    k256::{self, Scalar as K256Scalar, K256_SCALAR_SIZE},
    p224::{self, Scalar as P224Scalar, P224_SCALAR_SIZE},
    p256::{self, Scalar as P256Scalar, P256_SCALAR_SIZE},
    p384::{self, Scalar as P384Scalar, P384_SCALAR_SIZE},
    p521::{self, Scalar as P521Scalar, P521_SCALAR_SIZE},
};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

fn create_ecdh_config() -> TestConfig {
    let mut config = TestConfig::default();
    config.num_warmup = 100;
    config.num_samples = 50;
    config.num_iterations = 20;
    config.practical_significance_threshold = 2.0;
    config
}

fn assert_scalar_mult_timing<W, M>(name: &str, warmup_op: W, measurement_op: M)
where
    W: FnMut(),
    M: FnMut(bool),
{
    let config = create_ecdh_config();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    let analysis = tester
        .calibrate_and_measure(warmup_op, measurement_op, &config, name)
        .expect("Calibration failed");

    println!("{name} Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, name));
    }

    assert!(analysis.is_constant_time);
}

#[test]
fn test_p224_scalar_mult_constant_time() {
    let base_point = p224::base_point_g();

    let mut low_weight_bytes = [0u8; P224_SCALAR_SIZE];
    low_weight_bytes[P224_SCALAR_SIZE - 1] = 1;
    let scalar_low = P224Scalar::new(low_weight_bytes).expect("Invalid scalar");

    let mut high_weight_bytes = [0xFFu8; P224_SCALAR_SIZE];
    high_weight_bytes[0] = 0x00; // Ensure < n
    let scalar_high = P224Scalar::new(high_weight_bytes).expect("Invalid scalar");

    assert_scalar_mult_timing(
        "ECDH P-224 Scalar Mult",
        || {
            let _ = base_point.mul(&scalar_low);
        },
        |high_weight| {
            if high_weight {
                let _ = base_point.mul(&scalar_high);
            } else {
                let _ = base_point.mul(&scalar_low);
            }
        },
    );
}

#[test]
fn test_p256_scalar_mult_constant_time() {
    let base_point = p256::base_point_g();

    let mut low_weight_bytes = [0u8; P256_SCALAR_SIZE];
    low_weight_bytes[P256_SCALAR_SIZE - 1] = 1;
    let scalar_low = P256Scalar::new(low_weight_bytes).expect("Invalid scalar");

    let mut high_weight_bytes = [0xFFu8; P256_SCALAR_SIZE];
    high_weight_bytes[0] = 0x00; // Ensure < n
    let scalar_high = P256Scalar::new(high_weight_bytes).expect("Invalid scalar");

    assert_scalar_mult_timing(
        "ECDH P-256 Scalar Mult",
        || {
            let _ = base_point.mul(&scalar_low);
        },
        |high_weight| {
            if high_weight {
                let _ = base_point.mul(&scalar_high);
            } else {
                let _ = base_point.mul(&scalar_low);
            }
        },
    );
}

#[test]
fn test_k256_scalar_mult_constant_time() {
    let base_point = k256::base_point_g();

    let mut low_weight_bytes = [0u8; K256_SCALAR_SIZE];
    low_weight_bytes[K256_SCALAR_SIZE - 1] = 1;
    let scalar_low = K256Scalar::new(low_weight_bytes).expect("Invalid scalar");

    let mut high_weight_bytes = [0xFFu8; K256_SCALAR_SIZE];
    high_weight_bytes[0] = 0x00; // Ensure < n
    let scalar_high = K256Scalar::new(high_weight_bytes).expect("Invalid scalar");

    assert_scalar_mult_timing(
        "ECDH K-256 Scalar Mult",
        || {
            let _ = base_point.mul(&scalar_low);
        },
        |high_weight| {
            if high_weight {
                let _ = base_point.mul(&scalar_high);
            } else {
                let _ = base_point.mul(&scalar_low);
            }
        },
    );
}

#[test]
fn test_p384_scalar_mult_constant_time() {
    let base_point = p384::base_point_g();

    let mut low_weight_bytes = [0u8; P384_SCALAR_SIZE];
    low_weight_bytes[P384_SCALAR_SIZE - 1] = 1;
    let scalar_low = P384Scalar::new(low_weight_bytes).expect("Invalid scalar");

    let mut high_weight_bytes = [0xFFu8; P384_SCALAR_SIZE];
    high_weight_bytes[0] = 0x00; // Ensure < n
    let scalar_high = P384Scalar::new(high_weight_bytes).expect("Invalid scalar");

    assert_scalar_mult_timing(
        "ECDH P-384 Scalar Mult",
        || {
            let _ = base_point.mul(&scalar_low);
        },
        |high_weight| {
            if high_weight {
                let _ = base_point.mul(&scalar_high);
            } else {
                let _ = base_point.mul(&scalar_low);
            }
        },
    );
}

#[test]
fn test_p521_scalar_mult_constant_time() {
    let base_point = p521::base_point_g();

    let mut low_weight_bytes = [0u8; P521_SCALAR_SIZE];
    low_weight_bytes[P521_SCALAR_SIZE - 1] = 1;
    let scalar_low = P521Scalar::new(low_weight_bytes).expect("Invalid scalar");

    let mut high_weight_bytes = [0xFFu8; P521_SCALAR_SIZE];
    high_weight_bytes[0] = 0x00; // Ensure < n
    let scalar_high = P521Scalar::new(high_weight_bytes).expect("Invalid scalar");

    assert_scalar_mult_timing(
        "ECDH P-521 Scalar Mult",
        || {
            let _ = base_point.mul(&scalar_low);
        },
        |high_weight| {
            if high_weight {
                let _ = base_point.mul(&scalar_high);
            } else {
                let _ = base_point.mul(&scalar_low);
            }
        },
    );
}
