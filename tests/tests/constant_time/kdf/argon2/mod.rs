// tests/tests/constant_time/kdf/argon2/mod.rs
use dcrypt_algorithms::kdf::argon2::{Algorithm, Argon2, Params};
use dcrypt_algorithms::kdf::PasswordHashFunction;
use dcrypt_algorithms::types::Salt;
use dcrypt_api::types::{SecretBytes, ZeroizingBytes};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    generate_test_insights, prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};

struct PreparedVerifyPassword {
    current: SecretBytes<32>,
    class_a: SecretBytes<32>,
    class_b: SecretBytes<32>,
}

impl PreparedVerifyPassword {
    fn prepare(&mut self, class: TimingClass) {
        let current_ptr = self.current.as_ref().as_ptr();
        let current_len = self.current.len();
        prepare_bytes(
            self.current.as_mut(),
            self.class_a.as_ref(),
            self.class_b.as_ref(),
            class,
        );
        assert_eq!(self.current.as_ref().as_ptr(), current_ptr);
        assert_eq!(self.current.len(), current_len);
    }
}

struct PreparedHash {
    current: ZeroizingBytes,
    class_a: ZeroizingBytes,
    class_b: ZeroizingBytes,
}

impl PreparedHash {
    fn prepare(&mut self, class: TimingClass) {
        let current_ptr = self.current.as_slice().as_ptr();
        let current_len = self.current.len();
        let current_capacity = self.current.capacity();
        prepare_bytes(
            self.current.as_mut_slice(),
            self.class_a.as_slice(),
            self.class_b.as_slice(),
            class,
        );
        assert_eq!(self.current.as_slice().as_ptr(), current_ptr);
        assert_eq!(self.current.len(), current_len);
        assert_eq!(self.current.capacity(), current_capacity);
    }
}

fn create_argon2_config() -> TestConfig {
    let mut config = TestConfig::default();
    config.num_warmup = 5;
    config.num_samples = 30;
    config.num_iterations = 3;
    config.practical_significance_threshold = 10.0; // Heavy op
    config
}

pub(super) fn measure_argon2id_verify_constant_time() -> Result<TimingAnalysis, String> {
    const SALT_LEN: usize = 16;

    let mut correct_pw_bytes = [0u8; 32];
    correct_pw_bytes[..16].copy_from_slice(b"correct_password");
    let correct_password = SecretBytes::<32>::new(correct_pw_bytes);

    let mut wrong_pw_bytes = [0u8; 32];
    wrong_pw_bytes[..14].copy_from_slice(b"wrong_password");
    let wrong_password_a = SecretBytes::<32>::new(wrong_pw_bytes);

    let mut other_wrong_pw_bytes = [0u8; 32];
    other_wrong_pw_bytes[..14].copy_from_slice(b"other_password");
    let wrong_password_b = SecretBytes::<32>::new(other_wrong_pw_bytes);

    let salt = Salt::<SALT_LEN>::new([0x42; SALT_LEN]);

    let params = Params {
        argon_type: Algorithm::Argon2id,
        version: 0x13,
        memory_cost: 8 * 4,
        time_cost: 1,
        parallelism: 4,
        output_len: 32,
        salt: salt.clone(),
        ad: None,
        secret: None,
    };

    let argon2 = Argon2::new_with_params(params);
    let hash_result = argon2
        .hash_password(correct_password.as_ref())
        .expect("Hashing failed");

    let stored_hash = dcrypt_algorithms::kdf::PasswordHash {
        algorithm: "argon2id".to_string(),
        params: [
            ("v".to_string(), "19".to_string()),
            ("m".to_string(), "32".to_string()),
            ("t".to_string(), "1".to_string()),
            ("p".to_string(), "4".to_string()),
        ]
        .iter()
        .cloned()
        .collect(),
        salt: salt.as_ref().to_vec(),
        hash: hash_result.into_inner().into_vec(),
    };
    let class_a_result = argon2.verify(&wrong_password_a, &stored_hash);
    let class_b_result = argon2.verify(&wrong_password_b, &stored_hash);
    assert_eq!(
        class_a_result.is_ok(),
        class_b_result.is_ok(),
        "Argon2 timing classes must have the same error/result class"
    );
    assert!(
        matches!(class_a_result, Ok(false)) && matches!(class_b_result, Ok(false)),
        "Argon2 timing classes must both be incorrect-password results"
    );
    let mut state = PreparedVerifyPassword {
        current: wrong_password_a.clone(),
        class_a: wrong_password_a,
        class_b: wrong_password_b,
    };

    let config = create_argon2_config();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedVerifyPassword| {
        let _ = std::hint::black_box(argon2.verify(&prepared.current, &stored_hash));
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedVerifyPassword::prepare,
        measurement_op,
        &config,
        "Argon2id Verify",
    )?;

    println!("Argon2id Verify Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "Argon2id Verify")
        );
    }

    Ok(analysis)
}

pub(super) fn measure_argon2_constant_time_compare() -> Result<TimingAnalysis, String> {
    const SALT_LEN: usize = 16;
    let salt = Salt::<SALT_LEN>::new([0x42; SALT_LEN]);

    let params = Params {
        argon_type: Algorithm::Argon2id,
        version: 0x13,
        memory_cost: 8 * 4,
        time_cost: 1,
        parallelism: 4,
        output_len: 32,
        salt: salt.clone(),
        ad: None,
        secret: None,
    };

    let mut pw_bytes = [0u8; 32];
    pw_bytes[..13].copy_from_slice(b"test_password");
    let password = SecretBytes::<32>::new(pw_bytes);

    let argon2 = Argon2::new_with_params(params);
    let hash1 = argon2.hash_password(password.as_ref()).unwrap();

    let mut hash2 = hash1.clone();
    if !hash2.is_empty() {
        hash2[0] ^= 0x01;
    }

    let mut hash3 = hash1.clone();
    if !hash3.is_empty() {
        let idx = hash3.len() - 1;
        hash3[idx] ^= 0x01;
    }
    assert_eq!(hash2.len(), hash3.len());
    let mut state = PreparedHash {
        current: hash2.clone(),
        class_a: hash2,
        class_b: hash3,
    };

    let config = create_argon2_config();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let measurement_op = |prepared: &PreparedHash| {
        std::hint::black_box(dcrypt_algorithms::kdf::common::constant_time_eq(
            hash1.as_slice(),
            prepared.current.as_slice(),
        ));
    };

    let analysis = tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedHash::prepare,
        measurement_op,
        &config,
        "Argon2 Comparison",
    )?;

    println!("Argon2 Comparison Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);

    if std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "Argon2 Comparison")
        );
    }

    Ok(analysis)
}
