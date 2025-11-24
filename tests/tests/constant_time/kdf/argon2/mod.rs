// tests/tests/constant_time/kdf/argon2/mod.rs
use dcrypt_algorithms::kdf::argon2::{Algorithm, Argon2, Params};
use dcrypt_algorithms::kdf::PasswordHashFunction;
use dcrypt_algorithms::types::Salt;
use dcrypt_api::types::SecretBytes;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

fn create_argon2_config() -> TestConfig {
    let mut config = TestConfig::default();
    config.num_warmup = 5;
    config.num_samples = 30;
    config.num_iterations = 3;
    config.practical_significance_threshold = 10.0; // Heavy op
    config
}

#[test]
fn test_argon2id_verify_constant_time() {
    const SALT_LEN: usize = 16;

    let mut correct_pw_bytes = [0u8; 32];
    correct_pw_bytes[..16].copy_from_slice(b"correct_password");
    let correct_password = SecretBytes::<32>::new(correct_pw_bytes);

    let mut wrong_pw_bytes = [0u8; 32];
    wrong_pw_bytes[..14].copy_from_slice(b"wrong_password");
    let wrong_password = SecretBytes::<32>::new(wrong_pw_bytes);

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
        salt: salt.as_ref().to_vec().into(),
        hash: hash_result,
    };

    let config = create_argon2_config();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = argon2.verify(&correct_password, &stored_hash);
    };

    let measurement_op = |use_wrong: bool| {
        if use_wrong {
            let _ = argon2.verify(&wrong_password, &stored_hash);
        } else {
            let _ = argon2.verify(&correct_password, &stored_hash);
        }
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "Argon2id Verify"
    ).expect("Calibration failed");

    println!("Argon2id Verify Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!("  99% CI: [{:.3}, {:.3}] ns", analysis.ci_lower, analysis.ci_upper);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "Argon2id Verify"));
    }

    assert!(analysis.is_constant_time);
}

#[test]
fn test_argon2_constant_time_compare() {
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
    if !hash2.is_empty() { hash2[0] ^= 0x01; }

    let mut hash3 = hash1.clone();
    if !hash3.is_empty() { 
        let idx = hash3.len() - 1;
        hash3[idx] ^= 0x01; 
    }

    let config = create_argon2_config();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
         dcrypt_algorithms::kdf::common::constant_time_eq(&hash1, &hash2);
    };

    let measurement_op = |use_hash3: bool| {
        if use_hash3 {
             dcrypt_algorithms::kdf::common::constant_time_eq(&hash1, &hash3);
        } else {
             dcrypt_algorithms::kdf::common::constant_time_eq(&hash1, &hash2);
        }
    };

    let analysis = tester.calibrate_and_measure(
        warmup_op,
        measurement_op,
        &config,
        "Argon2 Comparison"
    ).expect("Calibration failed");

    println!("Argon2 Comparison Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);

    assert!(analysis.is_constant_time);
}