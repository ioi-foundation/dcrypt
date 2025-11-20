// tests/tests/constant_time/kdf/argon2/mod.rs

use dcrypt_algorithms::kdf::argon2::{Algorithm, Argon2, Params};
use dcrypt_algorithms::kdf::PasswordHashFunction;
use dcrypt_algorithms::types::Salt;
use dcrypt_api::types::SecretBytes;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

fn create_argon2_config() -> TestConfig {
    TestConfig {
        num_warmup: 5,
        num_samples: 30,
        num_iterations: 3,
        mean_ratio_max: 1.4,
        mean_ratio_min: 0.6,
        t_stat_threshold: 5.0,
        std_dev_threshold: 0.25,
        combined_score_threshold: 3.0,

        // DTS Config
        enable_dynamic_scaling: true,
        noise_scale_factor: 1.0, 
        noise_sensitivity: 20.0,
        noise_soft_floor: 0.02,
        noise_hard_floor: 0.20, // Relaxed to 20%
    }
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
        &config
    ).expect("Calibration failed");

    println!("Argon2id Verify Timing Analysis:");
    println!("  Combined score: {:.3}", analysis.combined_score);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!("\n{}", generate_test_insights(&analysis, &config, "Argon2id Verify"));
    }

    assert!(analysis.is_constant_time, "Argon2id verify not constant-time");
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

    // Differs at start
    let mut hash2 = hash1.clone();
    if !hash2.is_empty() { hash2[0] ^= 0x01; }

    // Differs at end
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
        &config
    ).expect("Calibration failed");

    println!("Argon2 Hash Comparison Analysis:");
    println!("  Combined score: {:.3}", analysis.combined_score);

    assert!(analysis.is_constant_time);
}