// tests/tests/constant_time/ml_dsa.rs
use dcrypt_algorithms::xof::shake::ShakeXof256;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_api::Signature;
use dcrypt_sign::mldsa::{MlDsa65, MlDsaSignature};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};
use dcrypt_tests::test_rng::ChaCha20Rng;

fn create_ml_dsa_config() -> TestConfig {
    let mut config = TestConfig::for_pqc_sign();
    config.num_warmup = 30;
    config.num_samples = 80;
    config.num_iterations = 3;
    config
}

/// Return public, input-dependent verifier work: canonical hint weight,
/// SampleInBall rejection draws, and negative challenge terms.
fn ml_dsa_65_public_work(signature: &MlDsaSignature) -> (usize, usize, usize) {
    let bytes = signature.as_ref();
    let hint_weight = usize::from(bytes[bytes.len() - 1]);
    let mut xof = ShakeXof256::new();
    xof.update(&bytes[..48]).unwrap();
    let mut signs = [0u8; 8];
    xof.squeeze(&mut signs).unwrap();
    let negative_terms = (0..49)
        .filter(|index| ((signs[index / 8] >> (index % 8)) & 1) != 0)
        .count();
    let mut draws = 0usize;
    for i in (256usize - 49)..256 {
        loop {
            let mut byte = [0u8; 1];
            xof.squeeze(&mut byte).unwrap();
            draws += 1;
            if usize::from(byte[0]) <= i {
                break;
            }
        }
    }
    (hint_weight, draws, negative_terms)
}

#[test]
fn test_ml_dsa_65_equal_length_alternate_messages_verify() {
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message_a = b"Constant time test message for ML-DSA-65";
    let message_b = b"Constant time test message for ML-DSA-64";
    assert_eq!(message_a.len(), message_b.len());

    let (pk, sk) = MlDsa65::keypair(&mut rng).expect("Keygen failed");
    let valid_sig_a = MlDsa65::sign(message_a, &sk).expect("Signing failed");
    let valid_sig_b = MlDsa65::sign(message_b, &sk).expect("Signing failed");
    MlDsa65::verify(message_a, &valid_sig_a, &pk).expect("Signature A failed");
    MlDsa65::verify(message_b, &valid_sig_b, &pk).expect("Signature B failed");
}

#[test]
fn test_ml_dsa_65_verify_public_input_timing_diagnostic() {
    let config = create_ml_dsa_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message_a = b"Constant time test message for ML-DSA-65";
    let message_b = b"Another constant time test message for ML-DSA-65";

    let (pk, sk) = MlDsa65::keypair(&mut rng).expect("Keygen failed");
    let valid_sig_a = MlDsa65::sign(message_a, &sk).expect("Signing failed");
    let valid_sig_b = MlDsa65::sign(message_b, &sk).expect("Signing failed");
    MlDsa65::verify(message_a, &valid_sig_a, &pk).expect("Signature A failed");
    MlDsa65::verify(message_b, &valid_sig_b, &pk).expect("Signature B failed");

    // Verification consumes only the public key, message, signature, and
    // public validity result. FIPS 204's SampleInBall rejection loop and the
    // canonical hint decoder intentionally perform work determined by those
    // public inputs. Keep measuring and reporting that variation, but do not
    // misclassify it as a secret-dependent timing release gate.
    println!(
        "Public work (hint weight, SampleInBall draws, negative terms) A/B: {:?} / {:?}",
        ml_dsa_65_public_work(&valid_sig_a),
        ml_dsa_65_public_work(&valid_sig_b)
    );

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = MlDsa65::verify(message_a, &valid_sig_a, &pk);
    };

    let measurement_op = |use_b: bool| {
        if use_b {
            let _ = MlDsa65::verify(message_b, &valid_sig_b, &pk);
        } else {
            let _ = MlDsa65::verify(message_a, &valid_sig_a, &pk);
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "ML-DSA-65 Verify Public Inputs",
        )
        .expect("Calibration failed");

    println!("ML-DSA-65 Public-Input Verify Timing Diagnostic:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "ML-DSA-65 Verify Public Inputs")
        );
    }
    println!(
        "Diagnostic only: both measured operands and validity results are public; \
         secret-bearing and rejection-path timing assertions remain blocking."
    );
}

#[test]
fn test_ml_dsa_65_verify_rejection_path_constant_time() {
    let config = create_ml_dsa_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message = b"Constant time test message for ML-DSA-65";

    let (pk, sk) = MlDsa65::keypair(&mut rng).expect("Keygen failed");
    let valid_sig = MlDsa65::sign(message, &sk).expect("Signing failed");

    let mut invalid_sig_bytes = valid_sig.to_bytes().to_vec();
    if let Some(z_byte) = invalid_sig_bytes.get_mut(64) {
        *z_byte ^= 0x01;
    }
    let invalid_sig = MlDsaSignature::from_bytes(&invalid_sig_bytes)
        .expect("Failed to deserialize modified signature");
    assert!(MlDsa65::verify(message, &invalid_sig, &pk).is_err());

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = MlDsa65::verify(message, &valid_sig, &pk);
    };

    let measurement_op = |use_invalid: bool| {
        if use_invalid {
            let _ = MlDsa65::verify(message, &invalid_sig, &pk);
        } else {
            let _ = MlDsa65::verify(message, &valid_sig, &pk);
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "ML-DSA-65 Verify Reject",
        )
        .expect("Calibration failed");

    println!("ML-DSA-65 Verify Rejection Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "ML-DSA-65 Verify Reject")
        );
    }

    assert!(analysis.is_constant_time);
}
