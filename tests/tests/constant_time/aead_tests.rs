// tests/constant_time/aead_tests.rs
// Constant-time tests for AEAD ciphers (GCM and ChaCha20Poly1305)

use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_algorithms::aead::chacha20poly1305::{
    CHACHA20POLY1305_KEY_SIZE, CHACHA20POLY1305_NONCE_SIZE, CHACHA20POLY1305_TAG_SIZE,
};
use dcrypt_algorithms::aead::gcm::Gcm;
use dcrypt_algorithms::block::aes::Aes128;
use dcrypt_algorithms::block::BlockCipher;
use dcrypt_algorithms::types::Nonce;
use dcrypt_api::traits::AuthenticatedCipher;
use dcrypt_api::types::SecretBytes;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{generate_test_insights, TimingTester};

// Helper to set up the GCM instance once
fn make_gcm() -> (Gcm<Aes128>, Nonce<12>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let key_bytes = [0u8; 16];
    let key = SecretBytes::<16>::new(key_bytes);
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::<12>::new(nonce_bytes);
    let aad = b"additional data";
    let plain_a = b"secret message";
    let plain_b = b"second message";
    let cipher = Aes128::new(&key);
    let g = Gcm::new(cipher).unwrap();
    let ct_a = g.internal_encrypt(&nonce, plain_a, Some(aad)).unwrap();
    let ct_b = g.internal_encrypt(&nonce, plain_b, Some(aad)).unwrap();
    (g, nonce, ct_a, ct_b, aad.to_vec())
}

#[test]
fn test_gcm_success_path_constant_time() {
    let config = TestConfig::for_aead();
    let (gcm, nonce, ciphertext_a, ciphertext_b, aad) = make_gcm();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = gcm.internal_decrypt(&nonce, &ciphertext_a, Some(&aad));
    };

    let measurement_op = |use_b: bool| {
        if use_b {
            let _ = gcm.internal_decrypt(&nonce, &ciphertext_b, Some(&aad));
        } else {
            let _ = gcm.internal_decrypt(&nonce, &ciphertext_a, Some(&aad));
        }
    };

    let analysis = tester
        .calibrate_and_measure(warmup_op, measurement_op, &config, "GCM Success Path")
        .expect("Calibration failed");

    println!("GCM Success Path Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );
    println!("  Cohen's d: {:.3}", analysis.cohens_d);

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "GCM Success Path")
        );
    }

    assert!(
        analysis.is_constant_time,
        "GCM success path not constant time"
    );
}

fn assert_gcm_invalid_pair_constant_time(
    gcm: &Gcm<Aes128>,
    nonce: &Nonce<12>,
    invalid_a: &[u8],
    invalid_b: &[u8],
    aad: &[u8],
    name: &str,
) {
    let config = TestConfig::for_aead();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    assert!(gcm.internal_decrypt(nonce, invalid_a, Some(aad)).is_err());
    assert!(gcm.internal_decrypt(nonce, invalid_b, Some(aad)).is_err());

    let warmup_op = || {
        drop(std::hint::black_box(gcm.internal_decrypt(
            nonce,
            invalid_a,
            Some(aad),
        )));
    };

    let measurement_op = |use_b: bool| {
        if use_b {
            drop(std::hint::black_box(gcm.internal_decrypt(
                nonce,
                invalid_b,
                Some(aad),
            )));
        } else {
            drop(std::hint::black_box(gcm.internal_decrypt(
                nonce,
                invalid_a,
                Some(aad),
            )));
        }
    };

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

    assert!(
        analysis.is_constant_time,
        "{name} invalid classes are not constant time"
    );
}

#[test]
fn test_gcm_invalid_ciphertext_data_constant_time() {
    let (gcm, nonce, valid_ct, _, aad) = make_gcm();
    let tag_len = <Gcm<Aes128> as AuthenticatedCipher>::TAG_SIZE;
    let ciphertext_len = valid_ct.len() - tag_len;
    assert!(ciphertext_len > 0);

    // Both classes have the same public length and authentication-error result.
    // They differ only in attacker-controlled ciphertext bits that feed the
    // secret-H-derived GHASH accumulator.
    let mut invalid_a = valid_ct.clone();
    invalid_a[0] ^= 0x01;
    let mut invalid_b = valid_ct.clone();
    invalid_b[0] ^= 0x80;

    assert_gcm_invalid_pair_constant_time(
        &gcm,
        &nonce,
        &invalid_a,
        &invalid_b,
        &aad,
        "GCM Invalid Ciphertext Data",
    );
}

#[test]
fn test_gcm_first_vs_last_tag_mismatch_constant_time() {
    let (gcm, nonce, valid_ct, _, aad) = make_gcm();
    let tag_len = <Gcm<Aes128> as AuthenticatedCipher>::TAG_SIZE;
    let first_tag_index = valid_ct.len() - tag_len;

    // Both classes traverse the authentication-error path; only the mismatch
    // position within the equal-length received tag changes.
    let mut first_mismatch = valid_ct.clone();
    first_mismatch[first_tag_index] ^= 0x01;
    let mut last_mismatch = valid_ct.clone();
    let last_tag_index = last_mismatch.len() - 1;
    last_mismatch[last_tag_index] ^= 0x01;

    assert_gcm_invalid_pair_constant_time(
        &gcm,
        &nonce,
        &first_mismatch,
        &last_mismatch,
        &aad,
        "GCM First-vs-Last Tag Mismatch",
    );
}

fn make_chacha_poly() -> (ChaCha20Poly1305, Vec<u8>, Vec<u8>, Vec<u8>) {
    let key = [0x42; CHACHA20POLY1305_KEY_SIZE];
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    let aad = b"additional authenticated data";
    let plaintext_a = b"confidential message";
    let plaintext_b = b"another private msg!";

    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext_a = cipher.encrypt(&nonce, plaintext_a, Some(aad)).unwrap();
    let ciphertext_b = cipher.encrypt(&nonce, plaintext_b, Some(aad)).unwrap();
    (cipher, ciphertext_a, ciphertext_b, aad.to_vec())
}

#[test]
fn test_chacha_poly_success_constant_time() {
    let config = TestConfig::for_chacha_poly();
    let (cipher, ciphertext_a, ciphertext_b, aad) = make_chacha_poly();
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    assert_eq!(ciphertext_a.len(), ciphertext_b.len());

    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    let warmup_op = || {
        let _ = cipher.decrypt(&nonce, &ciphertext_a, Some(&aad));
    };

    let measurement_op = |use_b: bool| {
        if use_b {
            let _ = cipher.decrypt(&nonce, &ciphertext_b, Some(&aad));
        } else {
            let _ = cipher.decrypt(&nonce, &ciphertext_a, Some(&aad));
        }
    };

    let analysis = tester
        .calibrate_and_measure(
            warmup_op,
            measurement_op,
            &config,
            "ChaChaPoly Success Path",
        )
        .expect("Calibration failed");

    println!("ChaChaPoly Success Path Timing Analysis:");
    println!("  Mean diff: {:.3} ns", analysis.mean_diff);
    println!(
        "  99% CI: [{:.3}, {:.3}] ns",
        analysis.ci_lower, analysis.ci_upper
    );

    if !analysis.is_constant_time || std::env::var("VERBOSE").is_ok() {
        println!(
            "\n{}",
            generate_test_insights(&analysis, &config, "ChaChaPoly Success Path")
        );
    }

    assert!(analysis.is_constant_time);
}

fn assert_chacha_poly_invalid_pair_constant_time(
    cipher: &ChaCha20Poly1305,
    nonce: &Nonce<CHACHA20POLY1305_NONCE_SIZE>,
    invalid_a: &[u8],
    invalid_b: &[u8],
    aad: &[u8],
    name: &str,
) {
    let config = TestConfig::for_chacha_poly();
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    assert!(cipher.decrypt(nonce, invalid_a, Some(aad)).is_err());
    assert!(cipher.decrypt(nonce, invalid_b, Some(aad)).is_err());

    let warmup_op = || {
        drop(std::hint::black_box(cipher.decrypt(
            nonce,
            invalid_a,
            Some(aad),
        )));
    };

    let measurement_op = |use_b: bool| {
        if use_b {
            drop(std::hint::black_box(cipher.decrypt(
                nonce,
                invalid_b,
                Some(aad),
            )));
        } else {
            drop(std::hint::black_box(cipher.decrypt(
                nonce,
                invalid_a,
                Some(aad),
            )));
        }
    };

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

    assert!(
        analysis.is_constant_time,
        "{name} invalid classes are not constant time"
    );
}

#[test]
fn test_chacha_poly_invalid_ciphertext_data_constant_time() {
    let (cipher, valid_ct, _, aad) = make_chacha_poly();
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    let ciphertext_len = valid_ct.len() - CHACHA20POLY1305_TAG_SIZE;
    assert!(ciphertext_len > 0);

    let mut invalid_a = valid_ct.clone();
    invalid_a[0] ^= 0x01;
    let mut invalid_b = valid_ct.clone();
    invalid_b[0] ^= 0x80;

    assert_chacha_poly_invalid_pair_constant_time(
        &cipher,
        &nonce,
        &invalid_a,
        &invalid_b,
        &aad,
        "ChaChaPoly Invalid Ciphertext Data",
    );
}

#[test]
fn test_chacha_poly_first_vs_last_tag_mismatch_constant_time() {
    let (cipher, valid_ct, _, aad) = make_chacha_poly();
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    let first_tag_index = valid_ct.len() - CHACHA20POLY1305_TAG_SIZE;

    let mut first_mismatch = valid_ct.clone();
    first_mismatch[first_tag_index] ^= 0x01;
    let mut last_mismatch = valid_ct.clone();
    let last_tag_index = last_mismatch.len() - 1;
    last_mismatch[last_tag_index] ^= 0x01;

    assert_chacha_poly_invalid_pair_constant_time(
        &cipher,
        &nonce,
        &first_mismatch,
        &last_mismatch,
        &aad,
        "ChaChaPoly First-vs-Last Tag Mismatch",
    );
}
