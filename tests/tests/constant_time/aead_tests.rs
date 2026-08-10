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
use dcrypt_tests::suites::constant_time::tester::{
    prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};
use std::hint::black_box;

/// One allocation is reused for both timing classes. Preparation reads both
/// equal-length templates and mask-selects into `current` without resizing it.
struct PreparedAeadInput {
    current: Vec<u8>,
    input_a: Vec<u8>,
    input_b: Vec<u8>,
    current_address: usize,
    current_len: usize,
    current_capacity: usize,
}

impl PreparedAeadInput {
    fn new(input_a: &[u8], input_b: &[u8]) -> Result<Self, String> {
        if input_a.len() != input_b.len() {
            return Err(format!(
                "timing classes have different public ciphertext lengths: {} != {}",
                input_a.len(),
                input_b.len()
            ));
        }

        let current = input_a.to_vec();
        let current_address = current.as_ptr().addr();
        let current_len = current.len();
        let current_capacity = current.capacity();

        Ok(Self {
            current,
            input_a: input_a.to_vec(),
            input_b: input_b.to_vec(),
            current_address,
            current_len,
            current_capacity,
        })
    }

    fn prepare(&mut self, class: TimingClass) {
        self.enforce_stable_storage();
        prepare_bytes(&mut self.current, &self.input_a, &self.input_b, class);
        self.enforce_stable_storage();
    }

    fn enforce_stable_storage(&self) {
        assert_eq!(self.current.as_ptr().addr(), self.current_address);
        assert_eq!(self.current.len(), self.current_len);
        assert_eq!(self.current.capacity(), self.current_capacity);
    }
}

// Helper to set up the GCM instance once.
fn make_gcm() -> Result<(Gcm<Aes128>, Nonce<12>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let key_bytes = [0u8; 16];
    let key = SecretBytes::<16>::new(key_bytes);
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::<12>::new(nonce_bytes);
    let aad = b"additional data";
    let plain_a = b"secret message";
    let plain_b = b"second message";
    let cipher = Aes128::new(&key);
    let g = Gcm::new(cipher).map_err(|error| format!("GCM timing setup failed: {error}"))?;
    let ct_a = g
        .internal_encrypt(&nonce, plain_a, Some(aad))
        .map_err(|error| format!("GCM class A timing setup failed: {error}"))?;
    let ct_b = g
        .internal_encrypt(&nonce, plain_b, Some(aad))
        .map_err(|error| format!("GCM class B timing setup failed: {error}"))?;
    Ok((g, nonce, ct_a, ct_b, aad.to_vec()))
}

pub(super) fn measure_gcm_success_path() -> Result<TimingAnalysis, String> {
    let config = TestConfig::for_aead();
    let (gcm, nonce, ciphertext_a, ciphertext_b, aad) = make_gcm()?;

    if gcm
        .internal_decrypt(&nonce, &ciphertext_a, Some(&aad))
        .is_err()
        || gcm
            .internal_decrypt(&nonce, &ciphertext_b, Some(&aad))
            .is_err()
    {
        return Err("GCM success timing fixture did not decrypt successfully".to_string());
    }

    let mut state = PreparedAeadInput::new(&ciphertext_a, &ciphertext_b)?;
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedAeadInput::prepare,
        |state| {
            drop(black_box(gcm.internal_decrypt(
                &nonce,
                black_box(state.current.as_slice()),
                Some(&aad),
            )));
        },
        &config,
        "GCM Success Path",
    )
}

fn measure_gcm_invalid_pair(
    gcm: &Gcm<Aes128>,
    nonce: &Nonce<12>,
    invalid_a: &[u8],
    invalid_b: &[u8],
    aad: &[u8],
    name: &str,
) -> Result<TimingAnalysis, String> {
    if gcm.internal_decrypt(nonce, invalid_a, Some(aad)).is_ok()
        || gcm.internal_decrypt(nonce, invalid_b, Some(aad)).is_ok()
    {
        return Err(format!("{name} fixture did not reject both classes"));
    }

    let config = TestConfig::for_aead();
    let mut state = PreparedAeadInput::new(invalid_a, invalid_b)?;
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedAeadInput::prepare,
        |state| {
            drop(black_box(gcm.internal_decrypt(
                nonce,
                black_box(state.current.as_slice()),
                Some(aad),
            )));
        },
        &config,
        name,
    )
}

pub(super) fn measure_gcm_invalid_ciphertext_data() -> Result<TimingAnalysis, String> {
    let (gcm, nonce, valid_ct, _, aad) = make_gcm()?;
    let tag_len = <Gcm<Aes128> as AuthenticatedCipher>::TAG_SIZE;
    let ciphertext_len = valid_ct
        .len()
        .checked_sub(tag_len)
        .ok_or_else(|| "GCM fixture ciphertext is shorter than its tag".to_string())?;
    if ciphertext_len == 0 {
        return Err("GCM fixture has no ciphertext data".to_string());
    }

    // Both classes have the same public length and authentication-error result.
    // They differ only in attacker-controlled ciphertext bits that feed the
    // secret-H-derived GHASH accumulator.
    let mut invalid_a = valid_ct.clone();
    invalid_a[0] ^= 0x01;
    let mut invalid_b = valid_ct.clone();
    invalid_b[0] ^= 0x80;

    measure_gcm_invalid_pair(
        &gcm,
        &nonce,
        &invalid_a,
        &invalid_b,
        &aad,
        "GCM Invalid Ciphertext Data",
    )
}

pub(super) fn measure_gcm_first_vs_last_tag_mismatch() -> Result<TimingAnalysis, String> {
    let (gcm, nonce, valid_ct, _, aad) = make_gcm()?;
    let tag_len = <Gcm<Aes128> as AuthenticatedCipher>::TAG_SIZE;
    let first_tag_index = valid_ct
        .len()
        .checked_sub(tag_len)
        .ok_or_else(|| "GCM fixture ciphertext is shorter than its tag".to_string())?;
    if tag_len == 0 || first_tag_index >= valid_ct.len() {
        return Err("GCM fixture has no authentication tag".to_string());
    }

    // Both classes traverse the authentication-error path; only the mismatch
    // position within the equal-length received tag changes.
    let mut first_mismatch = valid_ct.clone();
    first_mismatch[first_tag_index] ^= 0x01;
    let mut last_mismatch = valid_ct.clone();
    let last_tag_index = last_mismatch.len() - 1;
    last_mismatch[last_tag_index] ^= 0x01;

    measure_gcm_invalid_pair(
        &gcm,
        &nonce,
        &first_mismatch,
        &last_mismatch,
        &aad,
        "GCM First-vs-Last Tag Mismatch",
    )
}

fn make_chacha_poly() -> Result<(ChaCha20Poly1305, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let key = [0x42; CHACHA20POLY1305_KEY_SIZE];
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    let aad = b"additional authenticated data";
    let plaintext_a = b"confidential message";
    let plaintext_b = b"another private msg!";

    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext_a = cipher
        .encrypt(&nonce, plaintext_a, Some(aad))
        .map_err(|error| format!("ChaChaPoly class A timing setup failed: {error}"))?;
    let ciphertext_b = cipher
        .encrypt(&nonce, plaintext_b, Some(aad))
        .map_err(|error| format!("ChaChaPoly class B timing setup failed: {error}"))?;
    Ok((cipher, ciphertext_a, ciphertext_b, aad.to_vec()))
}

pub(super) fn measure_chacha_poly_success_path() -> Result<TimingAnalysis, String> {
    let config = TestConfig::for_chacha_poly();
    let (cipher, ciphertext_a, ciphertext_b, aad) = make_chacha_poly()?;
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);

    if cipher.decrypt(&nonce, &ciphertext_a, Some(&aad)).is_err()
        || cipher.decrypt(&nonce, &ciphertext_b, Some(&aad)).is_err()
    {
        return Err("ChaChaPoly success timing fixture did not decrypt successfully".to_string());
    }

    let mut state = PreparedAeadInput::new(&ciphertext_a, &ciphertext_b)?;
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedAeadInput::prepare,
        |state| {
            drop(black_box(cipher.decrypt(
                &nonce,
                black_box(state.current.as_slice()),
                Some(&aad),
            )));
        },
        &config,
        "ChaChaPoly Success Path",
    )
}

fn measure_chacha_poly_invalid_pair(
    cipher: &ChaCha20Poly1305,
    nonce: &Nonce<CHACHA20POLY1305_NONCE_SIZE>,
    invalid_a: &[u8],
    invalid_b: &[u8],
    aad: &[u8],
    name: &str,
) -> Result<TimingAnalysis, String> {
    if cipher.decrypt(nonce, invalid_a, Some(aad)).is_ok()
        || cipher.decrypt(nonce, invalid_b, Some(aad)).is_ok()
    {
        return Err(format!("{name} fixture did not reject both classes"));
    }

    let config = TestConfig::for_chacha_poly();
    let mut state = PreparedAeadInput::new(invalid_a, invalid_b)?;
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedAeadInput::prepare,
        |state| {
            drop(black_box(cipher.decrypt(
                nonce,
                black_box(state.current.as_slice()),
                Some(aad),
            )));
        },
        &config,
        name,
    )
}

pub(super) fn measure_chacha_poly_invalid_ciphertext_data() -> Result<TimingAnalysis, String> {
    let (cipher, valid_ct, _, aad) = make_chacha_poly()?;
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    let ciphertext_len = valid_ct
        .len()
        .checked_sub(CHACHA20POLY1305_TAG_SIZE)
        .ok_or_else(|| "ChaChaPoly fixture ciphertext is shorter than its tag".to_string())?;
    if ciphertext_len == 0 {
        return Err("ChaChaPoly fixture has no ciphertext data".to_string());
    }

    let mut invalid_a = valid_ct.clone();
    invalid_a[0] ^= 0x01;
    let mut invalid_b = valid_ct.clone();
    invalid_b[0] ^= 0x80;

    measure_chacha_poly_invalid_pair(
        &cipher,
        &nonce,
        &invalid_a,
        &invalid_b,
        &aad,
        "ChaChaPoly Invalid Ciphertext Data",
    )
}

pub(super) fn measure_chacha_poly_first_vs_last_tag_mismatch() -> Result<TimingAnalysis, String> {
    let (cipher, valid_ct, _, aad) = make_chacha_poly()?;
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);
    let first_tag_index = valid_ct
        .len()
        .checked_sub(CHACHA20POLY1305_TAG_SIZE)
        .ok_or_else(|| "ChaChaPoly fixture ciphertext is shorter than its tag".to_string())?;
    if CHACHA20POLY1305_TAG_SIZE == 0 || first_tag_index >= valid_ct.len() {
        return Err("ChaChaPoly fixture has no authentication tag".to_string());
    }

    let mut first_mismatch = valid_ct.clone();
    first_mismatch[first_tag_index] ^= 0x01;
    let mut last_mismatch = valid_ct.clone();
    let last_tag_index = last_mismatch.len() - 1;
    last_mismatch[last_tag_index] ^= 0x01;

    measure_chacha_poly_invalid_pair(
        &cipher,
        &nonce,
        &first_mismatch,
        &last_mismatch,
        &aad,
        "ChaChaPoly First-vs-Last Tag Mismatch",
    )
}
