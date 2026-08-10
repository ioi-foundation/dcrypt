//! Constant-time smoke tests for ML-KEM decapsulation.
use dcrypt_api::Kem;
use dcrypt_kem::ml_kem::MlKem768;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};
use dcrypt_tests::test_rng::ChaCha20Rng;
use std::hint::black_box;

fn create_ml_kem_config() -> TestConfig {
    let mut config = TestConfig::for_pqc_kem();
    config.num_samples = 50;
    config.num_iterations = 10;
    config
}

struct PreparedCiphertext {
    current: Vec<u8>,
    class_a: Vec<u8>,
    class_b: Vec<u8>,
    current_ptr: *const u8,
    current_len: usize,
    current_capacity: usize,
}

impl PreparedCiphertext {
    fn new(class_a: Vec<u8>, class_b: Vec<u8>) -> Self {
        assert_eq!(class_a.len(), class_b.len());
        let current = class_a.clone();
        let current_ptr = current.as_ptr();
        let current_len = current.len();
        let current_capacity = current.capacity();
        Self {
            current,
            class_a,
            class_b,
            current_ptr,
            current_len,
            current_capacity,
        }
    }

    fn prepare(&mut self, class: TimingClass) {
        self.assert_stable();
        prepare_bytes(&mut self.current, &self.class_a, &self.class_b, class);
        self.assert_stable();
    }

    fn assert_stable(&self) {
        assert_eq!(self.current.as_ptr(), self.current_ptr);
        assert_eq!(self.current.len(), self.current_len);
        assert_eq!(self.current.capacity(), self.current_capacity);
    }
}

pub(super) fn measure_ml_kem768_decapsulate_success_path() -> Result<TimingAnalysis, String> {
    let config = create_ml_kem_config();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = MlKem768::keypair(&mut rng).map_err(|error| error.to_string())?;
    let pk = MlKem768::public_key(&keypair);
    let sk = MlKem768::secret_key(&keypair);
    let (valid_ct_a, _) =
        MlKem768::encapsulate(&mut rng, &pk).map_err(|error| error.to_string())?;
    let (valid_ct_b, _) =
        MlKem768::encapsulate(&mut rng, &pk).map_err(|error| error.to_string())?;
    let mut state = PreparedCiphertext::new(valid_ct_a.to_bytes(), valid_ct_b.to_bytes());
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedCiphertext::prepare,
        |prepared| {
            prepared.assert_stable();
            // The public ML-KEM ciphertext wrapper is immutable. Decode from
            // one stable input allocation so both classes use an identical
            // Deserialize + Decapsulate call path.
            let ciphertext = <MlKem768 as Kem>::Ciphertext::from_bytes(&prepared.current)
                .expect("prepared ML-KEM ciphertext must retain its fixed width");
            let _ = black_box(MlKem768::decapsulate(&sk, &ciphertext));
        },
        &config,
        "MlKem768 Decapsulate Success",
    )
}

pub(super) fn measure_ml_kem768_decapsulate_rejection_path() -> Result<TimingAnalysis, String> {
    let config = create_ml_kem_config();
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let keypair = MlKem768::keypair(&mut rng).map_err(|error| error.to_string())?;
    let pk = MlKem768::public_key(&keypair);
    let sk = MlKem768::secret_key(&keypair);
    let (valid_ct, _) = MlKem768::encapsulate(&mut rng, &pk).map_err(|error| error.to_string())?;
    let mut invalid_a = valid_ct.to_bytes();
    let mut invalid_b = invalid_a.clone();
    let last = invalid_a
        .len()
        .checked_sub(1)
        .ok_or_else(|| "empty ML-KEM ciphertext".to_string())?;
    invalid_a[last] ^= 0x55;
    invalid_b[last] ^= 0xaa;
    let parsed_a =
        <MlKem768 as Kem>::Ciphertext::from_bytes(&invalid_a).map_err(|error| error.to_string())?;
    let parsed_b =
        <MlKem768 as Kem>::Ciphertext::from_bytes(&invalid_b).map_err(|error| error.to_string())?;
    // FIPS 203 implicit rejection returns a shared secret for both invalid
    // ciphertexts, so the public result class is identical.
    MlKem768::decapsulate(&sk, &parsed_a).map_err(|error| error.to_string())?;
    MlKem768::decapsulate(&sk, &parsed_b).map_err(|error| error.to_string())?;

    let mut state = PreparedCiphertext::new(invalid_a, invalid_b);
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedCiphertext::prepare,
        |prepared| {
            prepared.assert_stable();
            let ciphertext = <MlKem768 as Kem>::Ciphertext::from_bytes(&prepared.current)
                .expect("prepared ML-KEM ciphertext must retain its fixed width");
            let _ = black_box(MlKem768::decapsulate(&sk, &ciphertext));
        },
        &config,
        "MlKem768 Decapsulate Reject",
    )
}
