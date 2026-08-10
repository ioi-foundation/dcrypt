use dcrypt_api::{Kem, Serialize};
use dcrypt_hybrid::kem::EcdhP256MlKem768;
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};
use dcrypt_tests::test_rng::ChaCha20Rng;
use std::hint::black_box;

fn create_hybrid_config() -> TestConfig {
    let mut config = TestConfig::for_pqc_kem();
    config.num_samples = 50;
    config.num_iterations = 5;
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

pub(super) fn measure_hybrid_kem_decapsulate_success_path() -> Result<TimingAnalysis, String> {
    let config = create_hybrid_config();
    let mut rng = ChaCha20Rng::from_seed([77u8; 32]);
    let (pk, sk) = EcdhP256MlKem768::keypair(&mut rng).map_err(|error| error.to_string())?;
    let (valid_ct_a, _) =
        EcdhP256MlKem768::encapsulate(&mut rng, &pk).map_err(|error| error.to_string())?;
    let (valid_ct_b, _) =
        EcdhP256MlKem768::encapsulate(&mut rng, &pk).map_err(|error| error.to_string())?;
    let mut state = PreparedCiphertext::new(valid_ct_a.to_bytes(), valid_ct_b.to_bytes());
    let tester = TimingTester::new(config.num_samples, config.num_iterations);

    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedCiphertext::prepare,
        |prepared| {
            prepared.assert_stable();
            // Hybrid ciphertext fields are intentionally opaque. Decode from
            // the one stable input buffer so both classes cross the same
            // public Deserialize + Decapsulate boundary.
            let ciphertext = <EcdhP256MlKem768 as Kem>::Ciphertext::from_bytes(&prepared.current)
                .expect("prepared hybrid ciphertext must retain its fixed width");
            let _ = black_box(EcdhP256MlKem768::decapsulate(&sk, &ciphertext));
        },
        &config,
        "Hybrid KEM Decapsulate Success",
    )
}

pub(super) fn measure_hybrid_kem_decapsulate_rejection_path() -> Result<TimingAnalysis, String> {
    let config = create_hybrid_config();
    let mut rng = ChaCha20Rng::from_seed([77u8; 32]);
    let (pk, sk) = EcdhP256MlKem768::keypair(&mut rng).map_err(|error| error.to_string())?;
    let (valid_ct, _) =
        EcdhP256MlKem768::encapsulate(&mut rng, &pk).map_err(|error| error.to_string())?;

    let mut invalid_a = valid_ct.to_bytes();
    let mut invalid_b = invalid_a.clone();
    let last = invalid_a
        .len()
        .checked_sub(1)
        .ok_or_else(|| "empty hybrid ciphertext".to_string())?;
    invalid_a[last] ^= 0x55;
    invalid_b[last] ^= 0xaa;
    let parsed_a = <EcdhP256MlKem768 as Kem>::Ciphertext::from_bytes(&invalid_a)
        .map_err(|error| error.to_string())?;
    let parsed_b = <EcdhP256MlKem768 as Kem>::Ciphertext::from_bytes(&invalid_b)
        .map_err(|error| error.to_string())?;
    // Hybrid KEM implicit rejection deliberately returns a shared secret for
    // both invalid operands, keeping the public result class identical.
    EcdhP256MlKem768::decapsulate(&sk, &parsed_a).map_err(|error| error.to_string())?;
    EcdhP256MlKem768::decapsulate(&sk, &parsed_b).map_err(|error| error.to_string())?;

    let mut state = PreparedCiphertext::new(invalid_a, invalid_b);
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedCiphertext::prepare,
        |prepared| {
            prepared.assert_stable();
            let ciphertext = <EcdhP256MlKem768 as Kem>::Ciphertext::from_bytes(&prepared.current)
                .expect("prepared hybrid ciphertext must retain its fixed width");
            let _ = black_box(EcdhP256MlKem768::decapsulate(&sk, &ciphertext));
        },
        &config,
        "Hybrid KEM Decapsulate Reject",
    )
}
