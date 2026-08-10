use dcrypt_algorithms::xof::shake::ShakeXof256;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_api::Signature;
use dcrypt_sign::mldsa::{MlDsa65, MlDsaSignature};
use dcrypt_tests::suites::constant_time::config::TestConfig;
use dcrypt_tests::suites::constant_time::tester::{
    generate_test_insights, prepare_bytes, TimingAnalysis, TimingClass, TimingTester,
};
use dcrypt_tests::test_rng::ChaCha20Rng;
use std::hint::black_box;

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

struct PreparedVerification {
    current_message: Vec<u8>,
    current_signature: Vec<u8>,
    message_a: Vec<u8>,
    message_b: Vec<u8>,
    signature_a: Vec<u8>,
    signature_b: Vec<u8>,
    message_ptr: *const u8,
    message_len: usize,
    message_capacity: usize,
    signature_ptr: *const u8,
    signature_len: usize,
    signature_capacity: usize,
}

impl PreparedVerification {
    fn new(
        message_a: &[u8],
        signature_a: &MlDsaSignature,
        message_b: &[u8],
        signature_b: &MlDsaSignature,
    ) -> Self {
        assert_eq!(message_a.len(), message_b.len());
        assert_eq!(signature_a.as_ref().len(), signature_b.as_ref().len());
        let current_message = message_a.to_vec();
        let current_signature = signature_a.as_ref().to_vec();
        let message_ptr = current_message.as_ptr();
        let message_len = current_message.len();
        let message_capacity = current_message.capacity();
        let signature_ptr = current_signature.as_ptr();
        let signature_len = current_signature.len();
        let signature_capacity = current_signature.capacity();
        Self {
            current_message,
            current_signature,
            message_a: message_a.to_vec(),
            message_b: message_b.to_vec(),
            signature_a: signature_a.as_ref().to_vec(),
            signature_b: signature_b.as_ref().to_vec(),
            message_ptr,
            message_len,
            message_capacity,
            signature_ptr,
            signature_len,
            signature_capacity,
        }
    }

    fn prepare(&mut self, class: TimingClass) {
        self.assert_stable();
        prepare_bytes(
            &mut self.current_message,
            &self.message_a,
            &self.message_b,
            class,
        );
        prepare_bytes(
            &mut self.current_signature,
            &self.signature_a,
            &self.signature_b,
            class,
        );
        self.assert_stable();
    }

    fn assert_stable(&self) {
        assert_eq!(self.current_message.as_ptr(), self.message_ptr);
        assert_eq!(self.current_message.len(), self.message_len);
        assert_eq!(self.current_message.capacity(), self.message_capacity);
        assert_eq!(self.current_signature.as_ptr(), self.signature_ptr);
        assert_eq!(self.current_signature.len(), self.signature_len);
        assert_eq!(self.current_signature.capacity(), self.signature_capacity);
    }
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
    let message_b = b"Constant time test message for ML-DSA-64";
    assert_eq!(message_a.len(), message_b.len());

    let (pk, sk) = MlDsa65::keypair(&mut rng).expect("Keygen failed");
    let valid_sig_a = MlDsa65::sign(message_a, &sk).expect("Signing failed");
    let valid_sig_b = MlDsa65::sign(message_b, &sk).expect("Signing failed");
    MlDsa65::verify(message_a, &valid_sig_a, &pk).expect("Signature A failed");
    MlDsa65::verify(message_b, &valid_sig_b, &pk).expect("Signature B failed");

    println!(
        "Public work (hint weight, SampleInBall draws, negative terms) A/B: {:?} / {:?}",
        ml_dsa_65_public_work(&valid_sig_a),
        ml_dsa_65_public_work(&valid_sig_b)
    );

    let mut state = PreparedVerification::new(message_a, &valid_sig_a, message_b, &valid_sig_b);
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    let analysis = tester
        .calibrate_and_measure_prepared(
            &mut state,
            PreparedVerification::prepare,
            |prepared| {
                prepared.assert_stable();
                let signature = MlDsaSignature::from_bytes(&prepared.current_signature)
                    .expect("prepared ML-DSA signature must remain canonical");
                let _ = black_box(MlDsa65::verify(&prepared.current_message, &signature, &pk));
            },
            &config,
            "ML-DSA-65 Verify Public Inputs",
        )
        .expect("public-input diagnostic measurement failed");

    println!(
        "{}",
        generate_test_insights(&analysis, &config, "ML-DSA-65 Verify Public Inputs")
    );
    println!(
        "Diagnostic only: both measured operands and validity results are public; \
         this analysis is intentionally excluded from the 29-case blocking family."
    );
}

pub(super) fn measure_ml_dsa_65_verify_rejection_path() -> Result<TimingAnalysis, String> {
    let config = create_ml_dsa_config();
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let message = b"Constant time test message for ML-DSA-65";
    let (pk, sk) = MlDsa65::keypair(&mut rng).map_err(|error| error.to_string())?;
    let valid_sig = MlDsa65::sign(message, &sk).map_err(|error| error.to_string())?;

    let mut invalid_a_bytes = valid_sig.to_bytes().to_vec();
    let mut invalid_b_bytes = invalid_a_bytes.clone();
    invalid_a_bytes[64] ^= 0x01;
    invalid_b_bytes[65] ^= 0x02;
    let invalid_a =
        MlDsaSignature::from_bytes(&invalid_a_bytes).map_err(|error| error.to_string())?;
    let invalid_b =
        MlDsaSignature::from_bytes(&invalid_b_bytes).map_err(|error| error.to_string())?;
    if MlDsa65::verify(message, &invalid_a, &pk).is_ok()
        || MlDsa65::verify(message, &invalid_b, &pk).is_ok()
    {
        return Err("ML-DSA rejection fixtures must both be invalid".to_string());
    }

    let mut state = PreparedVerification::new(message, &invalid_a, message, &invalid_b);
    let tester = TimingTester::new(config.num_samples, config.num_iterations);
    tester.calibrate_and_measure_prepared(
        &mut state,
        PreparedVerification::prepare,
        |prepared| {
            prepared.assert_stable();
            let signature = MlDsaSignature::from_bytes(&prepared.current_signature)
                .expect("prepared ML-DSA rejection signature must remain canonical");
            let result = MlDsa65::verify(&prepared.current_message, &signature, &pk);
            debug_assert!(result.is_err());
            let _ = black_box(result);
        },
        &config,
        "ML-DSA-65 Verify Reject",
    )
}
