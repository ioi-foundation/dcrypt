use super::*;
use dcrypt_algorithms::hash::{HashFunction, Sha256, Shake256};
use dcrypt_internal::{ChaCha20Rng, CryptoRng, Error as RngError, RngCore};

const MESSAGE: &[u8] = b"FIPS 204 ML-DSA interoperability test";

#[derive(Clone)]
struct ReplayRng {
    bytes: Vec<u8>,
    position: usize,
}

impl ReplayRng {
    fn from_hex(value: &str) -> Self {
        Self {
            bytes: hex::decode(value).unwrap(),
            position: 0,
        }
    }

    fn take(&mut self, output: &mut [u8]) {
        let end = self.position + output.len();
        output.copy_from_slice(
            self.bytes
                .get(self.position..end)
                .expect("NIST replay RNG exhausted"),
        );
        self.position = end;
    }
}

impl RngCore for ReplayRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.take(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.take(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.take(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.take(dest);
        Ok(())
    }
}

impl CryptoRng for ReplayRng {}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes).unwrap().as_ref())
}

macro_rules! roundtrip_test {
    ($name:ident, $scheme:ty, $pk_len:expr, $sk_len:expr, $sig_len:expr, $expected_name:expr) => {
        #[test]
        fn $name() {
            let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
            let (public_key, secret_key) = <$scheme>::keypair(&mut rng).unwrap();
            let signature = <$scheme>::sign_with_rng(MESSAGE, &secret_key, &mut rng).unwrap();

            assert_eq!(<$scheme>::name(), $expected_name);
            assert_eq!(public_key.as_ref().len(), $pk_len);
            assert_eq!(secret_key.as_ref().len(), $sk_len);
            assert_eq!(signature.as_ref().len(), $sig_len);
            assert!(<$scheme>::verify(MESSAGE, &signature, &public_key).is_ok());
            assert!(<$scheme>::verify(b"wrong message", &signature, &public_key).is_err());

            let decoded_public = MlDsaPublicKey::from_bytes(public_key.as_ref()).unwrap();
            let decoded_secret =
                MlDsaSecretKey::from_bytes_with_public_key(secret_key.as_ref(), &public_key)
                    .unwrap();
            let decoded_signature = MlDsaSignature::from_bytes(signature.as_ref()).unwrap();
            assert_eq!(decoded_public.as_ref(), public_key.as_ref());
            assert_eq!(decoded_secret.as_ref(), secret_key.as_ref());
            assert_eq!(decoded_signature.as_ref(), signature.as_ref());
            assert_eq!(
                decoded_secret.public_key().unwrap().as_ref(),
                public_key.as_ref()
            );
        }
    };
}

#[test]
fn expanded_key_import_derives_and_validates_public_key() {
    let mut rng = ChaCha20Rng::from_seed([0x35; 32]);
    let (public, secret) = MlDsa44::keypair(&mut rng).unwrap();
    let imported = MlDsaSecretKey::from_bytes(secret.as_ref()).unwrap();
    assert_eq!(imported.public_key().unwrap().as_ref(), public.as_ref());
}

#[test]
fn paired_import_rejects_incoherent_t0_without_panicking() {
    let mut rng = ChaCha20Rng::from_seed([0x36; 32]);
    let (public, secret) = MlDsa44::keypair(&mut rng).unwrap();
    let mut malformed = secret.as_ref().to_vec();
    // ML-DSA-44: 128-byte rho/K/tr prefix plus eight eta=2 polynomials
    // encoded at 96 bytes each. The remaining bytes encode t0.
    malformed[128 + 8 * 96..].fill(0);

    assert!(MlDsaSecretKey::from_bytes_with_public_key(&malformed, &public).is_err());
}

roundtrip_test!(ml_dsa_44_roundtrip, MlDsa44, 1312, 2560, 2420, "ML-DSA-44");
roundtrip_test!(ml_dsa_65_roundtrip, MlDsa65, 1952, 4032, 3309, "ML-DSA-65");
roundtrip_test!(ml_dsa_87_roundtrip, MlDsa87, 2592, 4896, 4627, "ML-DSA-87");

#[test]
fn signing_interfaces_bind_context_randomizer_and_supplied_mu() {
    let mut key_rng = ChaCha20Rng::from_seed([0x51; 32]);
    let (public, secret) = MlDsa44::keypair(&mut key_rng).unwrap();
    let context = b"application domain";

    let deterministic =
        MlDsa44::sign_deterministic_with_context(MESSAGE, context, &secret).unwrap();
    let deterministic_again =
        MlDsa44::sign_deterministic_with_context(MESSAGE, context, &secret).unwrap();
    assert_eq!(deterministic.as_ref(), deterministic_again.as_ref());
    assert!(MlDsa44::verify_with_context(MESSAGE, context, &deterministic, &public).is_ok());
    assert!(
        MlDsa44::verify_with_context(MESSAGE, b"wrong domain", &deterministic, &public).is_err()
    );

    let mut signing_rng = ChaCha20Rng::from_seed([0x52; 32]);
    let randomized =
        MlDsa44::sign_with_context_rng(MESSAGE, context, &secret, &mut signing_rng).unwrap();
    assert_ne!(randomized.as_ref(), deterministic.as_ref());
    assert!(MlDsa44::verify_with_context(MESSAGE, context, &randomized, &public).is_ok());

    let mut formatted = Vec::with_capacity(2 + context.len() + MESSAGE.len());
    formatted.extend_from_slice(&[0, context.len() as u8]);
    formatted.extend_from_slice(context);
    formatted.extend_from_slice(MESSAGE);
    let internal =
        MlDsa44::sign_internal_with_randomizer(&formatted, &secret, &[0x5a; 32]).unwrap();
    assert!(MlDsa44::verify_internal_message(&formatted, &internal, &public).is_ok());
    assert!(MlDsa44::verify_with_context(MESSAGE, context, &internal, &public).is_ok());

    let mu = [0x33; 64];
    let mu_signature = MlDsa44::sign_mu_with_randomizer(&mu, &secret, &[0x6b; 32]).unwrap();
    assert!(MlDsa44::verify_mu(&mu, &mu_signature, &public).is_ok());
    let mut wrong_mu = mu;
    wrong_mu[0] ^= 1;
    assert!(MlDsa44::verify_mu(&wrong_mu, &mu_signature, &public).is_err());

    let oversized_context = [0u8; 256];
    assert!(
        MlDsa44::sign_deterministic_with_context(MESSAGE, &oversized_context, &secret).is_err()
    );
    assert!(
        MlDsa44::verify_with_context(MESSAGE, &oversized_context, &deterministic, &public,)
            .is_err()
    );
}

#[test]
fn expanded_key_decoder_rejects_malformed_or_incoherent_components() {
    let mut rng = ChaCha20Rng::from_seed([0x62; 32]);
    let (public, secret) = MlDsa44::keypair(&mut rng).unwrap();

    let mut malformed_tr = secret.as_ref().to_vec();
    malformed_tr[64] ^= 1;
    assert!(MlDsaSecretKey::from_bytes(&malformed_tr).is_err());

    // For eta=2 each secret coefficient occupies three bits and only encoded
    // values 0..=4 are canonical. Seven must be rejected before coherence work.
    let mut noncanonical_s1 = secret.as_ref().to_vec();
    noncanonical_s1[128] = (noncanonical_s1[128] & !0x07) | 0x07;
    assert!(MlDsaSecretKey::from_bytes(&noncanonical_s1).is_err());

    let mut incoherent_s1 = secret.as_ref().to_vec();
    incoherent_s1[128] ^= 1;
    assert!(MlDsaSecretKey::from_bytes(&incoherent_s1).is_err());

    let mut incoherent_t0 = secret.as_ref().to_vec();
    incoherent_t0[128 + 8 * 96] ^= 1;
    assert!(MlDsaSecretKey::from_bytes(&incoherent_t0).is_err());

    let (different_public, _) = MlDsa44::keypair(&mut rng).unwrap();
    assert!(
        MlDsaSecretKey::from_bytes_with_public_key(secret.as_ref(), &different_public).is_err()
    );
    assert!(MlDsaSecretKey::from_bytes_with_public_key(secret.as_ref(), &public).is_ok());
}

macro_rules! nist_keygen_kat {
    (
        $name:ident,
        $scheme:ty,
        $seed:expr,
        $public_sha256:expr,
        $secret_sha256:expr
    ) => {
        #[test]
        fn $name() {
            // Repository ACVP-format ML-DSA-keyGen-FIPS204
            // internalProjection.json. The digests keep the local fixture
            // compact while pinning every byte of the expected public and
            // expanded-private-key outputs; upstream acquisition provenance is
            // unverified.
            let mut rng = ReplayRng::from_hex($seed);
            let (public, secret) = <$scheme>::keypair(&mut rng).unwrap();
            assert_eq!(sha256_hex(public.as_ref()), $public_sha256);
            assert_eq!(sha256_hex(secret.as_ref()), $secret_sha256);
        }
    };
}

nist_keygen_kat!(
    nist_acvp_keygen_ml_dsa_44_tc1,
    MlDsa44,
    "93EF2E6EF1FB08999D142ABE0295482370D3F43BDB254A78E2B0D5168ECA065F",
    "6995b20ecd5cde41719035028a712ccf35b1adf53b913030423d9d6fa188d673",
    "16a35d4b59f932aeada987dc689b075add0df57b4815bb103be7443ee3c1c561"
);
nist_keygen_kat!(
    nist_acvp_keygen_ml_dsa_65_tc26,
    MlDsa65,
    "70CEFB9AED5B68E018B079DA8284B9D5CAD5499ED9C265FF73588005D85C225C",
    "646b26b8d09dbc9e865b6a006c693a3127b065e62fab5fbe8b159c416462feb6",
    "3894dc56a4553781d68ff0d1b6fcf1b4876085ea602fb6f8738def50ed7d4c75"
);
nist_keygen_kat!(
    nist_acvp_keygen_ml_dsa_87_tc51,
    MlDsa87,
    "38359FBCD79582CFFE609E137EE2EFE8A8DBCBAD18BA92BB433AB4F09B49299D",
    "ea374a09356e5f89be784f28f4ef938e8976cb5c4db00fbacb257663491748d4",
    "a0cc3d4f703057c09b9261336ba45563d2c781d173f7fc634910698e95eee375"
);

macro_rules! tr_test {
    ($name:ident, $scheme:ty) => {
        #[test]
        fn $name() {
            let mut rng = ChaCha20Rng::from_seed([0xA5; 32]);
            let (public, secret) = <$scheme>::keypair(&mut rng).unwrap();
            let expected_tr = Shake256::digest(public.as_ref()).unwrap();

            assert_eq!(&secret.as_ref()[64..128], expected_tr.as_ref());
            assert!(secret.as_ref()[96..128].iter().any(|&byte| byte != 0));
        }
    };
}

tr_test!(expanded_key_has_fips_tr_44, MlDsa44);
tr_test!(expanded_key_has_fips_tr_65, MlDsa65);
tr_test!(expanded_key_has_fips_tr_87, MlDsa87);

#[test]
fn signature_parser_rejects_noncanonical_hint_encodings() {
    const HINT_OFFSET: usize = 32 + 4 * 576;
    const OMEGA: usize = 80;

    let canonical_empty_hint = vec![0u8; 2420];
    assert!(MlDsaSignature::from_bytes(&canonical_empty_hint).is_ok());

    let mut nonzero_padding = canonical_empty_hint.clone();
    nonzero_padding[HINT_OFFSET] = 1;
    assert!(MlDsaSignature::from_bytes(&nonzero_padding).is_err());

    let mut duplicate_indices = canonical_empty_hint.clone();
    duplicate_indices[HINT_OFFSET] = 7;
    duplicate_indices[HINT_OFFSET + 1] = 7;
    duplicate_indices[HINT_OFFSET + OMEGA..HINT_OFFSET + OMEGA + 4].copy_from_slice(&[2, 2, 2, 2]);
    assert!(MlDsaSignature::from_bytes(&duplicate_indices).is_err());

    let mut unsorted_indices = canonical_empty_hint.clone();
    unsorted_indices[HINT_OFFSET] = 8;
    unsorted_indices[HINT_OFFSET + 1] = 3;
    unsorted_indices[HINT_OFFSET + OMEGA..HINT_OFFSET + OMEGA + 4].copy_from_slice(&[2, 2, 2, 2]);
    assert!(MlDsaSignature::from_bytes(&unsorted_indices).is_err());

    let mut nonmonotonic_boundaries = canonical_empty_hint;
    nonmonotonic_boundaries[HINT_OFFSET] = 3;
    nonmonotonic_boundaries[HINT_OFFSET + 1] = 9;
    nonmonotonic_boundaries[HINT_OFFSET + OMEGA..HINT_OFFSET + OMEGA + 4]
        .copy_from_slice(&[2, 1, 1, 1]);
    assert!(MlDsaSignature::from_bytes(&nonmonotonic_boundaries).is_err());
}

#[test]
fn verify_rechecks_signature_canonicality_after_mutation() {
    let mut rng = ChaCha20Rng::from_seed([0x19; 32]);
    let (public, secret) = MlDsa44::keypair(&mut rng).unwrap();
    let mut signature = MlDsa44::sign_with_rng(MESSAGE, &secret, &mut rng).unwrap();
    let hint_offset = 32 + 4 * 576;
    let final_boundary = hint_offset + 80 + 3;
    signature.as_mut()[final_boundary] = 81;

    assert!(MlDsa44::verify(MESSAGE, &signature, &public).is_err());
}

#[test]
fn verification_rejects_a_canonical_encoding_with_out_of_range_z() {
    let mut rng = ChaCha20Rng::from_seed([0x1a; 32]);
    let (public, secret) = MlDsa44::keypair(&mut rng).unwrap();
    let signature = MlDsa44::sign_deterministic(MESSAGE, &secret).unwrap();
    let mut encoded = signature.as_ref().to_vec();

    // The first ML-DSA-44 z coefficient begins after the 32-byte challenge.
    // Encoding it as zero decodes to +gamma1: structurally canonical, but
    // outside the verification bound gamma1-beta.
    encoded[32] = 0;
    encoded[33] = 0;
    encoded[34] &= !0x03;
    let malformed = MlDsaSignature::from_bytes(&encoded).unwrap();
    assert!(MlDsa44::verify(MESSAGE, &malformed, &public).is_err());
}

#[test]
fn old_32_byte_tr_plus_padding_private_key_fails_paired_import() {
    let mut rng = ChaCha20Rng::from_seed([0xC7; 32]);
    let (public, secret) = MlDsa44::keypair(&mut rng).unwrap();
    let bytes = secret.as_ref();

    let mut legacy_layout = Vec::with_capacity(bytes.len());
    legacy_layout.extend_from_slice(&bytes[..96]);
    legacy_layout.extend_from_slice(&bytes[128..]);
    legacy_layout.extend_from_slice(&[0u8; 32]);
    assert_eq!(legacy_layout.len(), 2560);

    assert!(MlDsaSecretKey::from_bytes_with_public_key(&legacy_layout, &public).is_err());
}
