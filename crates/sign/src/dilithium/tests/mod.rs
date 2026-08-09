use super::*;
use dcrypt_algorithms::hash::{HashFunction, Sha256, Shake256};
use fips204::traits::{SerDes, Signer, Verifier};
use rand::{CryptoRng, Error as RngError, RngCore};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

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

            let decoded_public = DilithiumPublicKey::from_bytes(public_key.as_ref()).unwrap();
            let decoded_secret =
                DilithiumSecretKey::from_bytes_with_public_key(secret_key.as_ref(), &public_key)
                    .unwrap();
            let decoded_signature = DilithiumSignatureData::from_bytes(signature.as_ref()).unwrap();
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
fn unpaired_expanded_key_import_never_guesses_a_public_key() {
    let mut rng = ChaCha20Rng::from_seed([0x35; 32]);
    let (_, secret) = MlDsa44::keypair(&mut rng).unwrap();
    let imported = DilithiumSecretKey::from_bytes(secret.as_ref()).unwrap();
    assert!(imported.public_key().is_err());
}

#[test]
fn paired_import_rejects_incoherent_t0_without_panicking() {
    let mut rng = ChaCha20Rng::from_seed([0x36; 32]);
    let (public, secret) = MlDsa44::keypair(&mut rng).unwrap();
    let mut malformed = secret.as_ref().to_vec();
    // ML-DSA-44: 128-byte rho/K/tr prefix plus eight eta=2 polynomials
    // encoded at 96 bytes each. The remaining bytes encode t0.
    malformed[128 + 8 * 96..].fill(0);

    assert!(DilithiumSecretKey::from_bytes_with_public_key(&malformed, &public).is_err());
}

roundtrip_test!(ml_dsa_44_roundtrip, MlDsa44, 1312, 2560, 2420, "ML-DSA-44");
roundtrip_test!(ml_dsa_65_roundtrip, MlDsa65, 1952, 4032, 3309, "ML-DSA-65");
roundtrip_test!(ml_dsa_87_roundtrip, MlDsa87, 2592, 4896, 4627, "ML-DSA-87");

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
            // NIST ACVP ML-DSA-keyGen-FIPS204 internalProjection.json.
            // The digests keep the repository fixture compact while pinning every
            // byte of the official public and expanded-private-key outputs.
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
    assert!(DilithiumSignatureData::from_bytes(&canonical_empty_hint).is_ok());

    let mut nonzero_padding = canonical_empty_hint.clone();
    nonzero_padding[HINT_OFFSET] = 1;
    assert!(DilithiumSignatureData::from_bytes(&nonzero_padding).is_err());

    let mut duplicate_indices = canonical_empty_hint.clone();
    duplicate_indices[HINT_OFFSET] = 7;
    duplicate_indices[HINT_OFFSET + 1] = 7;
    duplicate_indices[HINT_OFFSET + OMEGA..HINT_OFFSET + OMEGA + 4].copy_from_slice(&[2, 2, 2, 2]);
    assert!(DilithiumSignatureData::from_bytes(&duplicate_indices).is_err());

    let mut unsorted_indices = canonical_empty_hint.clone();
    unsorted_indices[HINT_OFFSET] = 8;
    unsorted_indices[HINT_OFFSET + 1] = 3;
    unsorted_indices[HINT_OFFSET + OMEGA..HINT_OFFSET + OMEGA + 4].copy_from_slice(&[2, 2, 2, 2]);
    assert!(DilithiumSignatureData::from_bytes(&unsorted_indices).is_err());

    let mut nonmonotonic_boundaries = canonical_empty_hint;
    nonmonotonic_boundaries[HINT_OFFSET] = 3;
    nonmonotonic_boundaries[HINT_OFFSET + 1] = 9;
    nonmonotonic_boundaries[HINT_OFFSET + OMEGA..HINT_OFFSET + OMEGA + 4]
        .copy_from_slice(&[2, 1, 1, 1]);
    assert!(DilithiumSignatureData::from_bytes(&nonmonotonic_boundaries).is_err());
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

macro_rules! interoperability_test {
    (
        $name:ident,
        $scheme:ty,
        $module:ident,
        $pk_len:expr,
        $sk_len:expr,
        $sig_len:expr
    ) => {
        #[test]
        fn $name() {
            let mut rng = ChaCha20Rng::from_seed([0x73; 32]);
            let (dcrypt_public, dcrypt_secret) = <$scheme>::keypair(&mut rng).unwrap();

            let backend_public = fips204::$module::PublicKey::try_from_bytes(
                <[u8; $pk_len]>::try_from(dcrypt_public.as_ref()).unwrap(),
            )
            .unwrap();
            let backend_secret = fips204::$module::PrivateKey::try_from_bytes(
                <[u8; $sk_len]>::try_from(dcrypt_secret.as_ref()).unwrap(),
            )
            .unwrap();

            let dcrypt_signature =
                <$scheme>::sign_with_rng(MESSAGE, &dcrypt_secret, &mut rng).unwrap();
            let backend_signature = <[u8; $sig_len]>::try_from(dcrypt_signature.as_ref()).unwrap();
            assert!(backend_public.verify(MESSAGE, &backend_signature, &[]));

            let independent_signature = backend_secret
                .try_sign_with_rng(&mut rng, MESSAGE, &[])
                .unwrap();
            let wrapped_signature =
                DilithiumSignatureData::from_bytes(&independent_signature).unwrap();
            assert!(<$scheme>::verify(MESSAGE, &wrapped_signature, &dcrypt_public).is_ok());
            assert_eq!(
                backend_secret.get_public_key().into_bytes().as_slice(),
                dcrypt_public.as_ref()
            );
        }
    };
}

interoperability_test!(
    fips204_interoperability_44,
    MlDsa44,
    ml_dsa_44,
    1312,
    2560,
    2420
);
interoperability_test!(
    fips204_interoperability_65,
    MlDsa65,
    ml_dsa_65,
    1952,
    4032,
    3309
);
interoperability_test!(
    fips204_interoperability_87,
    MlDsa87,
    ml_dsa_87,
    2592,
    4896,
    4627
);

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

    assert!(DilithiumSecretKey::from_bytes_with_public_key(&legacy_layout, &public).is_err());
}
