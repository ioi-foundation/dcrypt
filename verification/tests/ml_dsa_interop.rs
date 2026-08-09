#![forbid(unsafe_code)]

use dcrypt_api::Signature as _;
use dcrypt_internal::ChaCha20Rng;
use dcrypt_sign::mldsa::{
    MlDsa44 as DcryptMlDsa44, MlDsa65 as DcryptMlDsa65, MlDsa87 as DcryptMlDsa87, MlDsaSignature,
};
use fips204::traits::{SerDes, Signer, Verifier};

const MESSAGE: &[u8] = b"FIPS 204 ML-DSA interoperability test";
const CONTEXT: &[u8] = b"dcrypt verification workspace";
const RANDOMIZER: [u8; 32] = [0xA7; 32];

fn formatted_pure_message() -> Vec<u8> {
    let mut formatted = Vec::with_capacity(2 + CONTEXT.len() + MESSAGE.len());
    formatted.push(0);
    formatted.push(CONTEXT.len() as u8);
    formatted.extend_from_slice(CONTEXT);
    formatted.extend_from_slice(MESSAGE);
    formatted
}

macro_rules! interoperability_test {
    (
        $name:ident,
        $dcrypt:ty,
        $fips:ident,
        $libcrux:ident,
        $libcrux_sk:ident,
        $libcrux_pk:ident,
        $libcrux_sig:ident,
        $rustcrypto:ty,
        $pk_len:expr,
        $sk_len:expr,
        $sig_len:expr
    ) => {
        #[test]
        fn $name() {
            let mut key_rng = ChaCha20Rng::from_seed([0x73; 32]);
            let (dcrypt_public, dcrypt_secret) = <$dcrypt>::keypair(&mut key_rng).unwrap();
            let formatted = formatted_pure_message();

            // The public deterministic API must be repeatable. Its zero-rnd
            // result is pinned byte-for-byte against three independent FIPS
            // 204 implementations below.
            let deterministic =
                <$dcrypt>::sign_deterministic_with_context(MESSAGE, CONTEXT, &dcrypt_secret)
                    .unwrap();
            let deterministic_again =
                <$dcrypt>::sign_deterministic_with_context(MESSAGE, CONTEXT, &dcrypt_secret)
                    .unwrap();
            assert_eq!(deterministic.as_ref(), deterministic_again.as_ref());

            // Exercise dcrypt's exact internal interface with a fixed nonzero
            // rnd and require it to differ from the deterministic variant.
            let randomized =
                <$dcrypt>::sign_internal_with_randomizer(&formatted, &dcrypt_secret, &RANDOMIZER)
                    .unwrap();
            assert_ne!(deterministic.as_ref(), randomized.as_ref());
            assert!(
                <$dcrypt>::verify_with_context(MESSAGE, CONTEXT, &randomized, &dcrypt_public,)
                    .is_ok()
            );

            // fips204: import dcrypt's expanded keys, verify dcrypt output,
            // generate both variants, and verify those back in dcrypt.
            let fips_public = fips204::$fips::PublicKey::try_from_bytes(
                <[u8; $pk_len]>::try_from(dcrypt_public.as_ref()).unwrap(),
            )
            .unwrap();
            let fips_secret = fips204::$fips::PrivateKey::try_from_bytes(
                <[u8; $sk_len]>::try_from(dcrypt_secret.as_ref()).unwrap(),
            )
            .unwrap();
            assert_eq!(
                fips_secret.get_public_key().into_bytes().as_slice(),
                dcrypt_public.as_ref(),
            );
            let deterministic_array = <[u8; $sig_len]>::try_from(deterministic.as_ref()).unwrap();
            let randomized_array = <[u8; $sig_len]>::try_from(randomized.as_ref()).unwrap();
            assert!(fips_public.verify(MESSAGE, &deterministic_array, CONTEXT));
            assert!(fips_public.verify(MESSAGE, &randomized_array, CONTEXT));
            let fips_deterministic = fips_secret
                .try_sign_with_seed(&[0u8; 32], MESSAGE, CONTEXT)
                .unwrap();
            let fips_randomized = fips_secret
                .try_sign_with_seed(&RANDOMIZER, MESSAGE, CONTEXT)
                .unwrap();
            assert_eq!(fips_deterministic.as_slice(), deterministic.as_ref());
            assert_eq!(fips_randomized.as_slice(), randomized.as_ref());
            for signature in [&fips_deterministic[..], &fips_randomized[..]] {
                let signature = MlDsaSignature::from_bytes(signature).unwrap();
                assert!(<$dcrypt>::verify_with_context(
                    MESSAGE,
                    CONTEXT,
                    &signature,
                    &dcrypt_public,
                )
                .is_ok());
            }

            // libcrux: use the portable backend so the oracle's result is not
            // conditional on the host's SIMD support.
            let libcrux_public = libcrux_ml_dsa::$libcrux::$libcrux_pk::new(
                <[u8; $pk_len]>::try_from(dcrypt_public.as_ref()).unwrap(),
            );
            let libcrux_secret = libcrux_ml_dsa::$libcrux::$libcrux_sk::new(
                <[u8; $sk_len]>::try_from(dcrypt_secret.as_ref()).unwrap(),
            );
            let libcrux_deterministic = libcrux_ml_dsa::$libcrux::portable::sign(
                &libcrux_secret,
                MESSAGE,
                CONTEXT,
                [0u8; 32],
            )
            .unwrap();
            let libcrux_randomized = libcrux_ml_dsa::$libcrux::portable::sign(
                &libcrux_secret,
                MESSAGE,
                CONTEXT,
                RANDOMIZER,
            )
            .unwrap();
            assert_eq!(libcrux_deterministic.as_slice(), deterministic.as_ref());
            assert_eq!(libcrux_randomized.as_slice(), randomized.as_ref());
            for signature in [&deterministic_array, &randomized_array] {
                let signature = libcrux_ml_dsa::$libcrux::$libcrux_sig::new(*signature);
                assert!(libcrux_ml_dsa::$libcrux::portable::verify(
                    &libcrux_public,
                    MESSAGE,
                    CONTEXT,
                    &signature,
                )
                .is_ok());
            }
            for signature in [
                libcrux_deterministic.as_slice(),
                libcrux_randomized.as_slice(),
            ] {
                let signature = MlDsaSignature::from_bytes(signature).unwrap();
                assert!(<$dcrypt>::verify_with_context(
                    MESSAGE,
                    CONTEXT,
                    &signature,
                    &dcrypt_public,
                )
                .is_ok());
            }

            // RustCrypto: its internal API accepts the same M' and exact rnd,
            // which provides an independent byte-for-byte check of both paths.
            let rustcrypto_public_bytes =
                ml_dsa::EncodedVerifyingKey::<$rustcrypto>::try_from(dcrypt_public.as_ref())
                    .unwrap();
            let rustcrypto_public =
                ml_dsa::VerifyingKey::<$rustcrypto>::decode(&rustcrypto_public_bytes);
            let rustcrypto_secret_bytes =
                ml_dsa::ExpandedSigningKeyBytes::<$rustcrypto>::try_from(dcrypt_secret.as_ref())
                    .unwrap();
            #[allow(deprecated)]
            let rustcrypto_secret =
                ml_dsa::ExpandedSigningKey::<$rustcrypto>::from_expanded(&rustcrypto_secret_bytes);
            assert_eq!(
                rustcrypto_public.encode().as_slice(),
                dcrypt_public.as_ref()
            );

            let zero_rnd = ml_dsa::B32::try_from(&[0u8; 32][..]).unwrap();
            let fixed_rnd = ml_dsa::B32::try_from(&RANDOMIZER[..]).unwrap();
            let rustcrypto_deterministic = rustcrypto_secret
                .sign_internal(&[formatted.as_slice()], &zero_rnd)
                .encode();
            let rustcrypto_randomized = rustcrypto_secret
                .sign_internal(&[formatted.as_slice()], &fixed_rnd)
                .encode();
            assert_eq!(rustcrypto_deterministic.as_slice(), deterministic.as_ref());
            assert_eq!(rustcrypto_randomized.as_slice(), randomized.as_ref());

            for signature in [deterministic.as_ref(), randomized.as_ref()] {
                let encoded = ml_dsa::EncodedSignature::<$rustcrypto>::try_from(signature).unwrap();
                let signature = ml_dsa::Signature::<$rustcrypto>::decode(&encoded).unwrap();
                assert!(rustcrypto_public.verify_with_context(MESSAGE, CONTEXT, &signature));
            }
            for signature in [
                rustcrypto_deterministic.as_slice(),
                rustcrypto_randomized.as_slice(),
            ] {
                let signature = MlDsaSignature::from_bytes(signature).unwrap();
                assert!(<$dcrypt>::verify_with_context(
                    MESSAGE,
                    CONTEXT,
                    &signature,
                    &dcrypt_public,
                )
                .is_ok());
            }
        }
    };
}

interoperability_test!(
    ml_dsa_44_bidirectional_interoperability,
    DcryptMlDsa44,
    ml_dsa_44,
    ml_dsa_44,
    MLDSA44SigningKey,
    MLDSA44VerificationKey,
    MLDSA44Signature,
    ml_dsa::MlDsa44,
    1312,
    2560,
    2420
);

interoperability_test!(
    ml_dsa_65_bidirectional_interoperability,
    DcryptMlDsa65,
    ml_dsa_65,
    ml_dsa_65,
    MLDSA65SigningKey,
    MLDSA65VerificationKey,
    MLDSA65Signature,
    ml_dsa::MlDsa65,
    1952,
    4032,
    3309
);

interoperability_test!(
    ml_dsa_87_bidirectional_interoperability,
    DcryptMlDsa87,
    ml_dsa_87,
    ml_dsa_87,
    MLDSA87SigningKey,
    MLDSA87VerificationKey,
    MLDSA87Signature,
    ml_dsa::MlDsa87,
    2592,
    4896,
    4627
);
