#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_api::Signature;
use dcrypt_sign::ecdsa::{
    EcdsaP224, EcdsaP224PublicKey, EcdsaP224SecretKey, EcdsaP224Signature, EcdsaP256,
    EcdsaP256PublicKey, EcdsaP256SecretKey, EcdsaP256Signature, EcdsaP384, EcdsaP384PublicKey,
    EcdsaP384SecretKey, EcdsaP384Signature, EcdsaP521, EcdsaP521PublicKey, EcdsaP521SecretKey,
    EcdsaP521Signature,
};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 4 * 1024;
const MAGIC: &[u8] = b"DCRYPT:ECDSA:V1:";

macro_rules! exercise {
    (
        $scheme:ty,
        $public_ty:ty,
        $secret_ty:ty,
        $signature_ty:ty,
        $secret_size:expr,
        $input:expr,
        $domain:expr
    ) => {{
        let message = support::message($input, 2, 2 * 1024);
        let state = support::selector($input.get(1).copied().unwrap_or(0), 6);
        match state {
            // Prove RFC 6979 determinism without coupling the state to EC key
            // generation or verification work. Scalar one is canonical and
            // nonzero for every supported curve.
            0 => {
                let mut secret_bytes = vec![0u8; $secret_size];
                secret_bytes[$secret_size - 1] = 1;
                let secret = <$secret_ty>::from_bytes(&secret_bytes)
                    .expect("fixed canonical ECDSA secret imports");
                let signature = <$scheme>::sign(message, &secret).expect("ECDSA signing succeeds");
                let repeated =
                    <$scheme>::sign(message, &secret).expect("repeated ECDSA signing succeeds");
                assert_eq!(signature.to_bytes(), repeated.to_bytes());
            }
            // One key generation, one signature, and one verification.
            1 => {
                let mut rng = support::rng($input, $domain);
                let keypair =
                    <$scheme>::keypair(&mut rng).expect("input RNG yields an ECDSA keypair");
                let public = <$scheme>::public_key(&keypair);
                let secret = <$scheme>::secret_key(&keypair);
                let signature = <$scheme>::sign(message, &secret).expect("ECDSA signing succeeds");
                <$scheme>::verify(message, &signature, &public)
                    .expect("generated ECDSA signature verifies");
            }
            // Key imports are tested independently from signing so this state
            // has exactly one key generation and no signature operation.
            2 => {
                let mut rng = support::rng($input, $domain);
                let keypair =
                    <$scheme>::keypair(&mut rng).expect("input RNG yields an ECDSA keypair");
                let public = <$scheme>::public_key(&keypair);
                let secret = <$scheme>::secret_key(&keypair);
                let parsed_public = <$public_ty>::from_bytes(public.to_bytes())
                    .expect("generated ECDSA public key roundtrips");
                let secret_bytes = secret.to_bytes_zeroizing();
                let parsed_secret = <$secret_ty>::from_bytes(&secret_bytes)
                    .expect("generated ECDSA secret key roundtrips");
                assert_eq!(public.to_bytes(), parsed_public.to_bytes());
                assert_eq!(&secret_bytes[..], &parsed_secret.to_bytes_zeroizing()[..]);
            }
            // Strict DER import is independent from key generation and
            // verification; the positive verification state is state 1.
            3 => {
                let mut secret_bytes = vec![0u8; $secret_size];
                secret_bytes[$secret_size - 1] = 1;
                let secret = <$secret_ty>::from_bytes(&secret_bytes)
                    .expect("fixed canonical ECDSA secret imports");
                let signature = <$scheme>::sign(message, &secret).expect("ECDSA signing succeeds");
                let parsed_signature = <$signature_ty>::from_bytes(signature.to_bytes())
                    .expect("generated ECDSA DER roundtrips");
                assert_eq!(signature.to_bytes(), parsed_signature.to_bytes());
            }
            4 => {
                let mut rng = support::rng($input, $domain);
                let keypair =
                    <$scheme>::keypair(&mut rng).expect("input RNG yields an ECDSA keypair");
                let public = <$scheme>::public_key(&keypair);
                let secret = <$scheme>::secret_key(&keypair);
                let signature = <$scheme>::sign(message, &secret).expect("ECDSA signing succeeds");
                let different_message = support::tamper(message, usize::from($domain));
                assert!(<$scheme>::verify(&different_message, &signature, &public).is_err());
            }
            _ => {
                let mut rng = support::rng($input, $domain);
                let keypair =
                    <$scheme>::keypair(&mut rng).expect("input RNG yields an ECDSA keypair");
                let public = <$scheme>::public_key(&keypair);
                let secret = <$scheme>::secret_key(&keypair);
                let signature = <$scheme>::sign(message, &secret).expect("ECDSA signing succeeds");
                let modified = support::tamper(signature.to_bytes(), usize::from($domain) + 3);
                if let Ok(modified) = <$signature_ty>::from_bytes(&modified) {
                    assert!(<$scheme>::verify(message, &modified, &public).is_err());
                }
            }
        }
    }};
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];
    let Some(input) = support::semantic_payload(input, MAGIC) else {
        return;
    };
    let Some(selector) = input.first().copied() else {
        return;
    };
    match support::selector(selector, 4) {
        0 => exercise!(
            EcdsaP224,
            EcdsaP224PublicKey,
            EcdsaP224SecretKey,
            EcdsaP224Signature,
            28usize,
            input,
            0xb1u8
        ),
        1 => exercise!(
            EcdsaP256,
            EcdsaP256PublicKey,
            EcdsaP256SecretKey,
            EcdsaP256Signature,
            32usize,
            input,
            0xb2u8
        ),
        2 => exercise!(
            EcdsaP384,
            EcdsaP384PublicKey,
            EcdsaP384SecretKey,
            EcdsaP384Signature,
            48usize,
            input,
            0xb3u8
        ),
        _ => exercise!(
            EcdsaP521,
            EcdsaP521PublicKey,
            EcdsaP521SecretKey,
            EcdsaP521Signature,
            66usize,
            input,
            0xb4u8
        ),
    }
});
