#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_api::Signature;
use dcrypt_sign::eddsa::{Ed25519, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 4 * 1024;
const MAGIC: &[u8] = b"DCRYPT:ED25519:V1:";

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];
    let Some(input) = support::semantic_payload(input, MAGIC) else {
        return;
    };
    if input.is_empty() {
        return;
    }
    let seed = support::seed(input, 0xa1);
    let secret = Ed25519SecretKey::from_seed(&seed).expect("fixed-size Ed25519 seed");
    let public = secret.public_key().expect("seed derives a public key");
    let message = support::message(input, 1, 2 * 1024);

    let signature = Ed25519::sign(message, &secret).expect("Ed25519 signing succeeds");
    let repeated = Ed25519::sign(message, &secret).expect("Ed25519 signing is repeatable");
    assert_eq!(signature.to_bytes(), repeated.to_bytes());
    Ed25519::verify(message, &signature, &public).expect("generated Ed25519 signature verifies");

    let parsed_public = Ed25519PublicKey::from_bytes(&public.to_bytes())
        .expect("generated Ed25519 public key roundtrips");
    let parsed_signature = Ed25519Signature::from_bytes(&signature.to_bytes())
        .expect("generated Ed25519 signature roundtrips");
    Ed25519::verify(message, &parsed_signature, &parsed_public)
        .expect("roundtripped Ed25519 values verify");
    let exported_seed = secret.export_seed();
    let exported_seed: &[u8; 32] = (&exported_seed[..])
        .try_into()
        .expect("Ed25519 seed export is exact");
    let parsed_secret =
        Ed25519SecretKey::from_seed(exported_seed).expect("exported Ed25519 seed imports");
    assert_eq!(
        public.to_bytes(),
        parsed_secret.public_key().unwrap().to_bytes()
    );

    let different_message = support::tamper(message, input.len());
    assert!(Ed25519::verify(&different_message, &signature, &public).is_err());
    let modified = support::tamper(&signature.to_bytes(), input.len() + 11);
    if let Ok(modified) = Ed25519Signature::from_bytes(&modified) {
        assert!(Ed25519::verify(message, &modified, &public).is_err());
    }

    // Strict import rejects the identity encoding rather than admitting the
    // classic universal-forgery shape.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(Ed25519PublicKey::from_bytes(&identity).is_err());
});
