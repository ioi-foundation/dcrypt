#![no_main]
#![forbid(unsafe_code)]

use dcrypt_api::Signature;
use dcrypt_sign::ecdsa::{common::SignatureComponents, EcdsaP384PublicKey, EcdsaP384Signature};
use dcrypt_sign::eddsa::{Ed25519, Ed25519PublicKey, Ed25519Signature};
use dcrypt_sign::mldsa::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 16 * 1024;

fn expanded(data: &[u8], offset: usize, length: usize) -> Vec<u8> {
    let mut output = vec![0u8; length];
    if data.is_empty() {
        return output;
    }
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = data[(offset + index) % data.len()];
    }
    output
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];

    // Exercise the length parser directly as well as the public P-384 wrapper.
    let _ = SignatureComponents::from_der(input);
    let _ = EcdsaP384Signature::from_bytes(input);
    let _ = EcdsaP384PublicKey::from_bytes(input);

    // Exact-size normalization lets mutation reach canonical point/scalar
    // checks instead of spending nearly all iterations at a length check.
    let public_bytes = expanded(input, 0, 32);
    let signature_bytes = expanded(input, 17, 64);
    let public_key = Ed25519PublicKey::from_bytes(&public_bytes);
    let signature = Ed25519Signature::from_bytes(&signature_bytes);
    if let (Ok(public_key), Ok(signature)) = (public_key, signature) {
        let message = input.get(64..).unwrap_or_default();
        let _ = Ed25519::verify(message, &signature, &public_key);
    }

    // Select one FIPS 204 parameter set per iteration and normalize to its
    // exact public/private/signature sizes so coefficient and hint decoders run.
    let (public_len, secret_len, signature_len) = match input.first().copied().unwrap_or(0) % 3 {
        0 => (1312, 2560, 2420),
        1 => (1952, 4032, 3309),
        _ => (2592, 4896, 4627),
    };
    let ml_dsa_public = expanded(input, 1, public_len);
    let ml_dsa_secret = expanded(input, 29, secret_len);
    let ml_dsa_signature = expanded(input, 61, signature_len);
    let _ = MlDsaPublicKey::from_bytes(&ml_dsa_public);
    let _ = MlDsaSecretKey::from_bytes(&ml_dsa_secret);
    let _ = MlDsaSignature::from_bytes(&ml_dsa_signature);

    // Preserve direct malformed-length coverage as well.
    let _ = MlDsaPublicKey::from_bytes(input);
    let _ = MlDsaSecretKey::from_bytes(input);
    let _ = MlDsaSignature::from_bytes(input);
});
