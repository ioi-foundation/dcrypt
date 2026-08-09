//! Tests for ECDSA P-192

use super::*; // Import from parent mod (p192/mod.rs)
use dcrypt_api::Signature; // The main Signature trait
use rand::rngs::OsRng;

#[test]
fn test_ecdsa_p192_keypair_generation() {
    let mut rng = OsRng;
    let keypair_result = EcdsaP192::keypair(&mut rng);
    assert!(
        keypair_result.is_ok(),
        "Keypair generation failed: {:?}",
        keypair_result.err()
    );
}

#[test]
fn test_ecdsa_p192_sign_verify_roundtrip() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP192::keypair(&mut rng).expect("Keypair generation failed");

    let message = b"This is a test message for ECDSA P-192 signing.";

    // Sign the message
    let signature_result = EcdsaP192::sign(message, &secret_key);
    assert!(
        signature_result.is_ok(),
        "Signing failed: {:?}",
        signature_result.err()
    );
    let signature = signature_result.unwrap();

    // Verify the signature
    let verification_result = EcdsaP192::verify(message, &signature, &public_key);
    assert!(
        verification_result.is_ok(),
        "Verification failed: {:?}",
        verification_result.err()
    );
}

#[test]
fn test_ecdsa_p192_signatures_are_low_s_and_high_s_is_rejected() {
    let (public_key, secret_key) = EcdsaP192::keypair(&mut OsRng).unwrap();
    let message = b"canonical";
    let signature = EcdsaP192::sign(message, &secret_key).unwrap();
    let components = crate::ecdsa::common::SignatureComponents::from_der(&signature.0).unwrap();
    let mut s = [0u8; ec::P192_SCALAR_SIZE];
    s[ec::P192_SCALAR_SIZE - components.s.len()..].copy_from_slice(&components.s);
    let s = ec::Scalar::new(s).unwrap();
    assert!(!is_high_s(&s.serialize(), &NIST_P192.n));

    let high_s = s.negate();
    assert!(is_high_s(&high_s.serialize(), &NIST_P192.n));
    let malleable = EcdsaP192Signature(
        crate::ecdsa::common::SignatureComponents {
            r: components.r.clone(),
            s: high_s.serialize().to_vec(),
        }
        .to_der(),
    );
    assert!(EcdsaP192::verify(message, &malleable, &public_key).is_err());

    let out_of_range = EcdsaP192Signature(
        crate::ecdsa::common::SignatureComponents {
            r: NIST_P192.n.to_vec(),
            s: s.serialize().to_vec(),
        }
        .to_der(),
    );
    assert!(EcdsaP192::verify(message, &out_of_range, &public_key).is_err());
}

#[test]
fn test_ecdsa_p192_sign_verify_failure_wrong_key() {
    let mut rng = OsRng;
    let (_public_key1, secret_key1) =
        EcdsaP192::keypair(&mut rng).expect("Keypair 1 generation failed");
    let (public_key2, _secret_key2) =
        EcdsaP192::keypair(&mut rng).expect("Keypair 2 generation failed");

    let message = b"Test message for wrong key verification.";

    // Sign with sk1
    let signature = EcdsaP192::sign(message, &secret_key1).expect("Signing failed");

    // Verify with pk2 (should fail)
    let verification_result = EcdsaP192::verify(message, &signature, &public_key2);
    assert!(
        verification_result.is_err(),
        "Verification should have failed with wrong public key"
    );
}

#[test]
fn test_ecdsa_p192_sign_verify_failure_tampered_message() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP192::keypair(&mut rng).expect("Keypair generation failed");

    let original_message = b"Original test message.";
    let tampered_message = b"Tampered test message.";

    // Sign the original message
    let signature = EcdsaP192::sign(original_message, &secret_key).expect("Signing failed");

    // Verify with the tampered message (should fail)
    let verification_result = EcdsaP192::verify(tampered_message, &signature, &public_key);
    assert!(
        verification_result.is_err(),
        "Verification should have failed with tampered message"
    );
}

#[test]
fn test_ecdsa_p192_sign_verify_failure_tampered_signature() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdsaP192::keypair(&mut rng).expect("Keypair generation failed");
    let message = b"Test message for tampered signature.";

    let mut signature = EcdsaP192::sign(message, &secret_key).expect("Signing failed");

    // Tamper with the signature (e.g., flip a bit in r or s within the DER structure)
    // This is a bit tricky as DER is structured. Let's just flip a byte.
    if !signature.0.is_empty() {
        // Find a byte that is not part of a length or tag if possible to avoid parse error
        // For simplicity, just flip a byte in the middle.
        let mid_index = signature.0.len() / 2;
        if mid_index > 0 {
            // Ensure there's something to flip
            signature.0[mid_index] ^= 0xff;
        } else if !signature.0.is_empty() {
            signature.0[0] ^= 0xff; // if very short, flip first byte
        }
    } else {
        // if signature is empty (should not happen for valid sign), this test is trivial
        // but we add a dummy byte to make it different if it was somehow an empty valid sig
        signature.0.push(0xff);
    }

    // Verify with the tampered signature (should fail) - FIXED: Changed EcdsaP224 to EcdsaP192
    let verification_result = EcdsaP192::verify(message, &signature, &public_key);
    match verification_result {
        Ok(_) => panic!("Verification should have failed with tampered signature"),
        Err(ApiError::InvalidSignature { .. }) => { /* Expected */ }
        Err(e) => panic!("Verification failed with unexpected error: {:?}", e),
    }
}

#[test]
fn test_ecdsa_p192_key_extraction() {
    let mut rng = OsRng;
    let keypair = EcdsaP192::keypair(&mut rng).expect("Keypair generation failed");
    let pk = EcdsaP192::public_key(&keypair);
    let sk = EcdsaP192::secret_key(&keypair);

    assert_eq!(pk.as_ref().len(), ec::P192_POINT_UNCOMPRESSED_SIZE);
    assert_eq!(sk.as_ref().len(), ec::P192_SCALAR_SIZE);
}
