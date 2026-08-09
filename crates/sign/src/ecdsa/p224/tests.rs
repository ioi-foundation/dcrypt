use super::*;
use dcrypt_api::Signature as SignatureTrait;
use dcrypt_internal::ChaCha20Rng;

fn test_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x42; 32])
}

#[test]
fn rfc6979_sha224_sample_signature_matches() {
    let bytes: [u8; ec::P224_SCALAR_SIZE] =
        hex::decode("F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1")
            .unwrap()
            .try_into()
            .unwrap();
    let secret = EcdsaP224SecretKey {
        raw: ec::Scalar::new(bytes).unwrap(),
        bytes,
    };
    let signature = EcdsaP224::sign(b"sample", &secret).unwrap();
    let components = SignatureComponents::from_der(signature.as_ref()).unwrap();

    assert_eq!(
        components.r,
        hex::decode("1CDFE6662DDE1E4A1EC4CDEDF6A1F5A2FB7FBD9145C12113E6ABFD3E").unwrap()
    );
    let expected_rfc_s: [u8; ec::P224_SCALAR_SIZE] =
        hex::decode("A6694FD7718A21053F225D3F46197CA699D45006C06F871808F43EBC")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_rfc_s = ec::Scalar::new(expected_rfc_s).unwrap();
    let expected_low_s = expected_rfc_s.negate().serialize();
    assert_eq!(components.s, expected_low_s.to_vec());
}

#[test]
fn test_ecdsa_p224_keypair_generation() {
    let keypair_result = EcdsaP224::keypair(&mut test_rng());
    assert!(
        keypair_result.is_ok(),
        "Keypair generation failed: {:?}",
        keypair_result.err()
    );
    let (pk, sk) = keypair_result.unwrap();
    assert_eq!(pk.as_ref().len(), ec::P224_POINT_UNCOMPRESSED_SIZE);
    assert_eq!(sk.as_ref().len(), ec::P224_SCALAR_SIZE);
}

#[test]
fn test_ecdsa_p224_sign_verify_roundtrip() {
    let (pk, sk) = EcdsaP224::keypair(&mut test_rng()).expect("Keygen failed");
    let message = b"This is a test message for ECDSA P-224.";

    let signature_result = EcdsaP224::sign(message, &sk);
    assert!(
        signature_result.is_ok(),
        "Signing failed: {:?}",
        signature_result.err()
    );
    let signature = signature_result.unwrap();

    let verification_result = EcdsaP224::verify(message, &signature, &pk);
    assert!(
        verification_result.is_ok(),
        "Verification failed: {:?}",
        verification_result.err()
    );
}

#[test]
fn test_ecdsa_p224_signatures_are_low_s_and_high_s_is_rejected() {
    let (public_key, secret_key) = EcdsaP224::keypair(&mut test_rng()).unwrap();
    let message = b"canonical";
    let signature = EcdsaP224::sign(message, &secret_key).unwrap();
    let components = crate::ecdsa::common::SignatureComponents::from_der(&signature.0).unwrap();
    let mut s = [0u8; ec::P224_SCALAR_SIZE];
    s[ec::P224_SCALAR_SIZE - components.s.len()..].copy_from_slice(&components.s);
    let s = ec::Scalar::new(s).unwrap();
    assert!(!is_high_s(&s.serialize(), &NIST_P224.n));

    let high_s = s.negate();
    assert!(is_high_s(&high_s.serialize(), &NIST_P224.n));
    let malleable = EcdsaP224Signature(
        crate::ecdsa::common::SignatureComponents {
            r: components.r.clone(),
            s: high_s.serialize().to_vec(),
        }
        .to_der(),
    );
    assert!(EcdsaP224::verify(message, &malleable, &public_key).is_err());

    let out_of_range = EcdsaP224Signature(
        crate::ecdsa::common::SignatureComponents {
            r: NIST_P224.n.to_vec(),
            s: s.serialize().to_vec(),
        }
        .to_der(),
    );
    assert!(EcdsaP224::verify(message, &out_of_range, &public_key).is_err());
}

#[test]
fn test_ecdsa_p224_verify_tampered_message() {
    let (pk, sk) = EcdsaP224::keypair(&mut test_rng()).expect("Keygen failed");
    let message = b"Original message.";
    let tampered_message = b"Tampered message!";

    let signature = EcdsaP224::sign(message, &sk).expect("Signing failed");

    let verification_result = EcdsaP224::verify(tampered_message, &signature, &pk);
    assert!(
        verification_result.is_err(),
        "Verification should fail for tampered message"
    );
}

#[test]
fn test_ecdsa_p224_verify_tampered_signature() {
    let (pk, sk) = EcdsaP224::keypair(&mut test_rng()).expect("Keygen failed");
    let message = b"Another test message.";

    let mut signature_vec = EcdsaP224::sign(message, &sk).expect("Signing failed").0;
    if !signature_vec.is_empty() {
        signature_vec[0] ^= 0xFF;
    }
    let tampered_signature_data = EcdsaP224Signature(signature_vec);

    let verification_result = EcdsaP224::verify(message, &tampered_signature_data, &pk);
    assert!(
        verification_result.is_err(),
        "Verification should fail for tampered signature"
    );
}

#[test]
fn test_ecdsa_p224_verify_wrong_public_key() {
    let mut rng = test_rng();
    let (_pk1, sk1) = EcdsaP224::keypair(&mut rng).expect("Keygen1 failed");
    let (pk2, _sk2) = EcdsaP224::keypair(&mut rng).expect("Keygen2 failed");
    let message = b"Message signed with key1.";

    let signature = EcdsaP224::sign(message, &sk1).expect("Signing failed");

    let verification_result = EcdsaP224::verify(message, &signature, &pk2);
    assert!(
        verification_result.is_err(),
        "Verification should fail with wrong public key"
    );
}
