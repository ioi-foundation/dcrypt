// File: crates/pke/src/ecies/p384/tests.rs
use super::*;
use crate::test_rng::TestRng;
use dcrypt_api::error::Error as ApiError; // Alias for clarity

#[test]
fn test_ecies_p384_keypair_generation() {
    let mut rng = TestRng;
    let result = EciesP384::keypair(&mut rng);
    assert!(
        result.is_ok(),
        "Keypair generation failed: {:?}",
        result.err()
    );
    let (pk, sk) = result.unwrap();
    assert_eq!(pk.as_ref().len(), ec::P384_POINT_UNCOMPRESSED_SIZE);
    assert_eq!(sk.as_ref().len(), ec::P384_SCALAR_SIZE);
}

#[test]
fn test_ecies_p384_encrypt_decrypt_no_aad() {
    let mut rng = TestRng;
    let (pk, sk) = EciesP384::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b"Hello, ECIES P384!";
    let aad: Option<&[u8]> = None;

    let ciphertext_vec =
        EciesP384::encrypt(&pk, plaintext, aad, &mut rng).expect("Encryption failed");

    let decrypted_plaintext =
        EciesP384::decrypt(&sk, &ciphertext_vec, aad).expect("Decryption failed");

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}

#[test]
fn test_ecies_p384_encrypt_decrypt_with_aad() {
    let mut rng = TestRng;
    let (pk, sk) = EciesP384::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b"Authenticated Encryption Test P384";
    let aad_data = *b"Some Associated Authenticated Data P384";
    let aad: Option<&[u8]> = Some(&aad_data);

    let ciphertext_vec =
        EciesP384::encrypt(&pk, plaintext, aad, &mut rng).expect("Encryption with AAD failed");

    let decrypted_plaintext =
        EciesP384::decrypt(&sk, &ciphertext_vec, aad).expect("Decryption with AAD failed");

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}

#[test]
fn test_ecies_p384_decrypt_wrong_key() {
    let mut rng = TestRng;
    let (pk, _sk) = EciesP384::keypair(&mut rng).expect("Keypair generation failed");
    let (_pk_wrong, sk_wrong) =
        EciesP384::keypair(&mut rng).expect("Second keypair generation failed");
    let plaintext = b"Test with wrong key P384";
    let aad_data = *b"AAD for wrong key test P384";
    let aad: Option<&[u8]> = Some(&aad_data);

    let ciphertext_vec =
        EciesP384::encrypt(&pk, plaintext, aad, &mut rng).expect("Encryption failed");

    let result = EciesP384::decrypt(&sk_wrong, &ciphertext_vec, aad);
    assert!(result.is_err(), "Decryption with wrong key should fail");

    match result.err().unwrap() {
        ApiError::DecryptionFailed { context, .. } => {
            assert!(context.contains("ECIES Decryption"));
        }
        e => panic!("Expected DecryptionFailed, got {:?}", e),
    }
}

#[test]
fn test_ecies_p384_decrypt_tampered_ciphertext() {
    let mut rng = TestRng;
    let (pk, sk) = EciesP384::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b"Do not tamper with this P384!";
    let aad_data = *b"Tamper test AAD P384";
    let aad: Option<&[u8]> = Some(&aad_data);

    let mut ciphertext_vec =
        EciesP384::encrypt(&pk, plaintext, aad, &mut rng).expect("Encryption failed");

    if !ciphertext_vec.is_empty() {
        let last_byte_index = ciphertext_vec.len() - 1;
        ciphertext_vec[last_byte_index] ^= 0x01;
    }

    let result = EciesP384::decrypt(&sk, &ciphertext_vec, aad);
    assert!(
        result.is_err(),
        "Decryption of tampered ciphertext should fail"
    );

    match result.err().unwrap() {
        ApiError::DecryptionFailed { context, .. } => {
            assert!(context.contains("ECIES Decryption"));
        }
        e => panic!("Expected DecryptionFailed due to tampering, got {:?}", e),
    }
}

#[test]
fn test_ecies_p384_decrypt_wrong_aad() {
    let mut rng = TestRng;
    let (pk, sk) = EciesP384::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b"AAD sensitivity test P384";
    let aad1_data = *b"Correct AAD P384";
    let aad1: Option<&[u8]> = Some(&aad1_data);
    let aad2_data = *b"Incorrect AAD P384";
    let aad2: Option<&[u8]> = Some(&aad2_data);

    let ciphertext_vec =
        EciesP384::encrypt(&pk, plaintext, aad1, &mut rng).expect("Encryption failed");

    let result = EciesP384::decrypt(&sk, &ciphertext_vec, aad2);
    assert!(result.is_err(), "Decryption with wrong AAD should fail");

    match result.err().unwrap() {
        ApiError::DecryptionFailed { context, .. } => {
            assert!(context.contains("ECIES Decryption"));
        }
        e => panic!("Expected DecryptionFailed due to wrong AAD, got {:?}", e),
    }
}

#[test]
fn test_ecies_p384_empty_plaintext() {
    let mut rng = TestRng;
    let (pk, sk) = EciesP384::keypair(&mut rng).expect("Keypair generation failed");
    let plaintext = b""; // Empty plaintext
    let aad_data = *b"Empty plaintext AAD P384";
    let aad: Option<&[u8]> = Some(&aad_data);

    let ciphertext_vec = EciesP384::encrypt(&pk, plaintext, aad, &mut rng)
        .expect("Encryption of empty plaintext failed");

    let decrypted_plaintext = EciesP384::decrypt(&sk, &ciphertext_vec, aad)
        .expect("Decryption of empty plaintext failed");

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}
