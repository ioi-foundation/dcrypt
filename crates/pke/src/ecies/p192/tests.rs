//! Tests for ECIES P-192

use super::*; // Import from parent mod (p192/mod.rs)
use crate::test_rng::TestRng;
use dcrypt_api::traits::Pke; // The main PKE trait

#[test]
fn test_ecies_p192_keypair_generation() {
    let mut rng = TestRng;
    let keypair_result = EciesP192::keypair(&mut rng);
    assert!(
        keypair_result.is_ok(),
        "Keypair generation failed: {:?}",
        keypair_result.err()
    );
    if let Ok((pk, sk)) = keypair_result {
        assert_eq!(pk.as_ref().len(), ec::P192_POINT_UNCOMPRESSED_SIZE);
        assert_eq!(sk.as_ref().len(), ec::P192_SCALAR_SIZE);
    }
}

#[test]
fn test_ecies_p192_encrypt_decrypt_roundtrip_no_aad() {
    let mut rng = TestRng;
    let (pk_recipient, sk_recipient) =
        EciesP192::keypair(&mut rng).expect("Keypair generation failed");

    let plaintext = b"This is a secret message for ECIES P-192!";
    let aad: Option<&[u8]> = None;

    // Encrypt
    let ciphertext_result = EciesP192::encrypt(&pk_recipient, plaintext, aad, &mut rng);
    assert!(
        ciphertext_result.is_ok(),
        "Encryption failed: {:?}",
        ciphertext_result.err()
    );
    let ciphertext = ciphertext_result.unwrap();

    // Decrypt
    let decrypted_result = EciesP192::decrypt(&sk_recipient, &ciphertext, aad);
    assert!(
        decrypted_result.is_ok(),
        "Decryption failed: {:?}",
        decrypted_result.err()
    );
    let decrypted_plaintext = decrypted_result.unwrap();

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}

#[test]
fn test_ecies_p192_encrypt_decrypt_roundtrip_with_aad() {
    let mut rng = TestRng;
    let (pk_recipient, sk_recipient) =
        EciesP192::keypair(&mut rng).expect("Keypair generation failed");

    let plaintext = b"Another secret message for ECIES P-192 with AAD.";
    let aad = Some(b"Authenticated Associated Data".as_slice());

    // Encrypt
    let ciphertext =
        EciesP192::encrypt(&pk_recipient, plaintext, aad, &mut rng).expect("Encryption failed");

    // Decrypt
    let decrypted_plaintext =
        EciesP192::decrypt(&sk_recipient, &ciphertext, aad).expect("Decryption failed");

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}

#[test]
fn test_ecies_p192_decrypt_wrong_key() {
    let mut rng = TestRng;
    let (pk_recipient1, _sk_recipient1) =
        EciesP192::keypair(&mut rng).expect("Keypair 1 generation failed");
    let (_pk_recipient2, sk_recipient2) =
        EciesP192::keypair(&mut rng).expect("Keypair 2 generation failed"); // Wrong key

    let plaintext = b"Message for recipient 1.";
    let aad: Option<&[u8]> = None;

    // Encrypt for recipient 1
    let ciphertext =
        EciesP192::encrypt(&pk_recipient1, plaintext, aad, &mut rng).expect("Encryption failed");

    // Try to decrypt with recipient 2's key (should fail)
    let decrypted_result = EciesP192::decrypt(&sk_recipient2, &ciphertext, aad);
    assert!(
        decrypted_result.is_err(),
        "Decryption with wrong key should fail"
    );
    if let Err(ApiError::DecryptionFailed { context, .. }) = decrypted_result {
        assert!(context.contains("ECIES Decryption"));
    } else {
        panic!(
            "Expected DecryptionFailed error, got {:?}",
            decrypted_result
        );
    }
}

#[test]
fn test_ecies_p192_decrypt_tampered_ciphertext() {
    let mut rng = TestRng;
    let (pk_recipient, sk_recipient) =
        EciesP192::keypair(&mut rng).expect("Keypair generation failed");

    let plaintext = b"Message to be tampered.";
    let aad: Option<&[u8]> = None;

    let mut ciphertext =
        EciesP192::encrypt(&pk_recipient, plaintext, aad, &mut rng).expect("Encryption failed");

    // Tamper with the ciphertext (e.g., flip a bit in the AEAD part)
    if ciphertext.len() > ec::P192_POINT_UNCOMPRESSED_SIZE + CHACHA20POLY1305_NONCE_LEN + 5 {
        // Ensure we are past headers
        let target_index = ec::P192_POINT_UNCOMPRESSED_SIZE + CHACHA20POLY1305_NONCE_LEN + 4 + 1; // after R, N, CT_len, first byte of C
        if target_index < ciphertext.len() {
            ciphertext[target_index] ^= 0xff;
        }
    }

    let decrypted_result = EciesP192::decrypt(&sk_recipient, &ciphertext, aad);
    assert!(
        decrypted_result.is_err(),
        "Decryption of tampered ciphertext should fail"
    );
    if let Err(ApiError::DecryptionFailed { context, .. }) = decrypted_result {
        assert!(context.contains("AEAD authentication failed"));
    } else {
        panic!(
            "Expected DecryptionFailed (AEAD) error, got {:?}",
            decrypted_result
        );
    }
}

#[test]
fn test_ecies_p192_decrypt_wrong_aad() {
    let mut rng = TestRng;
    let (pk_recipient, sk_recipient) =
        EciesP192::keypair(&mut rng).expect("Keypair generation failed");

    let plaintext = b"Message with specific AAD.";
    let aad_encrypt = Some(b"Correct AAD".as_slice());
    let aad_decrypt = Some(b"Incorrect AAD".as_slice());

    let ciphertext = EciesP192::encrypt(&pk_recipient, plaintext, aad_encrypt, &mut rng)
        .expect("Encryption failed");

    // Try to decrypt with wrong AAD (should fail)
    let decrypted_result = EciesP192::decrypt(&sk_recipient, &ciphertext, aad_decrypt);
    assert!(
        decrypted_result.is_err(),
        "Decryption with wrong AAD should fail"
    );
}
