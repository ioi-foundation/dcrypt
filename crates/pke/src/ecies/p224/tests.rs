use super::*;
use crate::test_rng::TestRng;
use dcrypt_api::traits::Pke as PkeTrait;

#[test]
fn test_ecies_p224_keypair_generation() {
    let keypair_result = EciesP224::keypair(&mut TestRng);
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
fn test_ecies_p224_encrypt_decrypt_roundtrip_no_aad() {
    let (pk_r, sk_r) = EciesP224::keypair(&mut TestRng).expect("Recipient keygen failed");
    let plaintext = b"This is a secret message for ECIES P-224 without AAD.";

    let encrypt_result = EciesP224::encrypt(&pk_r, plaintext, None::<&[u8]>, &mut TestRng); // Explicit type for None
    assert!(
        encrypt_result.is_ok(),
        "Encryption failed: {:?}",
        encrypt_result.err()
    );
    let ciphertext = encrypt_result.unwrap();

    let decrypt_result = EciesP224::decrypt(&sk_r, &ciphertext, None::<&[u8]>); // Explicit type for None
    assert!(
        decrypt_result.is_ok(),
        "Decryption failed: {:?}",
        decrypt_result.err()
    );
    let decrypted_plaintext = decrypt_result.unwrap();

    assert_eq!(
        plaintext,
        decrypted_plaintext.as_slice(),
        "Decrypted plaintext does not match original"
    );
}

#[test]
fn test_ecies_p224_encrypt_decrypt_roundtrip_with_aad() {
    let (pk_r, sk_r) = EciesP224::keypair(&mut TestRng).expect("Recipient keygen failed");
    let plaintext = b"Another secret message with P-224 ECIES.";
    let aad_val = b"Authenticated Associated Data";
    let aad: Option<&[u8]> = Some(&aad_val[..]); // Cast to slice

    let ciphertext =
        EciesP224::encrypt(&pk_r, plaintext, aad, &mut TestRng).expect("Encryption failed");
    let decrypted_plaintext =
        EciesP224::decrypt(&sk_r, &ciphertext, aad).expect("Decryption failed");

    assert_eq!(plaintext, decrypted_plaintext.as_slice());
}

#[test]
fn test_ecies_p224_decrypt_wrong_secret_key() {
    let (pk_r, _sk_r1) = EciesP224::keypair(&mut TestRng).expect("Recipient keygen1 failed");
    let (_pk_r2, sk_r2) = EciesP224::keypair(&mut TestRng).expect("Recipient keygen2 failed");
    let plaintext = b"Message for key1.";

    let ciphertext = EciesP224::encrypt(&pk_r, plaintext, None::<&[u8]>, &mut TestRng)
        .expect("Encryption failed");
    let decrypt_result = EciesP224::decrypt(&sk_r2, &ciphertext, None::<&[u8]>);

    assert!(
        decrypt_result.is_err(),
        "Decryption should fail with wrong secret key"
    );
    if let Err(ApiError::DecryptionFailed { .. }) = decrypt_result {
        // Expected error type
    } else {
        panic!(
            "Expected DecryptionFailed error, got {:?}",
            decrypt_result.err()
        );
    }
}

#[test]
fn test_ecies_p224_decrypt_tampered_ciphertext_ephemeral_pk() {
    let (pk_r, sk_r) = EciesP224::keypair(&mut TestRng).expect("Recipient keygen failed");
    let plaintext = b"Sensitive data.";

    let mut ciphertext = EciesP224::encrypt(&pk_r, plaintext, None::<&[u8]>, &mut TestRng)
        .expect("Encryption failed");
    if !ciphertext.is_empty() {
        ciphertext[1] ^= 0xFF;
    }

    let decrypt_result = EciesP224::decrypt(&sk_r, &ciphertext, None::<&[u8]>);
    assert!(
        decrypt_result.is_err(),
        "Decryption should fail with tampered ephemeral PK"
    );
}

#[test]
fn test_ecies_p224_decrypt_tampered_ciphertext_aead_part() {
    let (pk_r, sk_r) = EciesP224::keypair(&mut TestRng).expect("Recipient keygen failed");
    let plaintext = b"More sensitive data.";

    let mut ciphertext = EciesP224::encrypt(&pk_r, plaintext, None::<&[u8]>, &mut TestRng)
        .expect("Encryption failed");
    if ciphertext.len()
        > ec::P224_POINT_UNCOMPRESSED_SIZE + 1 + CHACHA20POLY1305_NONCE_LEN + 1 + 4 + 1
    {
        let last_idx = ciphertext.len() - 1;
        ciphertext[last_idx] ^= 0xFF;
    }

    let decrypt_result = EciesP224::decrypt(&sk_r, &ciphertext, None::<&[u8]>);
    assert!(
        decrypt_result.is_err(),
        "Decryption should fail with tampered AEAD ciphertext/tag"
    );
    if let Err(ApiError::DecryptionFailed { .. }) = decrypt_result {
        // Expected because AEAD auth should fail
    } else {
        panic!(
            "Expected DecryptionFailed from AEAD, got {:?}",
            decrypt_result.err()
        );
    }
}

#[test]
fn test_ecies_p224_decrypt_wrong_aad() {
    let (pk_r, sk_r) = EciesP224::keypair(&mut TestRng).expect("Recipient keygen failed");
    let plaintext = b"Data with AAD.";
    let aad1_val = b"Correct AAD";
    let aad1: Option<&[u8]> = Some(&aad1_val[..]);
    let aad2_val = b"Incorrect AAD";
    let aad2: Option<&[u8]> = Some(&aad2_val[..]);

    let ciphertext =
        EciesP224::encrypt(&pk_r, plaintext, aad1, &mut TestRng).expect("Encryption failed");
    let decrypt_result = EciesP224::decrypt(&sk_r, &ciphertext, aad2);

    assert!(
        decrypt_result.is_err(),
        "Decryption should fail with wrong AAD"
    );
    if let Err(ApiError::DecryptionFailed { .. }) = decrypt_result {
        // Expected error
    } else {
        panic!(
            "Expected DecryptionFailed error for wrong AAD, got {:?}",
            decrypt_result.err()
        );
    }
}
