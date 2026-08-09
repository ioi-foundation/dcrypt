// dcrypt-primitives/src/aead/chacha20poly1305/tests.rs
use super::*;
use crate::types::Nonce;
use hex;

#[test]
fn test_chacha20poly1305_rfc8439() {
    // Test vector from RFC 8439
    let key =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
    let nonce = hex::decode("070000004041424344454647").unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
        .unwrap();
    let expected_ciphertext = hex::decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")
        .unwrap();

    // Convert to proper types
    let key_bytes: [u8; CHACHA20POLY1305_KEY_SIZE] = key.try_into().expect("Invalid key length");
    let nonce_bytes: [u8; CHACHA20POLY1305_NONCE_SIZE] =
        nonce.try_into().expect("Invalid nonce length");

    // Create the Nonce object from the byte array
    let nonce_obj = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);

    // Create cipher
    let chacha_poly = ChaCha20Poly1305::new(&key_bytes);

    // Encrypt
    let ciphertext = chacha_poly
        .encrypt(&nonce_obj, &plaintext, Some(&aad))
        .expect("Encryption failed");

    assert_eq!(ciphertext, expected_ciphertext);

    // Decrypt
    let decrypted = chacha_poly
        .decrypt(&nonce_obj, &ciphertext, Some(&aad))
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_chacha20poly1305_encrypt_decrypt() {
    // Test with random key and nonce
    let key = [0x42; CHACHA20POLY1305_KEY_SIZE];
    let nonce_bytes = [0x24; CHACHA20POLY1305_NONCE_SIZE];

    // Create the Nonce object from the byte array
    let nonce = Nonce::<CHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);

    let aad = b"Additional authenticated data";
    let plaintext = b"Secret message that needs protection";

    let chacha_poly = ChaCha20Poly1305::new(&key);

    // Encrypt
    let ciphertext = chacha_poly
        .encrypt(&nonce, plaintext, Some(aad))
        .expect("Encryption failed");

    // Verify ciphertext is longer than plaintext (includes tag)
    assert_eq!(
        ciphertext.len(),
        plaintext.len() + CHACHA20POLY1305_TAG_SIZE
    );

    // Decrypt
    let decrypted = chacha_poly
        .decrypt(&nonce, &ciphertext, Some(aad))
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);

    // Verify that tampering with ciphertext results in authentication failure
    let mut tampered = ciphertext.clone();
    if !tampered.is_empty() {
        tampered[0] ^= 1; // Flip a bit
    }

    let result = chacha_poly.decrypt(&nonce, &tampered, Some(aad));
    assert!(result.is_err());

    // Verify that tampering with AAD results in authentication failure
    let wrong_aad = b"Wrong authenticated data";
    let result = chacha_poly.decrypt(&nonce, &ciphertext, Some(wrong_aad));
    assert!(result.is_err());
}

#[test]
#[cfg(target_pointer_width = "64")]
fn rejects_messages_past_the_chacha20_counter_limit_before_allocation() {
    let max_bytes = usize::try_from(CHACHA20POLY1305_MAX_DATA_BYTES).unwrap();
    assert!(validate_data_length(max_bytes).is_ok());
    assert!(validate_data_length(max_bytes + 1).is_err());
}
