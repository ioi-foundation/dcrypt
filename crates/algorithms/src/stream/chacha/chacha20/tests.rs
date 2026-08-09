use super::*;
use crate::types::key::SymmetricKey;
use crate::types::Nonce;
use crate::types::RandomGeneration;
use crate::ChaCha20Algorithm;
use hex;
use rand::rngs::OsRng;

#[test]
fn test_chacha20_rfc8439() {
    // Test vector from RFC 8439
    let key =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
    let nonce = hex::decode("000000000000004a00000000").unwrap();
    let plaintext = hex::decode("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
        .unwrap();
    let expected_ciphertext = hex::decode("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d")
        .unwrap();

    // Convert to proper types
    let key_bytes: [u8; CHACHA20_KEY_SIZE] = key.try_into().expect("Invalid key length");
    let nonce_array: [u8; CHACHA20_NONCE_SIZE] = nonce.try_into().expect("Invalid nonce length");

    // Create a Nonce<12> from the byte array
    let nonce = Nonce::<CHACHA20_NONCE_SIZE>::new(nonce_array);

    // Create cipher with counter=1
    let mut chacha = ChaCha20::with_counter(&key_bytes, &nonce, 1);

    // Encrypt
    let mut output = plaintext.clone();
    chacha.encrypt(&mut output).unwrap();

    assert_eq!(output, expected_ciphertext);

    // Test decryption
    let mut chacha = ChaCha20::with_counter(&key_bytes, &nonce, 1);
    let mut decrypted = expected_ciphertext.clone();
    chacha.decrypt(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_chacha20_keystream() {
    // Test with a sample key and nonce
    let key = [0x42; CHACHA20_KEY_SIZE];
    let nonce_array = [0x24; CHACHA20_NONCE_SIZE];

    // Create a Nonce<12> from the byte array
    let nonce = Nonce::<CHACHA20_NONCE_SIZE>::new(nonce_array);

    let mut chacha = ChaCha20::new(&key, &nonce);

    // Generate keystream and test encryption
    let mut keystream = [0u8; 64];
    chacha.keystream(&mut keystream).unwrap();

    let plaintext = [0x12; 64];
    let mut ciphertext = plaintext;

    // Reset to start
    chacha.reset();
    chacha.encrypt(&mut ciphertext).unwrap();

    // Manual XOR to verify
    let mut expected = [0u8; 64];
    for i in 0..64 {
        expected[i] = plaintext[i] ^ keystream[i];
    }

    assert_eq!(ciphertext, expected);
}

#[test]
fn test_chacha20_seek() {
    // Test seeking to a specific counter
    let key = [0x42; CHACHA20_KEY_SIZE];
    let nonce_array = [0x24; CHACHA20_NONCE_SIZE];

    // Create a Nonce<12> from the byte array
    let nonce = Nonce::<CHACHA20_NONCE_SIZE>::new(nonce_array);

    // Create two ciphers
    let mut chacha1 = ChaCha20::new(&key, &nonce);
    let mut chacha2 = ChaCha20::new(&key, &nonce);

    // Advance chacha1 by processing some data
    let mut data = [0u8; 200];
    chacha1.process(&mut data).unwrap();

    // Seek chacha2 to where chacha1 should be
    chacha2.seek(3).unwrap(); // After 200 bytes (3 full blocks + part of 4th)

    // Both should now produce the same keystream
    let mut ks1 = [0u8; 64];
    let mut ks2 = [0u8; 64];

    chacha1.keystream(&mut ks1).unwrap();
    chacha2.keystream(&mut ks2).unwrap();

    assert_eq!(ks1, ks2);
}
#[test]
fn test_chacha20_with_secure_key() {
    // Create a secure key
    let key = SymmetricKey::<ChaCha20Algorithm, 32>::random(&mut OsRng).unwrap();
    let nonce = Nonce::<12>::random(&mut OsRng);

    // Create cipher with secure key
    let mut cipher = ChaCha20::new(key.as_ref().try_into().unwrap(), &nonce);

    // Test encryption/decryption
    let plaintext = b"test message";
    let mut buffer = plaintext.to_vec();

    cipher.encrypt(&mut buffer).unwrap();
    assert_ne!(&buffer[..], plaintext);

    cipher.reset();
    cipher.decrypt(&mut buffer).unwrap();
    assert_eq!(&buffer[..], plaintext);
}

#[test]
fn test_chacha20_zeroization() {
    let key = [0x42u8; 32];
    let nonce = Nonce::<12>::zeroed();

    let mut cipher = ChaCha20::new(&key, &nonce);
    let mut keystream = [0u8; 64];
    cipher.keystream(&mut keystream).unwrap();

    // Verify keystream was generated
    assert_ne!(keystream, [0u8; 64]);

    // Reset should clear the buffer
    cipher.reset();
    // Note: We can't directly access the buffer to verify it's zeroed
    // but reset() calls zeroize on it
}

#[test]
fn counter_exhaustion_fails_before_reusing_a_block() {
    let key = [0x42; CHACHA20_KEY_SIZE];
    let nonce = Nonce::<CHACHA20_NONCE_SIZE>::new([0x24; CHACHA20_NONCE_SIZE]);
    let mut cipher = ChaCha20::with_counter(&key, &nonce, u32::MAX);

    // The last representable counter block may be consumed exactly once.
    let mut final_block = [0u8; CHACHA20_BLOCK_SIZE];
    cipher.encrypt(&mut final_block).unwrap();

    // A subsequent request is rejected before mutating caller data.
    let mut sentinel = [0x5a];
    assert!(cipher.encrypt(&mut sentinel).is_err());
    assert_eq!(sentinel, [0x5a]);

    // Seeking to a position whose next counter would wrap is rejected too.
    assert!(cipher.seek(u32::MAX).is_err());
}
