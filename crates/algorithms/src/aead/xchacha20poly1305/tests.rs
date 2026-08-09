// dcrypt-primitives/src/aead/xchacha20poly1305/tests.rs
use super::*;
use crate::types::Nonce;

#[test]
fn hchacha20_draft_vector() {
    let key: [u8; 32] =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
    let nonce: [u8; 16] = hex::decode("000000090000004a0000000031415927")
        .unwrap()
        .try_into()
        .unwrap();
    let expected =
        hex::decode("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc").unwrap();

    assert_eq!(
        crate::stream::chacha::chacha20::hchacha20(&key, &nonce).as_slice(),
        expected
    );
}

#[test]
fn xchacha20poly1305_draft_aead_vector() {
    let key: [u8; 32] =
        hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap()
            .try_into()
            .unwrap();
    let nonce: [u8; 24] = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
        .unwrap()
        .try_into()
        .unwrap();
    let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
    let plaintext = hex::decode(concat!(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173",
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f",
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73",
        "637265656e20776f756c642062652069742e"
    ))
    .unwrap();
    let expected = hex::decode(concat!(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb",
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452",
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9",
        "21f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780a",
        "cf49"
    ))
    .unwrap();

    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = Nonce::<24>::new(nonce);
    let ciphertext = cipher.encrypt(&nonce, &plaintext, Some(&aad)).unwrap();
    assert_eq!(ciphertext, expected);
    assert_eq!(
        cipher.decrypt(&nonce, &ciphertext, Some(&aad)).unwrap(),
        plaintext
    );
}

#[test]
fn test_xchacha20poly1305() {
    // Simple test for XChaCha20Poly1305
    let key = [0x42; CHACHA20POLY1305_KEY_SIZE];
    let nonce_bytes = [0x24; XCHACHA20POLY1305_NONCE_SIZE];

    // Create the Nonce object from the byte array
    let nonce = Nonce::<XCHACHA20POLY1305_NONCE_SIZE>::new(nonce_bytes);

    let plaintext = b"Extended nonce allows for random nonces";

    let xchacha = XChaCha20Poly1305::new(&key);

    // Encrypt - now returns Result<Vec<u8>> so we need to expect/unwrap it
    let ciphertext = xchacha
        .encrypt(&nonce, plaintext, None)
        .expect("Encryption failed");

    // Decrypt
    let decrypted = xchacha
        .decrypt(&nonce, &ciphertext, None)
        .expect("Decryption failed");

    assert_eq!(decrypted, plaintext);
}
