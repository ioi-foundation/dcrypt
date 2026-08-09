use dcrypt_internal::{random::Error as RandomError, CryptoRng, RngCore};
use dcrypt_symmetric::{
    aes::{derive_aes256_key, generate_salt as generate_aes_salt},
    derive_chacha20poly1305_key, Aead, Aes128Gcm, Aes128Key, ChaCha20Poly1305Cipher,
    ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, ChaCha20Rng, GcmNonce, SymmetricCipher,
    XChaCha20Poly1305Cipher, XChaCha20Poly1305Nonce,
};

struct FailingRng;

impl RngCore for FailingRng {
    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> core::result::Result<(), RandomError> {
        destination.fill(0xa5);
        Err(RandomError)
    }
}

impl CryptoRng for FailingRng {}

#[test]
fn explicit_nonce_apis_round_trip() {
    let aes_key = Aes128Key::new([0x11; 16]);
    let aes = Aes128Gcm::new(&aes_key).unwrap();
    let aes_nonce = GcmNonce::new([0x22; 12]);
    let aes_ciphertext = aes
        .encrypt(&aes_nonce, b"AES plaintext", Some(b"context"))
        .unwrap();
    assert_eq!(
        aes.decrypt(&aes_nonce, &aes_ciphertext, Some(b"context"))
            .unwrap(),
        b"AES plaintext"
    );

    let chacha_key = ChaCha20Poly1305Key::new([0x33; 32]);
    let chacha = ChaCha20Poly1305Cipher::new(&chacha_key).unwrap();
    let chacha_nonce = ChaCha20Poly1305Nonce::new([0x44; 12]);
    let chacha_ciphertext = chacha
        .encrypt(&chacha_nonce, b"ChaCha plaintext", Some(b"context"))
        .unwrap();
    assert_eq!(
        chacha
            .decrypt(&chacha_nonce, &chacha_ciphertext, Some(b"context"))
            .unwrap(),
        b"ChaCha plaintext"
    );

    let xchacha = XChaCha20Poly1305Cipher::new(&chacha_key).unwrap();
    let xchacha_nonce = XChaCha20Poly1305Nonce::new([0x55; 24]);
    let xchacha_ciphertext = xchacha
        .encrypt(&xchacha_nonce, b"XChaCha plaintext", Some(b"context"))
        .unwrap();
    assert_eq!(
        xchacha
            .decrypt(&xchacha_nonce, &xchacha_ciphertext, Some(b"context"),)
            .unwrap(),
        b"XChaCha plaintext"
    );
}

#[test]
fn caller_seeded_generation_is_reproducible() {
    let mut left_rng = ChaCha20Rng::from_seed([0x61; 32]);
    let mut right_rng = ChaCha20Rng::from_seed([0x61; 32]);

    let left_key = ChaCha20Poly1305Key::generate(&mut left_rng).unwrap();
    let right_key = ChaCha20Poly1305Key::generate(&mut right_rng).unwrap();
    assert_eq!(left_key.as_bytes(), right_key.as_bytes());

    let left_nonce = XChaCha20Poly1305Nonce::generate(&mut left_rng).unwrap();
    let right_nonce = XChaCha20Poly1305Nonce::generate(&mut right_rng).unwrap();
    assert_eq!(left_nonce, right_nonce);

    let left_salt = generate_aes_salt(&mut left_rng, 32).unwrap();
    let right_salt = generate_aes_salt(&mut right_rng, 32).unwrap();
    assert_eq!(left_salt, right_salt);
}

#[test]
fn public_randomized_apis_propagate_source_failures() {
    let mut rng = FailingRng;
    assert!(matches!(
        Aes128Key::generate(&mut rng),
        Err(dcrypt_symmetric::Error::RandomGenerationError { .. })
    ));
    assert!(matches!(
        Aes128Gcm::generate_nonce(&mut rng),
        Err(dcrypt_symmetric::Error::RandomGenerationError { .. })
    ));
    assert!(matches!(
        generate_aes_salt(&mut rng, 16),
        Err(dcrypt_symmetric::Error::RandomGenerationError { .. })
    ));
}

#[test]
fn owned_pbkdf2_matches_rfc_compatible_vector() {
    let expected = [
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7, 0x22, 0x52, 0x56, 0xc4, 0xf8,
        0x37, 0xa8, 0x65, 0x48, 0xc9, 0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b,
        0xe1, 0x7b,
    ];
    assert_eq!(
        derive_aes256_key(b"password", b"salt", 1)
            .unwrap()
            .as_bytes(),
        &expected
    );
    assert_eq!(
        derive_chacha20poly1305_key(b"password", b"salt", 1)
            .unwrap()
            .as_bytes(),
        &expected
    );
}
