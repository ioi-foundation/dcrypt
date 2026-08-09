#![forbid(unsafe_code)]

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use dcrypt_legacy_xchacha20poly1305_migration::decrypt_legacy_v1;

const KEY: [u8; 32] = [0x42; 32];
const NONCE_24: [u8; 24] = [0x24; 24];
const PLAINTEXT: &[u8] = b"Extended nonce allows for random nonces";
const HISTORICAL_CIPHERTEXT: [u8; 55] = [
    0x67, 0x2c, 0x3b, 0x97, 0xcd, 0x47, 0x79, 0xf4, 0x49, 0xbd, 0x39, 0xba, 0x13, 0xbf, 0x4d, 0x21,
    0x36, 0x22, 0x06, 0x74, 0x76, 0xb0, 0xcb, 0xfc, 0x0e, 0x05, 0x3d, 0x1d, 0x9f, 0xb9, 0xc7, 0x90,
    0xe6, 0x96, 0xfe, 0x06, 0x63, 0x67, 0xd0, 0x75, 0x37, 0x4e, 0x3b, 0xe5, 0x12, 0x0e, 0x61, 0x6b,
    0x50, 0x4e, 0xd6, 0x99, 0x8f, 0xaf, 0xa6,
];

fn rustcrypto_historical_reference(plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut subkey = [0u8; 32];
    let mut derivation = chacha20::ChaCha20::new((&KEY).into(), (&NONCE_24[..12]).into());
    derivation.apply_keystream(&mut subkey);

    let cipher = ChaCha20Poly1305::new((&subkey).into());
    let result = cipher
        .encrypt(
            Nonce::from_slice(&NONCE_24[12..]),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap();
    subkey.fill(0);
    result
}

#[test]
fn historical_construction_matches_independent_primitives() {
    let ciphertext = rustcrypto_historical_reference(PLAINTEXT, &[]);
    assert_eq!(ciphertext, HISTORICAL_CIPHERTEXT);

    let recovered = decrypt_legacy_v1(&KEY, &NONCE_24, &ciphertext, None).unwrap();
    assert_eq!(&recovered[..], PLAINTEXT);
}

#[test]
fn associated_data_is_bound() {
    let ciphertext = rustcrypto_historical_reference(PLAINTEXT, b"record metadata");
    assert!(decrypt_legacy_v1(&KEY, &NONCE_24, &ciphertext, None).is_err());
    let recovered =
        decrypt_legacy_v1(&KEY, &NONCE_24, &ciphertext, Some(b"record metadata")).unwrap();
    assert_eq!(&recovered[..], PLAINTEXT);
}
