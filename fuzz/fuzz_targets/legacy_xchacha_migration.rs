#![no_main]
#![forbid(unsafe_code)]

use dcrypt_algorithms::aead::chacha20poly1305::ChaCha20Poly1305;
use dcrypt_algorithms::stream::chacha::chacha20::ChaCha20;
use dcrypt_algorithms::types::Nonce;
use dcrypt_legacy_xchacha20poly1305_migration::decrypt_legacy;
use libfuzzer_sys::fuzz_target;

fn split_aad(payload: &[u8]) -> (Option<&[u8]>, &[u8]) {
    match payload.iter().position(|byte| *byte == b'|') {
        Some(boundary) => (Some(&payload[..boundary]), &payload[boundary + 1..]),
        None => (None, payload),
    }
}

fn historical_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let mut subkey = [0u8; 32];
    let prefix = Nonce::<12>::new(nonce[..12].try_into().ok()?);
    ChaCha20::new(key, &prefix).keystream(&mut subkey).ok()?;
    let encrypted = ChaCha20Poly1305::new(&subkey)
        .encrypt_with_nonce(&nonce[12..].try_into().ok()?, plaintext, aad)
        .ok();
    subkey.fill(0);
    encrypted
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 57 {
        return;
    }

    let synthesize_valid_ciphertext = data[0] & 1 == 1;
    let key: &[u8; 32] = data[1..33].try_into().unwrap();
    let nonce: &[u8; 24] = data[33..57].try_into().unwrap();
    let (aad, payload) = split_aad(&data[57..]);

    if synthesize_valid_ciphertext {
        let Some(ciphertext) = historical_encrypt(key, nonce, payload, aad) else {
            return;
        };
        let recovered = decrypt_legacy(key, nonce, &ciphertext, aad).unwrap();
        assert_eq!(&recovered[..], payload);
    } else {
        let _ = decrypt_legacy(key, nonce, payload, aad);
    }
});
