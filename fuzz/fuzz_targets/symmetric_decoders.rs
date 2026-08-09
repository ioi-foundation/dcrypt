#![no_main]
#![forbid(unsafe_code)]

use dcrypt_symmetric::{
    Aead, Aes128Gcm, Aes128Key, AesCiphertextPackage, ChaCha20Poly1305Cipher,
    ChaCha20Poly1305CiphertextPackage, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce, GcmNonce,
    SymmetricCipher, XChaCha20Poly1305Cipher, XChaCha20Poly1305Nonce,
};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 64 * 1024;

fn fixed<const N: usize>(input: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    if input.is_empty() {
        return output;
    }
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = input[(offset + index) % input.len()];
    }
    output
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];

    if let Ok(serialized) = core::str::from_utf8(input) {
        let _ = Aes128Key::from_secure_string(serialized);
        let _ = ChaCha20Poly1305Key::from_secure_string(serialized);
        let _ = GcmNonce::from_string(serialized);
        let _ = ChaCha20Poly1305Nonce::from_string(serialized);
        let _ = XChaCha20Poly1305Nonce::from_string(serialized);
        let _ = AesCiphertextPackage::from_string(serialized);
        let _ = ChaCha20Poly1305CiphertextPackage::from_string(serialized);
    }

    let ciphertext = input.get(24..).unwrap_or_default();
    let aad = input.get(..input.len().min(24));
    let key = ChaCha20Poly1305Key::new(fixed::<32>(input, 3));

    let chacha = ChaCha20Poly1305Cipher::new(&key).expect("fixed-size key");
    let chacha_nonce = ChaCha20Poly1305Nonce::new(fixed::<12>(input, 11));
    let _ = chacha.decrypt(&chacha_nonce, ciphertext, aad);

    let xchacha = XChaCha20Poly1305Cipher::new(&key).expect("fixed-size key");
    let xchacha_nonce = XChaCha20Poly1305Nonce::new(fixed::<24>(input, 19));
    let _ = xchacha.decrypt(&xchacha_nonce, ciphertext, aad);

    let aes_key = Aes128Key::new(fixed::<16>(input, 7));
    let gcm = Aes128Gcm::new(&aes_key).expect("fixed-size key");
    let gcm_nonce = GcmNonce::new(fixed::<12>(input, 13));
    let _ = gcm.decrypt(&gcm_nonce, ciphertext, aad);
});
