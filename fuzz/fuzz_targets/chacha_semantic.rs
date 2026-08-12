#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_algorithms::{
    aead::{chacha20poly1305::ChaCha20Poly1305, xchacha20poly1305::XChaCha20Poly1305},
    mac::poly1305::Poly1305,
    stream::chacha::chacha20::ChaCha20,
    types::Nonce,
};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 64 * 1024;
const MAGIC: &[u8] = b"DCRYPT:CHACHA:V1:";

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];
    let Some(input) = support::semantic_payload(input, MAGIC) else {
        return;
    };
    if input.is_empty() {
        return;
    }
    let selector = input.first().copied().unwrap_or(0);
    let key = support::seed(input, 0xe1);
    let nonce_material = support::seed(input, 0xe2);
    let nonce12: [u8; 12] = nonce_material[..12].try_into().unwrap();
    let nonce24_material = [support::seed(input, 0xe3), support::seed(input, 0xe4)].concat();
    let nonce24 = Nonce::<24>::new(nonce24_material[..24].try_into().unwrap());
    let aad_len = usize::from(selector % 33);
    let aad_material = support::seed(input, 0xe5);
    let aad = &aad_material[..aad_len];
    let plaintext = support::message(input, 1, 32 * 1024);

    let chacha = ChaCha20Poly1305::new(&key);
    let ciphertext = chacha
        .encrypt_with_nonce(&nonce12, plaintext, Some(aad))
        .expect("ChaCha20-Poly1305 encryption succeeds");
    assert_eq!(
        chacha
            .decrypt_with_nonce(&nonce12, &ciphertext, Some(aad))
            .unwrap(),
        plaintext
    );
    assert!(chacha
        .decrypt_with_nonce(
            &nonce12,
            &support::tamper(&ciphertext, usize::from(selector)),
            Some(aad)
        )
        .is_err());
    assert!(chacha
        .decrypt_with_nonce(
            &nonce12,
            &ciphertext,
            Some(&support::tamper(aad, usize::from(selector) + 1))
        )
        .is_err());

    let xchacha = XChaCha20Poly1305::new(&key);
    let xciphertext = xchacha
        .encrypt(&nonce24, plaintext, Some(aad))
        .expect("XChaCha20-Poly1305 encryption succeeds");
    assert_eq!(
        xchacha.decrypt(&nonce24, &xciphertext, Some(aad)).unwrap(),
        plaintext
    );
    assert!(xchacha
        .decrypt(
            &nonce24,
            &support::tamper(&xciphertext, usize::from(selector) + 2),
            Some(aad)
        )
        .is_err());

    let nonce = Nonce::<12>::new(nonce12);
    let mut whole = plaintext.to_vec();
    ChaCha20::new(&key, &nonce).process(&mut whole).unwrap();
    let split_at = if plaintext.is_empty() {
        0
    } else {
        usize::from(selector) % (plaintext.len() + 1)
    };
    let mut chunked = plaintext.to_vec();
    let mut stream = ChaCha20::new(&key, &nonce);
    stream.process(&mut chunked[..split_at]).unwrap();
    stream.process(&mut chunked[split_at..]).unwrap();
    assert_eq!(whole, chunked);
    ChaCha20::new(&key, &nonce).process(&mut whole).unwrap();
    assert_eq!(whole, plaintext);

    let mut one_shot = Poly1305::new(&key).unwrap();
    one_shot.update(plaintext).unwrap();
    let one_shot = one_shot.finalize();
    let mut chunked = Poly1305::new(&key).unwrap();
    chunked.update(&plaintext[..split_at]).unwrap();
    chunked.update(&plaintext[split_at..]).unwrap();
    assert_eq!(one_shot.as_ref(), chunked.finalize().as_ref());
});
