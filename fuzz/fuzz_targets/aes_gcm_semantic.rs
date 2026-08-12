#![no_main]
#![forbid(unsafe_code)]

mod support;

use dcrypt_algorithms::{
    aead::gcm::Gcm,
    block::{Aes128, Aes192, Aes256, BlockCipher},
    types::{Nonce, SecretBytes},
};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 64 * 1024;
const MAGIC: &[u8] = b"DCRYPT:AESGCM:V1:";

fn block_roundtrip(input: &[u8]) {
    let material = support::seed(input, 0xd1);
    let original: [u8; 16] = material[..16].try_into().expect("fixed block");

    let key128 = SecretBytes::<16>::new(material[..16].try_into().unwrap());
    let aes128 = Aes128::new(&key128);
    let mut block = original;
    aes128.encrypt_block(&mut block).unwrap();
    aes128.decrypt_block(&mut block).unwrap();
    assert_eq!(block, original);

    let key192 = SecretBytes::<24>::new(material[..24].try_into().unwrap());
    let aes192 = Aes192::new(&key192);
    let mut block = original;
    aes192.encrypt_block(&mut block).unwrap();
    aes192.decrypt_block(&mut block).unwrap();
    assert_eq!(block, original);

    let key256 = SecretBytes::<32>::new(material);
    let aes256 = Aes256::new(&key256);
    let mut block = original;
    aes256.encrypt_block(&mut block).unwrap();
    aes256.decrypt_block(&mut block).unwrap();
    assert_eq!(block, original);
}

macro_rules! gcm_roundtrip {
    ($aes:ty, $key_len:expr, $input:expr, $domain:expr) => {{
        let key_material = support::seed($input, $domain);
        let key = SecretBytes::<$key_len>::new(key_material[..$key_len].try_into().unwrap());
        let gcm = Gcm::new(<$aes>::new(&key)).expect("AES uses 128-bit blocks");
        let nonce_material = support::seed($input, $domain.wrapping_add(1));
        let nonce = Nonce::<12>::new(nonce_material[..12].try_into().unwrap());
        let aad_len = usize::from($input.first().copied().unwrap_or(0) % 33);
        let aad_material = support::seed($input, $domain.wrapping_add(2));
        let aad = &aad_material[..aad_len];
        let plaintext = support::message($input, 1, 32 * 1024);

        let ciphertext = gcm
            .internal_encrypt(&nonce, plaintext, Some(aad))
            .expect("GCM encryption succeeds");
        let recovered = gcm
            .internal_decrypt(&nonce, &ciphertext, Some(aad))
            .expect("GCM ciphertext authenticates");
        assert_eq!(recovered, plaintext);

        let modified = support::tamper(&ciphertext, usize::from($domain));
        assert!(gcm.internal_decrypt(&nonce, &modified, Some(aad)).is_err());
        let wrong_aad = support::tamper(aad, usize::from($domain) + 5);
        assert!(gcm
            .internal_decrypt(&nonce, &ciphertext, Some(&wrong_aad))
            .is_err());

        // Empty and partial-block messages transitively exercise GHASH length
        // encoding and padding, without claiming a direct GHASH oracle.
        for boundary in [0usize, 1, 15, 16, 17] {
            let boundary_plaintext = &key_material[..boundary.min(key_material.len())];
            let ciphertext = gcm
                .internal_encrypt(&nonce, boundary_plaintext, Some(aad))
                .unwrap();
            assert_eq!(
                gcm.internal_decrypt(&nonce, &ciphertext, Some(aad))
                    .unwrap(),
                boundary_plaintext
            );
        }
    }};
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];
    let Some(input) = support::semantic_payload(input, MAGIC) else {
        return;
    };
    let Some(selector) = input.first().copied() else {
        return;
    };
    block_roundtrip(input);
    if support::selector(selector, 2) == 0 {
        gcm_roundtrip!(Aes128, 16, input, 0xd2u8);
    } else {
        gcm_roundtrip!(Aes256, 32, input, 0xd3u8);
    }
});
