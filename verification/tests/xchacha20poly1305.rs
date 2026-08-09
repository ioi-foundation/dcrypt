use chacha20poly1305::aead::{Aead as OracleAead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305 as OracleXChaCha20Poly1305, XNonce};
use dcrypt_algorithms::aead::XChaCha20Poly1305;
use dcrypt_algorithms::types::Nonce;

fn bytes(len: usize, domain: u8) -> Vec<u8> {
    (0..len)
        .map(|index| domain.wrapping_add((index as u8).wrapping_mul(0x3d)))
        .collect()
}

#[test]
fn owned_xchacha20poly1305_matches_independent_implementation() {
    let lengths = [0, 1, 15, 16, 17, 63, 64, 65, 255, 1024];

    for (case, plaintext_len) in lengths.into_iter().enumerate() {
        let key: [u8; 32] =
            core::array::from_fn(|index| (case as u8).wrapping_mul(17).wrapping_add(index as u8));
        let nonce_bytes: [u8; 24] = core::array::from_fn(|index| {
            (case as u8)
                .wrapping_mul(29)
                .wrapping_add((index as u8).wrapping_mul(7))
        });
        let plaintext = bytes(plaintext_len, 0x31 ^ case as u8);
        let aad = bytes((case * 11) % 37, 0xa5 ^ case as u8);

        let owned = XChaCha20Poly1305::new(&key);
        let owned_nonce = Nonce::<24>::new(nonce_bytes);
        let oracle = OracleXChaCha20Poly1305::new_from_slice(&key).unwrap();
        let oracle_nonce = XNonce::from_slice(&nonce_bytes);

        let owned_ciphertext = owned.encrypt(&owned_nonce, &plaintext, Some(&aad)).unwrap();
        let oracle_ciphertext = oracle
            .encrypt(
                oracle_nonce,
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();

        assert_eq!(owned_ciphertext, oracle_ciphertext, "case {case}");
        assert_eq!(
            owned
                .decrypt(&owned_nonce, &oracle_ciphertext, Some(&aad))
                .unwrap(),
            plaintext,
            "owned decrypt case {case}"
        );
        assert_eq!(
            oracle
                .decrypt(
                    oracle_nonce,
                    Payload {
                        msg: &owned_ciphertext,
                        aad: &aad,
                    },
                )
                .unwrap(),
            plaintext,
            "oracle decrypt case {case}"
        );
    }
}

#[test]
fn owned_xchacha20poly1305_rejects_modified_tag() {
    let key = [0x53; 32];
    let nonce = Nonce::<24>::new([0xa7; 24]);
    let cipher = XChaCha20Poly1305::new(&key);
    let mut ciphertext = cipher
        .encrypt(&nonce, b"authenticated plaintext", Some(b"context"))
        .unwrap();
    *ciphertext.last_mut().unwrap() ^= 0x80;

    assert!(cipher
        .decrypt(&nonce, &ciphertext, Some(b"context"))
        .is_err());
}
