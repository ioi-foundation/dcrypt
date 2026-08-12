#![forbid(unsafe_code)]

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
fn owned_xchacha20poly1305_matches_shared_lineage_comparator() {
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

#[test]
fn shared_lineage_comparator_negative_matrix_agrees() {
    let key = [0x53; 32];
    let wrong_key = [0x54; 32];
    let nonce_bytes = [0xa7; 24];
    let mut wrong_nonce_bytes = nonce_bytes;
    wrong_nonce_bytes[23] ^= 1;
    let nonce = Nonce::<24>::new(nonce_bytes);
    let wrong_nonce = Nonce::<24>::new(wrong_nonce_bytes);
    let owned = XChaCha20Poly1305::new(&key);
    let owned_wrong_key = XChaCha20Poly1305::new(&wrong_key);
    let oracle = OracleXChaCha20Poly1305::new_from_slice(&key).unwrap();
    let oracle_wrong_key = OracleXChaCha20Poly1305::new_from_slice(&wrong_key).unwrap();
    let oracle_nonce = XNonce::from_slice(&nonce_bytes);
    let oracle_wrong_nonce = XNonce::from_slice(&wrong_nonce_bytes);
    let plaintext = b"authenticated plaintext";
    let aad = b"context";

    let ciphertext = owned.encrypt(&nonce, plaintext, Some(aad)).unwrap();
    assert_eq!(
        ciphertext,
        oracle
            .encrypt(
                oracle_nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap()
    );

    assert!(owned_wrong_key
        .decrypt(&nonce, &ciphertext, Some(aad))
        .is_err());
    assert!(oracle_wrong_key
        .decrypt(
            oracle_nonce,
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .is_err());

    assert!(owned.decrypt(&wrong_nonce, &ciphertext, Some(aad)).is_err());
    assert!(oracle
        .decrypt(
            oracle_wrong_nonce,
            Payload {
                msg: &ciphertext,
                aad,
            },
        )
        .is_err());

    assert!(owned
        .decrypt(&nonce, &ciphertext, Some(b"wrong context"))
        .is_err());
    assert!(oracle
        .decrypt(
            oracle_nonce,
            Payload {
                msg: &ciphertext,
                aad: b"wrong context",
            },
        )
        .is_err());

    for index in [0, ciphertext.len() / 2, ciphertext.len() - 1] {
        let mut corrupted = ciphertext.clone();
        corrupted[index] ^= 0x80;
        assert!(owned.decrypt(&nonce, &corrupted, Some(aad)).is_err());
        assert!(oracle
            .decrypt(
                oracle_nonce,
                Payload {
                    msg: &corrupted,
                    aad,
                },
            )
            .is_err());
    }

    for length in [0, 1, 15] {
        let truncated = &ciphertext[..length];
        assert!(owned.decrypt(&nonce, truncated, Some(aad)).is_err());
        assert!(oracle
            .decrypt(
                oracle_nonce,
                Payload {
                    msg: truncated,
                    aad,
                },
            )
            .is_err());
    }
}
