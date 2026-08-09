//! Differential checks for the published, owned traditional EC arithmetic.
//!
//! The RustCrypto crates imported here are independent test oracles. This
//! workspace is excluded from dcrypt's published workspace and dependency
//! closure.

use dcrypt_algorithms::ec::{k256 as owned_k256, p224 as owned_p224, p256 as owned_p256};
use dcrypt_algorithms::ec::{p384 as owned_p384, p521 as owned_p521};
use p256::elliptic_curve::sec1::ToEncodedPoint;

fn decode_hex<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), N * 2);
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    output
}

fn minus_one<const N: usize>(mut value: [u8; N]) -> [u8; N] {
    for byte in value.iter_mut().rev() {
        let (next, borrow) = byte.overflowing_sub(1);
        *byte = next;
        if !borrow {
            break;
        }
    }
    value
}

#[test]
fn canonical_scalar_boundaries_match_independent_oracles() {
    let p224_order = decode_hex::<28>(
        "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
    );
    assert!(owned_p224::Scalar::new(p224_order).is_err());
    assert!(p224::SecretKey::from_slice(&p224_order).is_err());
    let p224_max = minus_one(p224_order);
    assert!(owned_p224::Scalar::new(p224_max).is_ok());
    assert!(p224::SecretKey::from_slice(&p224_max).is_ok());

    let p256_order = decode_hex::<32>(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    );
    assert!(owned_p256::Scalar::new(p256_order).is_err());
    assert!(p256::SecretKey::from_slice(&p256_order).is_err());
    let p256_max = minus_one(p256_order);
    assert!(owned_p256::Scalar::new(p256_max).is_ok());
    assert!(p256::SecretKey::from_slice(&p256_max).is_ok());

    let p384_order = decode_hex::<48>(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    );
    assert!(owned_p384::Scalar::new(p384_order).is_err());
    assert!(p384::SecretKey::from_slice(&p384_order).is_err());
    let p384_max = minus_one(p384_order);
    assert!(owned_p384::Scalar::new(p384_max).is_ok());
    assert!(p384::SecretKey::from_slice(&p384_max).is_ok());

    let p521_order = decode_hex::<66>(
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    );
    assert!(owned_p521::Scalar::new(p521_order).is_err());
    assert!(p521::SecretKey::from_slice(&p521_order).is_err());
    let p521_max = minus_one(p521_order);
    assert!(owned_p521::Scalar::new(p521_max).is_ok());
    assert!(p521::SecretKey::from_slice(&p521_max).is_ok());

    let k256_order = decode_hex::<32>(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    );
    assert!(owned_k256::Scalar::new(k256_order).is_err());
    assert!(k256::SecretKey::from_slice(&k256_order).is_err());
    let k256_max = minus_one(k256_order);
    assert!(owned_k256::Scalar::new(k256_max).is_ok());
    assert!(k256::SecretKey::from_slice(&k256_max).is_ok());

    assert!(owned_p224::Scalar::new([0; 28]).is_err());
    assert!(owned_p256::Scalar::new([0; 32]).is_err());
    assert!(owned_p384::Scalar::new([0; 48]).is_err());
    assert!(owned_p521::Scalar::new([0; 66]).is_err());
    assert!(owned_k256::Scalar::new([0; 32]).is_err());
}

fn candidates<const N: usize>(top_mask: u8) -> impl Iterator<Item = [u8; N]> {
    (1u8..=24).map(move |case| {
        let mut bytes = core::array::from_fn(|index| {
            case.wrapping_mul(0x3d)
                .wrapping_add((index as u8).wrapping_mul(0xa7))
                .rotate_left((index % 7) as u32)
        });
        bytes[0] &= top_mask;
        bytes[N - 1] |= 1;
        bytes
    })
}

#[test]
fn p224_base_multiplication_and_ecdh_match_oracle() {
    let peer_bytes = {
        let mut bytes = [0u8; 28];
        bytes[27] = 0x2b;
        bytes
    };
    let peer_owned = owned_p224::Scalar::new(peer_bytes).unwrap();
    let peer_point = owned_p224::scalar_mult_base_g(&peer_owned).unwrap();
    let peer_oracle = p224::SecretKey::from_slice(&peer_bytes).unwrap().public_key();

    for bytes in candidates::<28>(0x7f) {
        let scalar = owned_p224::Scalar::new(bytes).unwrap();
        let public = owned_p224::scalar_mult_base_g(&scalar).unwrap();
        let oracle_secret = p224::SecretKey::from_slice(&bytes).unwrap();
        assert_eq!(
            public.serialize_uncompressed().as_slice(),
            oracle_secret.public_key().to_encoded_point(false).as_bytes(),
        );

        let shared = owned_p224::scalar_mult(&scalar, &peer_point).unwrap();
        let oracle_shared =
            p224::ecdh::diffie_hellman(oracle_secret.to_nonzero_scalar(), peer_oracle.as_affine());
        assert_eq!(
            shared.x_coordinate_bytes().as_slice(),
            oracle_shared.raw_secret_bytes().as_slice(),
        );
    }
}

#[test]
fn p256_base_multiplication_and_ecdh_match_oracle() {
    let peer_bytes = {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x2b;
        bytes
    };
    let peer_owned = owned_p256::Scalar::new(peer_bytes).unwrap();
    let peer_point = owned_p256::scalar_mult_base_g(&peer_owned).unwrap();
    let peer_oracle = p256::SecretKey::from_slice(&peer_bytes).unwrap().public_key();

    for bytes in candidates::<32>(0x7f) {
        let scalar = owned_p256::Scalar::new(bytes).unwrap();
        let public = owned_p256::scalar_mult_base_g(&scalar).unwrap();
        let oracle_secret = p256::SecretKey::from_slice(&bytes).unwrap();
        assert_eq!(
            public.serialize_uncompressed().as_slice(),
            oracle_secret.public_key().to_encoded_point(false).as_bytes(),
        );

        let shared = owned_p256::scalar_mult(&scalar, &peer_point).unwrap();
        let oracle_shared =
            p256::ecdh::diffie_hellman(oracle_secret.to_nonzero_scalar(), peer_oracle.as_affine());
        assert_eq!(
            shared.x_coordinate_bytes().as_slice(),
            oracle_shared.raw_secret_bytes().as_slice(),
        );
    }
}

#[test]
fn p384_base_multiplication_and_ecdh_match_oracle() {
    let peer_bytes = {
        let mut bytes = [0u8; 48];
        bytes[47] = 0x2b;
        bytes
    };
    let peer_owned = owned_p384::Scalar::new(peer_bytes).unwrap();
    let peer_point = owned_p384::scalar_mult_base_g(&peer_owned).unwrap();
    let peer_oracle = p384::SecretKey::from_slice(&peer_bytes).unwrap().public_key();

    for bytes in candidates::<48>(0x7f) {
        let scalar = owned_p384::Scalar::new(bytes).unwrap();
        let public = owned_p384::scalar_mult_base_g(&scalar).unwrap();
        let oracle_secret = p384::SecretKey::from_slice(&bytes).unwrap();
        assert_eq!(
            public.serialize_uncompressed().as_slice(),
            oracle_secret.public_key().to_encoded_point(false).as_bytes(),
        );

        let shared = owned_p384::scalar_mult(&scalar, &peer_point).unwrap();
        let oracle_shared =
            p384::ecdh::diffie_hellman(oracle_secret.to_nonzero_scalar(), peer_oracle.as_affine());
        assert_eq!(
            shared.x_coordinate_bytes().as_slice(),
            oracle_shared.raw_secret_bytes().as_slice(),
        );
    }
}

#[test]
fn p521_base_multiplication_and_ecdh_match_oracle() {
    let peer_bytes = {
        let mut bytes = [0u8; 66];
        bytes[65] = 0x2b;
        bytes
    };
    let peer_owned = owned_p521::Scalar::new(peer_bytes).unwrap();
    let peer_point = owned_p521::scalar_mult_base_g(&peer_owned).unwrap();
    let peer_oracle = p521::SecretKey::from_slice(&peer_bytes).unwrap().public_key();

    for bytes in candidates::<66>(0x01) {
        let Ok(scalar) = owned_p521::Scalar::new(bytes) else {
            continue;
        };
        let public = owned_p521::scalar_mult_base_g(&scalar).unwrap();
        let oracle_secret = p521::SecretKey::from_slice(&bytes).unwrap();
        assert_eq!(
            public.serialize_uncompressed().as_slice(),
            oracle_secret.public_key().to_encoded_point(false).as_bytes(),
        );

        let shared = owned_p521::scalar_mult(&scalar, &peer_point).unwrap();
        let oracle_shared =
            p521::ecdh::diffie_hellman(oracle_secret.to_nonzero_scalar(), peer_oracle.as_affine());
        assert_eq!(
            shared.x_coordinate_bytes().as_slice(),
            oracle_shared.raw_secret_bytes().as_slice(),
        );
    }
}

#[test]
fn secp256k1_base_multiplication_and_ecdh_match_oracle() {
    let peer_bytes = {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x2b;
        bytes
    };
    let peer_owned = owned_k256::Scalar::new(peer_bytes).unwrap();
    let peer_point = owned_k256::scalar_mult_base_g(&peer_owned).unwrap();
    let peer_oracle = k256::SecretKey::from_slice(&peer_bytes).unwrap().public_key();

    for bytes in candidates::<32>(0x7f) {
        let scalar = owned_k256::Scalar::new(bytes).unwrap();
        let public = owned_k256::scalar_mult_base_g(&scalar).unwrap();
        let oracle_secret = k256::SecretKey::from_slice(&bytes).unwrap();
        assert_eq!(
            public.serialize_uncompressed().as_slice(),
            oracle_secret.public_key().to_encoded_point(false).as_bytes(),
        );

        let shared = owned_k256::scalar_mult(&scalar, &peer_point).unwrap();
        let oracle_shared =
            k256::ecdh::diffie_hellman(oracle_secret.to_nonzero_scalar(), peer_oracle.as_affine());
        assert_eq!(
            shared.x_coordinate_bytes().as_slice(),
            oracle_shared.raw_secret_bytes().as_slice(),
        );
    }
}
