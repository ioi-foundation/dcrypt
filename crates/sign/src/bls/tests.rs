use super::*;
use dcrypt_internal::zeroing::{boxed_bytes_from_slice, ZeroizingBytes};

fn secret(value: u8) -> Bls12381SecretKey {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    Bls12381SecretKey::from_bytes(&bytes).unwrap()
}

#[test]
fn secret_key_is_canonical_nonzero_and_debug_redacted() {
    assert!(Bls12381SecretKey::from_bytes(&[0u8; 32]).is_err());
    assert!(Bls12381SecretKey::from_bytes(&[0xff; 32]).is_err());
    assert!(Bls12381SecretKey::from_bytes(&[1u8; 31]).is_err());

    let secret = secret(7);
    assert_eq!(format!("{secret:?}"), "Bls12381SecretKey([REDACTED])");
    assert_eq!(secret.to_bytes_zeroizing()[31], 7);
}

#[test]
fn keygen_matches_fixed_draft07_and_eth2_v4_values() {
    assert!(Bls12381SecretKey::key_gen(&[0x42; 31], b"salt").is_err());

    let ikm: [u8; 32] = core::array::from_fn(|index| index as u8);
    let standard = Bls12381SecretKey::key_gen(&ikm, b"dcrypt draft-07 required salt").unwrap();
    let standard_bytes = standard.to_bytes_zeroizing();
    assert_eq!(
        hex::encode(&standard_bytes[..]),
        "1255d4ea9af906ede90de74bc3ab9b884c3bb995e194aea7eb52ee4e7c4f36db"
    );

    let eth2 = Eth2Bls12381G2PopV4::key_gen(&ikm).unwrap();
    let eth2_bytes = eth2.to_bytes_zeroizing();
    assert_eq!(
        hex::encode(&eth2_bytes[..]),
        "23360db7e337b0a32b264e06bc11c1b474d16f55665373de1ce93cf15ddb3456"
    );
}

#[test]
fn eth2_keygen_matches_erc2333_hkdf_mod_r_vectors() {
    // Source: ERC-2333, "Test Cases", https://eips.ethereum.org/EIPS/eip-2333
    // (accessed 2026-08-09). Its Version section records the 2020-09-17
    // update to draft-v4 KeyGen. ERC-2333's `derive_master_SK(seed)` is exactly
    // `HKDF_mod_r(seed)`, so these are authoritative v4 KeyGen vectors.
    let vectors = [
        (
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070",
        ),
        (
            "3141592653589793238462643383279502884197169399375105820974944592",
            "41c9e07822b092a93fd6797396338c3ada4170cc81829fdfce6b5d34bd5e7ec7",
        ),
        (
            "0099ff991111002299dd7744ee3355bbdd8844115566cc55663355668888cc00",
            "3cfa341ab3910a7d00d933d8f7c4fe87c91798a0397421d6b19fd5b815132e80",
        ),
        (
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            "2a0e28ffa5fbbe2f8e7aad4ed94f745d6bf755c51182e119bb1694fe61d3afca",
        ),
    ];

    for (seed_hex, expected_secret_hex) in vectors {
        let seed = hex::decode(seed_hex).unwrap();
        let secret = Eth2Bls12381G2PopV4::key_gen(&seed).unwrap();
        let secret_bytes = secret.to_bytes_zeroizing();
        assert_eq!(hex::encode(&secret_bytes[..]), expected_secret_hex);
    }
}

#[test]
fn keygen_retries_with_hashed_salt_after_zero_candidate() {
    let ikm = [0x42u8; 32];
    let initial_salt = b"retry salt";
    let mut calls = 0usize;
    let mut observed_salts = Vec::new();

    let key =
        Bls12381SecretKey::key_gen_inner(&ikm, initial_salt, &[], |salt, protected_ikm, info| {
            calls += 1;
            observed_salts.push(salt.to_vec());
            assert_eq!(&protected_ikm[..32], &ikm);
            assert_eq!(protected_ikm[32], 0);
            assert_eq!(info, &[0, 48]);
            let mut output = [0u8; KEYGEN_L];
            if calls == 2 {
                output[KEYGEN_L - 1] = 1;
            }
            Ok(ZeroizingBytes::new(boxed_bytes_from_slice(&output)))
        })
        .unwrap();

    assert_eq!(calls, 2);
    assert_eq!(observed_salts[0], initial_salt);
    assert_eq!(
        observed_salts[1],
        Sha256::digest(initial_salt).unwrap().as_ref()
    );
    assert_eq!(key.to_bytes_zeroizing()[31], 1);
}

#[test]
fn basic_aug_and_pop_round_trip_and_cross_domain_reject() {
    let secret = secret(42);
    let public = secret.public_key().unwrap();
    let message = b"BLS draft-07 message";

    let basic = Bls12381G2Basic::sign(&secret, message).unwrap();
    Bls12381G2Basic::verify(&public, message, &basic).unwrap();
    assert!(Bls12381G2Basic::verify(&public, b"wrong", &basic).is_err());

    let augmented = Bls12381G2MessageAugmentation::sign(&secret, message).unwrap();
    Bls12381G2MessageAugmentation::verify(&public, message, &augmented).unwrap();
    assert!(Bls12381G2Basic::verify(&public, message, &augmented).is_err());

    let proof = Bls12381G2ProofOfPossession::pop_prove(&secret).unwrap();
    Bls12381G2ProofOfPossession::pop_verify(&public, &proof).unwrap();
    let pop = Bls12381G2ProofOfPossession::sign(&secret, message).unwrap();
    Bls12381G2ProofOfPossession::verify(&public, &proof, message, &pop).unwrap();
    assert!(Bls12381G2ProofOfPossession::verify(&public, &proof, b"wrong", &pop).is_err());
}

#[test]
fn aggregation_enforces_each_scheme_rogue_key_rule() {
    let secret_a = secret(5);
    let secret_b = secret(9);
    let public_keys = vec![
        secret_a.public_key().unwrap(),
        secret_b.public_key().unwrap(),
    ];
    let distinct_messages: [&[u8]; 2] = [b"first", b"second"];

    let basic_signatures = vec![
        Bls12381G2Basic::sign(&secret_a, distinct_messages[0]).unwrap(),
        Bls12381G2Basic::sign(&secret_b, distinct_messages[1]).unwrap(),
    ];
    let basic_aggregate = Bls12381G2Basic::aggregate(&basic_signatures).unwrap();
    Bls12381G2Basic::aggregate_verify(&public_keys, &distinct_messages, &basic_aggregate).unwrap();
    assert!(
        Bls12381G2Basic::aggregate_verify(&public_keys, &[b"same", b"same"], &basic_aggregate,)
            .is_err()
    );

    let shared = b"same message".as_slice();
    let duplicate_basic_signatures = vec![
        Bls12381G2Basic::sign(&secret_a, shared).unwrap(),
        Bls12381G2Basic::sign(&secret_b, shared).unwrap(),
    ];
    let duplicate_basic_aggregate =
        Bls12381G2Basic::aggregate(&duplicate_basic_signatures).unwrap();
    assert!(Bls12381G2Basic::aggregate_verify(
        &public_keys,
        &[shared, shared],
        &duplicate_basic_aggregate,
    )
    .is_err());

    let augmented_signatures = vec![
        Bls12381G2MessageAugmentation::sign(&secret_a, shared).unwrap(),
        Bls12381G2MessageAugmentation::sign(&secret_b, shared).unwrap(),
    ];
    let augmented_aggregate =
        Bls12381G2MessageAugmentation::aggregate(&augmented_signatures).unwrap();
    Bls12381G2MessageAugmentation::aggregate_verify(
        &public_keys,
        &[shared, shared],
        &augmented_aggregate,
    )
    .unwrap();

    let proofs = vec![
        Bls12381G2ProofOfPossession::pop_prove(&secret_a).unwrap(),
        Bls12381G2ProofOfPossession::pop_prove(&secret_b).unwrap(),
    ];
    let pop_signatures = vec![
        Bls12381G2ProofOfPossession::sign(&secret_a, shared).unwrap(),
        Bls12381G2ProofOfPossession::sign(&secret_b, shared).unwrap(),
    ];
    let pop_aggregate = Bls12381G2ProofOfPossession::aggregate(&pop_signatures).unwrap();
    Bls12381G2ProofOfPossession::fast_aggregate_verify(
        &public_keys,
        &proofs,
        shared,
        &pop_aggregate,
    )
    .unwrap();
    Bls12381G2ProofOfPossession::aggregate_verify(
        &public_keys,
        &proofs,
        &[shared, shared],
        &pop_aggregate,
    )
    .unwrap();

    let wrong_proofs = vec![proofs[1].clone(), proofs[0].clone()];
    assert!(Bls12381G2ProofOfPossession::fast_aggregate_verify(
        &public_keys,
        &wrong_proofs,
        shared,
        &pop_aggregate,
    )
    .is_err());
}

#[test]
fn identity_contracts_distinguish_standard_and_eth2_empty_extension() {
    let identity_bytes = G2Projective::identity().to_bytes();
    let identity = Bls12381Signature::from_bytes(&identity_bytes).unwrap();
    assert!(identity.is_identity());

    assert!(Bls12381PublicKey::from_bytes(&G1Projective::identity().to_bytes()).is_err());
    let ordinary_secret = secret(2);
    assert!(Bls12381G2Basic::verify(
        &ordinary_secret.public_key().unwrap(),
        b"message",
        &identity,
    )
    .is_err());
    assert!(Bls12381Signature::aggregate(&[]).is_err());
    assert!(
        Bls12381G2ProofOfPossession::fast_aggregate_verify(&[], &[], b"message", &identity,)
            .is_err()
    );

    Eth2Bls12381G2PopV4::fast_aggregate_verify(&[], &[0u8; 32], &identity).unwrap();
    let nonidentity = Bls12381G2ProofOfPossession::sign(&secret(3), &[0u8; 32]).unwrap();
    assert!(Eth2Bls12381G2PopV4::fast_aggregate_verify(&[], &[0u8; 32], &nonidentity,).is_err());
}

#[test]
fn same_message_splitting_zero_public_keys_are_rejected() {
    let secret_one = secret(1);
    let largest_scalar = [
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ];
    let secret_minus_one = Bls12381SecretKey::from_bytes(&largest_scalar).unwrap();
    let public_keys = vec![
        secret_one.public_key().unwrap(),
        secret_minus_one.public_key().unwrap(),
    ];
    assert!(Bls12381PublicKey::aggregate(&public_keys).is_err());

    let message = b"same message".as_slice();
    let signatures = vec![
        Bls12381G2ProofOfPossession::sign(&secret_one, message).unwrap(),
        Bls12381G2ProofOfPossession::sign(&secret_minus_one, message).unwrap(),
    ];
    let aggregate = Bls12381Signature::aggregate(&signatures).unwrap();
    assert!(aggregate.is_identity());
    let proofs = vec![
        Bls12381G2ProofOfPossession::pop_prove(&secret_one).unwrap(),
        Bls12381G2ProofOfPossession::pop_prove(&secret_minus_one).unwrap(),
    ];

    assert!(Bls12381G2ProofOfPossession::aggregate_verify(
        &public_keys,
        &proofs,
        &[message, message],
        &aggregate,
    )
    .is_err());
    assert!(Bls12381G2ProofOfPossession::fast_aggregate_verify(
        &public_keys,
        &proofs,
        message,
        &aggregate,
    )
    .is_err());
    assert!(
        Eth2Bls12381G2PopV4::fast_aggregate_verify(&public_keys, &[0u8; 32], &aggregate,).is_err()
    );
}

#[test]
fn malformed_encodings_and_count_mismatches_are_rejected() {
    assert!(Bls12381PublicKey::from_bytes(&[0u8; 48]).is_err());
    assert!(Bls12381Signature::from_bytes(&[0u8; 96]).is_err());
    assert!(Bls12381ProofOfPossession::from_bytes(&[0u8; 96]).is_err());

    let secret = secret(11);
    let public = secret.public_key().unwrap();
    let signature = Bls12381G2Basic::sign(&secret, b"message").unwrap();
    assert!(Bls12381G2Basic::aggregate_verify(&[public], &[], &signature).is_err());
}
