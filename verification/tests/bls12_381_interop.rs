//! Differential BLS12-381 checks against the excluded zkcrypto oracle.

#![forbid(unsafe_code)]
//!
//! `verification` is excluded from the published workspace, so the oracle and
//! its dependency graph never become normal or build dependencies of dcrypt.

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve, HashToField},
    G1Affine as OracleG1Affine, G1Projective as OracleG1, G2Affine as OracleG2Affine,
    G2Projective as OracleG2, Scalar as OracleScalar,
};
use dcrypt_algorithms::ec::bls12_381::{
    Bls12_381Scalar, G1Affine, G1Projective, G2Affine, G2Projective,
};
use dcrypt_sign::bls::{
    Bls12381G2Basic, Bls12381G2MessageAugmentation, Bls12381G2ProofOfPossession,
    Bls12381ProofOfPossession, Bls12381PublicKey, Bls12381SecretKey, Bls12381Signature,
    Eth2Bls12381G2PopV4, BLS_AUG_G2_DST, BLS_BASIC_G2_DST, BLS_POP_G2_DST, BLS_POP_PROOF_G2_DST,
};
use hkdf::Hkdf as OracleHkdf;
use sha2::Sha256;
use sha2_010::{Digest as Digest010, Sha256 as Sha256_010};

const G1_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
const G2_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

#[test]
fn standard_generator_encodings_match_oracle() {
    assert_eq!(
        G1Affine::generator().to_compressed(),
        OracleG1Affine::generator().to_compressed()
    );
    assert_eq!(
        G1Affine::generator().to_uncompressed(),
        OracleG1Affine::generator().to_uncompressed()
    );
    assert_eq!(
        G2Affine::generator().to_compressed(),
        OracleG2Affine::generator().to_compressed()
    );
    assert_eq!(
        G2Affine::generator().to_uncompressed(),
        OracleG2Affine::generator().to_uncompressed()
    );
}

#[test]
fn standard_group_encodings_and_checked_decoders_interoperate() {
    for scalar in [1u64, 2, 3, 42, u16::MAX as u64] {
        let ours_scalar = Bls12_381Scalar::from(scalar);
        let oracle_scalar = OracleScalar::from(scalar);
        assert_eq!(ours_scalar.to_bytes(), oracle_scalar.to_bytes());
        let mut oracle_big_endian = oracle_scalar.to_bytes();
        oracle_big_endian.reverse();
        assert_eq!(ours_scalar.to_be_bytes(), oracle_big_endian);

        let ours_g1 = G1Affine::from(G1Projective::generator() * ours_scalar);
        let oracle_g1 = OracleG1Affine::from(OracleG1::generator() * oracle_scalar);
        assert_eq!(ours_g1.to_compressed(), oracle_g1.to_compressed());
        assert_eq!(ours_g1.to_uncompressed(), oracle_g1.to_uncompressed());
        assert_eq!(
            G1Affine::from_compressed(&oracle_g1.to_compressed())
                .unwrap()
                .to_compressed(),
            oracle_g1.to_compressed()
        );
        assert_eq!(
            OracleG1Affine::from_compressed(&ours_g1.to_compressed())
                .unwrap()
                .to_compressed(),
            ours_g1.to_compressed()
        );

        let ours_g2 = G2Affine::from(G2Projective::generator() * ours_scalar);
        let oracle_g2 = OracleG2Affine::from(OracleG2::generator() * oracle_scalar);
        assert_eq!(ours_g2.to_compressed(), oracle_g2.to_compressed());
        assert_eq!(ours_g2.to_uncompressed(), oracle_g2.to_uncompressed());
        assert_eq!(
            G2Affine::from_compressed(&oracle_g2.to_compressed())
                .unwrap()
                .to_compressed(),
            oracle_g2.to_compressed()
        );
        assert_eq!(
            OracleG2Affine::from_compressed(&ours_g2.to_compressed())
                .unwrap()
                .to_compressed(),
            ours_g2.to_compressed()
        );
    }
}

fn messages() -> [&'static [u8]; 5] {
    [
        b"".as_slice(),
        b"abc".as_slice(),
        b"abcdef0123456789".as_slice(),
        b"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".as_slice(),
        b"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_slice(),
    ]
}

#[test]
fn rfc9380_g1_hash_to_curve_matches_oracle() {
    for message in messages() {
        let ours_g1 = G1Affine::from(G1Projective::hash_to_curve(message, G1_DST).unwrap());
        let oracle_g1 =
            <OracleG1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, G1_DST);
        assert_eq!(
            ours_g1.to_compressed(),
            OracleG1Affine::from(oracle_g1).to_compressed(),
            "G1 mismatch for message length {}",
            message.len()
        );
    }
}

#[test]
fn rfc9380_g2_hash_to_curve_matches_oracle() {
    for message in messages() {
        let ours_g2 = G2Affine::from(G2Projective::hash_to_curve(message, G2_DST).unwrap());
        let oracle_g2 =
            <OracleG2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, G2_DST);
        assert_eq!(
            ours_g2.to_compressed(),
            OracleG2Affine::from(oracle_g2).to_compressed(),
            "G2 mismatch for message length {}",
            message.len()
        );
    }
}

#[test]
fn deterministic_hash_to_curve_corpus_matches_oracle() {
    for length in 0usize..64 {
        let message: Vec<u8> = (0..length)
            .map(|index| (index as u8).wrapping_mul(73).wrapping_add(length as u8))
            .collect();

        let ours_g1 = G1Affine::from(G1Projective::hash_to_curve(&message, G1_DST).unwrap());
        let oracle_g1 =
            <OracleG1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&message, G1_DST);
        assert_eq!(
            ours_g1.to_compressed(),
            OracleG1Affine::from(oracle_g1).to_compressed(),
            "G1 mismatch for differential corpus length {length}"
        );

        let ours_g2 = G2Affine::from(G2Projective::hash_to_curve(&message, G2_DST).unwrap());
        let oracle_g2 =
            <OracleG2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&message, G2_DST);
        assert_eq!(
            ours_g2.to_compressed(),
            OracleG2Affine::from(oracle_g2).to_compressed(),
            "G2 mismatch for differential corpus length {length}"
        );
    }
}

#[test]
fn rfc9380_oversize_dst_matches_oracle() {
    let mut dst = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-".to_vec();
    dst.extend_from_slice(&[b'1'; 208]);
    assert_eq!(dst.len(), 256);

    let ours_g1 = G1Affine::from(G1Projective::hash_to_curve(b"abc", &dst).unwrap());
    let oracle_g1 = <OracleG1 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(b"abc", &dst);
    assert_eq!(
        ours_g1.to_compressed(),
        OracleG1Affine::from(oracle_g1).to_compressed()
    );

    let ours_g2 = G2Affine::from(G2Projective::hash_to_curve(b"abc", &dst).unwrap());
    let oracle_g2 = <OracleG2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(b"abc", &dst);
    assert_eq!(
        ours_g2.to_compressed(),
        OracleG2Affine::from(oracle_g2).to_compressed()
    );
}

#[test]
fn scalar_hash_to_field_matches_oracle() {
    for (message, dst) in messages().into_iter().zip([
        G1_DST,
        G2_DST,
        b"scalar-dst".as_slice(),
        b"BLS-SIG-KEYGEN-SALT-".as_slice(),
        b"".as_slice(),
    ]) {
        let ours = Bls12_381Scalar::hash_to_field(message, dst).unwrap();
        let mut oracle = [OracleScalar::from(0u64)];
        OracleScalar::hash_to_field::<ExpandMsgXmd<Sha256>>(message, dst, &mut oracle);
        assert_eq!(ours.to_bytes(), oracle[0].to_bytes());
    }
}

fn oracle_keygen(ikm: &[u8], initial_salt: &[u8], key_info: &[u8]) -> [u8; 32] {
    assert!(ikm.len() >= 32);
    let mut salt = initial_salt.to_vec();
    let mut protected_ikm = ikm.to_vec();
    protected_ikm.push(0);
    let mut info = key_info.to_vec();
    info.extend_from_slice(&48u16.to_be_bytes());

    loop {
        let hkdf = OracleHkdf::<Sha256_010>::new(Some(&salt), &protected_ikm);
        let mut okm = [0u8; 48];
        hkdf.expand(&info, &mut okm).unwrap();

        let mut wide = [0u8; 64];
        for (destination, source) in wide.iter_mut().zip(okm.iter().rev()) {
            *destination = *source;
        }
        let scalar = OracleScalar::from_bytes_wide(&wide);
        if scalar != OracleScalar::zero() {
            let mut bytes = scalar.to_bytes();
            bytes.reverse();
            return bytes;
        }
        salt = Sha256_010::digest(&salt).to_vec();
    }
}

fn oracle_scalar(secret_key: &Bls12381SecretKey) -> OracleScalar {
    let protected = secret_key.to_bytes_zeroizing();
    let mut little_endian = *protected;
    little_endian.reverse();
    OracleScalar::from_bytes(&little_endian).unwrap()
}

fn oracle_public_key(secret_key: &Bls12381SecretKey) -> [u8; 48] {
    OracleG1Affine::from(OracleG1::generator() * oracle_scalar(secret_key)).to_compressed()
}

fn oracle_signature(secret_key: &Bls12381SecretKey, message: &[u8], dst: &[u8]) -> [u8; 96] {
    let message_point =
        <OracleG2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, dst);
    OracleG2Affine::from(message_point * oracle_scalar(secret_key)).to_compressed()
}

#[test]
fn draft07_and_eth2_keygen_match_independent_hkdf_and_scalar_oracles() {
    let ikm: [u8; 32] = core::array::from_fn(|index| index as u8);
    let salt = b"draft-07 caller salt";
    let key_info = b"independent-key-info";
    let ours = Bls12381SecretKey::key_gen_with_info(&ikm, salt, key_info).unwrap();
    assert_eq!(
        &*ours.to_bytes_zeroizing(),
        &oracle_keygen(&ikm, salt, key_info)
    );

    let eth2_salt = Sha256_010::digest(b"BLS-SIG-KEYGEN-SALT-");
    let eth2 = Eth2Bls12381G2PopV4::key_gen_with_info(&ikm, key_info).unwrap();
    assert_eq!(
        &*eth2.to_bytes_zeroizing(),
        &oracle_keygen(&ikm, &eth2_salt, key_info)
    );
}

#[test]
fn high_level_min_pk_profiles_match_independent_group_oracle() {
    let secret_key = Bls12381SecretKey::from_bytes(&{
        let mut bytes = [0u8; 32];
        bytes[31] = 42;
        bytes
    })
    .unwrap();
    let public_key = secret_key.public_key().unwrap();
    assert_eq!(public_key.to_bytes(), oracle_public_key(&secret_key));

    let message = b"independent BLS signature oracle";
    let basic = Bls12381G2Basic::sign(&secret_key, message).unwrap();
    assert_eq!(
        basic.to_bytes(),
        oracle_signature(&secret_key, message, BLS_BASIC_G2_DST)
    );

    let mut augmented_message = public_key.to_bytes().to_vec();
    augmented_message.extend_from_slice(message);
    let augmented = Bls12381G2MessageAugmentation::sign(&secret_key, message).unwrap();
    assert_eq!(
        augmented.to_bytes(),
        oracle_signature(&secret_key, &augmented_message, BLS_AUG_G2_DST)
    );

    let pop = Bls12381G2ProofOfPossession::sign(&secret_key, message).unwrap();
    assert_eq!(
        pop.to_bytes(),
        oracle_signature(&secret_key, message, BLS_POP_G2_DST)
    );
    let eth2 = Eth2Bls12381G2PopV4::sign(&secret_key, message).unwrap();
    assert_eq!(eth2.to_bytes(), pop.to_bytes());
    Eth2Bls12381G2PopV4::verify(&public_key, message, &eth2).unwrap();
    let proof = Bls12381G2ProofOfPossession::pop_prove(&secret_key).unwrap();
    assert_eq!(
        proof.to_bytes(),
        oracle_signature(&secret_key, &public_key.to_bytes(), BLS_POP_PROOF_G2_DST)
    );

    // Oracle encodings import into the high-level validated types and verify.
    let imported_public = Bls12381PublicKey::from_bytes(&oracle_public_key(&secret_key)).unwrap();
    let imported_signature =
        Bls12381Signature::from_bytes(&oracle_signature(&secret_key, message, BLS_POP_G2_DST))
            .unwrap();
    let imported_proof = Bls12381ProofOfPossession::from_bytes(&oracle_signature(
        &secret_key,
        &public_key.to_bytes(),
        BLS_POP_PROOF_G2_DST,
    ))
    .unwrap();
    Bls12381G2ProofOfPossession::verify(
        &imported_public,
        &imported_proof,
        message,
        &imported_signature,
    )
    .unwrap();
}

#[test]
fn high_level_aggregate_matches_independent_group_oracle() {
    let mut secret_a = [0u8; 32];
    secret_a[31] = 17;
    let secret_a = Bls12381SecretKey::from_bytes(&secret_a).unwrap();
    let mut secret_b = [0u8; 32];
    secret_b[31] = 29;
    let secret_b = Bls12381SecretKey::from_bytes(&secret_b).unwrap();
    let message = b"aggregate oracle";

    let signature_a = Bls12381G2ProofOfPossession::sign(&secret_a, message).unwrap();
    let signature_b = Bls12381G2ProofOfPossession::sign(&secret_b, message).unwrap();
    let aggregate =
        Bls12381Signature::aggregate(&[signature_a.clone(), signature_b.clone()]).unwrap();

    let oracle_a = OracleG2Affine::from_compressed(&signature_a.to_bytes()).unwrap();
    let oracle_b = OracleG2Affine::from_compressed(&signature_b.to_bytes()).unwrap();
    let oracle_aggregate = OracleG2Affine::from(OracleG2::from(oracle_a) + oracle_b);
    assert_eq!(aggregate.to_bytes(), oracle_aggregate.to_compressed());

    let public_keys = vec![
        secret_a.public_key().unwrap(),
        secret_b.public_key().unwrap(),
    ];
    let proofs = vec![
        Bls12381G2ProofOfPossession::pop_prove(&secret_a).unwrap(),
        Bls12381G2ProofOfPossession::pop_prove(&secret_b).unwrap(),
    ];
    Bls12381G2ProofOfPossession::fast_aggregate_verify(&public_keys, &proofs, message, &aggregate)
        .unwrap();
}
