//! Differential BLS12-381 checks against the excluded zkcrypto oracle.
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
use sha2::Sha256;

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
