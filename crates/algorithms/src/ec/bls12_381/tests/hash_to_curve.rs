//! Tests for BLS12-381 Hash-to-Curve implementation

use crate::ec::bls12_381::hash_to_curve::{expand_message_xmd, hash_to_curve_g1, hash_to_curve_g2};
use crate::ec::bls12_381::{G1Affine, G2Affine};

const G1_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
const G2_DST: &[u8] = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

#[test]
fn test_g1_hash_to_curve_sanity() {
    let msg = b"abc";
    let dst = G1_DST;

    let point = hash_to_curve_g1(msg, dst).expect("Hash to G1 failed");

    // Check properties
    assert!(
        bool::from(point.is_on_curve()),
        "Hashed G1 point must be on curve"
    );

    // Note: G1Projective doesn't expose is_torsion_free directly in public API usually,
    // but we can check if it has order r by multiplying by scalar field modulus (if we had it exposed).
    // Instead, rely on clear_cofactor being called in implementation.

    // Determinism check
    let point2 = hash_to_curve_g1(msg, dst).expect("Hash to G1 failed");
    assert_eq!(point, point2, "Hash to curve must be deterministic");

    // DST separation check
    let dst_diff = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_DIFF";
    let point3 = hash_to_curve_g1(msg, dst_diff).expect("Hash to G1 failed");
    assert_ne!(point, point3, "Different DST must produce different point");

    // Message separation check
    let msg_diff = b"abd";
    let point4 = hash_to_curve_g1(msg_diff, dst).expect("Hash to G1 failed");
    assert_ne!(
        point, point4,
        "Different message must produce different point"
    );
}

#[test]
fn test_g2_hash_to_curve_sanity() {
    let msg = b"abc";
    let dst = G2_DST;

    let point = hash_to_curve_g2(msg, dst).expect("Hash to G2 failed");

    // Check properties
    assert!(
        bool::from(point.is_on_curve()),
        "Hashed G2 point must be on curve"
    );

    // Determinism check
    let point2 = hash_to_curve_g2(msg, dst).expect("Hash to G2 failed");
    assert_eq!(point, point2, "Hash to curve must be deterministic");

    // DST separation check
    let dst_diff = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_DIFF";
    let point3 = hash_to_curve_g2(msg, dst_diff).expect("Hash to G2 failed");
    assert_ne!(point, point3, "Different DST must produce different point");

    // Message separation check
    let msg_diff = b"abd";
    let point4 = hash_to_curve_g2(msg_diff, dst).expect("Hash to G2 failed");
    assert_ne!(
        point, point4,
        "Different message must produce different point"
    );
}

#[test]
fn rfc9380_g1_random_oracle_vectors() {
    // RFC 9380 Appendix J.9.1. Uncompressed encoding is x || y.
    let vectors = [
        (
            b"" as &[u8],
            concat!(
                "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4",
                "e8cf62d9c09db0fac349612b759e79a1",
                "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4",
                "cc68ee29813bb7994998f3eae0c9c6a265"
            ),
        ),
        (
            b"abc" as &[u8],
            concat!(
                "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3",
                "aee664ba5379a7655d3c68900be2f6903",
                "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533",
                "311f0b8dfaaa154fa6b88176c229f2885d"
            ),
        ),
    ];

    for (message, expected_hex) in vectors {
        let point = G1Affine::from(hash_to_curve_g1(message, G1_DST).unwrap());
        assert_eq!(
            point.to_uncompressed().as_slice(),
            hex::decode(expected_hex).unwrap()
        );
        assert!(bool::from(point.is_torsion_free()));
    }
}

#[test]
fn rfc9380_g2_random_oracle_vectors() {
    // RFC 9380 Appendix J.10.1 coordinates are c0 + I*c1. The standard
    // uncompressed encoding orders each Fp2 value as c1 || c0.
    let vectors = [
        (
            b"" as &[u8],
            concat!(
                "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff",
                "5bf5dd71b72418717047f5b0f37da03d",
                "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8",
                "d4ac44c1038e9dcdd5393faf5c41fb78a",
                "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f639",
                "5c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
                "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec",
                "076daf2d4bc358c4b190c0c98064fdd92"
            ),
        ),
        (
            b"abc" as &[u8],
            concat!(
                "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe",
                "4ca3a230ed250fbe3a2acf73a41177fd8",
                "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbe",
                "c7780ccc7954725f4168aff2787776e6",
                "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1",
                "e1ce70dd94a733534f106d4cec0eddd16",
                "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244",
                "aeb197642555a0645fb87bf7466b2ba48"
            ),
        ),
    ];

    for (message, expected_hex) in vectors {
        let point = G2Affine::from(hash_to_curve_g2(message, G2_DST).unwrap());
        assert_eq!(
            point.to_uncompressed().as_slice(),
            hex::decode(expected_hex).unwrap()
        );
        assert!(bool::from(point.is_torsion_free()));
    }
}

#[test]
fn rfc9380_expand_message_xmd_vectors_include_oversize_dst() {
    // RFC 9380 Appendix K.1.
    assert_eq!(
        expand_message_xmd(b"", b"QUUX-V01-CS02-with-expander-SHA256-128", 32).unwrap(),
        hex::decode("68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235").unwrap()
    );

    // RFC 9380 Appendix K.2. This 256-byte DST exercises the mandatory
    // H("H2C-OVERSIZE-DST-" || DST) normalization path.
    let mut long_dst = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-".to_vec();
    long_dst.extend_from_slice(&[b'1'; 208]);
    assert_eq!(long_dst.len(), 256);
    assert_eq!(
        expand_message_xmd(b"abc", &long_dst, 32).unwrap(),
        hex::decode("52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12").unwrap()
    );
}
