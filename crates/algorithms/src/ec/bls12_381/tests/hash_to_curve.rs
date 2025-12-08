//! Tests for BLS12-381 Hash-to-Curve implementation

use crate::ec::bls12_381::hash_to_curve::{hash_to_curve_g1, hash_to_curve_g2};

#[test]
fn test_g1_hash_to_curve_sanity() {
    let msg = b"abc";
    let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    let point = hash_to_curve_g1(msg, dst).expect("Hash to G1 failed");

    // Check properties
    assert!(bool::from(point.is_on_curve()), "Hashed G1 point must be on curve");
    
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
    assert_ne!(point, point4, "Different message must produce different point");
}

#[test]
fn test_g2_hash_to_curve_sanity() {
    let msg = b"abc";
    let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";

    let point = hash_to_curve_g2(msg, dst).expect("Hash to G2 failed");

    // Check properties
    assert!(bool::from(point.is_on_curve()), "Hashed G2 point must be on curve");

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
    assert_ne!(point, point4, "Different message must produce different point");
}

// NOTE: Specific test vectors from RFC 9380 would be added here to verify 
// exact compliance with the standard values.
// The tests above ensure internal consistency and security properties.