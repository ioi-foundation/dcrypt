//! sect283k1 unit tests

use super::*;
use dcrypt_internal::random::ChaCha20Rng;

#[test]
fn test_field_arithmetic() {
    let one = FieldElement::one();
    let mut two_bytes = [0u8; 36];
    two_bytes[35] = 2;
    let two = FieldElement::from_bytes(&two_bytes).unwrap();

    // a + a = 0 in binary field
    assert!(one.add(&one).is_zero());

    // 1 * 2 = 2
    assert_eq!(one.mul(&two), two);

    // 1 * 1^-1 = 1
    let inv_one = one.invert().unwrap();
    assert_eq!(one.mul(&inv_one), one);
}

#[test]
fn test_scalar_reduction() {
    // A scalar larger than the group order n
    let large_scalar_bytes = [0xFF; 36];
    let scalar = Scalar::new(large_scalar_bytes).unwrap();
    assert_ne!(scalar.serialize(), large_scalar_bytes);
    assert!(Scalar::new([0; 36]).is_err());
}

#[test]
fn test_point_operations() {
    let g = base_point_g();
    let g2 = g.double();

    // G + G = 2G
    assert_eq!(g.add(&g), g2);

    // G + (-G) = O, but in binary fields -G = G
    // For y^2+xy=x^3+ax^2+b, the negative of (x,y) is (x, x+y)
    let neg_g_y = g.x.add(&g.y);
    let neg_g = Point {
        is_identity: g.is_identity,
        x: g.x.clone(),
        y: neg_g_y,
    };
    assert!(g.add(&neg_g).is_identity());
}

#[test]
fn test_scalar_multiplication() {
    let g = base_point_g();

    let mut two_bytes = [0; 36];
    two_bytes[35] = 2;
    let two = Scalar::new(two_bytes).unwrap();

    let g2 = g.mul(&two).unwrap();
    assert_eq!(g2, g.double());
}

#[test]
fn test_keypair_generation() {
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let (sk, pk) = generate_keypair(&mut rng).unwrap();
    let pk_recomputed = scalar_mult_base_g(&sk).unwrap();
    assert_eq!(pk, pk_recomputed);
}

#[test]
fn test_point_compression_roundtrip() {
    let g = base_point_g();
    let compressed = g.serialize_compressed();
    let decompressed = Point::deserialize_compressed(&compressed).unwrap();
    assert_eq!(g, decompressed);

    let g2 = g.double();
    let compressed2 = g2.serialize_compressed();
    let decompressed2 = Point::deserialize_compressed(&compressed2).unwrap();
    assert_eq!(g2, decompressed2);
}

#[test]
fn test_base_point_on_curve() {
    // Verify that the base point is on the curve
    let g = base_point_g();
    assert!(!g.is_identity());

    // Test that the base point satisfies the curve equation
    let x = &g.x;
    let y = &g.y;

    // y^2 + xy = x^3 + 1
    let y_sq = y.square();
    let xy = x.mul(y);
    let lhs = y_sq.add(&xy);

    let x_cubed = x.square().mul(x);
    let rhs = x_cubed.add(&FieldElement::one());

    assert_eq!(lhs, rhs, "Base point must satisfy curve equation");
}

#[test]
fn test_ecdh_key_exchange() {
    // Generate two keypairs
    let mut rng = ChaCha20Rng::from_seed([0x43; 32]);
    let (sk1, pk1) = generate_keypair(&mut rng).unwrap();
    let (sk2, pk2) = generate_keypair(&mut rng).unwrap();

    // Compute shared secrets
    let shared1 = scalar_mult(&sk1, &pk2).unwrap();
    let shared2 = scalar_mult(&sk2, &pk1).unwrap();

    // They should be equal
    assert_eq!(shared1, shared2);
    assert!(!shared1.is_identity());
}

#[test]
fn test_kdf() {
    let input = b"test shared secret";
    let info = b"test info";

    let output1 = kdf_hkdf_sha384_for_ecdh_kem(input, Some(info)).unwrap();
    let output2 = kdf_hkdf_sha384_for_ecdh_kem(input, Some(info)).unwrap();

    // KDF should be deterministic
    assert_eq!(output1, output2);
    assert_eq!(output1.len(), B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE);

    // Different inputs should produce different outputs
    let output3 = kdf_hkdf_sha384_for_ecdh_kem(b"different input", Some(info)).unwrap();
    assert_ne!(output1, output3);
}
