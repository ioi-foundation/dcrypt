//! secp256k1 unit tests

use super::*;
use dcrypt_internal::random::{ChaCha20Rng, RngCore};

fn test_rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

#[test]
fn test_field_arithmetic() {
    let mut one_bytes = [0u8; 32];
    one_bytes[31] = 1;
    let one = FieldElement::from_bytes(&one_bytes).unwrap();

    let mut two_bytes = [0u8; 32];
    two_bytes[31] = 2;
    let two = FieldElement::from_bytes(&two_bytes).unwrap();

    // 1 + 1 = 2
    assert_eq!(one.add(&one), two);

    // 2 - 1 = 1
    assert_eq!(two.sub(&one), one);

    // 2 * 1 = 2
    assert_eq!(two.mul(&one), two);

    // 1 * 1^-1 = 1
    let inv_one = one.invert().unwrap();
    assert_eq!(one.mul(&inv_one), one);
}

#[test]
fn test_scalar_reduction() {
    // A scalar larger than the group order n
    let large_scalar_bytes = [0xFF; 32];
    let scalar = Scalar::new(large_scalar_bytes).unwrap();

    // The result should be different from the input
    assert_ne!(scalar.serialize(), large_scalar_bytes);

    // Test zero rejection
    assert!(Scalar::new([0; 32]).is_err());
}

#[test]
fn test_point_operations() {
    let g = base_point_g();
    let g2 = g.double();

    // G + G = 2G
    assert_eq!(g.add(&g), g2);

    // 2G - G = G (not implemented, but G + (-G) = O)
    // Here we check G + (-G) = O, but need to calculate -G first.
    let neg_g_y = g.y.negate();
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

    let mut two_bytes = [0; 32];
    two_bytes[31] = 2;
    let two = Scalar::new(two_bytes).unwrap();

    let g2 = g.mul(&two).unwrap();
    assert_eq!(g2, g.double());
}

#[test]
fn test_keypair_generation() {
    let (sk, pk) = generate_keypair(&mut test_rng(0x42)).unwrap();
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
fn test_point_uncompressed_roundtrip() {
    let g = base_point_g();
    let uncompressed = g.serialize_uncompressed();
    assert_eq!(
        uncompressed[0], 0x04,
        "Uncompressed point should start with 0x04"
    );

    let deserialized = Point::deserialize_uncompressed(&uncompressed).unwrap();
    assert_eq!(g, deserialized);

    // Test with doubled point
    let g2 = g.double();
    let uncompressed2 = g2.serialize_uncompressed();
    let deserialized2 = Point::deserialize_uncompressed(&uncompressed2).unwrap();
    assert_eq!(g2, deserialized2);

    // Test identity
    let identity = Point::identity();
    let uncompressed_id = identity.serialize_uncompressed();
    assert_eq!(
        uncompressed_id, [0u8; 65],
        "Identity should serialize to all zeros"
    );

    let deserialized_id = Point::deserialize_uncompressed(&uncompressed_id).unwrap();
    assert!(deserialized_id.is_identity());
}

#[test]
fn test_point_uncompressed_invalid() {
    // Test invalid format byte
    let mut invalid_format = [0u8; 65];
    invalid_format[0] = 0x05; // Invalid format byte
    assert!(Point::deserialize_uncompressed(&invalid_format).is_err());

    // Test point not on curve
    let mut not_on_curve = [0u8; 65];
    not_on_curve[0] = 0x04;
    not_on_curve[1] = 1; // x = 1
    not_on_curve[33] = 1; // y = 1 (not on curve)
    assert!(Point::deserialize_uncompressed(&not_on_curve).is_err());

    // Test wrong length
    let wrong_length = [0u8; 64];
    assert!(Point::deserialize_uncompressed(&wrong_length).is_err());
}

#[test]
fn test_point_validity() {
    let g = base_point_g();
    assert!(g.is_valid(), "Generator should be valid");

    let identity = Point::identity();
    assert!(identity.is_valid(), "Identity should be valid");

    // Test with random valid points
    let mut rng = test_rng(0x43);
    for _ in 0..10 {
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);
        if let Ok(scalar) = Scalar::new(scalar_bytes) {
            let point = g.mul(&scalar).unwrap();
            assert!(
                point.is_valid(),
                "Scalar multiplication should produce valid points"
            );
        }
    }
}

#[test]
fn test_field_parity() {
    let mut odd_bytes = [0u8; 32];
    odd_bytes[31] = 1; // value = 1 → odd
    let odd = FieldElement::from_bytes(&odd_bytes).unwrap();
    assert!(odd.is_odd());

    let mut even_bytes = [0u8; 32];
    even_bytes[30] = 1; // value = 256 → even
    let even = FieldElement::from_bytes(&even_bytes).unwrap();
    assert!(!even.is_odd());
}

// Additional property-based tests for better coverage

#[test]
fn test_point_compression_property() {
    let mut rng = test_rng(0x44);

    // Test with random scalars
    for _ in 0..100 {
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);

        // Skip if scalar is zero or >= order
        if let Ok(scalar) = Scalar::new(scalar_bytes) {
            let point = base_point_g().mul(&scalar).unwrap();

            // Compress and decompress
            let compressed = point.serialize_compressed();
            let decompressed = Point::deserialize_compressed(&compressed).unwrap();

            assert_eq!(point, decompressed, "Compression round-trip failed");
        }
    }
}

#[test]
fn test_point_uncompressed_property() {
    let mut rng = test_rng(0x45);

    // Test with random scalars
    for _ in 0..50 {
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);

        if let Ok(scalar) = Scalar::new(scalar_bytes) {
            let point = base_point_g().mul(&scalar).unwrap();

            // Test uncompressed serialization
            let uncompressed = point.serialize_uncompressed();
            let deserialized = Point::deserialize_uncompressed(&uncompressed).unwrap();

            assert_eq!(point, deserialized, "Uncompressed round-trip failed");

            // Verify the format
            assert_eq!(uncompressed[0], 0x04);
            assert_eq!(&uncompressed[1..33], &point.x_coordinate_bytes());
            assert_eq!(&uncompressed[33..65], &point.y_coordinate_bytes());
        }
    }
}

#[test]
fn test_field_sqrt_consistency() {
    let mut rng = test_rng(0x46);

    // Test that sqrt(x^2) = x or -x for random field elements
    for _ in 0..50 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        if let Ok(x) = FieldElement::from_bytes(&bytes) {
            let x_squared = x.square();

            if let Some(sqrt_result) = x_squared.sqrt() {
                // sqrt_result should be either x or -x
                assert!(
                    sqrt_result == x || sqrt_result == x.negate(),
                    "sqrt(x^2) should equal ±x"
                );

                // Verify that sqrt_result^2 = x^2
                assert_eq!(
                    sqrt_result.square(),
                    x_squared,
                    "sqrt consistency check failed"
                );
            }
        }
    }
}

#[test]
fn test_field_arithmetic_properties() {
    let mut rng = test_rng(0x47);

    for _ in 0..20 {
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        let mut c_bytes = [0u8; 32];
        rng.fill_bytes(&mut a_bytes);
        rng.fill_bytes(&mut b_bytes);
        rng.fill_bytes(&mut c_bytes);

        if let (Ok(a), Ok(b), Ok(c)) = (
            FieldElement::from_bytes(&a_bytes),
            FieldElement::from_bytes(&b_bytes),
            FieldElement::from_bytes(&c_bytes),
        ) {
            // Commutativity: a + b = b + a
            assert_eq!(a.add(&b), b.add(&a), "Addition not commutative");

            // Associativity: (a + b) + c = a + (b + c)
            assert_eq!(
                a.add(&b).add(&c),
                a.add(&b.add(&c)),
                "Addition not associative"
            );

            // Commutativity: a * b = b * a
            assert_eq!(a.mul(&b), b.mul(&a), "Multiplication not commutative");

            // Associativity: (a * b) * c = a * (b * c)
            assert_eq!(
                a.mul(&b).mul(&c),
                a.mul(&b.mul(&c)),
                "Multiplication not associative"
            );

            // Distributivity: a * (b + c) = a * b + a * c
            assert_eq!(
                a.mul(&b.add(&c)),
                a.mul(&b).add(&a.mul(&c)),
                "Multiplication not distributive"
            );

            // Identity: a + 0 = a
            assert_eq!(
                a.add(&FieldElement::zero()),
                a,
                "Zero not additive identity"
            );

            // Identity: a * 1 = a
            assert_eq!(
                a.mul(&FieldElement::one()),
                a,
                "One not multiplicative identity"
            );

            // Inverse: a + (-a) = 0
            assert_eq!(a.add(&a.negate()), FieldElement::zero(), "Negation failed");

            // Inverse: a * a^-1 = 1 (if a != 0)
            if !a.is_zero() {
                let a_inv = a.invert().unwrap();
                assert_eq!(a.mul(&a_inv), FieldElement::one(), "Inversion failed");
            }
        }
    }
}

#[test]
fn test_point_group_properties() {
    let mut rng = test_rng(0x48);
    let g = base_point_g();

    // Test associativity: (P + Q) + R = P + (Q + R)
    for _ in 0..10 {
        let mut s1_bytes = [0u8; 32];
        let mut s2_bytes = [0u8; 32];
        let mut s3_bytes = [0u8; 32];
        rng.fill_bytes(&mut s1_bytes);
        rng.fill_bytes(&mut s2_bytes);
        rng.fill_bytes(&mut s3_bytes);

        if let (Ok(s1), Ok(s2), Ok(s3)) = (
            Scalar::new(s1_bytes),
            Scalar::new(s2_bytes),
            Scalar::new(s3_bytes),
        ) {
            let p = g.mul(&s1).unwrap();
            let q = g.mul(&s2).unwrap();
            let r = g.mul(&s3).unwrap();

            let lhs = p.add(&q).add(&r);
            let rhs = p.add(&q.add(&r));

            assert_eq!(lhs, rhs, "Point addition not associative");
        }
    }

    // Test identity: P + O = P
    let identity = Point::identity();
    assert_eq!(g.add(&identity), g, "Identity element failed");

    // Test that nG = O for the group order n
    let n_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
        0x41, 0x41,
    ];
    let n = Scalar::new(n_bytes).unwrap();
    let result = g.mul(&n).unwrap();
    assert!(result.is_identity(), "nG should equal identity");
}

#[test]
fn test_edge_cases() {
    // Test identity point compression
    let identity = Point::identity();
    let compressed = identity.serialize_compressed();
    assert_eq!(
        compressed, [0u8; 33],
        "Identity should compress to all zeros"
    );

    let decompressed = Point::deserialize_compressed(&compressed).unwrap();
    assert!(
        decompressed.is_identity(),
        "Decompressed identity should be identity"
    );

    // Test field element edge cases
    assert!(FieldElement::zero().is_zero());
    assert!(!FieldElement::one().is_zero());
    assert_eq!(FieldElement::zero().double(), FieldElement::zero());
    assert_eq!(FieldElement::zero().square(), FieldElement::zero());
    assert_eq!(FieldElement::zero().negate(), FieldElement::zero());

    // Test that p-1 is valid but p is not
    let mut p_minus_1_bytes = [0u8; 32];
    p_minus_1_bytes.copy_from_slice(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFC, 0x2E,
    ]);
    assert!(FieldElement::from_bytes(&p_minus_1_bytes).is_ok());

    let mut p_bytes = [0u8; 32];
    p_bytes.copy_from_slice(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF,
        0xFC, 0x2F,
    ]);
    assert!(FieldElement::from_bytes(&p_bytes).is_err());
}
