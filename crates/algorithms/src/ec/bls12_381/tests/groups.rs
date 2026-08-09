//! Group operation tests for BLS12-381 G1 and G2

use super::super::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

use dcrypt_internal::constant_time::{Choice, ConditionallySelectable};
use dcrypt_internal::random::ChaCha20Rng;

// ============================================================================
// G1 Group Tests
// ============================================================================

#[test]
fn test_g1_identity_operations() {
    let identity = G1Projective::identity();
    let g = G1Projective::generator();
    let point = g * Scalar::from(42u64);

    // Identity + P = P
    assert_eq!(G1Affine::from(identity + point), G1Affine::from(point));
    assert_eq!(G1Affine::from(point + identity), G1Affine::from(point));

    // Identity * scalar = Identity
    let scalar = Scalar::from(42u64);
    assert_eq!(identity * scalar, identity);

    // Double of identity is identity
    assert_eq!(identity.double(), identity);

    // Negation of identity is identity
    assert_eq!(-identity, identity);
}

#[test]
fn test_g1_associativity() {
    // Use multiples of generator for deterministic behavior
    let g = G1Projective::generator();
    let p = g * Scalar::from(2u64);
    let q = g * Scalar::from(3u64);
    let r = g * Scalar::from(5u64);

    let sum1 = (p + q) + r;
    let sum2 = p + (q + r);

    // Compare as affine to handle different projective representations
    assert_eq!(G1Affine::from(sum1), G1Affine::from(sum2));
}

#[test]
fn test_g1_commutativity() {
    let g = G1Projective::generator();
    let p = g * Scalar::from(7u64);
    let q = g * Scalar::from(11u64);

    assert_eq!(G1Affine::from(p + q), G1Affine::from(q + p));
}

#[test]
fn test_g1_scalar_multiplication_distributivity() {
    let p = G1Projective::generator();
    let a = Scalar::from(42u64);
    let b = Scalar::from(69u64);

    // Test: [a+b]P == [a]P + [b]P
    let left = p * (a + b);
    let right = (p * a) + (p * b);

    // Compare as affine points to handle different projective representations
    assert_eq!(G1Affine::from(left), G1Affine::from(right));

    // Test: [a*b]P == [a]([b]P)
    let left = p * (a * b);
    let right = (p * b) * a;
    assert_eq!(G1Affine::from(left), G1Affine::from(right));
}

#[test]
fn test_g1_double_vs_add() {
    let g1 = G1Projective::generator();
    let p = g1 * Scalar::from(42u64);

    // Compare as affine points
    assert_eq!(G1Affine::from(p.double()), G1Affine::from(p + p));
}

#[test]
fn test_g1_mixed_addition_consistency() {
    let g = G1Projective::generator();
    let p_proj = g * Scalar::from(13u64);
    let q_proj = g * Scalar::from(17u64);
    let p_aff = G1Affine::from(p_proj);
    let q_aff = G1Affine::from(q_proj);

    // All combinations should give same result
    let result1 = p_proj + q_proj;
    let result2 = p_proj + q_aff;
    let result3 = p_aff + q_proj;
    let result4 = G1Projective::from(p_aff) + G1Projective::from(q_aff);

    // Compare as affine points
    let aff1 = G1Affine::from(result1);
    let aff2 = G1Affine::from(result2);
    let aff3 = G1Affine::from(result3);
    let aff4 = G1Affine::from(result4);

    assert_eq!(aff1, aff2);
    assert_eq!(aff1, aff3);
    assert_eq!(aff1, aff4);
}

#[test]
fn test_g1_batch_normalize() {
    let g = G1Projective::generator();
    let points: Vec<G1Projective> = (1..=10).map(|i| g * Scalar::from(i as u64)).collect();

    let mut batch_result = vec![G1Affine::identity(); points.len()];
    G1Projective::batch_normalize(&points, &mut batch_result);

    // Verify each conversion matches individual conversion
    for (proj, batch_aff) in points.iter().zip(batch_result.iter()) {
        let individual_aff = G1Affine::from(proj);
        assert_eq!(individual_aff, *batch_aff);
    }
}

#[test]
fn test_g1_batch_normalize_with_identity() {
    let points = vec![
        G1Projective::generator(),
        G1Projective::identity(),
        G1Projective::generator().double(),
        G1Projective::identity(),
    ];

    let mut batch_result = vec![G1Affine::identity(); points.len()];
    G1Projective::batch_normalize(&points, &mut batch_result);

    assert_eq!(batch_result[0], G1Affine::generator());
    assert_eq!(batch_result[1], G1Affine::identity());
    assert_eq!(
        batch_result[2],
        G1Affine::from(G1Projective::generator().double())
    );
    assert_eq!(batch_result[3], G1Affine::identity());
}

#[test]
fn test_g1_conditional_select() {
    let mut rng = ChaCha20Rng::from_seed([0x51; 32]);
    let p = G1Projective::random(&mut rng).unwrap();
    let q = G1Projective::random(&mut rng).unwrap();

    // Test with Choice::from(0)
    let selected =
        <G1Projective as ConditionallySelectable>::conditional_select(&p, &q, Choice::from(0u8));
    assert_eq!(selected, p);

    // Test with Choice::from(1)
    let selected =
        <G1Projective as ConditionallySelectable>::conditional_select(&p, &q, Choice::from(1u8));
    assert_eq!(selected, q);
}

#[test]
fn test_g1_sum() {
    let g = G1Projective::generator();
    let points: Vec<G1Projective> = (1..=5).map(|i| g * Scalar::from(i as u64)).collect();

    // Manual sum
    let mut manual_sum = G1Projective::identity();
    for p in &points {
        manual_sum += p;
    }

    // Using Sum trait
    let trait_sum: G1Projective = points.iter().map(|p| p.clone()).sum();

    // Compare as affine
    assert_eq!(G1Affine::from(manual_sum), G1Affine::from(trait_sum));
}

// ============================================================================
// G2 Group Tests
// ============================================================================

#[test]
fn test_g2_identity_operations() {
    let identity = G2Projective::identity();
    let g = G2Projective::generator();
    let point = g * Scalar::from(42u64);

    // Identity + P = P
    assert_eq!(G2Affine::from(identity + point), G2Affine::from(point));
    assert_eq!(G2Affine::from(point + identity), G2Affine::from(point));

    // Identity * scalar = Identity
    let scalar = Scalar::from(42u64);
    assert_eq!(identity * scalar, identity);

    // Double of identity is identity
    assert_eq!(identity.double(), identity);

    // Negation of identity is identity
    assert_eq!(-identity, identity);
}

#[test]
fn test_g2_associativity() {
    // Use multiples of generator for deterministic behavior
    let g = G2Projective::generator();
    let p = g * Scalar::from(2u64);
    let q = g * Scalar::from(3u64);
    let r = g * Scalar::from(5u64);

    let sum1 = (p + q) + r;
    let sum2 = p + (q + r);

    // Compare as affine to handle different projective representations
    assert_eq!(G2Affine::from(sum1), G2Affine::from(sum2));
}

#[test]
fn test_g2_commutativity() {
    let g = G2Projective::generator();
    let p = g * Scalar::from(7u64);
    let q = g * Scalar::from(11u64);

    assert_eq!(G2Affine::from(p + q), G2Affine::from(q + p));
}

#[test]
fn test_g2_scalar_multiplication_distributivity() {
    let p = G2Projective::generator();
    let a = Scalar::from(42u64);
    let b = Scalar::from(69u64);

    // Test: [a+b]P == [a]P + [b]P
    let left = p * (a + b);
    let right = (p * a) + (p * b);

    // Compare as affine points to handle different projective representations
    assert_eq!(G2Affine::from(left), G2Affine::from(right));

    // Test: [a*b]P == [a]([b]P)
    let left = p * (a * b);
    let right = (p * b) * a;
    assert_eq!(G2Affine::from(left), G2Affine::from(right));
}

#[test]
fn test_g2_double_vs_add() {
    let g2 = G2Projective::generator();
    let q = g2 * Scalar::from(42u64);

    assert_eq!(G2Affine::from(q.double()), G2Affine::from(q + q));
}

#[test]
fn test_g2_batch_normalize() {
    let g = G2Projective::generator();
    let points: Vec<G2Projective> = (1..=10).map(|i| g * Scalar::from(i as u64)).collect();

    let mut batch_result = vec![G2Affine::identity(); points.len()];
    G2Projective::batch_normalize(&points, &mut batch_result);

    // Verify each conversion matches individual conversion
    for (proj, batch_aff) in points.iter().zip(batch_result.iter()) {
        let individual_aff = G2Affine::from(proj);
        assert_eq!(individual_aff, *batch_aff);
    }
}

#[test]
fn test_g2_conditional_select() {
    let mut rng = ChaCha20Rng::from_seed([0x52; 32]);
    let p = G2Projective::random(&mut rng).unwrap();
    let q = G2Projective::random(&mut rng).unwrap();

    // Test with Choice::from(0)
    let selected =
        <G2Projective as ConditionallySelectable>::conditional_select(&p, &q, Choice::from(0u8));
    assert_eq!(selected, p);

    // Test with Choice::from(1)
    let selected =
        <G2Projective as ConditionallySelectable>::conditional_select(&p, &q, Choice::from(1u8));
    assert_eq!(selected, q);
}

#[test]
fn test_g2_sum() {
    let g = G2Projective::generator();
    let points: Vec<G2Projective> = (1..=5).map(|i| g * Scalar::from(i as u64)).collect();

    // Manual sum
    let mut manual_sum = G2Projective::identity();
    for p in &points {
        manual_sum += p;
    }

    // Using Sum trait
    let trait_sum: G2Projective = points.iter().map(|p| p.clone()).sum();

    // Compare as affine
    assert_eq!(G2Affine::from(manual_sum), G2Affine::from(trait_sum));
}

// ============================================================================
// Scalar Field Tests
// ============================================================================

#[test]
fn test_scalar_edge_cases() {
    let p = G1Projective::generator();

    // P * 0 = Identity
    assert_eq!(p * Scalar::zero(), G1Projective::identity());

    // P * 1 = P
    assert_eq!(p * Scalar::one(), p);

    // Test negation: P * (-1) should equal -P
    let minus_one = Scalar::zero() - Scalar::one();
    let p_times_minus_one = p * minus_one;
    let minus_p = -p;

    // Convert to affine for comparison to handle different projective representations
    assert_eq!(G1Affine::from(p_times_minus_one), G1Affine::from(minus_p));

    // Test with G2 as well
    let q = G2Projective::generator();
    assert_eq!(q * Scalar::zero(), G2Projective::identity());
    assert_eq!(q * Scalar::one(), q);

    let q_times_minus_one = q * minus_one;
    let minus_q = -q;
    assert_eq!(G2Affine::from(q_times_minus_one), G2Affine::from(minus_q));
}

#[test]
fn test_scalar_sum_and_product() {
    let scalars: Vec<Scalar> = (0..5).map(|i| Scalar::from((i + 1) as u64)).collect();

    // Test sum
    let expected_sum = Scalar::from(15u64); // 1 + 2 + 3 + 4 + 5
    let actual_sum: Scalar = scalars.iter().map(|s| *s).sum();
    assert_eq!(expected_sum, actual_sum);

    // Test product
    let expected_product = Scalar::from(120u64); // 1 * 2 * 3 * 4 * 5
    let actual_product: Scalar = scalars.iter().map(|s| *s).product();
    assert_eq!(expected_product, actual_product);
}

// ============================================================================
// Subgroup and Torsion Tests
// ============================================================================

#[test]
fn test_g1_torsion_free() {
    // Generator should be torsion-free
    assert!(bool::from(G1Affine::generator().is_torsion_free()));

    // Identity should be torsion-free
    assert!(bool::from(G1Affine::identity().is_torsion_free()));

    // Multiples of generator should be torsion-free
    let g = G1Projective::generator();
    for i in 1..=10 {
        let point = g * Scalar::from(i as u64);
        let cleared = point.clear_cofactor();
        assert!(bool::from(G1Affine::from(cleared).is_torsion_free()));
    }
}

#[test]
fn test_g2_torsion_free() {
    // Generator should be torsion-free
    assert!(bool::from(G2Affine::generator().is_torsion_free()));

    // Identity should be torsion-free
    assert!(bool::from(G2Affine::identity().is_torsion_free()));

    // Multiples of generator should be torsion-free
    let g = G2Projective::generator();
    for i in 1..=10 {
        let point = g * Scalar::from(i as u64);
        let cleared = point.clear_cofactor();
        assert!(bool::from(G2Affine::from(cleared).is_torsion_free()));
    }
}

#[test]
fn test_cofactor_clearing() {
    // Test that cofactor clearing produces valid subgroup elements
    // Use deterministic points to avoid issues with random generation
    let g1 = G1Projective::generator();
    for i in 1..=5 {
        let p1 = g1 * Scalar::from(i as u64);
        let p1_cleared = p1.clear_cofactor();

        // Should be in correct subgroup (torsion-free)
        assert!(bool::from(G1Affine::from(p1_cleared).is_torsion_free()));
    }

    let g2 = G2Projective::generator();
    for i in 1..=5 {
        let p2 = g2 * Scalar::from(i as u64);
        let p2_cleared = p2.clear_cofactor();

        // Should be in correct subgroup (torsion-free)
        assert!(bool::from(G2Affine::from(p2_cleared).is_torsion_free()));
    }
}

#[test]
fn test_g1_endomorphism() {
    // Test that points remain valid after cofactor clearing
    // which uses the endomorphism internally
    let g = G1Projective::generator();
    let p = g * Scalar::from(42u64);

    // After clearing cofactor, point should still be valid
    let cleared = p.clear_cofactor();
    let cleared_affine = G1Affine::from(cleared);

    // It should still be on the curve
    assert!(bool::from(cleared_affine.is_on_curve()));
    // And torsion-free
    assert!(bool::from(cleared_affine.is_torsion_free()));
}
