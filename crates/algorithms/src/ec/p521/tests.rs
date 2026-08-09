//! P-521 elliptic curve tests

use crate::ec::p521::{self, FieldElement, Point, PointFormat, Scalar, P521_SCALAR_SIZE};
use crate::error::Result;
use dcrypt_internal::random::ChaCha20Rng;
use dcrypt_params::traditional::ecdsa::NIST_P521;

#[test]
fn intermediate_scalar_reduction_allows_zero_and_reduces_order() {
    assert!(Scalar::from_bytes_reduced([0u8; P521_SCALAR_SIZE]).is_zero());
    assert!(Scalar::from_bytes_reduced(NIST_P521.n).is_zero());

    let mut order_plus_one = NIST_P521.n;
    for byte in order_plus_one.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
    let mut one = [0u8; P521_SCALAR_SIZE];
    one[P521_SCALAR_SIZE - 1] = 1;
    assert_eq!(
        Scalar::from_bytes_reduced(order_plus_one)
            .serialize()
            .as_ref(),
        &one
    );

    let expected_max = hex::decode(
        "000000000000000000000000000000000000000000000000000000000000000002d73cbc3e206834ca4019ff5b847b2d17e2251b23bb31dc28a2482470b763cdfb7f",
    )
    .unwrap();
    assert_eq!(
        Scalar::from_bytes_reduced([0xff; P521_SCALAR_SIZE])
            .serialize()
            .as_ref(),
        expected_max.as_slice()
    );
}

// ============================================================================
// FIELD ARITHMETIC TESTS
// ============================================================================

#[test]
fn test_field_element_operations() -> Result<()> {
    // Test basic field element operations
    let a = FieldElement::one();
    let b = FieldElement::one().add(&FieldElement::one()); // 2

    let c = a.add(&b);
    let d = c.sub(&a);

    // d should equal b
    assert_eq!(d.to_bytes(), b.to_bytes());

    // Test multiplication and squaring
    let e = a.mul(&b);
    let f = a.square();

    // Verify distributive property: a(a+b) = a² + ab
    let g = a.mul(&a.add(&b));
    let h = f.add(&e);
    assert_eq!(g.to_bytes(), h.to_bytes());

    // Test field element inversion
    let a_inv = a.invert()?;
    let one = FieldElement::one();
    let product = a.mul(&a_inv);
    assert_eq!(product.to_bytes(), one.to_bytes());

    Ok(())
}

#[test]
fn test_field_zero_one() {
    let zero = FieldElement::zero();
    let one = FieldElement::one();

    assert!(zero.is_zero());
    assert!(!one.is_zero());

    // Test that 0 + 1 = 1
    let sum = zero.add(&one);
    assert_eq!(sum, one);

    // Test that 1 * 1 = 1
    let product = one.mul(&one);
    assert_eq!(product, one);
}

#[test]
fn test_field_subtraction_edge_cases() {
    // 0 − 0 = 0
    assert_eq!(
        FieldElement::zero().sub(&FieldElement::zero()),
        FieldElement::zero()
    );

    // a − a = 0
    let a = FieldElement::from_bytes(&NIST_P521.g_x).unwrap();
    assert_eq!(a.sub(&a), FieldElement::zero());

    // 0 − 1 = p − 1
    let one = FieldElement::one();
    let zero_minus_one = FieldElement::zero().sub(&one);
    // p − 1 should have all bits set except the top bits of the last limb
    assert!(!zero_minus_one.is_zero());
    // Adding 1 should give us 0 (mod p)
    assert_eq!(zero_minus_one.add(&one), FieldElement::zero());
}

#[test]
fn test_field_square_consistency() -> Result<()> {
    // Test that squaring is consistent with multiplication
    let x = FieldElement::from_bytes(&NIST_P521.g_x)?;

    let via_square = x.square();
    let via_mul = x.mul(&x);

    assert_eq!(via_square, via_mul);

    Ok(())
}

#[test]
fn test_field_modular_inverse() -> Result<()> {
    // Test vectors for modular inverse: a * a^(-1) ≡ 1 (mod p)
    let test_values = [
        FieldElement::one(),
        FieldElement::one().add(&FieldElement::one()), // 2
        FieldElement::from_bytes(&NIST_P521.g_x)?,     // base point x-coordinate
    ];

    for value in test_values.iter() {
        let inverse = value.invert()?;
        let product = value.mul(&inverse);
        assert_eq!(product, FieldElement::one(), "Modular inverse test failed");
    }

    Ok(())
}

#[test]
fn test_field_sqrt() -> Result<()> {
    // Test that sqrt(1) = 1
    let one = FieldElement::one();
    let sqrt_one = one.sqrt().expect("sqrt(1) should exist");
    assert_eq!(sqrt_one.square(), one);

    // Test that sqrt(0) = 0
    let zero = FieldElement::zero();
    let sqrt_zero = zero.sqrt().expect("sqrt(0) should exist");
    assert_eq!(sqrt_zero, zero);

    // Test with a known square: 4
    let two = FieldElement::one().add(&FieldElement::one());
    let four = two.square();
    let sqrt_four = four.sqrt().expect("sqrt(4) should exist");
    // Note: could be 2 or p-2, both are valid square roots
    assert_eq!(sqrt_four.square(), four);

    Ok(())
}

// ============================================================================
// SCALAR ARITHMETIC TESTS
// ============================================================================

#[test]
fn test_scalar_operations() -> Result<()> {
    // Test scalar addition
    let mut one_bytes = [0u8; 66];
    one_bytes[65] = 1;
    let one = Scalar::new(one_bytes)?;

    let mut two_bytes = [0u8; 66];
    two_bytes[65] = 2;
    let two = Scalar::new(two_bytes)?;

    let three = one.add_mod_n(&two)?;

    // Test scalar subtraction: 3 - 2 = 1
    let result = three.sub_mod_n(&two)?;
    assert_eq!(result.serialize(), one.serialize());

    // Test scalar multiplication: 2 * 3 = 6
    let six = two.mul_mod_n(&three)?;
    let mut six_bytes = [0u8; 66];
    six_bytes[65] = 6;
    let expected_six = Scalar::new(six_bytes)?;
    assert_eq!(six.serialize(), expected_six.serialize());

    Ok(())
}

#[test]
fn test_scalar_inversion() -> Result<()> {
    // Test that a * a^(-1) = 1 (mod n)
    let mut scalar_bytes = [0u8; 66];
    scalar_bytes[65] = 5; // Use 5 as test value
    let a = Scalar::new(scalar_bytes)?;

    let a_inv = a.inv_mod_n()?;
    let product = a.mul_mod_n(&a_inv)?;

    let mut one_bytes = [0u8; 66];
    one_bytes[65] = 1;
    let one = Scalar::new(one_bytes)?;

    assert_eq!(product.serialize(), one.serialize());

    Ok(())
}

#[test]
fn test_scalar_negation() -> Result<()> {
    // Test that a + (-a) = 0 (mod n)
    let mut scalar_bytes = [0u8; 66];
    scalar_bytes[65] = 42; // arbitrary value
    let a = Scalar::new(scalar_bytes)?;

    let neg_a = a.negate();
    let sum = a.add_mod_n(&neg_a)?;

    assert!(sum.is_zero());

    Ok(())
}

#[test]
fn test_scalar_validation() -> Result<()> {
    // Test scalar validation with valid and invalid values

    // Valid scalar (less than curve order)
    let mut valid_scalar_bytes = [0u8; 66];
    valid_scalar_bytes[65] = 0x11; // Small value, definitely < n
    let valid_scalar = Scalar::new(valid_scalar_bytes)?;
    assert!(!valid_scalar.is_zero());

    // Test scalar that's larger than the curve order
    let invalid_scalar_bytes = [0xFF; 66]; // All 0xFF is definitely > n
    let result = Scalar::new(invalid_scalar_bytes);

    // Private scalar decoding is canonical and never reduces attacker input.
    assert!(result.is_err());
    assert!(Scalar::new(NIST_P521.n).is_err());

    // Test zero scalar which should be rejected
    let zero_scalar_bytes = [0; 66];
    let zero_result = Scalar::new(zero_scalar_bytes);
    assert!(zero_result.is_err());

    Ok(())
}

// ============================================================================
// POINT OPERATIONS TESTS
// ============================================================================

#[test]
fn test_point_operations() -> Result<()> {
    // Get the base point
    let g = p521::base_point_g();
    assert!(!g.is_identity());

    // Test point doubling: 2G
    let g2 = g.double();
    assert!(!g2.is_identity());

    // Test point addition: G + G should equal 2G
    let g_plus_g = g.add(&g);
    assert_eq!(g_plus_g, g2);

    // Test identity element
    let identity = Point::identity();
    assert!(identity.is_identity());

    // G + O = G
    let g_plus_identity = g.add(&identity);
    assert_eq!(g_plus_identity, g);

    // O + G = G
    let identity_plus_g = identity.add(&g);
    assert_eq!(identity_plus_g, g);

    Ok(())
}

#[test]
fn test_scalar_multiplication() -> Result<()> {
    let g = p521::base_point_g();

    // Test 1*G = G
    let mut one_bytes = [0u8; 66];
    one_bytes[65] = 1;
    let one = Scalar::new(one_bytes)?;
    let g1 = g.mul(&one)?;
    assert_eq!(g1, g);

    // Test 2*G = G + G
    let mut two_bytes = [0u8; 66];
    two_bytes[65] = 2;
    let two = Scalar::new(two_bytes)?;
    let g2 = g.mul(&two)?;
    let g_plus_g = g.add(&g);
    assert_eq!(g2, g_plus_g);

    // Test 0*G = O
    let zero = Scalar::from_bytes_reduced([0u8; 66]);
    let result = g.mul(&zero)?;
    assert!(result.is_identity());

    Ok(())
}

#[test]
fn test_point_serialization() -> Result<()> {
    let g = p521::base_point_g();

    // Test uncompressed serialization
    let uncompressed = g.serialize_uncompressed();
    assert_eq!(uncompressed[0], 0x04); // Check format byte

    let deserialized = Point::deserialize_uncompressed(&uncompressed)?;
    assert_eq!(deserialized, g);

    // Test compressed serialization
    let compressed = g.serialize_compressed();
    assert!(compressed[0] == 0x02 || compressed[0] == 0x03); // Check format byte

    let decompressed = Point::deserialize_compressed(&compressed)?;
    assert_eq!(decompressed, g);

    // Test identity serialization
    let identity = Point::identity();
    let id_uncompressed = identity.serialize_uncompressed();
    assert!(id_uncompressed.iter().all(|&b| b == 0));
    assert!(Point::deserialize_uncompressed(&id_uncompressed).is_err());

    let id_compressed = identity.serialize_compressed();
    assert!(id_compressed.iter().all(|&b| b == 0));
    assert!(Point::deserialize_compressed(&id_compressed).is_err());
    assert_eq!(Point::detect_format(&[0x00])?, PointFormat::Identity);

    Ok(())
}

#[test]
fn test_point_compression_roundtrip() -> Result<()> {
    // Test with multiple points to cover both even and odd y-coordinates
    let g = p521::base_point_g();

    for i in 1..5 {
        let mut scalar_bytes = [0u8; 66];
        scalar_bytes[65] = i;
        let scalar = Scalar::new(scalar_bytes)?;
        let point = g.mul(&scalar)?;

        // Compress and decompress
        let compressed = point.serialize_compressed();
        let decompressed = Point::deserialize_compressed(&compressed)?;

        // Should get the same point back
        assert_eq!(point, decompressed);
        assert_eq!(
            point.x_coordinate_bytes(),
            decompressed.x_coordinate_bytes()
        );
        assert_eq!(
            point.y_coordinate_bytes(),
            decompressed.y_coordinate_bytes()
        );
    }

    Ok(())
}

#[test]
fn test_curve_equation_base_point() -> Result<()> {
    // Verify that the P-521 base point satisfies y² = x³ − 3x + b
    let g = p521::base_point_g();
    assert!(!g.is_identity());

    let x = FieldElement::from_bytes(&NIST_P521.g_x)?;
    let y = FieldElement::from_bytes(&NIST_P521.g_y)?;

    let y2 = y.square();
    let x3 = x.square().mul(&x);
    let a_fe = FieldElement(FieldElement::A_M3); // a = −3 mod p
    let ax = a_fe.mul(&x);
    let b_fe = FieldElement::from_bytes(&NIST_P521.b)?;
    let rhs = x3.add(&ax).add(&b_fe);

    assert_eq!(
        y2, rhs,
        "P-521 base point fails curve equation y² = x³ − 3x + b"
    );
    Ok(())
}

#[test]
fn test_keypair_generation() -> Result<()> {
    // Generate a keypair and verify the public key is correctly derived
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let (private_key, public_key) = p521::generate_keypair(&mut rng)?;

    // Verify that scalar_mult_base_g(private_key) gives the expected public key
    let derived_public_key = p521::scalar_mult_base_g(&private_key)?;
    assert_eq!(derived_public_key, public_key);

    // Verify that the public key is on the curve
    let is_on_curve = Point::new_uncompressed(
        &public_key.x_coordinate_bytes(),
        &public_key.y_coordinate_bytes(),
    )
    .is_ok();
    assert!(is_on_curve);

    Ok(())
}

#[test]
fn test_kdf() -> Result<()> {
    // Test the KDF function with known inputs
    let ikm = b"test key material for P-521 KDF";
    let info = Some(&b"P-521 KDF test"[..]);

    let output = p521::kdf_hkdf_sha512_for_ecdh_kem(ikm, info)?;

    // Ensure output is the right size
    assert_eq!(output.len(), p521::P521_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE);

    // Same inputs should give same outputs
    let output2 = p521::kdf_hkdf_sha512_for_ecdh_kem(ikm, info)?;
    assert_eq!(output, output2);

    // Different info should give different outputs
    let output3 = p521::kdf_hkdf_sha512_for_ecdh_kem(ikm, Some(&b"Different info"[..]))?;
    assert_ne!(output, output3);

    Ok(())
}

// ============================================================================
// TEST VECTORS - Add NIST CAVP vectors here
// ============================================================================

#[cfg(test)]
mod scalar_multiplication_vectors {
    use super::*;

    #[test]
    fn test_base_point_coordinates() -> Result<()> {
        // Verify the base point coordinates match NIST specification
        let g = p521::base_point_g();
        let g_x = hex::encode(g.x_coordinate_bytes());
        let g_y = hex::encode(g.y_coordinate_bytes());

        // These are the standard NIST P-521 base point coordinates
        let expected_x = "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66";
        let expected_y = "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650";

        assert_eq!(g_x, expected_x);
        assert_eq!(g_y, expected_y);

        Ok(())
    }

    #[test]
    fn test_scalar_mult_vectors() -> Result<()> {
        // Test k=1 (should return base point)
        let mut k1_bytes = [0u8; 66];
        k1_bytes[65] = 1;
        let k1 = Scalar::new(k1_bytes)?;
        let result1 = p521::scalar_mult_base_g(&k1)?;
        let g = p521::base_point_g();
        assert_eq!(result1, g);

        // Additional test vectors would go here once we have NIST CAVP vectors
        // or can generate them from a reference implementation

        Ok(())
    }
}
