//! P-224 elliptic curve tests

use super::*;
use crate::ec::p224::{self, FieldElement, Point, Scalar};
use crate::error::Result;
use dcrypt_internal::random::{ChaCha20Rng, RngCore};
use dcrypt_params::traditional::ecdsa::NIST_P224;

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
fn intermediate_scalar_reduction_allows_zero_and_reduces_order() {
    assert!(Scalar::from_bytes_reduced([0u8; P224_SCALAR_SIZE]).is_zero());
    assert!(Scalar::from_bytes_reduced(NIST_P224.n).is_zero());

    let mut order_plus_one = NIST_P224.n;
    for byte in order_plus_one.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
    let mut one = [0u8; P224_SCALAR_SIZE];
    one[P224_SCALAR_SIZE - 1] = 1;
    assert_eq!(Scalar::from_bytes_reduced(order_plus_one).serialize(), one);
}

#[test]
fn test_point_operations() -> Result<()> {
    // Generate a random point by scalar multiplication of the base point
    let g = p224::base_point_g();
    let scalar = {
        let mut bytes = [0u8; 28];
        let mut rng = ChaCha20Rng::from_seed([0x21; 32]);
        rng.fill_bytes(&mut bytes);
        bytes[0] &= 0x7F; // Ensure it's less than the curve order
        Scalar::new(bytes)?
    };

    let point = g.mul(&scalar)?;

    // Test point addition: G + P = P + G
    let sum1 = g.add(&point);
    let sum2 = point.add(&g);
    assert_eq!(sum1, sum2);

    // Test point doubling: 2P = P + P
    let double1 = point.double();
    let double2 = point.add(&point);
    assert_eq!(double1, double2);

    // Test point serialization and deserialization
    let serialized = point.serialize_uncompressed();
    let deserialized = Point::deserialize_uncompressed(&serialized)?;
    assert_eq!(point, deserialized);

    // Test point at infinity
    let identity = Point::identity();
    assert!(identity.is_identity());

    // Identity + P = P
    let sum_with_identity = identity.add(&point);
    assert_eq!(sum_with_identity, point);

    Ok(())
}

#[test]
fn test_scalar_multiplication() -> Result<()> {
    // Test scalar multiplication against known test vectors
    let g = p224::base_point_g();

    // Create a small scalar for testing
    let mut scalar_bytes = [0u8; 28];
    scalar_bytes[27] = 1; // Set least significant byte to 1
    let scalar = Scalar::new(scalar_bytes)?;

    // 1*G should equal G
    let point = g.mul(&scalar)?;
    assert_eq!(point, g);

    // Test 2*G
    let mut scalar_two_bytes = [0u8; 28];
    scalar_two_bytes[27] = 2; // Set least significant byte to 2
    let scalar_two = Scalar::new(scalar_two_bytes)?;
    let point_two_g = g.mul(&scalar_two)?;
    let point_g_plus_g = g.add(&g);
    assert_eq!(point_two_g, point_g_plus_g);

    Ok(())
}

#[test]
fn test_compression_roundtrip() -> Result<()> {
    // Test with generator point
    let g = p224::base_point_g();
    let compressed = g.serialize_compressed();
    let decompressed = Point::deserialize_compressed(&compressed)?;
    assert_eq!(g, decompressed);

    // Test identity point
    let identity = Point::identity();
    let compressed_id = identity.serialize_compressed();
    let decompressed_id = Point::deserialize_compressed(&compressed_id)?;
    assert!(decompressed_id.is_identity());

    // Test multiple scalar multiples to cover even/odd y cases
    let scalar_2 = p224::Scalar::new([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ])?;

    let point_2g = g.mul(&scalar_2)?;
    let compressed_2g = point_2g.serialize_compressed();
    let decompressed_2g = Point::deserialize_compressed(&compressed_2g)?;
    assert_eq!(point_2g, decompressed_2g);

    Ok(())
}

#[test]
fn test_keypair_generation() -> Result<()> {
    // Generate a keypair and verify that the public key is correctly derived
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let (private_key, public_key) = p224::generate_keypair(&mut rng)?;

    // Verify that scalar_mult_base_g(private_key) gives the expected public key
    let derived_public_key = p224::scalar_mult_base_g(&private_key)?;
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
fn test_scalar_validation() -> Result<()> {
    // Test scalar validation with valid and invalid values

    // Valid scalar (less than curve order)
    let valid_scalar_bytes = [0x11; 28];
    let _valid_scalar = Scalar::new(valid_scalar_bytes)?;

    // Test scalar that's larger than the curve order
    let invalid_scalar_bytes = [0xFF; 28];
    let result = Scalar::new(invalid_scalar_bytes);

    // Should succeed but reduce the scalar mod order
    assert!(result.is_ok());
    let reduced_scalar = result.unwrap();

    // The reduced scalar should be valid and different from the original
    assert_ne!(reduced_scalar.serialize(), invalid_scalar_bytes);

    // Test zero scalar which should be rejected
    let zero_scalar_bytes = [0; 28];
    let zero_result = Scalar::new(zero_scalar_bytes);
    assert!(zero_result.is_err());

    Ok(())
}

#[test]
fn test_kdf() -> Result<()> {
    // Test the KDF function with known inputs
    let ikm = b"test key material for P-224 KDF";
    let info = Some(&b"P-224 KDF test"[..]);

    let output = p224::kdf_hkdf_sha256_for_ecdh_kem(ikm, info)?;

    // Ensure output is the right size
    assert_eq!(output.len(), p224::P224_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE);

    // Same inputs should give same outputs
    let output2 = p224::kdf_hkdf_sha256_for_ecdh_kem(ikm, info)?;
    assert_eq!(output, output2);

    // Different info should give different outputs
    let output3 = p224::kdf_hkdf_sha256_for_ecdh_kem(ikm, Some(&b"Different info"[..]))?;
    assert_ne!(output, output3);

    Ok(())
}

#[test]
fn test_curve_equation_base_point() -> Result<()> {
    // Verify that the P-224 base point satisfies y² = x³ − 3x + b
    let g = p224::base_point_g();
    assert!(!g.is_identity());

    let x = FieldElement::from_bytes(&NIST_P224.g_x)?;
    let y = FieldElement::from_bytes(&NIST_P224.g_y)?;

    let y2 = y.square();
    let x3 = x.square().mul(&x);
    let a_fe = FieldElement(FieldElement::A_M3); // a = −3 mod p
    let ax = a_fe.mul(&x);
    let b_fe = FieldElement::from_bytes(&NIST_P224.b)?;
    let rhs = x3.add(&ax).add(&b_fe);

    assert_eq!(
        y2, rhs,
        "P-224 base point fails curve equation y² = x³ − 3x + b"
    );
    Ok(())
}

#[test]
fn test_final_conditional_subtraction() {
    // Build "p + 1" by adding one to the modulus
    let p_bytes = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    // Try to create a field element from p itself (should fail validation)
    let p_result = FieldElement::from_bytes(&p_bytes);
    assert!(
        p_result.is_err(),
        "Creating field element from p should fail"
    );

    // Create p - 1 (which is valid)
    let mut p_minus_1_bytes = p_bytes;
    p_minus_1_bytes[27] = 0x00; // Subtract 1 from the least significant byte
    let p_minus_1 = FieldElement::from_bytes(&p_minus_1_bytes).unwrap();

    // Add 1 to get p (mod p) = 0
    let one = FieldElement::one();
    let should_be_zero = p_minus_1.add(&one);
    assert!(should_be_zero.is_zero(), "(p-1) + 1 mod p should equal 0");

    // Add 2 to p-1 to get (p+1) mod p = 1
    let two = one.add(&one);
    let should_be_one = p_minus_1.add(&two);
    assert_eq!(should_be_one, one, "(p-1) + 2 mod p should equal 1");
}

// ============================================================================
// TEST VECTORS - Add NIST CAVP vectors here when available
// ============================================================================

#[cfg(test)]
mod scalar_multiplication_vectors {
    use super::*;

    #[test]
    fn test_base_point_coordinates() -> Result<()> {
        // Verify the base point coordinates match NIST specification
        let g = p224::base_point_g();
        let g_x = hex::encode(g.x_coordinate_bytes());
        let g_y = hex::encode(g.y_coordinate_bytes());

        // Expected NIST P-224 base point coordinates
        let expected_x = "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21";
        let expected_y = "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34";

        assert_eq!(g_x, expected_x, "Base point X coordinate mismatch");
        assert_eq!(g_y, expected_y, "Base point Y coordinate mismatch");

        Ok(())
    }

    #[test]
    fn test_scalar_mult_vectors() -> Result<()> {
        // Test k=1 (should return base point)
        let mut k1_bytes = [0u8; 28];
        k1_bytes[27] = 1;
        let k1 = Scalar::new(k1_bytes)?;
        let result1 = p224::scalar_mult_base_g(&k1)?;
        let g = p224::base_point_g();
        assert_eq!(result1, g);

        Ok(())
    }
}
