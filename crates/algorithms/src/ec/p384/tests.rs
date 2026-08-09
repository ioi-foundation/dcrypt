// File: crates/algorithms/src/ec/p384/tests.rs
// Complete test file with separation of concerns - P-384 only

use super::*;
use crate::ec::p384::{self, FieldElement, Point, Scalar};
use crate::error::Result;
use dcrypt_internal::random::{ChaCha20Rng, RngCore};
use dcrypt_params::traditional::ecdsa::NIST_P384;

// ============================================================================
// P-384 FIELD CONSTANTS
// ============================================================================

// Correct P-384 prime minus 1
// FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFE
const P384_P_MINUS_1: [u8; 48] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFE,
];

// Correct (P-384 prime - 1) / 2
// 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFF800000000000000007FFFFF
const P384_P_MINUS_1_DIV_2: [u8; 48] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x7F, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF,
];

// ============================================================================
// BASIC ARITHMETIC TESTS
// ============================================================================

#[test]
fn sbb12_regression_wrap_borrow() {
    let a = FieldElement::from_bytes(&[0; 48]).unwrap();

    // Correctly compute p-1
    let mut p_minus_one = FieldElement::MOD_LIMBS;
    p_minus_one[0] -= 1; // Subtract 1 from least significant limb
    let b = FieldElement(p_minus_one);

    let one = FieldElement::one();
    let result = a.sub(&b).add(&one);

    // 0 - (p-1) + 1 ≡ 2 (mod p)
    let expected = FieldElement::one().add(&FieldElement::one());
    assert_eq!(result, expected);
}

#[test]
fn intermediate_scalar_reduction_allows_zero_and_reduces_order() {
    assert!(Scalar::from_bytes_reduced([0u8; P384_SCALAR_SIZE]).is_zero());
    assert!(Scalar::from_bytes_reduced(NIST_P384.n).is_zero());

    let mut order_plus_one = NIST_P384.n;
    for byte in order_plus_one.iter_mut().rev() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
    let mut one = [0u8; P384_SCALAR_SIZE];
    one[P384_SCALAR_SIZE - 1] = 1;
    assert_eq!(
        Scalar::from_bytes_reduced(order_plus_one)
            .serialize()
            .as_ref(),
        &one
    );
}

#[test]
fn test_compression_roundtrip() {
    // Test with generator point
    let g = p384::base_point_g();
    let compressed = g.serialize_compressed();
    let decompressed = Point::deserialize_compressed(&compressed).unwrap();
    assert_eq!(g, decompressed);

    // Fixed-width encodings cannot represent SEC 1's one-byte identity.
    let identity = Point::identity();
    let compressed_id = identity.serialize_compressed();
    assert!(Point::deserialize_compressed(&compressed_id).is_err());

    // Test multiple scalar multiples to cover even/odd y cases
    let scalar_2 = p384::Scalar::new([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ])
    .unwrap();

    let point_2g = g.mul(&scalar_2).unwrap();
    let compressed_2g = point_2g.serialize_compressed();
    let decompressed_2g = Point::deserialize_compressed(&compressed_2g).unwrap();
    assert_eq!(point_2g, decompressed_2g);
}

#[test]
fn test_compression_invalid_prefix() {
    let mut compressed = p384::base_point_g().serialize_compressed();
    compressed[0] = 0x04; // Invalid prefix for compressed format
    assert!(Point::deserialize_compressed(&compressed).is_err());

    compressed[0] = 0x00; // Another invalid prefix
    assert!(Point::deserialize_compressed(&compressed).is_err());

    compressed[0] = 0xFF; // Yet another invalid prefix
    assert!(Point::deserialize_compressed(&compressed).is_err());
}

#[test]
fn test_compression_non_residue() {
    // Construct an x-coordinate that's likely not on the curve
    let mut invalid_x = [0u8; P384_POINT_COMPRESSED_SIZE];
    invalid_x[0] = 0x02;
    // Fill with a pattern that's unlikely to be on curve
    for byte in invalid_x.iter_mut().skip(1) {
        *byte = 0xFF;
    }

    let result = Point::deserialize_compressed(&invalid_x);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("non-residue"));
}

#[test]
fn test_point_format_detection() {
    // Test uncompressed format
    let g = p384::base_point_g();
    let uncompressed = g.serialize_uncompressed();
    assert_eq!(
        Point::detect_format(&uncompressed).unwrap(),
        PointFormat::Uncompressed
    );

    // Test compressed format
    let compressed = g.serialize_compressed();
    assert_eq!(
        Point::detect_format(&compressed).unwrap(),
        PointFormat::Compressed
    );

    // SEC 1 identity is exactly one byte; reject fixed-width zero sentinels.
    assert_eq!(
        Point::detect_format(&[0x00]).unwrap(),
        PointFormat::Identity
    );
    assert!(Point::detect_format(&[0u8; P384_POINT_UNCOMPRESSED_SIZE]).is_err());

    // Test invalid formats
    assert!(Point::detect_format(&[]).is_err());
    assert!(Point::detect_format(&[0x04]).is_err()); // Too short
    assert!(Point::detect_format(&[0x05; 97]).is_err()); // Invalid prefix
}

#[test]
fn test_compression_preserves_coordinates() {
    let g = p384::base_point_g();
    let compressed = g.serialize_compressed();
    let decompressed = Point::deserialize_compressed(&compressed).unwrap();

    // X-coordinates must be identical
    assert_eq!(g.x_coordinate_bytes(), decompressed.x_coordinate_bytes());

    // Y-coordinates must be identical
    assert_eq!(g.y_coordinate_bytes(), decompressed.y_coordinate_bytes());
}

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

    // New arithmetic check: subtraction
    let three = b.add(&FieldElement::one()); // 3
    let diff = three.sub(&b);
    let expected_diff = FieldElement::one();
    assert_eq!(diff.to_bytes(), expected_diff.to_bytes());

    Ok(())
}

#[test]
fn test_point_operations() -> Result<()> {
    // Generate a random point by scalar multiplication of the base point
    let g = p384::base_point_g();
    let scalar = {
        let mut bytes = [0u8; 48];
        let mut rng = ChaCha20Rng::from_seed([0x23; 32]);
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
    let g = p384::base_point_g();

    // Create a small scalar for testing
    let mut scalar_bytes = [0u8; 48];
    scalar_bytes[47] = 1; // Set least significant byte to 1
    let scalar = Scalar::new(scalar_bytes)?;

    // 1*G should equal G
    let point = g.mul(&scalar)?;
    assert_eq!(point, g);

    // Test 2*G
    let mut scalar_two_bytes = [0u8; 48];
    scalar_two_bytes[47] = 2; // Set least significant byte to 2
    let scalar_two = Scalar::new(scalar_two_bytes)?;
    let point_two_g = g.mul(&scalar_two)?;
    let point_g_plus_g = g.add(&g);
    assert_eq!(point_two_g, point_g_plus_g);

    // Test scalar multiplication with larger values
    let scalar_bytes = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
        0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC,
        0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A,
        0xBC, 0xDE, 0x01,
    ];
    let scalar = Scalar::new(scalar_bytes)?;
    let point = g.mul(&scalar)?;

    // Verify point is on the curve
    let x_bytes = point.x_coordinate_bytes();
    let y_bytes = point.y_coordinate_bytes();
    let point_verified = Point::new_uncompressed(&x_bytes, &y_bytes)?;
    assert_eq!(point, point_verified);

    Ok(())
}

#[test]
fn test_keypair_generation() -> Result<()> {
    // Generate a keypair and verify that the public key is correctly derived
    let mut rng = ChaCha20Rng::from_seed([0x42; 32]);
    let (private_key, public_key) = p384::generate_keypair(&mut rng)?;

    // Verify that scalar_mult_base_g(private_key) gives the expected public key
    let derived_public_key = p384::scalar_mult_base_g(&private_key)?;
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
    let valid_scalar_bytes = [0x11; 48];
    let _valid_scalar = Scalar::new(valid_scalar_bytes)?;

    // Test scalar that's larger than the curve order
    // P-384 order is much larger, but all 0xFF is definitely larger than curve order
    let invalid_scalar_bytes = [0xFF; 48];
    let result = Scalar::new(invalid_scalar_bytes);

    // Private scalar decoding is canonical and never reduces attacker input.
    assert!(result.is_err());
    assert!(Scalar::new(NIST_P384.n).is_err());

    // Test zero scalar which should be rejected
    let zero_scalar_bytes = [0; 48];
    let zero_result = Scalar::new(zero_scalar_bytes);
    assert!(zero_result.is_err());

    Ok(())
}

#[test]
fn test_kdf() -> Result<()> {
    // Test the KDF function with known inputs
    let ikm = b"test key material for P-384 KDF";
    let info = Some(&b"P-384 KDF test"[..]);

    let output = p384::kdf_hkdf_sha384_for_ecdh_kem(ikm, info)?;

    // Ensure output is the right size
    assert_eq!(output.len(), p384::P384_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE);

    // Same inputs should give same outputs
    let output2 = p384::kdf_hkdf_sha384_for_ecdh_kem(ikm, info)?;
    assert_eq!(output, output2);

    // Different info should give different outputs
    let output3 = p384::kdf_hkdf_sha384_for_ecdh_kem(ikm, Some(&b"Different info"[..]))?;
    assert_ne!(output, output3);

    Ok(())
}

#[test]
fn add_fold_carry_edge() {
    // Use the correct p-1 constant
    let a = FieldElement::from_bytes(&P384_P_MINUS_1).unwrap(); // p-1
    let b = FieldElement::one(); // 1
    let sum = a.add(&b); // should be zero
    assert!(sum.is_zero());
}

#[test]
fn test_scalar_loop_order() {
    let mut scalar_bytes = [0u8; 48];
    scalar_bytes[47] = 0b10101010; // LSB = byte[47]
    let scalar = Scalar::new(scalar_bytes).unwrap();
    let mut bits = Vec::new();
    let scalar_bytes = scalar.serialize();
    for byte in scalar_bytes.iter() {
        for bit_pos in (0..8).rev() {
            bits.push((byte >> bit_pos) & 1);
        }
    }
    println!("Bits: {:?}", bits);
}

#[test]
fn test_one_serialization() {
    let one_val = FieldElement::one();
    let one_bytes = one_val.to_bytes();
    let mut expected_bytes = [0u8; P384_FIELD_ELEMENT_SIZE];
    expected_bytes[P384_FIELD_ELEMENT_SIZE - 1] = 1;
    assert_eq!(
        one_bytes, expected_bytes,
        "FieldElement::one().to_bytes() is incorrect. Expected {:?}, got {:?}",
        expected_bytes, one_bytes
    );
}

// ============================================================================
// DEBUG TESTS (with debug output conditionally compiled)
// ============================================================================

#[test]
fn test_curve_equation_base_point() -> Result<()> {
    // Verify that the P-384 base point satisfies y² = x³ − 3x + b
    let g = p384::base_point_g();
    assert!(!g.is_identity());

    let x = FieldElement::from_bytes(&NIST_P384.g_x)?;
    let y = FieldElement::from_bytes(&NIST_P384.g_y)?;

    let y2 = y.square();
    let x3 = x.square().mul(&x);
    let a_fe = FieldElement(FieldElement::A_M3); // a = −3 mod p
    let ax = a_fe.mul(&x);
    let b_fe = FieldElement::from_bytes(&NIST_P384.b)?;
    let rhs = x3.add(&ax).add(&b_fe);

    #[cfg(debug_assertions)]
    {
        println!("g_x      = {:02x?}", x.to_bytes());
        println!("g_y      = {:02x?}", y.to_bytes());
        println!("lhs y²   = {:02x?}", y2.to_bytes());
        println!("x³       = {:02x?}", x3.to_bytes());
        println!("−3·x     = {:02x?}", ax.to_bytes());
        println!("b        = {:02x?}", NIST_P384.b);
        println!("rhs      = {:02x?}", rhs.to_bytes());
    }

    assert_eq!(
        y2, rhs,
        "P-384 base point fails curve equation y² = x³ − 3x + b"
    );
    Ok(())
}

#[test]
fn test_square_mul_equivalence() {
    // load the base‐point x
    let x = FieldElement::from_bytes(&NIST_P384.g_x).unwrap();

    // compute x² two different ways
    let via_square = x.square();
    let via_mul = x.mul(&x);

    // they *must* be identical
    assert_eq!(
        via_square.to_bytes(),
        via_mul.to_bytes(),
        "FieldElement::square() and .mul(&self) disagree"
    );
}

#[test]
fn test_b_parameter_validation() {
    let b_be = NIST_P384.b;
    let b_fe = FieldElement::from_bytes(&b_be).unwrap();
    assert_eq!(
        b_fe.to_bytes(),
        b_be,
        "NIST_P384.b should round-trip through FieldElement"
    );
}

#[test]
fn test_a_m3_constant_correctness() {
    // build the "expected" p − 3 in big–endian bytes
    let mut p_be = FieldElement::get_modulus().to_bytes();
    // subtract 3 from the 384-bit number
    let mut borrow = 3u8;
    for i in (0..48).rev() {
        let (r, under) = p_be[i].overflowing_sub(borrow);
        p_be[i] = r;
        borrow = if under { 1 } else { 0 };
    }

    let a_fe = FieldElement(FieldElement::A_M3);
    let a_be = a_fe.to_bytes();

    #[cfg(debug_assertions)]
    println!(
        "A_M3 as bytes = {:02x?}",
        FieldElement(FieldElement::A_M3).to_bytes()
    );

    assert_eq!(
        a_be, p_be,
        "A_M3 is supposed to be p−3 (big-endian), but got {:?} instead of {:?}",
        a_be, p_be
    );
}

#[test]
fn test_multiplication_by_minus3() {
    // pick a non‐zero x—e.g. the base‐point's x‐coord
    let x = FieldElement::from_bytes(&NIST_P384.g_x).unwrap();

    // compute 3·x by repeated addition:
    let three_x = x.add(&x).add(&x);

    // true "-3x mod p" = (p - 3x)
    let expected = FieldElement::get_modulus().sub(&three_x);

    // your A_M3 multiplier:
    let a = FieldElement(FieldElement::A_M3);
    let got = a.mul(&x);

    #[cfg(debug_assertions)]
    if got.to_bytes() != expected.to_bytes() {
        eprintln!("  raw   x = {}", hex::encode(x.to_bytes()));
        eprintln!("  3·x     = {}", hex::encode(three_x.to_bytes()));
        eprintln!(
            "  p       = {}",
            hex::encode(FieldElement::get_modulus().to_bytes())
        );
        eprintln!("  expect  = {}", hex::encode(expected.to_bytes()));
        eprintln!("  got     = {}", hex::encode(got.to_bytes()));
    }

    assert_eq!(got.to_bytes(), expected.to_bytes());
}

#[test]
fn test_subtraction_edge_cases() {
    // 0 − 0 = 0
    assert_eq!(
        FieldElement::zero().sub(&FieldElement::zero()),
        FieldElement::zero()
    );

    // a − a = 0
    let a = FieldElement::from_bytes(&NIST_P384.g_x).unwrap();
    assert_eq!(a.sub(&a), FieldElement::zero());

    // 0 − 1 = p − 1 (use the correct p-1)
    let one = FieldElement::one();
    let zero_minus_one = FieldElement::zero().sub(&one);
    let expect = FieldElement::from_bytes(&P384_P_MINUS_1).unwrap();
    assert_eq!(zero_minus_one, expect);
}

#[test]
fn test_add_subtract_inverse_operations() {
    let a = FieldElement::from_bytes(&NIST_P384.g_x).unwrap();
    let b = FieldElement::one();
    let r = a.add(&b).sub(&b);
    assert_eq!(
        r.to_bytes(),
        NIST_P384.g_x,
        "Add then sub (by one) didn't restore original"
    );
}

#[test]
fn test_solinas_reduction_correctness() {
    // Verify Solinas reduction: (p−3)·Gx ≡ p − 3·Gx mod p
    let x = FieldElement::from_bytes(&NIST_P384.g_x).unwrap();
    let a = FieldElement(FieldElement::A_M3);

    // Compute via FieldElement::mul (uses reduce_wide)
    let actual = a.mul(&x);

    // Compute expected: p − 3·x  (three subtractions)
    let expected = FieldElement::get_modulus().sub(&x).sub(&x).sub(&x);

    assert_eq!(
        actual, expected,
        "Solinas reduction mismatch: (p−3)·Gx did not equal p − 3·Gx mod p"
    );
}

// ============================================================================
// OFFICIAL TEST VECTORS
// ============================================================================

/// Test vectors from NIST CAVP for P-384 scalar multiplication
/// These test k*G for various scalar values k
#[cfg(test)]
mod scalar_multiplication_vectors {
    use super::*;

    #[test]
    fn test_point_multiplication_vectors() -> Result<()> {
        let test_vectors = [
            // k=1: Should return base point G
            (
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
                "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
                "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
            ),
            // k=2
            (
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
                "08D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B96A9C75295DF61",
                "8E80F1FA5B1B3CEDB7BFE8DFFD6DBA74B275D875BC6CC43E904E505F256AB4255FFD43E94D39E22D61501E700A940E80"
            ),
            // k=3
            (
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
                "077A41D4606FFA1464793C7E5FDC7D98CB9D3910202DCD06BEA4F240D3566DA6B408BBAE5026580D02D7E5C70500C831",
                "C995F7CA0B0C42837D0BBE9602A9FC998520B41C85115AA5F7684C0EDC111EACC24ABD6BE4B5D298B65F28600A2F1DF1"
            ),
            // k=4
            (
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004",
                "138251CD52AC9298C1C8AAD977321DEB97E709BD0B4CA0ACA55DC8AD51DCFC9D1589A1597E3A5120E1EFD631C63E1835",
                "CACAE29869A62E1631E8A28181AB56616DC45D918ABC09F3AB0E63CF792AA4DCED7387BE37BBA569549F1C02B270ED67"
            ),
            // k = 0x112233445566778899112233445566778899  (96-digit / 48-byte scalar)
            (
                "000000000000000000000000000000000000000000000000000000000000112233445566778899112233445566778899",
                "F96347E91F2ED348D2127EBE4F23CDCC3B4E77C59FB323764106E6C33EC8E33BFA37289E9DFFE70EAB8484BD62207FD4",
                "BE8995D695D21E1C68C184344F715BF1DE74198D518B9E695B7D0B148D1AB64C73E1B5CA13A449E02C4265FEFBF79B10"
            ),
        ];

        for (k_hex, expected_x_hex, expected_y_hex) in test_vectors.iter() {
            let k_bytes = hex::decode(k_hex).map_err(|_| Error::param("hex", "Invalid hex"))?;
            let mut k_array = [0u8; 48];
            k_array[48 - k_bytes.len()..].copy_from_slice(&k_bytes);

            // DIAGNOSTIC: print original scalar
            println!("\n---\nTesting scalar k = {}", k_hex);
            println!("Input scalar bytes: {:02x?}", &k_array);

            let scalar = Scalar::new(k_array)?;
            // DIAGNOSTIC: print scalar bytes after reduction
            println!("Scalar bytes after reduction: {:02x?}", scalar.serialize());

            let result = p384::scalar_mult_base_g(&scalar)?;

            let expected_x =
                hex::decode(expected_x_hex).map_err(|_| Error::param("hex", "Invalid hex"))?;
            let expected_y =
                hex::decode(expected_y_hex).map_err(|_| Error::param("hex", "Invalid hex"))?;

            let mut x_array = [0u8; 48];
            let mut y_array = [0u8; 48];
            x_array.copy_from_slice(&expected_x);
            y_array.copy_from_slice(&expected_y);

            let expected_point = Point::new_uncompressed(&x_array, &y_array)?;

            // DIAGNOSTIC: print computed and expected coordinates
            println!("Computed X: {:02x?}", result.x_coordinate_bytes());
            println!("Expected X: {:02x?}", x_array);
            println!("Computed Y: {:02x?}", result.y_coordinate_bytes());
            println!("Expected Y: {:02x?}", y_array);

            assert_eq!(
                result, expected_point,
                "Scalar multiplication failed for k={}",
                k_hex
            );
        }

        Ok(())
    }

    #[test]
    fn test_order_minus_one_scalar() -> Result<()> {
        // k = n-1 where n is the curve order
        let k_hex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52972";
        let expected_x_hex = "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7";
        let expected_y_hex = "C9E821B569D9D390A26167406D6D23D6070BE242D765EB831625CEEC4A0F473EF59F4E30E2817E6285BCE2846F15F1A0";

        let k_bytes = hex::decode(k_hex).map_err(|_| Error::param("hex", "Invalid hex"))?;
        let mut k_array = [0u8; 48];
        k_array.copy_from_slice(&k_bytes);

        let scalar = Scalar::new(k_array)?;
        let result = p384::scalar_mult_base_g(&scalar)?;

        let expected_x =
            hex::decode(expected_x_hex).map_err(|_| Error::param("hex", "Invalid hex"))?;
        let expected_y =
            hex::decode(expected_y_hex).map_err(|_| Error::param("hex", "Invalid hex"))?;

        let mut x_array = [0u8; 48];
        let mut y_array = [0u8; 48];
        x_array.copy_from_slice(&expected_x);
        y_array.copy_from_slice(&expected_y);

        let expected_point = Point::new_uncompressed(&x_array, &y_array)?;

        assert_eq!(
            result, expected_point,
            "Scalar multiplication failed for n-1"
        );
        Ok(())
    }
}

/// Field arithmetic test vectors
#[cfg(test)]
mod field_arithmetic_vectors {
    use super::*;

    #[test]
    fn test_field_modular_inverse() -> Result<()> {
        // Test vectors for modular inverse: a * a^(-1) ≡ 1 (mod p)
        // Test with direct byte arrays
        let test_values: Vec<[u8; 48]> = vec![
            // 1
            {
                let mut arr = [0u8; 48];
                arr[47] = 1;
                arr
            },
            // 2
            {
                let mut arr = [0u8; 48];
                arr[47] = 2;
                arr
            },
            // p-1
            P384_P_MINUS_1,
            // (p-1)/2
            P384_P_MINUS_1_DIV_2,
        ];

        for value_array in test_values.iter() {
            let field_element = FieldElement::from_bytes(value_array)?;
            let inverse = field_element.invert()?;
            let product = field_element.mul(&inverse);

            assert_eq!(product, FieldElement::one(), "Modular inverse test failed");
        }

        Ok(())
    }

    #[test]
    fn test_field_square_consistency() -> Result<()> {
        // Test that squaring operations are consistent
        let test_values = [
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", // 1
            "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004", // 4 (perfect square)
        ];

        for value_hex in test_values.iter() {
            let value_bytes = hex::decode(value_hex).unwrap();
            let mut value_array = [0u8; 48];
            value_array.copy_from_slice(&value_bytes);

            let field_element = FieldElement::from_bytes(&value_array)?;
            let squared = field_element.square();

            // For this test, we're just verifying the square operation is consistent
            let double_squared = squared.square();
            let quad_root = field_element.square().square(); // (a^2)^2 = a^4

            assert_eq!(
                double_squared, quad_root,
                "Square consistency test failed for {}",
                value_hex
            );
        }

        Ok(())
    }

    #[test]
    fn test_field_addition_subtraction() -> Result<()> {
        // Test that (a + b) - b = a
        let test_pairs = [
            (
                "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0",
                "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"
            ),
        ];

        for (a_hex, b_hex) in test_pairs.iter() {
            let a_bytes = hex::decode(a_hex).unwrap();
            let b_bytes = hex::decode(b_hex).unwrap();

            let mut a_array = [0u8; 48];
            let mut b_array = [0u8; 48];
            a_array.copy_from_slice(&a_bytes);
            b_array.copy_from_slice(&b_bytes);

            let a = FieldElement::from_bytes(&a_array)?;
            let b = FieldElement::from_bytes(&b_array)?;

            let sum = a.add(&b);
            let result = sum.sub(&b);

            assert_eq!(result, a, "Addition/subtraction test failed");
        }

        Ok(())
    }
}

/// Point validation test vectors
#[cfg(test)]
mod point_validation_vectors {
    use super::*;

    #[test]
    fn test_invalid_points() {
        // Points that should NOT be on the curve
        let invalid_points = [
            // Random point not on curve
            (
                "100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
            // Point with x-coordinate larger than field modulus
            (
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
                "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"
            ),
        ];

        for (x_hex, y_hex) in invalid_points.iter() {
            let x_bytes = hex::decode(x_hex).unwrap();
            let y_bytes = hex::decode(y_hex).unwrap();

            let mut x_array = [0u8; 48];
            let mut y_array = [0u8; 48];

            // Handle different lengths
            if x_bytes.len() <= 48 {
                x_array[48 - x_bytes.len()..].copy_from_slice(&x_bytes);
            }
            if y_bytes.len() <= 48 {
                y_array[48 - y_bytes.len()..].copy_from_slice(&y_bytes);
            }

            let result = Point::new_uncompressed(&x_array, &y_array);
            assert!(
                result.is_err(),
                "Point ({}, {}) should be invalid",
                x_hex,
                y_hex
            );
        }
    }

    #[test]
    fn test_point_compression_decompression() -> Result<()> {
        // Test with the base point
        let g = p384::base_point_g();
        let serialized = g.serialize_uncompressed();
        let deserialized = Point::deserialize_uncompressed(&serialized)?;

        assert_eq!(
            g, deserialized,
            "Point serialization/deserialization failed"
        );

        // Fixed-width all-zero identity sentinels are non-canonical SEC 1.
        let identity = Point::identity();
        let serialized_identity = identity.serialize_uncompressed();
        assert!(Point::deserialize_uncompressed(&serialized_identity).is_err());

        Ok(())
    }
}

/// Edge case test vectors
#[cfg(test)]
mod edge_case_vectors {
    use super::*;

    #[test]
    fn test_scalar_edge_cases() -> Result<()> {
        // Test scalar = 1
        let one_bytes = [0u8; 47]
            .iter()
            .chain([1u8].iter())
            .cloned()
            .collect::<Vec<_>>();
        let mut one_array = [0u8; 48];
        one_array.copy_from_slice(&one_bytes);
        let scalar_one = Scalar::new(one_array)?;
        let result_one = p384::scalar_mult_base_g(&scalar_one)?;
        let base_point = p384::base_point_g();
        assert_eq!(result_one, base_point, "1 * G should equal G");

        // Test scalar = 2
        let two_bytes = [0u8; 47]
            .iter()
            .chain([2u8].iter())
            .cloned()
            .collect::<Vec<_>>();
        let mut two_array = [0u8; 48];
        two_array.copy_from_slice(&two_bytes);
        let scalar_two = Scalar::new(two_array)?;
        let result_two = p384::scalar_mult_base_g(&scalar_two)?;
        let expected_two = base_point.add(&base_point); // G + G = 2G
        assert_eq!(result_two, expected_two, "2 * G should equal G + G");

        Ok(())
    }

    #[test]
    fn test_point_addition_edge_cases() -> Result<()> {
        let g = p384::base_point_g();
        let identity = Point::identity();

        // G + O = G
        let result1 = g.add(&identity);
        assert_eq!(result1, g, "G + identity should equal G");

        // O + G = G
        let result2 = identity.add(&g);
        assert_eq!(result2, g, "identity + G should equal G");

        // G + G = 2G
        let double_g = g.double();
        let add_g_g = g.add(&g);
        assert_eq!(double_g, add_g_g, "G.double() should equal G + G");

        Ok(())
    }
}

// ============================================================================
// DEBUGGING TESTS - P-384 FOCUSED
// ============================================================================

#[test]
fn step_1_verify_p384_base_point() -> Result<()> {
    println!("=== STEP 1: Verify P-384 Base Point Loading ===");

    let g = p384::base_point_g();
    let g_x = hex::encode(g.x_coordinate_bytes());
    let g_y = hex::encode(g.y_coordinate_bytes());

    println!("P-384 G_x: {}", g_x);
    println!("P-384 G_y: {}", g_y);

    // These should match the NIST P-384 constants exactly
    assert_eq!(g_x, "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7");
    assert_eq!(g_y, "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f");

    Ok(())
}

#[test]
fn step_2_verify_p384_field_one() -> Result<()> {
    println!("=== STEP 2: Verify P-384 Field Element One ===");

    let one = FieldElement::one();
    let one_bytes = one.to_bytes();
    println!("P-384 FieldElement::one(): {}", hex::encode(one_bytes));

    // Should be 0x00...01 (big-endian)
    let mut expected = [0u8; 48];
    expected[47] = 1;
    assert_eq!(one_bytes, expected);

    Ok(())
}

#[test]
fn step_3_trace_p384_doubling() -> Result<()> {
    println!("=== STEP 3: Trace P-384 Point Doubling ===");

    let g = p384::base_point_g();
    let doubled = g.double();

    println!("2G x = {}", hex::encode(doubled.x_coordinate_bytes()));
    println!("2G y = {}", hex::encode(doubled.y_coordinate_bytes()));

    // Compare with expected P-384 test vector for 2*G
    let expected_2g_x = "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e4fe0e86ebe0e64f85b96a9c75295df61";
    let expected_2g_y = "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4255ffd43e94d39e22d61501e700a940e80";

    assert_eq!(hex::encode(doubled.x_coordinate_bytes()), expected_2g_x);
    assert_eq!(hex::encode(doubled.y_coordinate_bytes()), expected_2g_y);

    Ok(())
}

#[test]
fn step_4_p384_scalar_mult_k3() -> Result<()> {
    println!("=== STEP 4: P-384 Scalar Mult for k=3 ===");

    let g = p384::base_point_g();
    let mut scalar_bytes = [0u8; 48];
    scalar_bytes[47] = 3; // Binary: 00000011

    let scalar = Scalar::new(scalar_bytes)?;
    let result = g.mul(&scalar)?;

    println!("3G x = {}", hex::encode(result.x_coordinate_bytes()));
    println!("3G y = {}", hex::encode(result.y_coordinate_bytes()));

    // Expected P-384 test vector for 3*G
    let expected_3g_x = "077a41d4606ffa1464793c7e5fdc7d98cb9d3910202dcd06bea4f240d3566da6b408bbae5026580d02d7e5c70500c831";
    let expected_3g_y = "c995f7ca0b0c42837d0bbe9602a9fc998520b41c85115aa5f7684c0edc111eacc24abd6be4b5d298b65f28600a2f1df1";

    assert_eq!(hex::encode(result.x_coordinate_bytes()), expected_3g_x);
    assert_eq!(hex::encode(result.y_coordinate_bytes()), expected_3g_y);

    Ok(())
}

#[test]
fn step_5_p384_reference_doubling() -> Result<()> {
    println!("=== STEP 5: P-384 Reference Doubling Comparison ===");

    let g = p384::base_point_g();
    let x_bytes = g.x_coordinate_bytes();
    let y_bytes = g.y_coordinate_bytes();

    let x = FieldElement::from_bytes(&x_bytes)?;
    let y = FieldElement::from_bytes(&y_bytes)?;

    // Standard affine doubling formula
    let x_squared = x.square();
    let three_x_squared = x_squared.add(&x_squared).add(&x_squared);
    let three = FieldElement::one()
        .add(&FieldElement::one())
        .add(&FieldElement::one());
    let numerator = three_x_squared.sub(&three);
    let two_y = y.add(&y);
    let two_y_inv = two_y.invert()?;
    let lambda = numerator.mul(&two_y_inv);
    let lambda_squared = lambda.square();
    let two_x = x.add(&x);
    let x_prime = lambda_squared.sub(&two_x);
    let x_minus_xprime = x.sub(&x_prime);
    let lambda_times_diff = lambda.mul(&x_minus_xprime);
    let y_prime = lambda_times_diff.sub(&y);

    println!("Reference 2G x = {}", hex::encode(x_prime.to_bytes()));
    println!("Reference 2G y = {}", hex::encode(y_prime.to_bytes()));

    // Compare with the built-in doubling
    let your_2g = g.double();
    println!(
        "Your impl 2G x = {}",
        hex::encode(your_2g.x_coordinate_bytes())
    );
    println!(
        "Your impl 2G y = {}",
        hex::encode(your_2g.y_coordinate_bytes())
    );

    assert_eq!(x_prime.to_bytes(), your_2g.x_coordinate_bytes());
    assert_eq!(y_prime.to_bytes(), your_2g.y_coordinate_bytes());

    Ok(())
}
