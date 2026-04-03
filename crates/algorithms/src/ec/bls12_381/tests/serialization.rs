//! Serialization and deserialization tests for BLS12-381

use super::super::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};

#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::PathBuf;

// ============================================================================
// Test Vector Helpers
// ============================================================================

#[cfg(test)]
fn get_test_vector_path(filename: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // From crates/algorithms/ go up to workspace root
    path.pop(); // algorithms
    path.pop(); // crates
                // Now we're at workspace root, push down to test vectors
    path.push("tests");
    path.push("src");
    path.push("vectors");
    path.push("custom");
    path.push(filename);
    path
}

// ============================================================================
// G1 Serialization Tests
// ============================================================================

#[test]
fn test_g1_compression_round_trip() {
    // Test with deterministic points
    let g = G1Projective::generator();
    for i in 1..=20 {
        let original = G1Affine::from(g * Scalar::from(i as u64));
        let compressed = original.to_compressed();
        let decompressed = G1Affine::from_compressed(&compressed).unwrap();
        assert_eq!(original, decompressed);
    }

    // Test with special points
    let special_points = vec![
        G1Affine::identity(),
        G1Affine::generator(),
        -G1Affine::generator(),
    ];

    for point in special_points {
        let compressed = point.to_compressed();
        let decompressed = G1Affine::from_compressed(&compressed).unwrap();
        assert_eq!(point, decompressed);
    }
}

#[test]
fn test_g1_uncompressed_round_trip() {
    let g = G1Projective::generator();
    for i in 1..=20 {
        let original = G1Affine::from(g * Scalar::from(i as u64));
        let uncompressed = original.to_uncompressed();
        let restored = G1Affine::from_uncompressed(&uncompressed).unwrap();
        assert_eq!(original, restored);
    }
}

#[test]
fn test_g1_invalid_compressed_rejection() {
    // Test 1: Non-canonical field element (all 0xff)
    let bytes = [0xff; 48];
    assert!(G1Affine::from_compressed(&bytes).is_err());

    // Test 2: Field element >= p
    let mut bytes = [0xff; 48];
    bytes[0] = 0x9a; // Set compression bit but make value >= p
    assert!(G1Affine::from_compressed(&bytes).is_err());

    // Test 3: Invalid flag combinations
    let mut bytes = G1Affine::generator().to_compressed();
    bytes[0] |= 0b11100000; // Set multiple incompatible flags
    assert!(G1Affine::from_compressed(&bytes).is_err());

    // Test 4: Compression flag not set
    let mut bytes = G1Affine::generator().to_compressed();
    bytes[0] &= 0b01111111; // Clear compression flag
    assert!(G1Affine::from_compressed(&bytes).is_err());

    // Test 5: Point not on curve (random x coordinate)
    let mut bytes = [0; 48];
    bytes[0] = 0x80; // Set compression flag
    bytes[47] = 0x01; // Random x coordinate
                      // Either deserialization fails, or it succeeds but point is not on curve or has torsion
    let result = G1Affine::from_compressed(&bytes);
    assert!(result.is_err() || !bool::from(result.unwrap().is_on_curve()));
}

#[test]
fn test_g1_invalid_uncompressed_rejection() {
    // Test 1: Non-canonical field elements
    let bytes = [0xff; 96];
    assert!(bool::from(G1Affine::from_uncompressed(&bytes).is_none()));

    // Test 2: Compression flag set (should not be set for uncompressed)
    let mut bytes = G1Affine::generator().to_uncompressed();
    bytes[0] |= 0b10000000;
    assert!(bool::from(G1Affine::from_uncompressed(&bytes).is_none()));

    // Test 3: Point not on curve
    let mut bytes = [0; 96];
    bytes[47] = 0x01; // Random x
    bytes[95] = 0x02; // Random y
    let result = G1Affine::from_uncompressed(&bytes);
    assert!(bool::from(result.is_none()) || !bool::from(result.unwrap().is_on_curve()));

    // Test 4: Invalid infinity representation
    let mut bytes = [0; 96];
    bytes[0] = 0b01000000; // Set infinity flag
    bytes[47] = 0x01; // But x is non-zero
    assert!(bool::from(G1Affine::from_uncompressed(&bytes).is_none()));
}

// ============================================================================
// G2 Serialization Tests
// ============================================================================

#[test]
fn test_g2_compression_round_trip() {
    let g = G2Projective::generator();
    for i in 1..=20 {
        let original = G2Affine::from(g * Scalar::from(i as u64));
        let compressed = original.to_compressed();
        let decompressed = G2Affine::from_compressed(&compressed).unwrap();
        assert_eq!(original, decompressed);
    }

    // Test with special points
    let special_points = vec![
        G2Affine::identity(),
        G2Affine::generator(),
        -G2Affine::generator(),
    ];

    for point in special_points {
        let compressed = point.to_compressed();
        let decompressed = G2Affine::from_compressed(&compressed).unwrap();
        assert_eq!(point, decompressed);
    }
}

#[test]
fn test_g2_uncompressed_round_trip() {
    let g = G2Projective::generator();
    for i in 1..=20 {
        let original = G2Affine::from(g * Scalar::from(i as u64));
        let uncompressed = original.to_uncompressed();
        let restored = G2Affine::from_uncompressed(&uncompressed).unwrap();
        assert_eq!(original, restored);
    }
}

#[test]
fn test_g2_invalid_compressed_rejection() {
    // Test 1: Non-canonical field element
    let bytes = [0xff; 96];
    assert!(bool::from(G2Affine::from_compressed(&bytes).is_none()));

    // Test 2: Invalid flag combinations
    let mut bytes = G2Affine::generator().to_compressed();
    bytes[0] = 0b11100000; // Multiple flags set
    assert!(bool::from(G2Affine::from_compressed(&bytes).is_none()));

    // Test 3: Point not on curve
    let mut bytes = [0; 96];
    bytes[0] = 0x80; // Compression flag
    bytes[95] = 0x01; // Random x coordinate
    let result = G2Affine::from_compressed(&bytes);
    assert!(bool::from(result.is_none()) || !bool::from(result.unwrap().is_on_curve()));
}

#[test]
fn test_g2_invalid_uncompressed_rejection() {
    // Test 1: Non-canonical field elements
    let bytes = [0xff; 192];
    assert!(bool::from(G2Affine::from_uncompressed(&bytes).is_none()));

    // Test 2: Point not on curve
    let mut bytes = [0; 192];
    bytes[95] = 0x01; // Random x
    bytes[191] = 0x02; // Random y
    let result = G2Affine::from_uncompressed(&bytes);
    assert!(bool::from(result.is_none()) || !bool::from(result.unwrap().is_on_curve()));
}

// ============================================================================
// Test Vector Validation
// ============================================================================

#[test]
fn g1_uncompressed_valid_test_vectors() {
    let path = get_test_vector_path("g1_uncompressed_valid_test_vectors.dat");
    let bytes = fs::read(&path).expect(&format!("Failed to read test vector: {:?}", path));

    let mut e = G1Projective::identity();
    let mut v = vec![];
    let mut expected = bytes.as_slice();

    for _ in 0..1000 {
        let e_affine = G1Affine::from(e);
        let encoded = e_affine.to_uncompressed();
        v.extend_from_slice(&encoded[..]);

        let mut decoded = [0u8; 96];
        decoded.copy_from_slice(&expected[0..96]);
        expected = &expected[96..];

        let decoded_point = G1Affine::from_uncompressed(&decoded).unwrap();
        assert_eq!(e_affine, decoded_point);

        e = &e + &G1Projective::generator();
    }

    assert_eq!(&v[..], &bytes);
}

#[test]
fn g1_compressed_valid_test_vectors() {
    let path = get_test_vector_path("g1_compressed_valid_test_vectors.dat");
    let bytes = fs::read(&path).expect(&format!("Failed to read test vector: {:?}", path));

    let mut e = G1Projective::identity();
    let mut v = vec![];
    let mut expected = bytes.as_slice();

    for _ in 0..1000 {
        let e_affine = G1Affine::from(e);
        let encoded = e_affine.to_compressed();
        v.extend_from_slice(&encoded[..]);

        let mut decoded = [0u8; 48];
        decoded.copy_from_slice(&expected[0..48]);
        expected = &expected[48..];

        let decoded_point = G1Affine::from_compressed(&decoded).unwrap();
        assert_eq!(e_affine, decoded_point);

        e = &e + &G1Projective::generator();
    }

    assert_eq!(&v[..], &bytes);
}

#[test]
fn g2_uncompressed_valid_test_vectors() {
    let path = get_test_vector_path("g2_uncompressed_valid_test_vectors.dat");
    let bytes = fs::read(&path).expect(&format!("Failed to read test vector: {:?}", path));

    let mut e = G2Projective::identity();
    let mut v = vec![];
    let mut expected = bytes.as_slice();

    for _ in 0..1000 {
        let e_affine = G2Affine::from(e);
        let encoded = e_affine.to_uncompressed();
        v.extend_from_slice(&encoded[..]);

        let mut decoded = [0u8; 192];
        decoded.copy_from_slice(&expected[0..192]);
        expected = &expected[192..];

        let decoded_point = G2Affine::from_uncompressed(&decoded).unwrap();
        assert_eq!(e_affine, decoded_point);

        e = &e + &G2Projective::generator();
    }

    assert_eq!(&v[..], &bytes);
}

#[test]
fn g2_compressed_valid_test_vectors() {
    let path = get_test_vector_path("g2_compressed_valid_test_vectors.dat");
    let bytes = fs::read(&path).expect(&format!("Failed to read test vector: {:?}", path));

    let mut e = G2Projective::identity();
    let mut v = vec![];
    let mut expected = bytes.as_slice();

    for _ in 0..1000 {
        let e_affine = G2Affine::from(e);
        let encoded = e_affine.to_compressed();
        v.extend_from_slice(&encoded[..]);

        let mut decoded = [0u8; 96];
        decoded.copy_from_slice(&expected[0..96]);
        expected = &expected[96..];

        let decoded_point = G2Affine::from_compressed(&decoded).unwrap();
        assert_eq!(e_affine, decoded_point);

        e = &e + &G2Projective::generator();
    }

    assert_eq!(&v[..], &bytes);
}

// ============================================================================
// Field Element Serialization Tests
// ============================================================================

#[test]
fn test_fp_from_bytes_rejection() {
    use super::super::field::fp::Fp;

    // Test value >= p should be rejected
    let bytes = [0xff; 48];
    assert!(bool::from(Fp::from_bytes(&bytes).is_none()));

    // Test largest valid value (p - 1)
    // p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    // p - 1 in big-endian bytes:
    let p_minus_1: [u8; 48] = [
        0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac,
        0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0,
        0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff,
        0xff, 0xaa, 0xaa,
    ];

    // This should parse successfully as it's p - 1
    assert!(bool::from(Fp::from_bytes(&p_minus_1).is_some()));
}
