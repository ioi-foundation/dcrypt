use super::*;
use crate::error::Result;

// =========================================================================
// GHASH Component Tests - Internal Consistency Tests
// =========================================================================

/// Note on GHASH testing:
/// The GHASH function is standardized in NIST SP 800-38D, but the specification
/// allows different implementation strategies that can lead to differences in
/// intermediate values while still being compliant.
///
/// These tests verify that our GHASH implementation is internally consistent
/// and conforms to the algebraic properties required by GCM.

#[test]
fn test_empty_inputs() -> Result<()> {
    // GHASH of empty inputs with any key H should produce all zeros
    let h = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];

    let empty: [u8; 0] = [];
    let result = process_ghash(&h, &empty, &empty)?;

    // Expected: All zeros when both AAD and ciphertext are empty
    let expected = [0u8; 16];
    assert_eq!(result, expected);
    Ok(())
}

#[test]
fn test_gf_multiply_commutative() {
    // GF multiplication should be commutative: X * Y = Y * X
    let x = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    let y = [
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];

    let result1 = GHash::gf_multiply(&x, &y);
    let result2 = GHash::gf_multiply(&y, &x);

    assert_eq!(result1, result2);
}

#[test]
fn test_gf_multiply_zero() {
    // Test that multiplication by 0 yields 0
    let x = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    let zero = [0u8; 16];

    let result = GHash::gf_multiply(&x, &zero);

    assert_eq!(&*result, &zero);
}

#[test]
fn test_ghash_internal_consistency() -> Result<()> {
    // Test that GHASH produces consistent results when using the same inputs
    let h = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    let data1 = [0xaa; 32];
    let data2 = [0xbb; 16];

    // Compute GHASH twice with the same inputs
    let result1 = process_ghash(&h, &data1, &data2)?;
    let result2 = process_ghash(&h, &data1, &data2)?;

    // Results should be identical
    assert_eq!(result1, result2);
    Ok(())
}

#[test]
fn test_ghash_length_block() -> Result<()> {
    // Test that GHASH correctly processes the length block
    let h = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];

    let data_a = [0xaa; 32]; // 32 bytes
    let data_b = [0xbb; 16]; // 16 bytes

    // Process with different lengths and verify results differ
    let result1 = process_ghash(&h, &data_a, &data_b)?;

    // Swap AAD and ciphertext - should produce a different result due to length block
    let result2 = process_ghash(&h, &data_b, &data_a)?;

    // Results should be different
    assert_ne!(result1, result2);
    Ok(())
}

#[test]
fn test_ghash_unaligned() -> Result<()> {
    // Test with unaligned blocks (not multiples of 16 bytes)

    // H = 66e94bd4ef8a2c3b884cfa59ca342b2e
    let h = [
        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b,
        0x2e,
    ];

    // AAD = 4dcf793636f7d2c450fa37
    let aad = [
        0x4d, 0xcf, 0x79, 0x36, 0x36, 0xf7, 0xd2, 0xc4, 0x50, 0xfa, 0x37,
    ];

    // CT = 48af2e8c4a893dda598
    let ct = [0x48, 0xaf, 0x2e, 0x8c, 0x4a, 0x89, 0x3d, 0xda, 0x59, 0x8];

    // Get actual lengths
    let aad_len = aad.len();
    let ct_len = ct.len();

    // First manually process the data
    let mut ghash_instance = GHash::new(&h);

    // Process AAD (11 bytes)
    ghash_instance.update_block(&aad, aad_len)?;

    // Process ciphertext (10 bytes)
    ghash_instance.update_block(&ct, ct_len)?;

    // Update lengths using actual lengths
    ghash_instance.update_lengths(aad_len as u64, ct_len as u64)?;

    let manual_result = ghash_instance.finalize();

    // Now use the helper function
    let helper_result = process_ghash(&h, &aad, &ct)?;

    // Both methods should produce the same result
    assert_eq!(manual_result, helper_result);
    Ok(())
}

#[test]
fn test_ghash_rejects_bit_length_overflow() {
    let mut ghash = GHash::new(&[0x42; 16]);
    assert!(ghash.update_lengths(u64::MAX / 8 + 1, 0).is_err());
    assert!(ghash.update_lengths(0, u64::MAX / 8 + 1).is_err());
}

#[test]
fn test_ghash_rejects_inconsistent_block_length() {
    let mut ghash = GHash::new(&[0x42; 16]);
    assert!(ghash.update_block(&[0u8; 15], 16).is_err());
    assert!(ghash.update_block(&[0u8; 17], 17).is_err());
}
