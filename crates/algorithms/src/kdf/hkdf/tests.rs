use crate::hash::{HashFunction, Sha256, Sha512};
use crate::kdf::Hkdf;
use hex;

/// Test HKDF implementation against RFC 5869 Test Case 1
///
/// This test verifies the extract and expand functionality separately
/// and then together using the first official test vector.
#[test]
fn test_hkdf_sha256_rfc5869_1() {
    // Test Case 1 from RFC 5869
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let length = 42;

    // Expected values from the RFC
    let expected_prk =
        hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
    let expected_okm = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    )
    .unwrap();

    // Test extract function
    let prk = Hkdf::<Sha256>::extract(Some(&salt), &ikm).unwrap();
    // Compare the underlying bytes
    assert_eq!(prk.as_slice(), expected_prk.as_slice());

    // Test expand function
    let okm = Hkdf::<Sha256>::expand(&prk, Some(&info), length).unwrap();
    assert_eq!(okm.as_slice(), expected_okm.as_slice());

    // Test combined derive function
    let okm = Hkdf::<Sha256>::derive(Some(&salt), &ikm, Some(&info), length).unwrap();
    assert_eq!(okm.as_slice(), expected_okm.as_slice());
}

/// Test HKDF implementation against RFC 5869 Test Case 2
///
/// This test verifies the implementation with longer inputs.
#[test]
fn test_hkdf_sha256_rfc5869_2() {
    // Test Case 2 from RFC 5869 - uses much longer inputs
    let ikm = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").unwrap();
    let salt = hex::decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").unwrap();
    let info = hex::decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
    let length = 82;

    // Expected values from the RFC
    let expected_prk =
        hex::decode("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244").unwrap();
    let expected_okm = hex::decode("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87").unwrap();

    // Test extract function
    let prk = Hkdf::<Sha256>::extract(Some(&salt), &ikm).unwrap();
    assert_eq!(prk.as_slice(), expected_prk.as_slice());

    // Test expand function
    let okm = Hkdf::<Sha256>::expand(&prk, Some(&info), length).unwrap();
    assert_eq!(okm.as_slice(), expected_okm.as_slice());

    // Test combined derive function
    let okm = Hkdf::<Sha256>::derive(Some(&salt), &ikm, Some(&info), length).unwrap();
    assert_eq!(okm.as_slice(), expected_okm.as_slice());
}

/// Test HKDF implementation against RFC 5869 Test Case 3
///
/// This test verifies functionality with null salt and info parameters
#[test]
fn test_hkdf_sha256_rfc5869_3() {
    // Test Case 3 from RFC 5869 - tests with no salt and no info
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = None; // No salt
    let info = None; // No info
    let length = 42;

    // Expected values from the RFC
    let expected_prk =
        hex::decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04").unwrap();
    let expected_okm = hex::decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    )
    .unwrap();

    // Test extract function
    let prk = Hkdf::<Sha256>::extract(salt, &ikm).unwrap();
    assert_eq!(prk.as_slice(), expected_prk.as_slice());

    // Test expand function
    let okm = Hkdf::<Sha256>::expand(&prk, info, length).unwrap();
    assert_eq!(okm.as_slice(), expected_okm.as_slice());

    // Test combined derive function
    let okm = Hkdf::<Sha256>::derive(salt, &ikm, info, length).unwrap();
    assert_eq!(okm.as_slice(), expected_okm.as_slice());
}

/// Test HKDF with SHA-512 hash function
///
/// This test verifies the implementation works with a different hash function.
#[test]
fn test_hkdf_sha512() {
    // Simple test case with SHA-512
    let ikm = b"input key material";
    let salt = b"salt";
    let info = b"context info";
    let length = 64;

    // The PRK should be the size of the hash function output
    let prk = Hkdf::<Sha512>::extract(Some(salt), ikm).unwrap();
    assert_eq!(prk.len(), Sha512::output_size());

    // The OKM should be the requested length
    let okm = Hkdf::<Sha512>::expand(&prk, Some(info), length).unwrap();
    assert_eq!(okm.len(), length);

    // Test combined derive function
    let okm2 = Hkdf::<Sha512>::derive(Some(salt), ikm, Some(info), length).unwrap();
    assert_eq!(okm.as_slice(), okm2.as_slice());
}

/// Test HKDF with invalid parameters
///
/// This test verifies error handling for invalid input parameters:
/// 1. PRK too short
/// 2. Output length too large
#[test]
fn test_hkdf_invalid_parameters() {
    // Test with PRK too short (should be at least HashLen)
    let short_prk = [0; 16]; // Sha256::output_size is 32
    let info = b"info";
    let length = 32;

    let result = Hkdf::<Sha256>::expand(&short_prk, Some(info), length);
    assert!(result.is_err());

    // Test with output length too large (should be ≤ 255*HashLen)
    let prk = [0; 32];
    let max_length = 255 * Sha256::output_size();
    let too_large = max_length + 1;

    let result = Hkdf::<Sha256>::expand(&prk, Some(info), too_large);
    assert!(result.is_err());
}
