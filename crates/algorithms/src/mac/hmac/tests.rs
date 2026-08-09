use super::*;
use crate::hash::{Sha1, Sha256, Sha512};
use hex;

/// Test vectors for HMAC-SHA-1 from RFC 2202
///
/// RFC 2202 provides official test vectors for HMAC-SHA-1
#[test]
fn test_hmac_sha1_rfc2202() {
    // Test case 1
    let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let data = b"Hi There";
    let expected = hex::decode("b617318655057264e28bc0b6fb378c8ef146be00").unwrap();

    let mac = Hmac::<Sha1>::mac(&key, data).unwrap();
    assert_eq!(mac, expected);

    // Test case 2 - Key shorter than block size
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = hex::decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79").unwrap();

    let mac = Hmac::<Sha1>::mac(key, data).unwrap();
    assert_eq!(mac, expected);

    // Test case 3 - Key and data that will cause padding
    let key = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let data = hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
    let expected = hex::decode("125d7342b9ac11cd91a39af48aa17b4f63f175d3").unwrap();

    let mac = Hmac::<Sha1>::mac(&key, &data).unwrap();
    assert_eq!(mac, expected);

    // Test case 4 - Key longer than block size
    let key = hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
    let data = hex::decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap();
    let expected = hex::decode("4c9007f4026250c6bc8414f9bf50c86c2d7235da").unwrap();

    let mac = Hmac::<Sha1>::mac(&key, &data).unwrap();
    assert_eq!(mac, expected);
}

/// Test vectors for HMAC-SHA-256 from RFC 4231
///
/// RFC 4231 provides official test vectors for HMAC with SHA-2 functions
#[test]
fn test_hmac_sha256_rfc4231() {
    // Test Case 1 - Key and data shorter than block size
    let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let data = hex::decode("4869205468657265").unwrap(); // "Hi There"
    let expected =
        hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();

    let mac = Hmac::<Sha256>::mac(&key, &data).unwrap();
    assert_eq!(mac, expected);

    // Test Case 2 - Key shorter than block size
    let key = hex::decode("4a656665").unwrap(); // "Jefe"
    let data = hex::decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f").unwrap(); // "what do ya want for nothing?"
    let expected =
        hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap();

    let mac = Hmac::<Sha256>::mac(&key, &data).unwrap();
    assert_eq!(mac, expected);

    // Test Case 3 - Key of 20 bytes (RFC 4231 test vector)
    let key = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let data = hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap();
    let expected =
        hex::decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe").unwrap();

    let mac = Hmac::<Sha256>::mac(&key, &data).unwrap();
    assert_eq!(mac, expected);

    // Test Case 4 - Key longer than block size
    let key = hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap();
    let data = hex::decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap();
    let expected =
        hex::decode("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b").unwrap();

    let mac = Hmac::<Sha256>::mac(&key, &data).unwrap();
    assert_eq!(mac, expected);
}

/// Test vectors for HMAC-SHA-512 from RFC 4231
#[test]
fn test_hmac_sha512_rfc4231() {
    // Test Case 1
    let key = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let data = hex::decode("4869205468657265").unwrap(); // "Hi There"
    let expected = hex::decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854").unwrap();

    let mac = Hmac::<Sha512>::mac(&key, &data).unwrap();
    assert_eq!(mac, expected);

    // Test Case 2
    let key = hex::decode("4a656665").unwrap(); // "Jefe"
    let data = hex::decode("7768617420646f2079612077616e7420666f72206e6f7468696e673f").unwrap(); // "what do ya want for nothing?"
    let expected = hex::decode("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737").unwrap();

    let mac = Hmac::<Sha512>::mac(&key, &data).unwrap();
    assert_eq!(mac, expected);
}

/// Test HMAC incremental interface
///
/// This test verifies that the incremental update API works
/// correctly, giving the same result as the one-shot method.
#[test]
fn test_hmac_incremental() {
    let key = b"secret key";
    let data1 = b"first part";
    let data2 = b"second part";

    // Compute HMAC incrementally
    let mut hmac = Hmac::<Sha256>::new(key).unwrap();
    hmac.update(data1).unwrap();
    hmac.update(data2).unwrap();
    let mac1 = hmac.finalize().unwrap();

    // Compute HMAC in one shot with concatenated data
    let mut full_data = Vec::new();
    full_data.extend_from_slice(data1);
    full_data.extend_from_slice(data2);
    let mac2 = Hmac::<Sha256>::mac(key, &full_data).unwrap();

    // The results should be identical
    assert_eq!(mac1, mac2);
}

/// Test HMAC verification
///
/// This test verifies that the HMAC verification function
/// correctly authenticates valid tags and rejects invalid tags.
#[test]
fn test_hmac_verify() {
    let key = b"verification key";
    let message = b"test message for verification";

    // Generate a valid HMAC tag
    let tag = Hmac::<Sha256>::mac(key, message).unwrap();

    // Verify with correct data
    assert!(Hmac::<Sha256>::verify(key, message, &tag).unwrap());

    // Verify with incorrect key
    assert!(!Hmac::<Sha256>::verify(b"wrong key", message, &tag).unwrap());

    // Verify with incorrect message
    assert!(!Hmac::<Sha256>::verify(key, b"wrong message", &tag).unwrap());

    // Verify with incorrect tag
    let mut wrong_tag = tag.clone();
    if !wrong_tag.is_empty() {
        wrong_tag[0] ^= 1; // Flip a bit to create an invalid tag
    }
    assert!(!Hmac::<Sha256>::verify(key, message, &wrong_tag).unwrap());

    // Verify with different tag length
    let short_tag = Hmac::<Sha1>::mac(key, message).unwrap(); // SHA-1 produces shorter output
    assert!(!Hmac::<Sha256>::verify(key, message, &short_tag).unwrap());

    // Regression: the old `(len ^ expected) as u8` check accepted a valid
    // digest followed by 256 bytes because the mismatch narrowed to zero.
    let mut tag_plus_256 = tag.clone();
    tag_plus_256.extend_from_slice(&[0u8; 256]);
    assert!(!Hmac::<Sha256>::verify(key, message, &tag_plus_256).unwrap());
}

/// Test for error handling after finalization
///
/// This test verifies that the HMAC implementation correctly
/// prevents updates after finalization.
#[test]
fn test_hmac_error_after_finalize() {
    let mut hmac = Hmac::<Sha256>::new(b"key").unwrap();
    hmac.update(b"data").unwrap();

    // Finalize the HMAC
    let _mac = hmac.finalize().unwrap();

    // Attempt to update after finalization should fail
    let result = hmac.update(b"more data");
    assert!(result.is_err());
}
