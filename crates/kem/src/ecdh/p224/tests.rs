use super::*;
use crate::test_rng::TestRng;
use dcrypt_api::Kem as KemTrait; // Use the trait from api

#[cfg(test)]
mod test_utils {
    use dcrypt_common::security::SecretBuffer;

    /// Convert a slice to a SecretBuffer of the specified size
    /// This is a test-only utility for creating SecretBuffers from slices
    pub fn secret_buffer_from_slice<const N: usize>(slice: &[u8]) -> SecretBuffer<N> {
        assert_eq!(slice.len(), N, "Slice length must match SecretBuffer size");
        let mut buffer = [0u8; N];
        buffer.copy_from_slice(slice);
        SecretBuffer::new(buffer)
    }
}

#[cfg(test)]
use test_utils::secret_buffer_from_slice;

#[test]
fn test_ecdh_p224_kem_keypair_generation() {
    let keypair_result = EcdhP224::keypair(&mut TestRng);
    assert!(
        keypair_result.is_ok(),
        "Keypair generation failed: {:?}",
        keypair_result.err()
    );
    let (pk, sk) = keypair_result.unwrap();
    assert_eq!(pk.to_bytes().len(), ec::P224_POINT_COMPRESSED_SIZE);
    assert_eq!(sk.to_bytes().len(), ec::P224_SCALAR_SIZE);
}

#[test]
fn test_ecdh_p224_kem_encapsulate_decapsulate_roundtrip() {
    let (pk_r, sk_r) = EcdhP224::keypair(&mut TestRng).expect("Recipient keygen failed");

    let encapsulate_result = EcdhP224::encapsulate(&mut TestRng, &pk_r);
    assert!(
        encapsulate_result.is_ok(),
        "Encapsulation failed: {:?}",
        encapsulate_result.err()
    );
    let (ciphertext, shared_secret_sender) = encapsulate_result.unwrap();

    // Fix: Check for full ciphertext size (compressed point + auth tag)
    assert_eq!(ciphertext.to_bytes().len(), ec::P224_CIPHERTEXT_SIZE);
    assert_eq!(
        shared_secret_sender.to_bytes().len(),
        ec::P224_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE
    );

    let decapsulate_result = EcdhP224::decapsulate(&sk_r, &ciphertext);
    assert!(
        decapsulate_result.is_ok(),
        "Decapsulation failed: {:?}",
        decapsulate_result.err()
    );
    let shared_secret_receiver = decapsulate_result.unwrap();

    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_receiver.to_bytes(),
        "Shared secrets do not match"
    );
}

#[test]
fn test_ecdh_p224_kem_decapsulate_wrong_secret_key() {
    let (pk_r, _sk_r1) = EcdhP224::keypair(&mut TestRng).expect("Recipient keygen1 failed");
    let (_pk_r2, sk_r2) = EcdhP224::keypair(&mut TestRng).expect("Recipient keygen2 failed"); // Different secret key

    let (ciphertext, _shared_secret_sender) =
        EcdhP224::encapsulate(&mut TestRng, &pk_r).expect("Encapsulation failed");

    let decapsulate_result = EcdhP224::decapsulate(&sk_r2, &ciphertext); // Use wrong secret key
    assert!(
        decapsulate_result.is_err(),
        "Decapsulation should fail with wrong secret key"
    );
    // More specific error check if desired, e.g., expecting a DecryptionFailed
}

#[test]
fn test_ecdh_p224_kem_decapsulate_tampered_ciphertext() {
    let (pk_r, sk_r) = EcdhP224::keypair(&mut TestRng).expect("Recipient keygen failed");

    let (mut ciphertext, _shared_secret_sender) =
        EcdhP224::encapsulate(&mut TestRng, &pk_r).expect("Encapsulation failed");

    // Fix: Tamper with the first byte of the ephemeral public key portion
    // (avoiding accidental corruption of tag structure)
    ciphertext.0[0] ^= 0xFF;

    let decapsulate_result = EcdhP224::decapsulate(&sk_r, &ciphertext);
    assert!(
        decapsulate_result.is_err(),
        "Decapsulation should fail with tampered ciphertext"
    );
}

#[test]
fn test_ecdh_p224_kem_ciphertext_structure() {
    let (pk_r, _sk_r) = EcdhP224::keypair(&mut TestRng).expect("Recipient keygen failed");
    let (ciphertext, _shared_secret) =
        EcdhP224::encapsulate(&mut TestRng, &pk_r).expect("Encapsulation failed");

    // Verify ciphertext structure: compressed point + auth tag
    assert_eq!(ciphertext.to_bytes().len(), ec::P224_CIPHERTEXT_SIZE);
    assert_eq!(
        ciphertext.to_bytes().len(),
        ec::P224_POINT_COMPRESSED_SIZE + ec::P224_TAG_SIZE
    );

    // Verify the tag portion has the expected length
    let ct_bytes = ciphertext.to_bytes();
    let tag_portion = &ct_bytes[ec::P224_POINT_COMPRESSED_SIZE..];
    assert_eq!(tag_portion.len(), ec::P224_TAG_SIZE);
}

// Add these tests to crates/kem/src/ecdh/p224/tests.rs

#[test]
fn test_p224_public_key_serialization() {
    let mut rng = TestRng;
    let (pk, _) = EcdhP224::keypair(&mut rng).unwrap();

    // Round-trip
    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), 29);
    let restored = EcdhP224PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(pk.to_bytes(), restored.to_bytes());
}

#[test]
fn test_p224_secret_key_serialization() {
    let mut rng = TestRng;
    let (_, sk) = EcdhP224::keypair(&mut rng).unwrap();

    // Export and verify length
    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 28);

    // Import and verify functionality
    let restored = EcdhP224SecretKey::from_bytes(&bytes).unwrap();

    // Generate same public key from both
    let pk1 = ec::scalar_mult_base_g(
        &ec::Scalar::from_secret_buffer(secret_buffer_from_slice::<28>(&sk.to_bytes())).unwrap(),
    )
    .unwrap();
    let pk2 = ec::scalar_mult_base_g(
        &ec::Scalar::from_secret_buffer(secret_buffer_from_slice::<28>(&restored.to_bytes()))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pk1.serialize_compressed(), pk2.serialize_compressed());
}

#[test]
fn test_p224_authenticated_ciphertext_serialization() {
    let mut rng = TestRng;
    let (pk, _) = EcdhP224::keypair(&mut rng).unwrap();
    let (ct, _) = EcdhP224::encapsulate(&mut rng, &pk).unwrap();

    // Round-trip - P224 has authenticated ciphertext!
    let bytes = ct.to_bytes();
    assert_eq!(bytes.len(), 45); // 29 + 16 byte tag
    let restored = EcdhP224Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct.to_bytes(), restored.to_bytes());

    // Verify structure
    let pk_part = &bytes[..29];
    let tag_part = &bytes[29..];
    assert_eq!(pk_part.len(), 29);
    assert_eq!(tag_part.len(), 16);
}

#[test]
fn test_p224_invalid_public_key() {
    // Wrong length
    assert!(EcdhP224PublicKey::from_bytes(&[0u8; 28]).is_err());
    assert!(EcdhP224PublicKey::from_bytes(&[0u8; 30]).is_err());

    // Identity point
    assert!(EcdhP224PublicKey::from_bytes(&[0u8; 29]).is_err());
}

#[test]
fn test_p224_invalid_ciphertext() {
    // Wrong length for authenticated ciphertext
    assert!(EcdhP224Ciphertext::from_bytes(&[0u8; 29]).is_err());
    assert!(EcdhP224Ciphertext::from_bytes(&[0u8; 44]).is_err());
    assert!(EcdhP224Ciphertext::from_bytes(&[0u8; 46]).is_err());

    // Valid length but invalid point
    assert!(EcdhP224Ciphertext::from_bytes(&[0u8; 45]).is_err());
}

#[test]
fn test_p224_full_kem_with_serialization() {
    let mut rng = TestRng;

    // Generate and serialize
    let (pk, sk) = EcdhP224::keypair(&mut rng).unwrap();
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Restore and use
    let pk_restored = EcdhP224PublicKey::from_bytes(&pk_bytes).unwrap();
    let sk_restored = EcdhP224SecretKey::from_bytes(&sk_bytes).unwrap();

    // KEM operation with authenticated ciphertext
    let (ct, ss1) = EcdhP224::encapsulate(&mut rng, &pk_restored).unwrap();
    let ct_bytes = ct.to_bytes();
    assert_eq!(ct_bytes.len(), 45); // Verify authenticated format

    let ct_restored = EcdhP224Ciphertext::from_bytes(&ct_bytes).unwrap();
    let ss2 = EcdhP224::decapsulate(&sk_restored, &ct_restored).unwrap();

    assert_eq!(ss1.to_bytes(), ss2.to_bytes());
}
