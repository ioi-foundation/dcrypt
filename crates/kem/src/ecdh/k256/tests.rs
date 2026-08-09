// File: crates/kem/src/ecdh/k256/tests.rs
use super::*;
use crate::test_rng::TestRng;
use dcrypt_algorithms::ec::k256 as ec_k256;
use dcrypt_api::Kem;

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
fn test_k256_kem_basic_flow() {
    let mut rng = TestRng;

    // Generate recipient keypair
    let (recipient_pk, recipient_sk) = EcdhK256::keypair(&mut rng).unwrap();

    // Encapsulate
    let (ciphertext, shared_secret_sender) =
        EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();

    // Decapsulate
    let shared_secret_recipient = EcdhK256::decapsulate(&recipient_sk, &ciphertext).unwrap();

    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes(),
        "Shared secrets should match"
    );

    // Verify key and ciphertext sizes
    assert_eq!(
        recipient_pk.to_bytes().len(),
        ec_k256::K256_POINT_COMPRESSED_SIZE
    );
    assert_eq!(recipient_sk.to_bytes().len(), ec_k256::K256_SCALAR_SIZE);
    assert_eq!(
        ciphertext.to_bytes().len(),
        ec_k256::K256_POINT_COMPRESSED_SIZE
    );
    assert_eq!(
        shared_secret_sender.to_bytes().len(),
        ec_k256::K256_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE
    );
}

#[test]
fn test_k256_kem_wrong_secret_key() {
    let mut rng = TestRng;

    // Generate two keypairs
    let (recipient_pk, _) = EcdhK256::keypair(&mut rng).unwrap();
    let (_, wrong_sk) = EcdhK256::keypair(&mut rng).unwrap();

    // Encapsulate to first recipient
    let (ciphertext, shared_secret_sender) =
        EcdhK256::encapsulate(&mut rng, &recipient_pk).unwrap();

    // Try to decapsulate with wrong secret key
    let shared_secret_wrong = EcdhK256::decapsulate(&wrong_sk, &ciphertext).unwrap();

    // Shared secrets should NOT match
    assert_ne!(
        shared_secret_sender.to_bytes(),
        shared_secret_wrong.to_bytes(),
        "Shared secrets should not match with wrong key"
    );
}

#[test]
fn test_k256_kem_invalid_public_key() {
    let mut rng = TestRng;

    // Test with all-zero public key (invalid identity point encoding)
    let invalid_pk = EcdhK256PublicKey([0u8; ec_k256::K256_POINT_COMPRESSED_SIZE]);

    // Encapsulation should fail
    let result = EcdhK256::encapsulate(&mut rng, &invalid_pk);
    assert!(result.is_err());
}

#[test]
fn test_k256_kem_tampered_ciphertext() {
    let mut rng = TestRng;
    let (public_key, secret_key) = EcdhK256::keypair(&mut rng).expect("Keypair generation failed");
    let (mut ciphertext, shared_secret_sender) =
        EcdhK256::encapsulate(&mut rng, &public_key).expect("Encapsulation failed");

    // Tamper with the ciphertext
    ciphertext.0[5] ^= 0xff;

    let decapsulate_result = EcdhK256::decapsulate(&secret_key, &ciphertext);

    match decapsulate_result {
        Ok(ss_receiver) => {
            assert_ne!(
                shared_secret_sender.to_bytes(),
                ss_receiver.to_bytes(),
                "Shared secret should differ for tampered ciphertext if decapsulation succeeds."
            );
        }
        Err(e) => {
            // It's also acceptable for decapsulation to fail if the point becomes invalid
            println!(
                "Decapsulation failed as expected for tampered ciphertext: {:?}",
                e
            );
        }
    }
}

// Add these tests to crates/kem/src/ecdh/k256/tests.rs

#[test]
fn test_k256_public_key_serialization() {
    let mut rng = TestRng;
    let (pk, _) = EcdhK256::keypair(&mut rng).unwrap();

    // Round-trip
    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), 33);
    let restored = EcdhK256PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(pk.to_bytes(), restored.to_bytes());
}

#[test]
fn test_k256_secret_key_serialization() {
    let mut rng = TestRng;
    let (_, sk) = EcdhK256::keypair(&mut rng).unwrap();

    // Export and verify length
    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 32);

    // Import and verify functionality
    let restored = EcdhK256SecretKey::from_bytes(&bytes).unwrap();

    // Generate same public key from both
    let pk1 = ec_k256::scalar_mult_base_g(
        &ec_k256::Scalar::from_secret_buffer(secret_buffer_from_slice::<32>(&sk.to_bytes()))
            .unwrap(),
    )
    .unwrap();
    let pk2 = ec_k256::scalar_mult_base_g(
        &ec_k256::Scalar::from_secret_buffer(secret_buffer_from_slice::<32>(&restored.to_bytes()))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pk1.serialize_compressed(), pk2.serialize_compressed());
}

#[test]
fn test_k256_ciphertext_serialization() {
    let mut rng = TestRng;
    let (pk, _) = EcdhK256::keypair(&mut rng).unwrap();
    let (ct, _) = EcdhK256::encapsulate(&mut rng, &pk).unwrap();

    // Round-trip
    let bytes = ct.to_bytes();
    assert_eq!(bytes.len(), 33);
    let restored = EcdhK256Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct.to_bytes(), restored.to_bytes());
}

#[test]
fn test_k256_invalid_public_key() {
    // Wrong length
    assert!(EcdhK256PublicKey::from_bytes(&[0u8; 32]).is_err());
    assert!(EcdhK256PublicKey::from_bytes(&[0u8; 34]).is_err());

    // Identity point
    assert!(EcdhK256PublicKey::from_bytes(&[0u8; 33]).is_err());

    // Invalid compression prefix
    let mut invalid = [0u8; 33];
    invalid[0] = 0xFF; // Invalid prefix
    assert!(EcdhK256PublicKey::from_bytes(&invalid).is_err());
}

#[test]
fn test_k256_secp256k1_compatibility() {
    // Verify this is using secp256k1 curve
    let mut rng = TestRng;
    let (pk, _) = EcdhK256::keypair(&mut rng).unwrap();

    // secp256k1 compressed points start with 0x02 or 0x03
    let bytes = pk.to_bytes();
    assert!(bytes[0] == 0x02 || bytes[0] == 0x03);
}

#[test]
fn test_k256_full_kem_with_serialization() {
    let mut rng = TestRng;

    // Generate and serialize
    let (pk, sk) = EcdhK256::keypair(&mut rng).unwrap();
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Restore and use
    let pk_restored = EcdhK256PublicKey::from_bytes(&pk_bytes).unwrap();
    let sk_restored = EcdhK256SecretKey::from_bytes(&sk_bytes).unwrap();

    // KEM operation
    let (ct, ss1) = EcdhK256::encapsulate(&mut rng, &pk_restored).unwrap();
    let ct_bytes = ct.to_bytes();
    let ct_restored = EcdhK256Ciphertext::from_bytes(&ct_bytes).unwrap();
    let ss2 = EcdhK256::decapsulate(&sk_restored, &ct_restored).unwrap();

    assert_eq!(ss1.to_bytes(), ss2.to_bytes());
    assert_eq!(ss1.to_bytes().len(), 32); // SHA-256 output
}
