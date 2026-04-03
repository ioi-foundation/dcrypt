// File: crates/kem/src/ecdh/b283k/tests.rs
use super::*;
use dcrypt_algorithms::ec::b283k as ec_b283k;
use dcrypt_api::Kem;
use rand::rngs::OsRng;

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
fn test_b283k_kem_basic_flow() {
    let mut rng = OsRng;

    // Generate recipient keypair
    let (recipient_pk, recipient_sk) = EcdhB283k::keypair(&mut rng).unwrap();

    // Encapsulate
    let (ciphertext, shared_secret_sender) =
        EcdhB283k::encapsulate(&mut rng, &recipient_pk).unwrap();

    // Decapsulate
    let shared_secret_recipient = EcdhB283k::decapsulate(&recipient_sk, &ciphertext).unwrap();

    // Verify shared secrets match
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_recipient.to_bytes(),
        "Shared secrets should match"
    );

    // Verify key and ciphertext sizes
    assert_eq!(
        recipient_pk.to_bytes().len(),
        ec_b283k::B283K_POINT_COMPRESSED_SIZE
    );
    assert_eq!(recipient_sk.to_bytes().len(), ec_b283k::B283K_SCALAR_SIZE);
    assert_eq!(
        ciphertext.to_bytes().len(),
        ec_b283k::B283K_POINT_COMPRESSED_SIZE
    );
    assert_eq!(
        shared_secret_sender.to_bytes().len(),
        ec_b283k::B283K_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE
    );
}

#[test]
fn test_b283k_kem_wrong_secret_key() {
    let mut rng = OsRng;

    // Generate two keypairs
    let (recipient_pk, _) = EcdhB283k::keypair(&mut rng).unwrap();
    let (_, wrong_sk) = EcdhB283k::keypair(&mut rng).unwrap();

    // Encapsulate to first recipient
    let (ciphertext, shared_secret_sender) =
        EcdhB283k::encapsulate(&mut rng, &recipient_pk).unwrap();

    // Try to decapsulate with wrong secret key
    let shared_secret_wrong = EcdhB283k::decapsulate(&wrong_sk, &ciphertext).unwrap();

    // Shared secrets should NOT match
    assert_ne!(
        shared_secret_sender.to_bytes(),
        shared_secret_wrong.to_bytes(),
        "Shared secrets should not match with wrong key"
    );
}

#[test]
fn test_b283k_kem_invalid_public_key() {
    let mut rng = OsRng;

    // Test with all-zero public key (invalid identity point encoding)
    let invalid_pk = EcdhB283kPublicKey([0u8; ec_b283k::B283K_POINT_COMPRESSED_SIZE]);

    // Encapsulation should fail
    let result = EcdhB283k::encapsulate(&mut rng, &invalid_pk);
    assert!(result.is_err());
}

#[test]
fn test_b283k_kem_tampered_ciphertext() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdhB283k::keypair(&mut rng).expect("Keypair generation failed");
    let (mut ciphertext, shared_secret_sender) =
        EcdhB283k::encapsulate(&mut rng, &public_key).expect("Encapsulation failed");

    // Tamper with the ciphertext
    ciphertext.0[5] ^= 0xff;

    let decapsulate_result = EcdhB283k::decapsulate(&secret_key, &ciphertext);

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

// Add these tests to crates/kem/src/ecdh/b283k/tests.rs

#[test]
fn test_b283k_public_key_serialization() {
    let mut rng = OsRng;
    let (pk, _) = EcdhB283k::keypair(&mut rng).unwrap();

    // Round-trip
    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), 37);
    let restored = EcdhB283kPublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(pk.to_bytes(), restored.to_bytes());
}

#[test]
fn test_b283k_secret_key_serialization() {
    let mut rng = OsRng;
    let (_, sk) = EcdhB283k::keypair(&mut rng).unwrap();

    // Export and verify length
    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 36);

    // Import and verify functionality
    let restored = EcdhB283kSecretKey::from_bytes(&bytes).unwrap();

    // Generate same public key from both
    let pk1 = ec_b283k::scalar_mult_base_g(
        &ec_b283k::Scalar::from_secret_buffer(secret_buffer_from_slice::<36>(&sk.to_bytes()))
            .unwrap(),
    )
    .unwrap();
    let pk2 = ec_b283k::scalar_mult_base_g(
        &ec_b283k::Scalar::from_secret_buffer(secret_buffer_from_slice::<36>(&restored.to_bytes()))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pk1.serialize_compressed(), pk2.serialize_compressed());
}

#[test]
fn test_b283k_ciphertext_serialization() {
    let mut rng = OsRng;
    let (pk, _) = EcdhB283k::keypair(&mut rng).unwrap();
    let (ct, _) = EcdhB283k::encapsulate(&mut rng, &pk).unwrap();

    // Round-trip
    let bytes = ct.to_bytes();
    assert_eq!(bytes.len(), 37);
    let restored = EcdhB283kCiphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct.to_bytes(), restored.to_bytes());
}

#[test]
fn test_b283k_shared_secret_size() {
    let mut rng = OsRng;
    let (pk, sk) = EcdhB283k::keypair(&mut rng).unwrap();
    let (ct, ss) = EcdhB283k::encapsulate(&mut rng, &pk).unwrap();

    // B-283k uses SHA-384, so 48-byte shared secrets
    assert_eq!(ss.to_bytes().len(), 48);

    let ss_dec = EcdhB283k::decapsulate(&sk, &ct).unwrap();
    assert_eq!(ss_dec.to_bytes().len(), 48);
}

#[test]
fn test_b283k_invalid_public_key() {
    // Wrong length
    assert!(EcdhB283kPublicKey::from_bytes(&[0u8; 36]).is_err());
    assert!(EcdhB283kPublicKey::from_bytes(&[0u8; 38]).is_err());

    // Identity point
    assert!(EcdhB283kPublicKey::from_bytes(&[0u8; 37]).is_err());
}

#[test]
fn test_b283k_binary_curve_properties() {
    // Binary curves have different properties than prime curves
    let mut rng = OsRng;
    let (pk, _) = EcdhB283k::keypair(&mut rng).unwrap();

    // Binary curve compressed points can start with 0x02 or 0x03
    let bytes = pk.to_bytes();
    assert!(bytes[0] == 0x02 || bytes[0] == 0x03);

    // Field element size is 36 bytes for B-283k
    assert_eq!(ec_b283k::B283K_FIELD_ELEMENT_SIZE, 36);
}

#[test]
fn test_b283k_full_kem_with_serialization() {
    let mut rng = OsRng;

    // Generate and serialize
    let (pk, sk) = EcdhB283k::keypair(&mut rng).unwrap();
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Restore and use
    let pk_restored = EcdhB283kPublicKey::from_bytes(&pk_bytes).unwrap();
    let sk_restored = EcdhB283kSecretKey::from_bytes(&sk_bytes).unwrap();

    // KEM operation
    let (ct, ss1) = EcdhB283k::encapsulate(&mut rng, &pk_restored).unwrap();
    let ct_bytes = ct.to_bytes();
    let ct_restored = EcdhB283kCiphertext::from_bytes(&ct_bytes).unwrap();
    let ss2 = EcdhB283k::decapsulate(&sk_restored, &ct_restored).unwrap();

    assert_eq!(ss1.to_bytes(), ss2.to_bytes());
    assert_eq!(ss1.to_bytes().len(), 48); // SHA-384 output
}
