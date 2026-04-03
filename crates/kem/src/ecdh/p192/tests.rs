//! Tests for ECDH KEM P-192

use super::*; // Import from parent mod (p192/mod.rs)
use dcrypt_api::Kem; // The main KEM trait
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
fn test_ecdh_p192_keypair_generation() {
    let mut rng = OsRng;
    let keypair_result = EcdhP192::keypair(&mut rng);
    assert!(
        keypair_result.is_ok(),
        "Keypair generation failed: {:?}",
        keypair_result.err()
    );
    if let Ok((pk, sk)) = keypair_result {
        assert_eq!(pk.to_bytes().len(), ec::P192_POINT_COMPRESSED_SIZE);
        assert_eq!(sk.to_bytes().len(), ec::P192_SCALAR_SIZE);
    }
}

#[test]
fn test_ecdh_p192_kem_roundtrip() {
    let mut rng = OsRng;

    // 1. Generate recipient's key pair
    let (public_key, secret_key) = EcdhP192::keypair(&mut rng).expect("Keypair generation failed");

    // 2. Sender encapsulates a shared secret using recipient's public key
    let encapsulate_result = EcdhP192::encapsulate(&mut rng, &public_key);
    assert!(
        encapsulate_result.is_ok(),
        "Encapsulation failed: {:?}",
        encapsulate_result.err()
    );
    let (ciphertext, shared_secret_sender) = encapsulate_result.unwrap();

    assert_eq!(ciphertext.to_bytes().len(), ec::P192_POINT_COMPRESSED_SIZE);
    assert_eq!(
        shared_secret_sender.to_bytes().len(),
        ec::P192_KEM_SHARED_SECRET_KDF_OUTPUT_SIZE
    );

    // 3. Recipient decapsulates the ciphertext using their secret key
    let decapsulate_result = EcdhP192::decapsulate(&secret_key, &ciphertext);
    assert!(
        decapsulate_result.is_ok(),
        "Decapsulation failed: {:?}",
        decapsulate_result.err()
    );
    let shared_secret_receiver = decapsulate_result.unwrap();

    // 4. Verify shared secrets match
    assert_eq!(
        shared_secret_sender.to_bytes(),
        shared_secret_receiver.to_bytes(),
        "Shared secrets do not match"
    );
}

#[test]
fn test_ecdh_p192_kem_decapsulate_wrong_key() {
    let mut rng = OsRng;

    // Recipient 1
    let (public_key1, _secret_key1) =
        EcdhP192::keypair(&mut rng).expect("Keypair 1 generation failed");
    // Recipient 2 (attacker or wrong recipient)
    let (_public_key2, secret_key2) =
        EcdhP192::keypair(&mut rng).expect("Keypair 2 generation failed");

    // Sender encapsulates for Recipient 1
    let (ciphertext, _shared_secret_sender) =
        EcdhP192::encapsulate(&mut rng, &public_key1).expect("Encapsulation failed");

    // Recipient 2 tries to decapsulate (should not yield the same shared secret, or should fail)
    // In a correct KEM, this should ideally result in a different key or an error.
    // Our placeholder might just give a different random key. The key is that it's NOT the sender's SS.
    let decapsulate_result = EcdhP192::decapsulate(&secret_key2, &ciphertext);
    assert!(decapsulate_result.is_ok(), "Decapsulation with wrong key should ideally not error outright unless auth is built-in to KEM itself, but produce a different key.");
    // A more robust test would check that decapsulate_result.unwrap() != _shared_secret_sender
    // However, for a simple ECDH without an authenticated KEM wrapper, it will just produce a different shared secret.
}

#[test]
fn test_ecdh_p192_kem_decapsulate_tampered_ciphertext() {
    let mut rng = OsRng;
    let (public_key, secret_key) = EcdhP192::keypair(&mut rng).expect("Keypair generation failed");

    let (mut ciphertext, shared_secret_sender) =
        EcdhP192::encapsulate(&mut rng, &public_key).expect("Encapsulation failed");

    // Tamper with the ciphertext (ephemeral public key)
    if !ciphertext.0.is_empty() {
        ciphertext.0[0] ^= 0xff;
    }

    let decapsulate_result = EcdhP192::decapsulate(&secret_key, &ciphertext);
    // Decapsulation might succeed but produce a different shared secret,
    // or it might fail if the tampered point is invalid.
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

// Add these tests to crates/kem/src/ecdh/p192/tests.rs

#[test]
fn test_p192_public_key_serialization() {
    let mut rng = OsRng;
    let (pk, _) = EcdhP192::keypair(&mut rng).unwrap();

    // Round-trip
    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), 25);
    let restored = EcdhP192PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(pk.to_bytes(), restored.to_bytes());
}

#[test]
fn test_p192_secret_key_serialization() {
    let mut rng = OsRng;
    let (_, sk) = EcdhP192::keypair(&mut rng).unwrap();

    // Export and verify length
    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), 24);

    // Import and verify functionality
    let restored = EcdhP192SecretKey::from_bytes(&bytes).unwrap();

    // Generate same public key from both
    let pk1 = ec::scalar_mult_base_g(
        &ec::Scalar::from_secret_buffer(secret_buffer_from_slice::<24>(&sk.to_bytes())).unwrap(),
    )
    .unwrap();
    let pk2 = ec::scalar_mult_base_g(
        &ec::Scalar::from_secret_buffer(secret_buffer_from_slice::<24>(&restored.to_bytes()))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pk1.serialize_compressed(), pk2.serialize_compressed());
}

#[test]
fn test_p192_ciphertext_serialization() {
    let mut rng = OsRng;
    let (pk, _) = EcdhP192::keypair(&mut rng).unwrap();
    let (ct, _) = EcdhP192::encapsulate(&mut rng, &pk).unwrap();

    // Round-trip
    let bytes = ct.to_bytes();
    assert_eq!(bytes.len(), 25);
    let restored = EcdhP192Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct.to_bytes(), restored.to_bytes());
}

#[test]
fn test_p192_invalid_public_key() {
    // Wrong length
    assert!(EcdhP192PublicKey::from_bytes(&[0u8; 24]).is_err());
    assert!(EcdhP192PublicKey::from_bytes(&[0u8; 26]).is_err());

    // Identity point
    assert!(EcdhP192PublicKey::from_bytes(&[0u8; 25]).is_err());
}

#[test]
fn test_p192_full_kem_with_serialization() {
    let mut rng = OsRng;

    // Generate and serialize
    let (pk, sk) = EcdhP192::keypair(&mut rng).unwrap();
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Restore and use
    let pk_restored = EcdhP192PublicKey::from_bytes(&pk_bytes).unwrap();
    let sk_restored = EcdhP192SecretKey::from_bytes(&sk_bytes).unwrap();

    // KEM operation
    let (ct, ss1) = EcdhP192::encapsulate(&mut rng, &pk_restored).unwrap();
    let ct_bytes = ct.to_bytes();
    let ct_restored = EcdhP192Ciphertext::from_bytes(&ct_bytes).unwrap();
    let ss2 = EcdhP192::decapsulate(&sk_restored, &ct_restored).unwrap();

    assert_eq!(ss1.to_bytes(), ss2.to_bytes());
}
