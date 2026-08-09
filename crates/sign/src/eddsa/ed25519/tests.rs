use super::*;
use dcrypt_internal::{ChaCha20Rng, RngCore};

fn test_rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x42; 32])
}

#[test]
fn test_ed25519_keypair_generation() {
    let mut rng = test_rng();
    let result = Ed25519::keypair(&mut rng);
    assert!(
        result.is_ok(),
        "Keypair generation failed: {:?}",
        result.err()
    );

    let (public_key, secret_key) = result.unwrap();
    assert_eq!(public_key.0.len(), ED25519_PUBLIC_KEY_SIZE);
    assert_eq!(secret_key.seed.len(), ED25519_SECRET_KEY_SIZE);
}

#[test]
fn test_ed25519_sign() {
    let mut rng = test_rng();
    let (_, secret_key) = Ed25519::keypair(&mut rng).unwrap();

    let message = b"Test message for signing";
    let result = Ed25519::sign(message, &secret_key);
    assert!(result.is_ok(), "Signing failed: {:?}", result.err());

    let signature = result.unwrap();
    assert_eq!(signature.0.len(), ED25519_SIGNATURE_SIZE);

    // Check that R and s are not all zeros
    let r = &signature.0[0..32];
    let s = &signature.0[32..64];
    assert!(!r.iter().all(|&b| b == 0), "R should not be all zeros");
    assert!(!s.iter().all(|&b| b == 0), "s should not be all zeros");
}

#[test]
fn test_ed25519_sign_verify_cycle() {
    let mut rng = test_rng();
    let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();

    let message = b"Complete test message for Ed25519 sign/verify cycle";

    // Sign the message
    let signature = Ed25519::sign(message, &secret_key).expect("Signing should succeed");

    // Verify the signature
    let result = Ed25519::verify(message, &signature, &public_key);
    assert!(result.is_ok(), "Verification failed: {:?}", result.err());
}

#[test]
fn test_ed25519_deterministic_signatures() {
    let mut rng = test_rng();
    let (_, secret_key) = Ed25519::keypair(&mut rng).unwrap();

    let message = b"Test for deterministic signatures";

    // Sign the same message twice
    let sig1 = Ed25519::sign(message, &secret_key).unwrap();
    let sig2 = Ed25519::sign(message, &secret_key).unwrap();

    // Signatures should be identical
    assert_eq!(sig1.0, sig2.0, "Ed25519 signatures must be deterministic");
}

#[test]
fn test_ed25519_different_messages_different_signatures() {
    let mut rng = test_rng();
    let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();

    let msg1 = b"First message";
    let msg2 = b"Second message";

    let sig1 = Ed25519::sign(msg1, &secret_key).unwrap();
    let sig2 = Ed25519::sign(msg2, &secret_key).unwrap();

    // Signatures should be different
    assert_ne!(
        sig1.0, sig2.0,
        "Different messages must produce different signatures"
    );

    // Both should verify correctly
    assert!(Ed25519::verify(msg1, &sig1, &public_key).is_ok());
    assert!(Ed25519::verify(msg2, &sig2, &public_key).is_ok());

    // Cross-verification should fail
    assert!(
        Ed25519::verify(msg1, &sig2, &public_key).is_err(),
        "Wrong signature should fail"
    );
    assert!(
        Ed25519::verify(msg2, &sig1, &public_key).is_err(),
        "Wrong signature should fail"
    );
}

#[test]
fn test_ed25519_wrong_public_key_fails() {
    let mut rng = test_rng();
    let (_, secret_key1) = Ed25519::keypair(&mut rng).unwrap();
    let (public_key2, _) = Ed25519::keypair(&mut rng).unwrap();

    let message = b"Test message";
    let signature = Ed25519::sign(message, &secret_key1).unwrap();

    // Verification with wrong public key should fail
    let result = Ed25519::verify(message, &signature, &public_key2);
    assert!(
        result.is_err(),
        "Verification with wrong public key should fail"
    );
}

#[test]
fn test_ed25519_empty_message() {
    let mut rng = test_rng();
    let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();

    let message = b"";
    let signature = Ed25519::sign(message, &secret_key).unwrap();

    assert!(
        Ed25519::verify(message, &signature, &public_key).is_ok(),
        "Empty message should sign and verify correctly"
    );
}

#[test]
fn test_ed25519_invalid_signatures() {
    let mut rng = test_rng();
    let (public_key, _) = Ed25519::keypair(&mut rng).unwrap();

    let message = b"Test message";

    // Test 1: All-zero signature
    let zero_sig = Ed25519Signature([0u8; ED25519_SIGNATURE_SIZE]);
    assert!(
        Ed25519::verify(message, &zero_sig, &public_key).is_err(),
        "All-zero signature should fail"
    );

    // Test 2: Random invalid signature
    let mut random_sig = Ed25519Signature([0u8; ED25519_SIGNATURE_SIZE]);
    rng.fill_bytes(&mut random_sig.0);
    assert!(
        Ed25519::verify(message, &random_sig, &public_key).is_err(),
        "Random signature should fail"
    );

    // Test 3: Malformed signature (wrong size would be caught by type system)
    // So we test a signature with invalid s value (all zeros in s part)
    let mut invalid_s_sig = Ed25519Signature([0u8; ED25519_SIGNATURE_SIZE]);
    rng.fill_bytes(&mut invalid_s_sig.0[0..32]); // Random R
                                                 // s part stays all zeros
    assert!(
        Ed25519::verify(message, &invalid_s_sig, &public_key).is_err(),
        "Signature with zero s should fail"
    );
}

#[test]
fn test_ed25519_signature_malleability_resistance() {
    let mut rng = test_rng();
    let (public_key, secret_key) = Ed25519::keypair(&mut rng).unwrap();

    let message = b"Test malleability";
    let signature = Ed25519::sign(message, &secret_key).unwrap();

    // Try to create a malleable signature by modifying s
    // (In a proper implementation, this should fail verification)
    let mut malleable_sig = signature.clone();
    malleable_sig.0[32] ^= 0x01; // Flip one bit in s

    assert!(
        Ed25519::verify(message, &malleable_sig, &public_key).is_err(),
        "Modified signature should fail verification"
    );
}

#[test]
fn test_derive_public_from_secret() {
    let mut rng = test_rng();
    let (original_public, secret) = Ed25519::keypair(&mut rng).unwrap();

    // Derive public key from secret
    let derived_public =
        Ed25519::derive_public_from_secret(&secret).expect("Failed to derive public key");

    // Should match the original
    assert_eq!(
        original_public.0, derived_public.0,
        "Derived public key doesn't match original"
    );
}

#[test]
fn test_secret_key_public_key_method() {
    let mut rng = test_rng();
    let (original_public, secret) = Ed25519::keypair(&mut rng).unwrap();

    // Use the convenience method on SecretKey
    let derived_public = secret.public_key().expect("Failed to get public key");

    assert_eq!(
        original_public.0, derived_public.0,
        "Public key from method doesn't match original"
    );
}

#[test]
fn test_derived_public_key_can_verify() {
    let mut rng = test_rng();
    let (_, secret) = Ed25519::keypair(&mut rng).unwrap();

    // Derive public key
    let public = secret.public_key().unwrap();

    // Sign a message
    let message = b"Test message for verification";
    let signature = Ed25519::sign(message, &secret).unwrap();

    // Verify with derived public key
    assert!(
        Ed25519::verify(message, &signature, &public).is_ok(),
        "Verification failed with derived public key"
    );
}

#[test]
fn test_multiple_derivations_are_identical() {
    let mut rng = test_rng();
    let (_, secret) = Ed25519::keypair(&mut rng).unwrap();

    // Derive multiple times
    let public1 = secret.public_key().unwrap();
    let public2 = secret.public_key().unwrap();
    let public3 = Ed25519::derive_public_from_secret(&secret).unwrap();

    // All should be identical
    assert_eq!(public1.0, public2.0);
    assert_eq!(public2.0, public3.0);
}

#[test]
fn test_key_serialization_round_trip() {
    let mut rng = test_rng();
    let (original_public, secret) = Ed25519::keypair(&mut rng).unwrap();

    // Simulate saving/loading just the secret key
    let secret_bytes = secret.seed;

    // Reconstruct secret key from seed
    let reconstructed_secret = Ed25519SecretKey::from_seed(&secret_bytes).unwrap();

    // Derive public key from reconstructed secret
    let derived_public = reconstructed_secret.public_key().unwrap();

    // Should match original
    assert_eq!(
        original_public.0, derived_public.0,
        "Public key doesn't match after round-trip"
    );
}

#[test]
fn test_from_seed_matches_keypair() {
    // Generate a keypair
    let mut rng = test_rng();
    let (public1, secret1) = Ed25519::keypair(&mut rng).unwrap();

    // Reconstruct secret key from seed
    let secret2 = Ed25519SecretKey::from_seed(secret1.seed()).unwrap();

    // Derive public key from reconstructed secret
    let public2 = secret2.public_key().unwrap();

    // Should match
    assert_eq!(public1.0, public2.0);
    assert_eq!(secret1.seed, secret2.seed);
}

#[test]
fn test_sign_with_from_seed() {
    let seed = [99u8; 32];
    let secret = Ed25519SecretKey::from_seed(&seed).unwrap();
    let public = secret.public_key().unwrap();

    let message = b"Message signed with reconstructed key";
    let signature = Ed25519::sign(message, &secret).unwrap();

    assert!(
        Ed25519::verify(message, &signature, &public).is_ok(),
        "Verification failed with key from seed"
    );
}

// Security-focused tests
#[test]
fn test_secret_key_immutability() {
    let mut rng = test_rng();
    let (_, secret) = Ed25519::keypair(&mut rng).unwrap();

    // Secret keys no longer implement AsRef/AsMut, so we can't test those
    // Instead, test that we can only access through explicit methods

    // Seed access is read-only through method
    let seed = secret.seed();
    assert_eq!(seed.len(), 32);

    // Can export seed securely
    let exported = secret.export_seed();
    assert_eq!(exported.len(), 32);
}

#[test]
fn test_zeroization_on_drop() {
    let mut rng = test_rng();

    // Create a secret key in a limited scope
    let seed_copy = {
        let (_, secret) = Ed25519::keypair(&mut rng).unwrap();
        let seed = *secret.seed();
        seed
        // secret is dropped and zeroized here
    };

    // We can't test the actual memory was cleared without raw-pointer access,
    // but we can verify the type implements Drop + Zeroize
    let _secret = Ed25519SecretKey::from_seed(&seed_copy).unwrap();

    assert!(core::mem::needs_drop::<Ed25519SecretKey>());
}

#[test]
fn test_seed_validation() {
    // Test that from_seed properly validates and processes seeds
    let mut rng = test_rng();
    let (public1, secret1) = Ed25519::keypair(&mut rng).unwrap();

    // Get the seed
    let seed = secret1.seed();

    // Reconstruct multiple times - should be deterministic
    let secret2 = Ed25519SecretKey::from_seed(seed).unwrap();
    let secret3 = Ed25519SecretKey::from_seed(seed).unwrap();

    let public2 = secret2.public_key().unwrap();
    let public3 = secret3.public_key().unwrap();

    // All public keys should match
    assert_eq!(public1.0, public2.0);
    assert_eq!(public2.0, public3.0);
}

#[test]
fn test_no_key_material_in_debug() {
    let mut rng = test_rng();
    let (public, _secret) = Ed25519::keypair(&mut rng).unwrap();

    // Debug output should not contain key material
    let public_debug = format!("{:?}", public);

    // Verify the debug output doesn't contain the actual key bytes
    assert!(public_debug.contains("Ed25519PublicKey"));
    assert!(!public_debug.contains(&format!("{:?}", public.0)));
}

#[test]
fn test_type_safety() {
    // Verify that key types cannot be confused
    fn requires_public_key(_key: &Ed25519PublicKey) {
        // This function only accepts public keys
    }

    fn requires_secret_key(_key: &Ed25519SecretKey) {
        // This function only accepts secret keys
    }

    let mut rng = test_rng();
    let (public, secret) = Ed25519::keypair(&mut rng).unwrap();

    // These should compile
    requires_public_key(&public);
    requires_secret_key(&secret);

    // These should NOT compile (uncomment to verify):
    // requires_public_key(&secret);  // Type error
    // requires_secret_key(&public);  // Type error
}

#[test]
fn test_secure_comparison() {
    let mut rng = test_rng();
    let (_, secret1) = Ed25519::keypair(&mut rng).unwrap();
    let (_, secret2) = Ed25519::keypair(&mut rng).unwrap();

    // Sign the same message with different keys
    let message = b"test message";
    let sig1 = Ed25519::sign(message, &secret1).unwrap();
    let sig2 = Ed25519::sign(message, &secret2).unwrap();

    // Signatures should be different
    assert_ne!(sig1.0, sig2.0);

    // The verification internally uses constant-time comparison
    // This is tested implicitly through the verify function
}

#[test]
fn example_secure_seed_handling() {
    use dcrypt_internal::Zeroize;

    // Generate a keypair
    let mut rng = test_rng();
    let (_public, secret) = Ed25519::keypair(&mut rng).unwrap();

    // Get seed for storage
    let mut seed_bytes = *secret.seed();

    // In production, you would:
    // 1. Encrypt seed_bytes with a password or key
    // 2. Store encrypted bytes
    // 3. Clear the plaintext seed
    seed_bytes.zeroize();

    // When loading:
    // 1. Load and decrypt the seed
    // 2. Create the secret key
    // 3. Clear the decrypted seed

    // For this test, we'll use a dummy seed
    let mut loaded_seed = [99u8; 32];
    let loaded_secret = Ed25519SecretKey::from_seed(&loaded_seed).unwrap();
    loaded_seed.zeroize(); // Always clear seeds after use

    // Use the loaded key
    let message = b"secure message";
    let signature = Ed25519::sign(message, &loaded_secret).unwrap();
    let loaded_public = loaded_secret.public_key().unwrap();
    assert!(Ed25519::verify(message, &signature, &loaded_public).is_ok());
}

// Test the new explicit serialization methods
#[test]
fn test_explicit_serialization() {
    let mut rng = test_rng();
    let (public, secret) = Ed25519::keypair(&mut rng).unwrap();

    // Test public key serialization
    let public_bytes = public.to_bytes();
    let public_restored = Ed25519PublicKey::from_bytes(&public_bytes).unwrap();
    assert_eq!(public.0, public_restored.0);

    // Test secret key seed export
    let seed = secret.export_seed();
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed);
    let secret_restored = Ed25519SecretKey::from_seed(&seed_array).unwrap();
    assert_eq!(secret.seed, secret_restored.seed);

    // Test signature serialization
    let message = b"test";
    let sig = Ed25519::sign(message, &secret).unwrap();
    let sig_bytes = sig.to_bytes();
    let sig_restored = Ed25519Signature::from_bytes(&sig_bytes).unwrap();
    assert_eq!(sig.0, sig_restored.0);
}

#[test]
fn test_invalid_sizes() {
    // Test invalid public key size
    let result = Ed25519PublicKey::from_bytes(&[0u8; 31]);
    assert!(result.is_err());

    // Test invalid signature size
    let result = Ed25519Signature::from_bytes(&[0u8; 63]);
    assert!(result.is_err());

    // Note: Invalid seed size is already enforced at compile time by the type system
    // since from_seed takes a fixed-size array &[u8; 32]
}

#[test]
fn rejects_identity_public_key_and_universal_forgery() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert!(Ed25519PublicKey::from_bytes(&identity).is_err());

    // Even a key assembled through the public tuple field is revalidated by
    // verify. R = B and S = 1 used to verify for every message when A = 0.
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    let mut forgery = [0u8; 64];
    forgery[..32].copy_from_slice(&basepoint);
    forgery[32] = 1;
    assert!(Ed25519::verify(
        b"arbitrary message",
        &Ed25519Signature(forgery),
        &Ed25519PublicKey(identity),
    )
    .is_err());
}

#[test]
fn strict_verification_rejects_small_order_r() {
    let mut rng = test_rng();
    let (public, _) = Ed25519::keypair(&mut rng).unwrap();
    let mut signature = [0u8; 64];
    signature[0] = 1; // compressed Edwards identity R
    signature[32] = 1;
    assert!(Ed25519::verify(b"message", &Ed25519Signature(signature), &public).is_err());
}

#[test]
fn strict_verification_rejects_s_plus_group_order() {
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut rng = test_rng();
    let (public, secret) = Ed25519::keypair(&mut rng).unwrap();
    let mut signature = Ed25519::sign(b"malleability", &secret).unwrap();
    let mut carry = 0u16;
    for (s, l) in signature.0[32..].iter_mut().zip(L) {
        let sum = *s as u16 + l as u16 + carry;
        *s = sum as u8;
        carry = sum >> 8;
    }
    assert!(Ed25519::verify(b"malleability", &signature, &public).is_err());
}

#[test]
fn rejects_noncanonical_public_key_encoding() {
    assert!(Ed25519PublicKey::from_bytes(&[0xff; 32]).is_err());
}

#[test]
fn rfc8032_test_vector_one() {
    let seed: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_public: [u8; 32] =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_signature: [u8; 64] = hex::decode(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ))
    .unwrap()
    .try_into()
    .unwrap();

    let secret = Ed25519SecretKey::from_seed(&seed).unwrap();
    let public = secret.public_key().unwrap();
    let signature = Ed25519::sign(b"", &secret).unwrap();
    assert_eq!(public.to_bytes(), expected_public);
    assert_eq!(signature.to_bytes(), expected_signature);
    assert!(Ed25519::verify(b"", &signature, &public).is_ok());
}

#[test]
fn rfc8032_test_vector_two() {
    let seed: [u8; 32] =
        hex::decode("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_public: [u8; 32] =
        hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_signature: [u8; 64] = hex::decode(concat!(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ))
    .unwrap()
    .try_into()
    .unwrap();

    let secret = Ed25519SecretKey::from_seed(&seed).unwrap();
    let public = secret.public_key().unwrap();
    let signature = Ed25519::sign(&[0x72], &secret).unwrap();
    assert_eq!(public.to_bytes(), expected_public);
    assert_eq!(signature.to_bytes(), expected_signature);
    assert!(Ed25519::verify(&[0x72], &signature, &public).is_ok());
}

#[test]
fn rfc8032_test_vector_three() {
    let seed: [u8; 32] =
        hex::decode("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_public: [u8; 32] =
        hex::decode("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_signature: [u8; 64] = hex::decode(concat!(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac",
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ))
    .unwrap()
    .try_into()
    .unwrap();

    let secret = Ed25519SecretKey::from_seed(&seed).unwrap();
    let public = secret.public_key().unwrap();
    let signature = Ed25519::sign(&[0xaf, 0x82], &secret).unwrap();
    assert_eq!(public.to_bytes(), expected_public);
    assert_eq!(signature.to_bytes(), expected_signature);
    assert!(Ed25519::verify(&[0xaf, 0x82], &signature, &public).is_ok());
}

#[test]
fn rejects_every_strict_encoding_boundary() {
    const P: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    assert!(Ed25519PublicKey::from_bytes(&P).is_err());

    let mut negative_zero = [0u8; 32];
    negative_zero[0] = 1;
    negative_zero[31] = 0x80;
    assert!(Ed25519PublicKey::from_bytes(&negative_zero).is_err());

    // y=0 encodes an order-four point.
    assert!(Ed25519PublicKey::from_bytes(&[0u8; 32]).is_err());

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&P);
    signature[32] = 1;
    assert!(Ed25519Signature::from_bytes(&signature).is_err());

    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    signature[..32].copy_from_slice(&basepoint);
    signature[32..].copy_from_slice(&L);
    assert!(Ed25519Signature::from_bytes(&signature).is_err());
}

#[test]
fn rejects_non_torsion_free_public_key_and_commitment() {
    let torsion = EdwardsPoint::decompress(&[0u8; 32]).unwrap();
    let mixed = EdwardsPoint::basepoint().add(&torsion).compress();
    assert!(Ed25519PublicKey::from_bytes(&mixed).is_err());

    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&mixed);
    signature[32] = 1;
    assert!(Ed25519Signature::from_bytes(&signature).is_err());

    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    assert!(Ed25519::verify(
        b"strict subgroup check",
        &Ed25519Signature(signature),
        &Ed25519PublicKey(basepoint),
    )
    .is_err());
}
