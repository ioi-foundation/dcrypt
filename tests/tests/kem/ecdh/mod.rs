// File: tests/tests/src/kem/ecdh/mod.rs
use dcrypt_api::{Kem, Result as ApiResult};
use kem::ecdh::{
    EcdhP256, EcdhP256PublicKey, EcdhP256SecretKey, EcdhP256SharedSecret, EcdhP256Ciphertext,
    EcdhP384, EcdhP384PublicKey, EcdhP384SecretKey, EcdhP384SharedSecret, EcdhP384Ciphertext
};
use dcrypt_tests::test_rng::OsRng;

#[test]
fn test_p256_encapsulate_decapsulate_roundtrip() -> ApiResult<()> {
    // Generate recipient's keypair
    let (public_key, secret_key) = EcdhP256::keypair(&mut OsRng)?;
    
    // Encapsulate to generate a shared secret and ciphertext
    let (ciphertext, shared_secret1) = EcdhP256::encapsulate(&mut OsRng, &public_key)?;
    
    // Decapsulate to recover the shared secret
    let shared_secret2 = EcdhP256::decapsulate(&secret_key, &ciphertext)?;
    
    // The shared secrets should match
    assert_eq!(
        shared_secret1.as_ref(),
        shared_secret2.as_ref(),
        "Encapsulated and decapsulated secrets don't match"
    );
    
    Ok(())
}

#[test]
fn test_p384_encapsulate_decapsulate_roundtrip() -> ApiResult<()> {
    // Generate recipient's keypair
    let (public_key, secret_key) = EcdhP384::keypair(&mut OsRng)?;
    
    // Encapsulate to generate a shared secret and ciphertext
    let (ciphertext, shared_secret1) = EcdhP384::encapsulate(&mut OsRng, &public_key)?;
    
    // Decapsulate to recover the shared secret
    let shared_secret2 = EcdhP384::decapsulate(&secret_key, &ciphertext)?;
    
    // The shared secrets should match
    assert_eq!(
        shared_secret1.as_ref(),
        shared_secret2.as_ref(),
        "Encapsulated and decapsulated secrets don't match"
    );
    
    Ok(())
}

#[test]
fn test_p256_different_keypairs_produce_different_secrets() -> ApiResult<()> {
    // Generate two different recipient keypairs
    let (public_key1, secret_key1) = EcdhP256::keypair(&mut OsRng)?;
    let (public_key2, secret_key2) = EcdhP256::keypair(&mut OsRng)?;
    
    // Encapsulate to the first recipient
    let (ciphertext1, shared_secret1) = EcdhP256::encapsulate(&mut OsRng, &public_key1)?;
    
    // Encapsulate to the second recipient
    let (ciphertext2, shared_secret2) = EcdhP256::encapsulate(&mut OsRng, &public_key2)?;
    
    // The shared secrets should be different
    assert_ne!(
        shared_secret1.as_ref(),
        shared_secret2.as_ref(),
        "Shared secrets for different recipients should be different"
    );
    
    // The ciphertexts should be different
    assert_ne!(
        ciphertext1.as_ref(),
        ciphertext2.as_ref(),
        "Ciphertexts for different recipients should be different"
    );
    
    // Cross-decapsulation should fail or produce different secrets
    let crossed_secret1 = EcdhP256::decapsulate(&secret_key1, &ciphertext2);
    
    if let Ok(crossed_secret) = crossed_secret1 {
        assert_ne!(
            crossed_secret.as_ref(),
            shared_secret2.as_ref(),
            "Cross-decapsulation should produce different secret"
        );
    }
    
    Ok(())
}

#[test]
fn test_p256_same_public_key_different_encapsulations() -> ApiResult<()> {
    // Generate a recipient keypair
    let (public_key, secret_key) = EcdhP256::keypair(&mut OsRng)?;
    
    // Perform two different encapsulations to the same public key
    let (ciphertext1, shared_secret1) = EcdhP256::encapsulate(&mut OsRng, &public_key)?;
    let (ciphertext2, shared_secret2) = EcdhP256::encapsulate(&mut OsRng, &public_key)?;
    
    // The shared secrets should be different due to ephemeral key randomness
    assert_ne!(
        shared_secret1.as_ref(),
        shared_secret2.as_ref(),
        "Different encapsulations should produce different shared secrets"
    );
    
    // The ciphertexts should be different
    assert_ne!(
        ciphertext1.as_ref(),
        ciphertext2.as_ref(),
        "Different encapsulations should produce different ciphertexts"
    );
    
    // Both ciphertexts should decapsulate correctly
    let decapsulated1 = EcdhP256::decapsulate(&secret_key, &ciphertext1)?;
    let decapsulated2 = EcdhP256::decapsulate(&secret_key, &ciphertext2)?;
    
    assert_eq!(
        shared_secret1.as_ref(),
        decapsulated1.as_ref(),
        "First shared secret should match its decapsulation"
    );
    
    assert_eq!(
        shared_secret2.as_ref(),
        decapsulated2.as_ref(),
        "Second shared secret should match its decapsulation"
    );
    
    Ok(())
}

#[test]
fn test_p256_invalid_inputs() -> ApiResult<()> {
    // Test with invalid inputs to ensure proper error handling
    
    // Generate a keypair
    let (public_key, secret_key) = EcdhP256::keypair(&mut OsRng)?;
    
    // Create an invalid ciphertext (all zeros, representing the identity point)
    let invalid_ciphertext = EcdhP256Ciphertext([0; 65]);
    
    // Decapsulation should fail
    let result = EcdhP256::decapsulate(&secret_key, &invalid_ciphertext);
    assert!(result.is_err());
    
    // Create an invalid public key (all zeros)
    let invalid_public_key = EcdhP256PublicKey([0; 65]);
    
    // Encapsulation should fail
    let result = EcdhP256::encapsulate(&mut OsRng, &invalid_public_key);
    assert!(result.is_err());
    
    Ok(())
}

#[test]
fn test_known_answer_test_p256() -> ApiResult<()> {
    // This would be a known-answer test with specific inputs and outputs
    // For example, using test vectors from NIST or RFC 5903
    
    // For this example, we'll create our own "known answer" by running the
    // algorithm once and capturing the results for verification
    
    // In a real test, these would be hardcoded values from a standard:
    
    // 1. Create a fixed private key with a known value (for reproducibility)
    let private_key_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];
    
    // You would need to derive the actual keys and expected values based on standards
    // The test below is just a skeleton of what a known-answer test would look like
    
    // 2. Derive public key from private key (would be done with the algorithms module)
    // let public_key_bytes = [...]; // Derived from private_key_bytes and curve parameters
    
    // 3. Set up ephemeral key with fixed random (for reproducibility)
    // let ephemeral_bytes = [...];
    
    // 4. Expected shared x-coordinate and derived shared secret
    // let expected_shared_x = [...];
    // let expected_shared_secret = [...];
    
    // 5. Perform the operations with the fixed values and compare with expected results
    // This would use a special test implementation that allows fixed randomness
    
    Ok(())
}
