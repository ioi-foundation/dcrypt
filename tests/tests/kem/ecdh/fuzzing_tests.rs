// File: crates/tests/src/kem/ecdh_fuzzing.rs
use dcrypt_api::{Kem, Result as ApiResult};
use kem::ecdh::{EcdhP256, EcdhP384};
use dcrypt_internal::random::RngCore;
use dcrypt_tests::test_rng::OsRng;

#[test]
fn test_p256_multiple_encapsulations() -> ApiResult<()> {
    // Test with a large number of encapsulation/decapsulation cycles
    let iterations = 100; // Can be increased for more thorough testing
    
    for _ in 0..iterations {
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
    }
    
    Ok(())
}

#[test]
fn test_p256_multiple_recipients() -> ApiResult<()> {
    // Test with many recipients to ensure unique keys
    let num_recipients = 50; // Can be increased for more thorough testing
    
    // Generate keypairs for multiple recipients
    let mut keypairs = Vec::with_capacity(num_recipients);
    for _ in 0..num_recipients {
        keypairs.push(EcdhP256::keypair(&mut OsRng)?);
    }
    
    // Encapsulate to each recipient
    let mut ciphertexts = Vec::with_capacity(num_recipients);
    let mut shared_secrets = Vec::with_capacity(num_recipients);
    
    for (public_key, _) in &keypairs {
        let (ciphertext, shared_secret) = EcdhP256::encapsulate(&mut OsRng, public_key)?;
        ciphertexts.push(ciphertext);
        shared_secrets.push(shared_secret);
    }
    
    // Verify that all shared secrets are unique
    for i in 0..num_recipients {
        for j in i+1..num_recipients {
            assert_ne!(
                shared_secrets[i].as_ref(),
                shared_secrets[j].as_ref(),
                "Shared secrets {} and {} are identical", i, j
            );
        }
    }
    
    // Verify that each recipient can decrypt their own message
    for i in 0..num_recipients {
        let decapsulated = EcdhP256::decapsulate(&keypairs[i].1, &ciphertexts[i])?;
        
        assert_eq!(
            shared_secrets[i].as_ref(),
            decapsulated.as_ref(),
            "Decapsulation failed for recipient {}", i
        );
    }
    
    Ok(())
}

#[test]
fn test_p256_timing_consistency() -> ApiResult<()> {
    // This test is to ensure that the operations take consistent time
    // regardless of input (important for side-channel resistance)
    //
    // In practice, this is hard to test reliably in a unit test context
    // A proper timing analysis would require specialized tools
    
    // For this example, we'll just ensure that all operations complete
    // successfully with varied inputs
    
    // Generate different keypairs with different bit patterns
    let (pk1, sk1) = EcdhP256::keypair(&mut OsRng)?;
    
    // Create multiple encapsulations with different ephemeral keys
    let (ct1, ss1) = EcdhP256::encapsulate(&mut OsRng, &pk1)?;
    let (ct2, ss2) = EcdhP256::encapsulate(&mut OsRng, &pk1)?;
    
    // Decapsulate and verify all combinations work
    let ds1 = EcdhP256::decapsulate(&sk1, &ct1)?;
    let ds2 = EcdhP256::decapsulate(&sk1, &ct2)?;
    
    assert_eq!(ss1.as_ref(), ds1.as_ref());
    assert_eq!(ss2.as_ref(), ds2.as_ref());
    
    Ok(())
}

#[test]
fn test_shared_secret_entropy() -> ApiResult<()> {
    // Test that the shared secrets have good entropy
    // This is a basic test - ideally statistical tests would be used
    
    // Generate a keypair
    let (public_key, _) = EcdhP256::keypair(&mut OsRng)?;
    
    // Generate multiple shared secrets
    let num_samples = 20;
    let mut secrets = Vec::with_capacity(num_samples);
    
    for _ in 0..num_samples {
        let (_, shared_secret) = EcdhP256::encapsulate(&mut OsRng, &public_key)?;
        secrets.push(shared_secret);
    }
    
    // Check that all secrets are different
    for i in 0..num_samples {
        for j in i+1..num_samples {
            assert_ne!(
                secrets[i].as_ref(),
                secrets[j].as_ref(),
                "Shared secrets {} and {} are identical", i, j
            );
        }
    }
    
    // Simple entropy check (very basic)
    for secret in &secrets {
        let bytes = secret.as_ref();
        
        // Count number of zero bytes
        let zero_count = bytes.iter().filter(|&&b| b == 0).count();
        
        // In a 32-byte output, we shouldn't have too many zeros
        assert!(zero_count < 8, "Too many zero bytes in shared secret");
    }
    
    Ok(())
}
