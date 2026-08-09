// Test importing and accessing various constants

// Traditional cryptography constants
use dcrypt_params::traditional::ecdsa::NIST_P256;
use dcrypt_params::traditional::ed25519::{
    ED25519_PUBLIC_KEY_SIZE, ED25519_SECRET_KEY_SIZE, ED25519_SIGNATURE_SIZE,
};

// Post-quantum cryptography constants
use dcrypt_params::pqc::ml_dsa::{ML_DSA_65, ML_DSA_N, ML_DSA_Q};
use dcrypt_params::pqc::ml_kem::{ML_KEM_768, ML_KEM_N, ML_KEM_Q};

// Utility constants
use dcrypt_params::utils::hash::SHA256_OUTPUT_SIZE;
use dcrypt_params::utils::symmetric::{AES256_KEY_SIZE, CHACHA20_KEY_SIZE};

#[test]
fn test_ed25519_constants() {
    assert_eq!(ED25519_PUBLIC_KEY_SIZE, 32);
    assert_eq!(ED25519_SECRET_KEY_SIZE, 32);
    assert_eq!(ED25519_SIGNATURE_SIZE, 64);
}

#[test]
fn test_ecdsa_constants() {
    assert_eq!(NIST_P256.h, 1); // Cofactor
    assert_eq!(NIST_P256.p[0], 0xFF); // First byte of prime
}

#[test]
fn test_ml_kem_constants() {
    assert_eq!(ML_KEM_N, 256);
    assert_eq!(ML_KEM_Q, 3329);
    assert_eq!(ML_KEM_768.k, 3);
    assert_eq!(ML_KEM_768.shared_secret_size, 32);
}

#[test]
fn test_ml_dsa_constants() {
    assert_eq!(ML_DSA_N, 256);
    assert_eq!(ML_DSA_Q, 8380417);
    assert_eq!(ML_DSA_65.k, 6);
    assert_eq!(ML_DSA_65.l, 5);
}

#[test]
fn test_utility_constants() {
    assert_eq!(SHA256_OUTPUT_SIZE, 32);
    assert_eq!(AES256_KEY_SIZE, 32);
    assert_eq!(CHACHA20_KEY_SIZE, 32);
}
