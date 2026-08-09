use super::*;
use crate::block::aes::{Aes128, Aes192, Aes256};
use crate::block::CipherAlgorithm;
use crate::types::Nonce;
use crate::types::SecretBytes;
use hex;
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..") // up to crates/
        .join("..") // up to workspace root
        .join("tests")
        .join("src")
        .join("vectors")
        .join("legacy_rsp")
        .join("ctr")
}

#[test]
fn test_aes_ctr_nist_vectors() {
    let dir = vectors_dir();

    // Path to the test vector files
    let aes128_encrypt = dir.join("CTR-AES128-Encrypt.rsp");
    let aes128_decrypt = dir.join("CTR-AES128-Decrypt.rsp");
    let aes192_encrypt = dir.join("CTR-AES192-Encrypt.rsp");
    let aes192_decrypt = dir.join("CTR-AES192-Decrypt.rsp");
    let aes256_encrypt = dir.join("CTR-AES256-Encrypt.rsp");
    let aes256_decrypt = dir.join("CTR-AES256-Decrypt.rsp");

    // Check if files exist and provide helpful message if they don't
    for path in [
        &aes128_encrypt,
        &aes128_decrypt,
        &aes192_encrypt,
        &aes192_decrypt,
        &aes256_encrypt,
        &aes256_decrypt,
    ] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }

    // Run the tests
    run_aes128_ctr_tests(aes128_encrypt.to_str().unwrap(), "AES-128 Encrypt", true);
    run_aes128_ctr_tests(aes128_decrypt.to_str().unwrap(), "AES-128 Decrypt", false);
    run_aes192_ctr_tests(aes192_encrypt.to_str().unwrap(), "AES-192 Encrypt", true);
    run_aes192_ctr_tests(aes192_decrypt.to_str().unwrap(), "AES-192 Decrypt", false);
    run_aes256_ctr_tests(aes256_encrypt.to_str().unwrap(), "AES-256 Encrypt", true);
    run_aes256_ctr_tests(aes256_decrypt.to_str().unwrap(), "AES-256 Decrypt", false);
}

#[derive(Debug)]
struct AesCtrTestVector {
    count: usize,
    key: String,        // Hex-encoded key
    ctr: String,        // Hex-encoded initial counter
    plaintext: String,  // Hex-encoded plaintext
    ciphertext: String, // Hex-encoded ciphertext
}

fn parse_aes_ctr_test_file(filepath: &str) -> Vec<AesCtrTestVector> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut test_vectors = Vec::new();
    let mut current_vector: Option<AesCtrTestVector> = None;
    let mut _is_encrypt_mode = false;

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Detect test mode (encryption or decryption)
        if line == "[ENCRYPT]" {
            _is_encrypt_mode = true;
            continue;
        } else if line == "[DECRYPT]" {
            _is_encrypt_mode = false;
            continue;
        }

        if let Some(count_str) = line.strip_prefix("COUNT = ") {
            // Start of a new test case
            if let Some(vector) = current_vector.take() {
                test_vectors.push(vector);
            }

            // Extract count
            let count = count_str.parse::<usize>().unwrap();

            current_vector = Some(AesCtrTestVector {
                count,
                key: String::new(),
                ctr: String::new(),
                plaintext: String::new(),
                ciphertext: String::new(),
            });
        } else if let Some(ref mut vector) = current_vector {
            // Parse test vector data
            if let Some(key_str) = line.strip_prefix("KEY = ") {
                vector.key = key_str.to_string();
            } else if let Some(ctr_str) = line.strip_prefix("CTR = ") {
                vector.ctr = ctr_str.to_string();
            } else if let Some(plaintext_str) = line.strip_prefix("PLAINTEXT = ") {
                vector.plaintext = plaintext_str.to_string();
            } else if let Some(ciphertext_str) = line.strip_prefix("CIPHERTEXT = ") {
                vector.ciphertext = ciphertext_str.to_string();
            }
        }
    }

    // Add the last test vector if present
    if let Some(vector) = current_vector {
        test_vectors.push(vector);
    }

    test_vectors
}

// Process data using NIST CTR mode for AES-128
fn process_nist_ctr_aes128(cipher: &Aes128, ctr: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = Aes128::BLOCK_SIZE;
    let mut result = Vec::with_capacity(data.len());

    // Initialize counter block with the provided initial counter
    let mut counter_block = ctr.to_vec();
    assert_eq!(
        counter_block.len(),
        block_size,
        "Counter must be full block size"
    );

    // Process data in blocks
    for chunk in data.chunks(block_size) {
        // Create a new keystream block by encrypting the counter
        let mut keystream = counter_block.clone();
        cipher.encrypt_block(&mut keystream).unwrap();

        // XOR with plaintext/ciphertext
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }

        // Increment counter - This follows NIST SP 800-38A counter format
        // For test vectors, counter is incremented as a big-endian integer
        let len = counter_block.len();
        let mut i = len - 1;
        loop {
            counter_block[i] = counter_block[i].wrapping_add(1);
            if counter_block[i] != 0 || i == 0 {
                break;
            }
            i -= 1;
        }
    }

    result
}

// Process data using NIST CTR mode for AES-192
fn process_nist_ctr_aes192(cipher: &Aes192, ctr: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = Aes192::BLOCK_SIZE;
    let mut result = Vec::with_capacity(data.len());

    // Initialize counter block with the provided initial counter
    let mut counter_block = ctr.to_vec();
    assert_eq!(
        counter_block.len(),
        block_size,
        "Counter must be full block size"
    );

    // Process data in blocks
    for chunk in data.chunks(block_size) {
        // Create a new keystream block by encrypting the counter
        let mut keystream = counter_block.clone();
        cipher.encrypt_block(&mut keystream).unwrap();

        // XOR with plaintext/ciphertext
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }

        // Increment counter - This follows NIST SP 800-38A counter format
        let len = counter_block.len();
        let mut i = len - 1;
        loop {
            counter_block[i] = counter_block[i].wrapping_add(1);
            if counter_block[i] != 0 || i == 0 {
                break;
            }
            i -= 1;
        }
    }

    result
}

// Process data using NIST CTR mode for AES-256
fn process_nist_ctr_aes256(cipher: &Aes256, ctr: &[u8], data: &[u8]) -> Vec<u8> {
    let block_size = Aes256::BLOCK_SIZE;
    let mut result = Vec::with_capacity(data.len());

    // Initialize counter block with the provided initial counter
    let mut counter_block = ctr.to_vec();
    assert_eq!(
        counter_block.len(),
        block_size,
        "Counter must be full block size"
    );

    // Process data in blocks
    for chunk in data.chunks(block_size) {
        // Create a new keystream block by encrypting the counter
        let mut keystream = counter_block.clone();
        cipher.encrypt_block(&mut keystream).unwrap();

        // XOR with plaintext/ciphertext
        for (i, &byte) in chunk.iter().enumerate() {
            result.push(byte ^ keystream[i]);
        }

        // Increment counter - This follows NIST SP 800-38A counter format
        let len = counter_block.len();
        let mut i = len - 1;
        loop {
            counter_block[i] = counter_block[i].wrapping_add(1);
            if counter_block[i] != 0 || i == 0 {
                break;
            }
            i -= 1;
        }
    }

    result
}

// Test function for AES-128
fn run_aes128_ctr_tests(filepath: &str, name: &str, is_encrypt: bool) {
    let test_vectors = parse_aes_ctr_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Convert hex strings to bytes
        let key_bytes = hex::decode(&test.key).unwrap_or_else(|_| {
            panic!(
                "Invalid hex key in test vector {} (COUNT={}): {}",
                i, test.count, test.key
            )
        });

        let ctr = hex::decode(&test.ctr).unwrap_or_else(|_| {
            panic!(
                "Invalid hex CTR in test vector {} (COUNT={}): {}",
                i, test.count, test.ctr
            )
        });

        // Ensure key has the expected size for AES-128
        assert_eq!(
            key_bytes.len(),
            16,
            "Key size mismatch for {} test case {} (COUNT={}). Expected: 16, Got: {}",
            name,
            i,
            test.count,
            key_bytes.len()
        );

        // Create AES-128 cipher with SecretBytes wrapper
        let key = SecretBytes::<16>::new(key_bytes.try_into().unwrap());
        let cipher = Aes128::new(&key);

        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let result = process_nist_ctr_aes128(&cipher, &ctr, &plaintext);

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.plaintext,
                test.ciphertext,
                hex::encode(&result)
            );
        } else {
            // Test decryption (in CTR mode, decryption is the same as encryption)
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let result = process_nist_ctr_aes128(&cipher, &ctr, &ciphertext);

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.ciphertext,
                test.plaintext,
                hex::encode(&result)
            );
        }
    }
}

// Test function for AES-192
fn run_aes192_ctr_tests(filepath: &str, name: &str, is_encrypt: bool) {
    let test_vectors = parse_aes_ctr_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Convert hex strings to bytes
        let key_bytes = hex::decode(&test.key).unwrap_or_else(|_| {
            panic!(
                "Invalid hex key in test vector {} (COUNT={}): {}",
                i, test.count, test.key
            )
        });

        let ctr = hex::decode(&test.ctr).unwrap_or_else(|_| {
            panic!(
                "Invalid hex CTR in test vector {} (COUNT={}): {}",
                i, test.count, test.ctr
            )
        });

        // Ensure key has the expected size for AES-192
        assert_eq!(
            key_bytes.len(),
            24,
            "Key size mismatch for {} test case {} (COUNT={}). Expected: 24, Got: {}",
            name,
            i,
            test.count,
            key_bytes.len()
        );

        // Create AES-192 cipher with SecretBytes wrapper
        let key = SecretBytes::<24>::new(key_bytes.try_into().unwrap());
        let cipher = Aes192::new(&key);

        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let result = process_nist_ctr_aes192(&cipher, &ctr, &plaintext);

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.plaintext,
                test.ciphertext,
                hex::encode(&result)
            );
        } else {
            // Test decryption (in CTR mode, decryption is the same as encryption)
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let result = process_nist_ctr_aes192(&cipher, &ctr, &ciphertext);

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.ciphertext,
                test.plaintext,
                hex::encode(&result)
            );
        }
    }
}

// Test function for AES-256
fn run_aes256_ctr_tests(filepath: &str, name: &str, is_encrypt: bool) {
    let test_vectors = parse_aes_ctr_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Convert hex strings to bytes
        let key_bytes = hex::decode(&test.key).unwrap_or_else(|_| {
            panic!(
                "Invalid hex key in test vector {} (COUNT={}): {}",
                i, test.count, test.key
            )
        });

        let ctr = hex::decode(&test.ctr).unwrap_or_else(|_| {
            panic!(
                "Invalid hex CTR in test vector {} (COUNT={}): {}",
                i, test.count, test.ctr
            )
        });

        // Ensure key has the expected size for AES-256
        assert_eq!(
            key_bytes.len(),
            32,
            "Key size mismatch for {} test case {} (COUNT={}). Expected: 32, Got: {}",
            name,
            i,
            test.count,
            key_bytes.len()
        );

        // Create AES-256 cipher with SecretBytes wrapper
        let key = SecretBytes::<32>::new(key_bytes.try_into().unwrap());
        let cipher = Aes256::new(&key);

        if is_encrypt {
            // Test encryption
            let plaintext = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let expected = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let result = process_nist_ctr_aes256(&cipher, &ctr, &plaintext);

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.plaintext,
                test.ciphertext,
                hex::encode(&result)
            );
        } else {
            // Test decryption (in CTR mode, decryption is the same as encryption)
            let ciphertext = hex::decode(&test.ciphertext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex ciphertext in test vector {} (COUNT={}): {}",
                    i, test.count, test.ciphertext
                )
            });

            let expected = hex::decode(&test.plaintext).unwrap_or_else(|_| {
                panic!(
                    "Invalid hex plaintext in test vector {} (COUNT={}): {}",
                    i, test.count, test.plaintext
                )
            });

            let result = process_nist_ctr_aes256(&cipher, &ctr, &ciphertext);

            assert_eq!(
                result,
                expected,
                "{} test case {} (COUNT={}) failed.\nInput: {}\nExpected: {}\nGot: {}",
                name,
                i,
                test.count,
                test.ciphertext,
                test.plaintext,
                hex::encode(&result)
            );
        }
    }
}

#[test]
fn test_aes_ctr() {
    // NIST SP 800-38A F.5.1 test vector
    // Key: 2b7e151628aed2a6abf7158809cf4f3c
    // Initial Counter Block: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
    // Plaintext: 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710
    // Ciphertext: 874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee

    let key_bytes = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
    let key = SecretBytes::<16>::new(key_bytes.try_into().unwrap());
    let plaintext = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
    let expected_ciphertext = hex::decode("874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee").unwrap();

    // Create a complete implementation that exactly matches the NIST spec
    // The key part here is using the EXACT initial counter block from the spec
    let nist_counter_block = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();

    // Direct implementation for the specific NIST test vector
    let cipher = Aes128::new(&key);

    // Use this function to get precise control over the counter block
    fn nist_ctr_encrypt(cipher: &Aes128, counter_block: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter = counter_block.to_vec();
        let mut bytes_processed = 0;

        while bytes_processed < plaintext.len() {
            // Encrypt counter block to produce keystream
            let mut keystream = counter.clone();
            cipher.encrypt_block(&mut keystream).unwrap();

            // XOR plaintext with keystream
            let remaining = plaintext.len() - bytes_processed;
            let to_process = std::cmp::min(16, remaining);

            for i in 0..to_process {
                ciphertext.push(plaintext[bytes_processed + i] ^ keystream[i]);
            }

            // Increment counter (big-endian, rightmost 4 bytes)
            let mut ctr_value = u32::from_be_bytes(counter[12..16].try_into().unwrap());
            ctr_value = ctr_value.wrapping_add(1);
            counter[12..16].copy_from_slice(&ctr_value.to_be_bytes());

            bytes_processed += to_process;
        }

        ciphertext
    }

    // Using the exact NIST test vector details
    let ciphertext = nist_ctr_encrypt(&cipher, &nist_counter_block, &plaintext);
    assert_eq!(
        ciphertext, expected_ciphertext,
        "NIST direct implementation failed"
    );

    // Now test our Ctr implementation by manually setting up the counter block
    let cipher = Aes128::new(&key);

    // For our implementation, we need to set up the counter block to match the NIST spec exactly
    // The NIST counter block is: f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

    // Use just the first 12 bytes as the nonce
    let nonce_bytes = &nist_counter_block[0..12];

    // Convert to Nonce<12>
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(nonce_bytes);
    let nonce = Nonce::<12>::new(nonce_array);

    let mut ctr = Ctr::with_counter_params(cipher, &nonce, CounterPosition::Postfix, 4).unwrap();

    // Now manually set the last 4 bytes to match the NIST counter
    ctr.counter_block[12] = nist_counter_block[12]; // fc
    ctr.counter_block[13] = nist_counter_block[13]; // fd
    ctr.counter_block[14] = nist_counter_block[14]; // fe
    ctr.counter_block[15] = nist_counter_block[15]; // ff

    let ciphertext = ctr.encrypt(&plaintext).unwrap();
    assert_eq!(
        ciphertext, expected_ciphertext,
        "Ctr implementation with manual setup failed"
    );

    // Test decryption
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce, CounterPosition::Postfix, 4).unwrap();
    ctr.counter_block[12] = nist_counter_block[12];
    ctr.counter_block[13] = nist_counter_block[13];
    ctr.counter_block[14] = nist_counter_block[14];
    ctr.counter_block[15] = nist_counter_block[15];

    let decrypted = ctr.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, plaintext, "Decryption failed");
}

#[test]
fn test_ctr_with_custom_params() {
    let key_data = [0x42; 16]; // 16-byte key for AES-128
    let key = SecretBytes::<16>::new(key_data);

    // Create 8-byte nonce using Nonce<8>
    let nonce_array = [0x24; 8]; // 8-byte nonce
    let nonce = Nonce::<8>::new(nonce_array);

    // Test with 8-byte counter at beginning
    let plaintext = vec![0xAA; 32];

    // Counter at the beginning (8 bytes)
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce, CounterPosition::Prefix, 8).unwrap();

    let ciphertext = ctr.encrypt(&plaintext).unwrap();

    // Decrypt with same parameters
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce, CounterPosition::Prefix, 8).unwrap();
    let decrypted = ctr.decrypt(&ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);

    // Test with custom counter position
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce, CounterPosition::Custom(4), 4).unwrap();

    let ciphertext = ctr.encrypt(&plaintext).unwrap();

    // Decrypt with same parameters
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce, CounterPosition::Custom(4), 4).unwrap();
    let decrypted = ctr.decrypt(&ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_ctr_counter_overflow() {
    let key_data = [0x42; 16]; // 16-byte key for AES-128
    let key = SecretBytes::<16>::new(key_data);

    // Create 12-byte nonce using Nonce<12>
    let nonce_array = [0x24; 12]; // 12-byte nonce
    let nonce = Nonce::<12>::new(nonce_array);

    // Test with a small 1-byte counter to ensure overflow works correctly
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce, CounterPosition::Postfix, 1).unwrap();

    // Set counter to 255 (max for 1 byte)
    ctr.set_counter(255);

    // Generate enough keystream to force counter overflow
    let large_plaintext = vec![0xAA; 300];
    let ciphertext = ctr.encrypt(&large_plaintext).unwrap();

    // Decrypt with same parameters
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce, CounterPosition::Postfix, 1).unwrap();
    ctr.set_counter(255);

    let decrypted = ctr.decrypt(&ciphertext).unwrap();
    assert_eq!(decrypted, large_plaintext);
}

#[test]
fn test_ctr_long_message() {
    let key_data = [0x42; 16]; // 16-byte key for AES-128
    let key = SecretBytes::<16>::new(key_data);

    // Create 12-byte nonce using Nonce<12>
    let nonce_array = [0x24; 12]; // 12-byte nonce
    let nonce = Nonce::<12>::new(nonce_array);

    // Generate a longer message (multiple blocks)
    let plaintext = vec![0xAA; 1000];

    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::new(cipher, &nonce).unwrap();

    let ciphertext = ctr.encrypt(&plaintext).unwrap();

    // Ensure the ciphertext is the same length as the plaintext
    assert_eq!(ciphertext.len(), plaintext.len());

    // Ensure the ciphertext is different from plaintext
    assert_ne!(ciphertext, plaintext);

    // Decrypt and verify
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::new(cipher, &nonce).unwrap();
    let decrypted = ctr.decrypt(&ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_different_counter_sizes() {
    // Test with different counter sizes (1-byte, 2-byte, 8-byte)
    let key_data = [0x42; 16]; // 16-byte key for AES-128
    let key = SecretBytes::<16>::new(key_data);
    let plaintext = vec![0xAA; 64];

    // Create properly sized nonce for each test case

    // 1-byte counter - needs 11-byte nonce (since 11+1=12 for nonce+counter)
    let nonce_array1 = [0x24; 11];
    let nonce1 = Nonce::<11>::new(nonce_array1);

    // 2-byte counter - needs 10-byte nonce
    let nonce_array2 = [0x24; 10];
    let nonce2 = Nonce::<10>::new(nonce_array2);

    // 8-byte counter - needs 8-byte nonce
    let nonce_array3 = [0x24; 8];
    let nonce3 = Nonce::<8>::new(nonce_array3);

    // 1-byte counter
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce1, CounterPosition::Postfix, 1).unwrap();
    let ciphertext1 = ctr.encrypt(&plaintext).unwrap();

    // 2-byte counter
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce2, CounterPosition::Postfix, 2).unwrap();
    let ciphertext2 = ctr.encrypt(&plaintext).unwrap();

    // 8-byte counter
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce3, CounterPosition::Postfix, 8).unwrap();
    let ciphertext3 = ctr.encrypt(&plaintext).unwrap();

    // Verify different counter sizes produce different ciphertexts
    assert_ne!(ciphertext1, ciphertext2);
    assert_ne!(ciphertext2, ciphertext3);
    assert_ne!(ciphertext1, ciphertext3);

    // Verify decryption works for each
    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce1, CounterPosition::Postfix, 1).unwrap();
    let decrypted = ctr.decrypt(&ciphertext1).unwrap();
    assert_eq!(decrypted, plaintext);

    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce2, CounterPosition::Postfix, 2).unwrap();
    let decrypted = ctr.decrypt(&ciphertext2).unwrap();
    assert_eq!(decrypted, plaintext);

    let cipher = Aes128::new(&key);
    let mut ctr = Ctr::with_counter_params(cipher, &nonce3, CounterPosition::Postfix, 8).unwrap();
    let decrypted = ctr.decrypt(&ciphertext3).unwrap();
    assert_eq!(decrypted, plaintext);
}
