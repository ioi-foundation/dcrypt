use super::*;
use crate::block::aes::{Aes128, Aes192, Aes256};
use crate::types::Nonce;
use crate::types::SecretBytes;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, ZeroizeOnDrop};

use dcrypt_api::traits::symmetric::{DecryptOperation, EncryptOperation};
use dcrypt_api::traits::SymmetricCipher as ApiSymmetricCipher;

#[test]
fn test_aes_gcm() {
    // Basic sanity vector (128-bit key, 96-bit nonce, full tag)
    let key_bytes = hex::decode("feffe9928665731c6d6a8f9467308308").unwrap();
    let key = SecretBytes::<16>::from_slice(&key_bytes).expect("Invalid key length");

    // Convert the nonce vector to a Nonce<12> type
    let nonce_bytes = hex::decode("cafebabefacedbaddecaf888").unwrap();
    let nonce = Nonce::<12>::from_slice(&nonce_bytes).unwrap();

    let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
    let plaintext = hex::decode(
        "d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b39",
    )
    .unwrap();
    let expected_full = hex::decode(
        "42831ec2217774244b7221b784d0d49c\
         e3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa05\
         1ba30b396a0aac973d58e0915bc94fbc\
         3221a5db94fae95ae7121a47",
    )
    .unwrap();

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let ct = gcm
        .internal_encrypt(&nonce, &plaintext, Some(&aad))
        .unwrap();
    assert_eq!(ct.len(), expected_full.len());
    assert_eq!(hex::encode(&ct), hex::encode(&expected_full));

    // Round-trip
    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let pt = gcm.internal_decrypt(&nonce, &ct, Some(&aad)).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn test_gcm_tampered_ciphertext() {
    let key_array = [0x42; 16];
    let key = SecretBytes::new(key_array);
    let nonce = Nonce::<12>::new([0x24; 12]);
    let aad = [0x10; 16];
    let plaintext = [0xAA; 32];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();

    let mut ciphertext = gcm
        .internal_encrypt(&nonce, &plaintext, Some(&aad))
        .unwrap();
    if ciphertext.len() > 5 {
        ciphertext[5] ^= 0x01;
    }

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let result = gcm.internal_decrypt(&nonce, &ciphertext, Some(&aad));
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(Error::Authentication { algorithm: "GCM" })
    ));
}

#[test]
fn test_gcm_tampered_tag() {
    let key_array = [0x42; 16];
    let key = SecretBytes::new(key_array);
    let nonce = Nonce::<12>::new([0x24; 12]);
    let plaintext = [0xAA; 32];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();

    let mut ciphertext = gcm.internal_encrypt(&nonce, &plaintext, None).unwrap();
    let tag_len = GCM_TAG_SIZE;
    if ciphertext.len() >= tag_len {
        let tag_idx = ciphertext.len() - tag_len;
        ciphertext[tag_idx] ^= 0x01;
    }

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let result = gcm.internal_decrypt(&nonce, &ciphertext, None);
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(Error::Authentication { algorithm: "GCM" })
    ));
}

#[test]
fn test_gcm_empty_plaintext() {
    let key_array = [0x42; 16];
    let key = SecretBytes::new(key_array);
    let nonce = Nonce::<12>::new([0x24; 12]);
    let aad = [0x10; 16];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();

    let ciphertext = gcm.internal_encrypt(&nonce, &[], Some(&aad)).unwrap();
    assert_eq!(ciphertext.len(), GCM_TAG_SIZE);

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let decrypted = gcm
        .internal_decrypt(&nonce, &ciphertext, Some(&aad))
        .unwrap();
    assert_eq!(decrypted.len(), 0);
}

#[test]
fn test_gcm_invalid_nonce() {
    // Note: With the new trait system, invalid nonce sizes can't be used with GCM at compile time
    // We'll test nonce validation directly instead

    let key_array = [0x42; 16];
    let key = SecretBytes::new(key_array);
    let cipher = Aes128::new(&key);

    // Valid nonce sizes work with GCM
    let nonce12 = Nonce::<12>::new([0x24; 12]);
    let nonce16 = Nonce::<16>::new([0x24; 16]);

    let gcm = Gcm::new(cipher.clone()).unwrap();
    assert!(gcm.internal_encrypt(&nonce12, b"", None).is_ok());
    assert!(gcm.internal_encrypt(&nonce16, b"", None).is_ok());

    // Test that Nonce creation validates length
    let empty_bytes: [u8; 0] = [];
    let long_bytes = [0x24; 17];

    let result = Nonce::<12>::from_slice(&empty_bytes);
    assert!(result.is_err());

    let result = Nonce::<12>::from_slice(&long_bytes);
    assert!(result.is_err());
}

#[test]
fn test_gcm_short_ciphertext() {
    let key_array = [0x42; 16];
    let key = SecretBytes::new(key_array);
    let nonce = Nonce::<12>::new([0x24; 12]);
    let ciphertext = [0xAA; 8];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let result = gcm.internal_decrypt(&nonce, &ciphertext, None);
    assert!(result.is_err());
    assert!(matches!(result, Err(Error::Length { .. })));
}

#[test]
fn test_gcm_empty_associated_data() {
    let key_array = [0x42; 16];
    let key = SecretBytes::new(key_array);
    let nonce = Nonce::<12>::new([0x24; 12]);
    let plaintext = [0xAA; 32];
    let empty_aad: [u8; 0] = [];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let ciphertext = gcm
        .internal_encrypt(&nonce, &plaintext, Some(&empty_aad))
        .unwrap();

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let decrypted = gcm
        .internal_decrypt(&nonce, &ciphertext, Some(&empty_aad))
        .unwrap();
    assert_eq!(decrypted, plaintext);

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let decrypted = gcm.internal_decrypt(&nonce, &ciphertext, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_gcm_non_standard_nonce() {
    // Since Nonce<8> is not AesGcmCompatible, we'll test with Nonce<16> instead
    let key_array = [0x42; 16];
    let key = SecretBytes::new(key_array);
    let nonce = Nonce::<16>::new([0x24; 16]);
    let plaintext = [0xAA; 32];

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let ciphertext = gcm.internal_encrypt(&nonce, &plaintext, None).unwrap();

    let cipher = Aes128::new(&key);
    let gcm = Gcm::new(cipher).unwrap();
    let decrypted = gcm.internal_decrypt(&nonce, &ciphertext, None).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn nist_120_bit_iv_known_answer_with_full_safe_tag() {
    // NIST ACVP AES-GCM 1.0 internalProjection.json, tgId 2 / tcId 16.
    // The source group publishes only a 32-bit tag. We generate the safe full
    // tag and compare the published prefix, validating non-96-bit J0 without
    // exposing a short-tag verification API.
    let key: [u8; 16] = hex::decode("49bfa3bf9492dc7bcc93edafc725c730")
        .unwrap()
        .try_into()
        .unwrap();
    let iv: [u8; 15] = hex::decode("b40811be58d20804e60926ee571491")
        .unwrap()
        .try_into()
        .unwrap();
    let plaintext = hex::decode("f2dc083b4ca1c54bf5228a5bb67129").unwrap();
    let expected_ciphertext = hex::decode("e8f5854061720508ea3fbcceb78f4f").unwrap();
    let expected_tag_prefix = hex::decode("8ad3515a").unwrap();

    let key = SecretBytes::<16>::new(key);
    let nonce = Nonce::<15>::new(iv);
    let gcm = Gcm::new(Aes128::new(&key)).unwrap();
    let output = gcm.internal_encrypt(&nonce, &plaintext, None).unwrap();
    let (ciphertext, full_tag) = output.split_at(plaintext.len());

    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(&full_tag[..expected_tag_prefix.len()], expected_tag_prefix);
    assert_eq!(full_tag.len(), GCM_TAG_SIZE);
}

#[test]
fn operation_builder_uses_each_operation_nonce() {
    let key = SecretBytes::<16>::new([0x42; 16]);
    let nonce_a = Nonce::<12>::new([0x11; 12]);
    let nonce_b = Nonce::<12>::new([0x22; 12]);
    let gcm = Gcm::new(Aes128::new(&key)).unwrap();
    let plaintext = b"the nonce belongs to the operation";

    let ciphertext_a = ApiSymmetricCipher::encrypt(&gcm)
        .with_nonce(&nonce_a)
        .encrypt(plaintext)
        .unwrap();
    let ciphertext_b = ApiSymmetricCipher::encrypt(&gcm)
        .with_nonce(&nonce_b)
        .encrypt(plaintext)
        .unwrap();

    assert_ne!(ciphertext_a.as_ref(), ciphertext_b.as_ref());
    assert!(ApiSymmetricCipher::decrypt(&gcm)
        .with_nonce(&nonce_b)
        .decrypt(&ciphertext_a)
        .is_err());
    assert_eq!(
        ApiSymmetricCipher::decrypt(&gcm)
            .with_nonce(&nonce_a)
            .decrypt(&ciphertext_a)
            .unwrap(),
        plaintext
    );
}

#[test]
fn rejects_dangerously_short_tags() {
    let key = SecretBytes::<16>::new([0x42; 16]);
    assert!(Gcm::new_with_tag_len(Aes128::new(&key), 1).is_err());
    assert!(Gcm::new_with_tag_len(Aes128::new(&key), 11).is_err());
    assert!(Gcm::new_with_tag_len(Aes128::new(&key), 12).is_ok());
    assert!(Gcm::new_with_tag_len(Aes128::new(&key), 16).is_ok());
}

#[test]
#[cfg(target_pointer_width = "64")]
fn rejects_messages_past_the_gcm_counter_limit_before_allocation() {
    let max_blocks = (u32::MAX as usize) - 1;
    let max_bytes = max_blocks * GCM_BLOCK_SIZE;

    assert_eq!(gcm_block_count(max_bytes).unwrap(), max_blocks);
    assert!(gcm_block_count(max_bytes + 1).is_err());
}

// -------------------------------------------------------------------------
// NIST CAVP Test Vector Parser & Runner
// -------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct GcmTestVector {
    key: Vec<u8>,
    iv: Vec<u8>,
    pt: Option<Vec<u8>>,
    ct: Option<Vec<u8>>,
    aad: Vec<u8>,
    tag: Vec<u8>,
    fail_expected: bool,
}

#[derive(Debug)]
struct GcmTestGroup {
    key_len: usize,
    iv_len: usize,
    pt_len: usize,
    aad_len: usize,
    tag_len: usize,
    test_vectors: Vec<GcmTestVector>,
}

fn parse_gcm_test_file(filepath: &str) -> Vec<GcmTestGroup> {
    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut groups = Vec::new();
    let mut current: Option<GcmTestGroup> = None;
    let mut vector: Option<GcmTestVector> = None;

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let p = &line[1..line.len() - 1];
            let parts: Vec<&str> = p.split('=').collect();
            if parts.len() == 2 {
                let name = parts[0].trim();
                let val = parts[1].trim().parse().unwrap_or(0);
                match name {
                    "Keylen" => {
                        if let Some(g) = current.take() {
                            groups.push(g);
                        }
                        current = Some(GcmTestGroup {
                            key_len: val,
                            iv_len: 0,
                            pt_len: 0,
                            aad_len: 0,
                            tag_len: 0,
                            test_vectors: Vec::new(),
                        });
                    }
                    "IVlen" => current.as_mut().unwrap().iv_len = val,
                    "PTlen" => current.as_mut().unwrap().pt_len = val,
                    "AADlen" => current.as_mut().unwrap().aad_len = val,
                    "Taglen" => current.as_mut().unwrap().tag_len = val,
                    _ => {}
                }
            }
            continue;
        }

        // Handle bare FAIL lines (without '=')
        if !line.contains('=') {
            if line == "FAIL" {
                if let Some(ref mut v) = vector {
                    v.fail_expected = true;
                }
            }
            continue;
        }

        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() == 2 {
            let name = parts[0].trim();
            let val = parts[1].trim();
            match name {
                "Count" => {
                    if let Some(v) = vector.take() {
                        current.as_mut().unwrap().test_vectors.push(v);
                    }
                    vector = Some(GcmTestVector {
                        key: Vec::new(),
                        iv: Vec::new(),
                        pt: None,
                        ct: None,
                        aad: Vec::new(),
                        tag: Vec::new(),
                        fail_expected: false,
                    });
                }
                "Key" => {
                    if let Some(ref mut v) = vector {
                        v.key = if val.is_empty() {
                            Vec::new()
                        } else {
                            hex::decode(val)
                                .unwrap_or_else(|_| panic!("Invalid hex in Key: {}", val))
                        };
                    }
                }
                "IV" => {
                    if let Some(ref mut v) = vector {
                        v.iv = if val.is_empty() {
                            Vec::new()
                        } else {
                            hex::decode(val)
                                .unwrap_or_else(|_| panic!("Invalid hex in IV: {}", val))
                        };
                    }
                }
                "PT" => {
                    if let Some(ref mut v) = vector {
                        v.pt = if val.is_empty() {
                            Some(Vec::new())
                        } else {
                            Some(
                                hex::decode(val)
                                    .unwrap_or_else(|_| panic!("Invalid hex in PT: {}", val)),
                            )
                        };
                    }
                }
                "CT" => {
                    if let Some(ref mut v) = vector {
                        v.ct = if val.is_empty() {
                            Some(Vec::new())
                        } else {
                            Some(
                                hex::decode(val)
                                    .unwrap_or_else(|_| panic!("Invalid hex in CT: {}", val)),
                            )
                        };
                    }
                }
                "AAD" => {
                    if let Some(ref mut v) = vector {
                        v.aad = if val.is_empty() {
                            Vec::new()
                        } else {
                            hex::decode(val)
                                .unwrap_or_else(|_| panic!("Invalid hex in AAD: {}", val))
                        };
                    }
                }
                "Tag" => {
                    if let Some(ref mut v) = vector {
                        v.tag = if val.is_empty() {
                            Vec::new()
                        } else {
                            hex::decode(val)
                                .unwrap_or_else(|_| panic!("Invalid hex in Tag: {}", val))
                        };
                    }
                }
                "FAIL" => {
                    if let Some(ref mut v) = vector {
                        v.fail_expected = true;
                    }
                }
                _ => {}
            }
        }
    }
    if let Some(v) = vector {
        current.as_mut().unwrap().test_vectors.push(v);
    }
    if let Some(g) = current {
        groups.push(g);
    }
    groups
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..") // up to crates/
        .join("..") // up to workspace root
        .join("tests")
        .join("src")
        .join("vectors")
        .join("legacy_rsp")
        .join("gcm")
}

#[test]
fn test_aes_gcm_nist_decrypt_vectors() {
    let dir = vectors_dir();

    let files = [
        dir.join("gcmDecrypt128.rsp"),
        dir.join("gcmDecrypt192.rsp"),
        dir.join("gcmDecrypt256.rsp"),
    ];

    for f in &files {
        assert!(f.exists(), "Test vector file not found: {}", f.display());
    }

    run_gcm_decrypt_tests_128(files[0].to_str().unwrap());
    run_gcm_decrypt_tests_192(files[1].to_str().unwrap());
    run_gcm_decrypt_tests_256(files[2].to_str().unwrap());
}

#[test]
fn test_aes_gcm_nist_encrypt_vectors() {
    let dir = vectors_dir();

    let files = [
        dir.join("gcmEncryptExtIV128.rsp"),
        dir.join("gcmEncryptExtIV192.rsp"),
        dir.join("gcmEncryptExtIV256.rsp"),
    ];

    for f in &files {
        if !f.exists() {
            eprintln!("Missing file: {}", f.display());
            return;
        }
    }

    run_gcm_encrypt_tests_128(files[0].to_str().unwrap());
    run_gcm_encrypt_tests_192(files[1].to_str().unwrap());
    run_gcm_encrypt_tests_256(files[2].to_str().unwrap());
}

// Helper function to process test vectors with specific nonce sizes
fn process_gcm_test_with_nonce<const N: usize, B: BlockCipher + Zeroize + ZeroizeOnDrop>(
    test_index: usize,
    test: &GcmTestVector,
    cipher: B,
    tag_bytes: usize,
) where
    Nonce<N>: AesGcmCompatible,
{
    // Create nonce of the right size
    let nonce = match Nonce::<N>::from_slice(&test.iv) {
        Ok(n) => n,
        Err(e) => {
            println!("Skipping test {} - invalid IV: {}", test_index, e);
            return;
        }
    };

    // Create GCM instance
    let gcm = match Gcm::new_with_tag_len(cipher, tag_bytes) {
        Ok(g) => g,
        Err(e) => {
            println!("Skipping test {} - GCM creation failed: {}", test_index, e);
            return;
        }
    };

    // Build ciphertext + tag
    let mut cw = Vec::new();
    if let Some(ref ct) = test.ct {
        cw.extend_from_slice(ct);
    }
    cw.extend_from_slice(&test.tag);

    // Get AAD
    let aad = if test.aad.is_empty() {
        None
    } else {
        Some(&test.aad[..])
    };

    // Decrypt and verify
    let res = gcm.internal_decrypt(&nonce, &cw, aad);
    if test.fail_expected {
        assert!(res.is_err(), "Vector {} should fail", test_index);
    } else {
        match res {
            Ok(pt) => {
                if let Some(ref expected) = test.pt {
                    assert_eq!(pt, *expected, "PT mismatch at {}", test_index);
                }
            }
            Err(e) => panic!("Decrypt failed at {}: {}", test_index, e),
        }
    }
}

// Split the test runners into separate functions for each key size
fn run_gcm_decrypt_tests_128(filepath: &str) {
    let groups = parse_gcm_test_file(filepath);
    for group in groups {
        for (i, test) in group.test_vectors.iter().enumerate() {
            // Make sure the key length matches what we expect
            if group.key_len != 128 {
                println!(
                    "Skipping test {} - unexpected key length {}",
                    i, group.key_len
                );
                continue;
            }

            // Convert to SecretBytes<16>
            let key = match SecretBytes::<16>::from_slice(&test.key) {
                Ok(k) => k,
                Err(_) => {
                    println!("Skipping test {} - invalid key length", i);
                    continue;
                }
            };

            let cipher = Aes128::new(&key);
            let tag_bytes = test.tag.len(); // Use actual tag length from vector

            // Process each nonce size separately
            match test.iv.len() {
                12 => process_gcm_test_with_nonce::<12, _>(i, test, cipher, tag_bytes),
                15 => process_gcm_test_with_nonce::<15, _>(i, test, cipher, tag_bytes),
                16 => process_gcm_test_with_nonce::<16, _>(i, test, cipher, tag_bytes),
                // For unsupported nonce sizes:
                _ => println!(
                    "Skipping test {} - unsupported IV length {}",
                    i,
                    test.iv.len()
                ),
            }
        }
    }
}

fn run_gcm_decrypt_tests_192(filepath: &str) {
    let groups = parse_gcm_test_file(filepath);
    for group in groups {
        for (i, test) in group.test_vectors.iter().enumerate() {
            // Make sure the key length matches what we expect
            if group.key_len != 192 {
                println!(
                    "Skipping test {} - unexpected key length {}",
                    i, group.key_len
                );
                continue;
            }

            // Convert to SecretBytes<24>
            let key = match SecretBytes::<24>::from_slice(&test.key) {
                Ok(k) => k,
                Err(_) => {
                    println!("Skipping test {} - invalid key length", i);
                    continue;
                }
            };

            let cipher = Aes192::new(&key);
            let tag_bytes = test.tag.len(); // Use actual tag length from vector

            // Process each nonce size separately
            match test.iv.len() {
                12 => process_gcm_test_with_nonce::<12, _>(i, test, cipher, tag_bytes),
                15 => process_gcm_test_with_nonce::<15, _>(i, test, cipher, tag_bytes),
                16 => process_gcm_test_with_nonce::<16, _>(i, test, cipher, tag_bytes),
                // For unsupported nonce sizes:
                _ => println!(
                    "Skipping test {} - unsupported IV length {}",
                    i,
                    test.iv.len()
                ),
            }
        }
    }
}

fn run_gcm_decrypt_tests_256(filepath: &str) {
    let groups = parse_gcm_test_file(filepath);
    for group in groups {
        for (i, test) in group.test_vectors.iter().enumerate() {
            // Make sure the key length matches what we expect
            if group.key_len != 256 {
                println!(
                    "Skipping test {} - unexpected key length {}",
                    i, group.key_len
                );
                continue;
            }

            // Convert to SecretBytes<32>
            let key = match SecretBytes::<32>::from_slice(&test.key) {
                Ok(k) => k,
                Err(_) => {
                    println!("Skipping test {} - invalid key length", i);
                    continue;
                }
            };

            let cipher = Aes256::new(&key);
            let tag_bytes = test.tag.len(); // Use actual tag length from vector

            // Process each nonce size separately
            match test.iv.len() {
                12 => process_gcm_test_with_nonce::<12, _>(i, test, cipher, tag_bytes),
                15 => process_gcm_test_with_nonce::<15, _>(i, test, cipher, tag_bytes),
                16 => process_gcm_test_with_nonce::<16, _>(i, test, cipher, tag_bytes),
                // For unsupported nonce sizes:
                _ => println!(
                    "Skipping test {} - unsupported IV length {}",
                    i,
                    test.iv.len()
                ),
            }
        }
    }
}

// Helper function for encryption test vectors too
fn process_gcm_encrypt_test_with_nonce<const N: usize, B: BlockCipher + Zeroize + ZeroizeOnDrop>(
    test_index: usize,
    test: &GcmTestVector,
    cipher: B,
    tag_bytes: usize,
) where
    Nonce<N>: AesGcmCompatible,
{
    // Create nonce of the right size
    let nonce = match Nonce::<N>::from_slice(&test.iv) {
        Ok(n) => n,
        Err(e) => {
            println!("Skipping test {} - invalid IV: {}", test_index, e);
            return;
        }
    };

    // Create GCM instance with the correct tag length
    let gcm = match Gcm::new_with_tag_len(cipher, tag_bytes) {
        Ok(g) => g,
        Err(e) => {
            println!("Skipping test {} - GCM creation failed: {}", test_index, e);
            return;
        }
    };

    let plaintext = test.pt.as_ref().map_or(&[][..], |v| &v[..]);
    let aad = if test.aad.is_empty() {
        None
    } else {
        Some(&test.aad[..])
    };

    let cw = gcm.internal_encrypt(&nonce, plaintext, aad).unwrap();

    // split off ciphertext vs. tag by expected lengths
    let exp_ct_len = test.ct.as_ref().map_or(0, |v| v.len());
    let exp_tag_len = test.tag.len();
    assert_eq!(
        cw.len(),
        exp_ct_len + exp_tag_len,
        "Length mismatch for test case {}",
        test_index
    );

    let (ct, tag) = cw.split_at(exp_ct_len);
    if let Some(ref expected_ct) = test.ct {
        assert_eq!(
            ct,
            expected_ct.as_slice(),
            "Ciphertext mismatch at case {}",
            test_index
        );
    }
    assert_eq!(
        tag,
        test.tag.as_slice(),
        "Authentication tag mismatch for case {}",
        test_index
    );
}

fn run_gcm_encrypt_tests_128(filepath: &str) {
    let groups = parse_gcm_test_file(filepath);
    for group in groups {
        for (i, test) in group.test_vectors.iter().enumerate() {
            println!("Running encrypt test case {}", i);

            // Make sure the key length matches what we expect
            if group.key_len != 128 {
                println!(
                    "Skipping test {} - unexpected key length {}",
                    i, group.key_len
                );
                continue;
            }

            // Convert to SecretBytes<16>
            let key = match SecretBytes::<16>::from_slice(&test.key) {
                Ok(k) => k,
                Err(_) => {
                    println!("Skipping test {} - invalid key length", i);
                    continue;
                }
            };

            let cipher = Aes128::new(&key);
            let tag_bytes = test.tag.len(); // Use actual tag length from vector

            // Process each nonce size separately
            match test.iv.len() {
                12 => process_gcm_encrypt_test_with_nonce::<12, _>(i, test, cipher, tag_bytes),
                15 => process_gcm_encrypt_test_with_nonce::<15, _>(i, test, cipher, tag_bytes),
                16 => process_gcm_encrypt_test_with_nonce::<16, _>(i, test, cipher, tag_bytes),
                _ => println!(
                    "Skipping test {} - unsupported IV length {}",
                    i,
                    test.iv.len()
                ),
            }
        }
    }
}

fn run_gcm_encrypt_tests_192(filepath: &str) {
    let groups = parse_gcm_test_file(filepath);
    for group in groups {
        for (i, test) in group.test_vectors.iter().enumerate() {
            println!("Running encrypt test case {}", i);

            // Make sure the key length matches what we expect
            if group.key_len != 192 {
                println!(
                    "Skipping test {} - unexpected key length {}",
                    i, group.key_len
                );
                continue;
            }

            // Convert to SecretBytes<24>
            let key = match SecretBytes::<24>::from_slice(&test.key) {
                Ok(k) => k,
                Err(_) => {
                    println!("Skipping test {} - invalid key length", i);
                    continue;
                }
            };

            let cipher = Aes192::new(&key);
            let tag_bytes = test.tag.len(); // Use actual tag length from vector

            // Process each nonce size separately
            match test.iv.len() {
                12 => process_gcm_encrypt_test_with_nonce::<12, _>(i, test, cipher, tag_bytes),
                15 => process_gcm_encrypt_test_with_nonce::<15, _>(i, test, cipher, tag_bytes),
                16 => process_gcm_encrypt_test_with_nonce::<16, _>(i, test, cipher, tag_bytes),
                _ => println!(
                    "Skipping test {} - unsupported IV length {}",
                    i,
                    test.iv.len()
                ),
            }
        }
    }
}

fn run_gcm_encrypt_tests_256(filepath: &str) {
    let groups = parse_gcm_test_file(filepath);
    for group in groups {
        for (i, test) in group.test_vectors.iter().enumerate() {
            println!("Running encrypt test case {}", i);

            // Make sure the key length matches what we expect
            if group.key_len != 256 {
                println!(
                    "Skipping test {} - unexpected key length {}",
                    i, group.key_len
                );
                continue;
            }

            // Convert to SecretBytes<32>
            let key = match SecretBytes::<32>::from_slice(&test.key) {
                Ok(k) => k,
                Err(_) => {
                    println!("Skipping test {} - invalid key length", i);
                    continue;
                }
            };

            let cipher = Aes256::new(&key);
            let tag_bytes = test.tag.len(); // Use actual tag length from vector

            // Process each nonce size separately
            match test.iv.len() {
                12 => process_gcm_encrypt_test_with_nonce::<12, _>(i, test, cipher, tag_bytes),
                15 => process_gcm_encrypt_test_with_nonce::<15, _>(i, test, cipher, tag_bytes),
                16 => process_gcm_encrypt_test_with_nonce::<16, _>(i, test, cipher, tag_bytes),
                _ => println!(
                    "Skipping test {} - unsupported IV length {}",
                    i,
                    test.iv.len()
                ),
            }
        }
    }
}
