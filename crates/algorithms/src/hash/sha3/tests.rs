use super::*;
use hex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..") // up to crates/
        .join("..") // up to workspace root
        .join("tests")
        .join("src")
        .join("vectors")
        .join("legacy_rsp")
        .join("sha3")
}

fn patterned_bit_string(bit_len: usize) -> Vec<u8> {
    let mut message: Vec<u8> = (0..(bit_len + 7) / 8)
        .map(|index| (index as u8).wrapping_mul(73).wrapping_add(41))
        .collect();
    if bit_len % 8 != 0 {
        *message.last_mut().unwrap() &= 0xff << (8 - bit_len % 8);
    }
    message
}

// Basic sanity check tests - keep these for quick development feedback
#[test]
fn test_sha3_256_empty() {
    // NIST test vector: Empty string
    let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";

    let hash = Sha3_256::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[test]
fn test_sha3_224_empty() {
    // NIST test vector: Empty string
    let expected = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";

    let hash = Sha3_224::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[test]
fn test_sha3_bit_oriented_nist_vectors() {
    // NIST ACVP uses the most-significant positions of the final byte for a
    // partial input.  These vectors exercise both possible first bits and a
    // multi-bit prefix, so a byte-hash or reversed bit order cannot pass.
    let sha3_224_two_bits = Sha3_224::digest_bits(&[0xc0], 2).unwrap();
    assert_eq!(
        hex::encode(sha3_224_two_bits.as_ref()),
        "dfeb54cd8a7a549089ae3709307923b49116dba1ad3cbc3fe403b6e8"
    );

    let sha3_256_one_zero_bit = Sha3_256::digest_bits(&[0x00], 1).unwrap();
    assert_eq!(
        hex::encode(sha3_256_one_zero_bit.as_ref()),
        "1b2e61923578e35f3b4629e04a0ff3b73daa571ae01130d9c16ef7da7a4cfdc2"
    );
}

#[test]
fn test_sha3_bit_oriented_api_preserves_byte_hashing_and_rejects_ambiguity() {
    let ordinary = Sha3_256::digest(b"abc").unwrap();
    let bit_oriented = Sha3_256::digest_bits(b"abc", 24).unwrap();
    assert_eq!(ordinary.as_ref(), bit_oriented.as_ref());

    // A two-bit input must have its six unused low bits cleared, and must be
    // represented by exactly one byte.
    assert!(Sha3_256::digest_bits(&[0xc1], 2).is_err());
    assert!(Sha3_256::digest_bits(&[0xc0, 0x00], 2).is_err());
}

#[test]
fn test_sha3_bit_suffix_at_and_across_rate_boundary() {
    // Cross-checked against XKCP Keccak_HashUpdate/Final.  1149/1085 input
    // bits plus the three-bit SHA-3 delimited suffix exactly fill a rate
    // block; the following lengths force the suffix across that boundary.
    for (bit_len, expected) in [
        (
            1149,
            "57eb731d6e05d3b5c43c0ff08276f76c5f506b6ce76a7d3cb879598c",
        ),
        (
            1150,
            "3494129888cc45ad1b6a7f46e769e13b9b32c3b9e0ffab8820a7e5f5",
        ),
    ] {
        let digest = Sha3_224::digest_bits(&patterned_bit_string(bit_len), bit_len).unwrap();
        assert_eq!(hex::encode(digest.as_ref()), expected);
    }

    for (bit_len, expected) in [
        (
            1085,
            "4ee84e128d913715d2a50c9752500201ce2efa54e019a83f7c28ce55ed6b87f4",
        ),
        (
            1086,
            "2cba2d7426f1beb3920b33acf200eaea35a6697b8f52c1dd3a0002c6bfbcd613",
        ),
    ] {
        let digest = Sha3_256::digest_bits(&patterned_bit_string(bit_len), bit_len).unwrap();
        assert_eq!(hex::encode(digest.as_ref()), expected);
    }
}

#[test]
fn test_sha3_384_empty() {
    // NIST test vector: Empty string
    let expected = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";

    let hash = Sha3_384::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[test]
fn test_sha3_512_empty() {
    // NIST test vector: Empty string
    let expected = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";

    let hash = Sha3_512::digest(&[]).unwrap();
    assert_eq!(hex::encode(&hash), expected);
}

#[derive(Debug)]
struct Sha3TestVector {
    len: usize,  // Bit length
    msg: String, // Hex-encoded message
    md: String,  // Hex-encoded digest (expected hash)
}

fn parse_sha3_test_file(filepath: &str) -> Vec<Sha3TestVector> {
    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut test_vectors = Vec::new();
    let mut current_vector: Option<Sha3TestVector> = None;

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(len_str) = line.strip_prefix("Len = ") {
            // Start of a new test case
            if let Some(vector) = current_vector.take() {
                test_vectors.push(vector);
            }

            // Extract bit length
            let len = len_str.parse::<usize>().unwrap();

            current_vector = Some(Sha3TestVector {
                len,
                msg: String::new(),
                md: String::new(),
            });
        } else if let Some(ref mut vector) = current_vector {
            // Parse test vector data
            if let Some(msg) = line.strip_prefix("Msg = ") {
                vector.msg = msg.to_string();
            } else if let Some(md) = line.strip_prefix("MD = ") {
                vector.md = md.to_string();
            }
        }
    }

    // Add the last test vector if present
    if let Some(vector) = current_vector {
        test_vectors.push(vector);
    }

    test_vectors
}

// Modified with trait bounds to handle the type comparison
fn run_sha3_tests<H: HashFunction>(filepath: &str, name: &str) {
    let test_vectors = parse_sha3_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Check if bit length is 0
        if test.len == 0 {
            // If bit length is 0, use an empty message regardless of what's in the msg field
            let hash = H::digest(&[]).unwrap();

            // Convert expected hash to bytes
            let expected = hex::decode(&test.md)
                .unwrap_or_else(|_| panic!("Invalid hex in expected result {}: {}", i, test.md));

            // Convert the hash to Vec<u8> before comparison
            let hash_vec = hash.as_ref().to_vec();

            // Compare results
            assert_eq!(
                hash_vec,
                expected,
                "{} test case {} failed. Input: empty, Expected: {}, Got: {}",
                name,
                i,
                test.md,
                hex::encode(&hash)
            );

            continue;
        }

        // For non-zero bit lengths, convert hex string to bytes and proceed as before
        let msg = if test.msg.is_empty() {
            Vec::new()
        } else {
            hex::decode(&test.msg)
                .unwrap_or_else(|_| panic!("Invalid hex in test vector {}: {}", i, test.msg))
        };

        // Handle partial bytes if bit length is not a multiple of 8
        if test.len % 8 != 0 {
            let bytes = test.len / 8;
            let bits = test.len % 8;

            if bytes < msg.len() {
                let mut truncated_msg = msg[..bytes].to_vec();
                if bits > 0 {
                    // Keep only the specified number of bits in the last byte
                    let mask = (1u8 << bits) - 1;
                    truncated_msg.push(msg[bytes] & mask);
                }
                let hash = H::digest(&truncated_msg).unwrap();

                // Convert expected hash to bytes
                let expected = hex::decode(&test.md).unwrap_or_else(|_| {
                    panic!("Invalid hex in expected result {}: {}", i, test.md)
                });

                // Convert the hash to Vec<u8> before comparison
                let hash_vec = hash.as_ref().to_vec();

                // Compare results
                assert_eq!(
                    hash_vec,
                    expected,
                    "{} test case {} failed. Input: {}, Expected: {}, Got: {}",
                    name,
                    i,
                    test.msg,
                    test.md,
                    hex::encode(&hash)
                );

                continue;
            }
        }

        // Hash the message
        let hash = H::digest(&msg).unwrap();

        // Convert expected hash to bytes
        let expected = hex::decode(&test.md)
            .unwrap_or_else(|_| panic!("Invalid hex in expected result {}: {}", i, test.md));

        // Convert the hash to Vec<u8> before comparison
        let hash_vec = hash.as_ref().to_vec();

        // Compare results
        assert_eq!(
            hash_vec,
            expected,
            "{} test case {} failed. Input: {}, Expected: {}, Got: {}",
            name,
            i,
            test.msg,
            test.md,
            hex::encode(&hash)
        );
    }
}

#[test]
fn test_sha3_nist_short_vectors() {
    let dir = vectors_dir();

    // Path to the test vector files
    let sha3_224_path = dir.join("SHA3_224ShortMsg.rsp");
    let sha3_256_path = dir.join("SHA3_256ShortMsg.rsp");
    let sha3_384_path = dir.join("SHA3_384ShortMsg.rsp");
    let sha3_512_path = dir.join("SHA3_512ShortMsg.rsp");

    // Check if files exist and FAIL if they don't
    for path in [
        &sha3_224_path,
        &sha3_256_path,
        &sha3_384_path,
        &sha3_512_path,
    ] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }

    // Run the tests
    run_sha3_tests::<Sha3_224>(sha3_224_path.to_str().unwrap(), "SHA3-224");
    run_sha3_tests::<Sha3_256>(sha3_256_path.to_str().unwrap(), "SHA3-256");
    run_sha3_tests::<Sha3_384>(sha3_384_path.to_str().unwrap(), "SHA3-384");
    run_sha3_tests::<Sha3_512>(sha3_512_path.to_str().unwrap(), "SHA3-512");
}

#[test]
fn test_sha3_nist_long_vectors() {
    let dir = vectors_dir();

    // Path to the long message test vector files
    let sha3_224_path = dir.join("SHA3_224LongMsg.rsp");
    let sha3_256_path = dir.join("SHA3_256LongMsg.rsp");
    let sha3_384_path = dir.join("SHA3_384LongMsg.rsp");
    let sha3_512_path = dir.join("SHA3_512LongMsg.rsp");

    // Check if files exist and FAIL if they don't
    for path in [
        &sha3_224_path,
        &sha3_256_path,
        &sha3_384_path,
        &sha3_512_path,
    ] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }

    // Run the same test functions for long messages
    run_sha3_tests::<Sha3_224>(sha3_224_path.to_str().unwrap(), "SHA3-224");
    run_sha3_tests::<Sha3_256>(sha3_256_path.to_str().unwrap(), "SHA3-256");
    run_sha3_tests::<Sha3_384>(sha3_384_path.to_str().unwrap(), "SHA3-384");
    run_sha3_tests::<Sha3_512>(sha3_512_path.to_str().unwrap(), "SHA3-512");
}

#[derive(Debug)]
struct Sha3MonteTestVector {
    seed: String,     // Initial seed
    count: usize,     // Number of iterations
    expected: String, // Expected final MD value
}

fn parse_sha3_monte_test_file(filepath: &str) -> Vec<Sha3MonteTestVector> {
    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut test_vectors = Vec::new();
    let mut current_seed = String::new();
    let mut current_expected = String::new();
    let mut count = 0;

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(seed) = line.strip_prefix("Seed = ") {
            // Start of a new test case
            if !current_seed.is_empty() && !current_expected.is_empty() {
                test_vectors.push(Sha3MonteTestVector {
                    seed: current_seed.clone(),
                    count,
                    expected: current_expected.clone(),
                });
            }

            current_seed = seed.to_string();
            current_expected = String::new();
            count = 0;
        } else if let Some(count_str) = line.strip_prefix("COUNT = ") {
            count = count_str.trim().parse::<usize>().unwrap_or(0);
        } else if line.starts_with("MD = ") && count == 100 {
            // Last iteration
            current_expected = line.strip_prefix("MD = ").unwrap().to_string();
        }
    }

    // Add the last test vector if present
    if !current_seed.is_empty() && !current_expected.is_empty() {
        test_vectors.push(Sha3MonteTestVector {
            seed: current_seed,
            count,
            expected: current_expected,
        });
    }

    test_vectors
}

// Modified to convert the hash function output to Vec<u8>
fn run_sha3_monte_tests<H: HashFunction>(filepath: &str, name: &str) {
    let test_vectors = parse_sha3_monte_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Convert seed to bytes
        let seed_bytes = hex::decode(&test.seed).unwrap_or_else(|_| {
            panic!(
                "{} Monte Carlo test {}: Invalid seed hex: {}",
                name, i, test.seed
            )
        });

        // Perform Monte Carlo test according to NIST procedure
        let mut md = seed_bytes.clone();

        // Perform the specified number of iterations (typically 100 for SHA-3)
        for _j in 0..=test.count {
            // Create a new hash instance
            let mut hasher = H::new();

            // Update with the current MD value
            hasher.update(&md).unwrap();

            // Generate the next MD value - convert to Vec<u8> to match md's type
            md = hasher.finalize().unwrap().as_ref().to_vec();
        }

        // Verify the final result matches the expected value
        let expected = hex::decode(&test.expected).unwrap_or_else(|_| {
            panic!(
                "{} Monte Carlo test {}: Invalid expected hex: {}",
                name, i, test.expected
            )
        });

        assert_eq!(
            hex::encode(&md),
            hex::encode(&expected),
            "{} Monte Carlo test case {} failed.\nExpected: {}\nGot: {}",
            name,
            i,
            test.expected,
            hex::encode(&md)
        );
    }
}

#[test]
fn test_sha3_nist_monte_vectors() {
    let dir = vectors_dir();

    // Path to the Monte Carlo test vector files
    let sha3_224_path = dir.join("SHA3_224Monte.rsp");
    let sha3_256_path = dir.join("SHA3_256Monte.rsp");
    let sha3_384_path = dir.join("SHA3_384Monte.rsp");
    let sha3_512_path = dir.join("SHA3_512Monte.rsp");

    // Check if files exist and FAIL if they don't
    for path in [
        &sha3_224_path,
        &sha3_256_path,
        &sha3_384_path,
        &sha3_512_path,
    ] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }

    // Run Monte Carlo tests for each SHA-3 variant
    run_sha3_monte_tests::<Sha3_224>(sha3_224_path.to_str().unwrap(), "SHA3-224");
    run_sha3_monte_tests::<Sha3_256>(sha3_256_path.to_str().unwrap(), "SHA3-256");
    run_sha3_monte_tests::<Sha3_384>(sha3_384_path.to_str().unwrap(), "SHA3-384");
    run_sha3_monte_tests::<Sha3_512>(sha3_512_path.to_str().unwrap(), "SHA3-512");
}
