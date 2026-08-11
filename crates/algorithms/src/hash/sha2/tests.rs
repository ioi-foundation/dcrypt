use super::*;
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
        .join("sha2")
}

#[test]
fn test_sha256_empty() {
    // NIST test vector: Empty string
    let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let hash = Sha256::digest(&[]).unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha256_abc() {
    // NIST test vector: "abc"
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    let hash = Sha256::digest(b"abc").unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha256_long() {
    // NIST test vector: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    let hash = Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha224_empty() {
    // NIST test vector: Empty string
    let expected = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";

    let hash = Sha224::digest(&[]).unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha512_empty() {
    // NIST test vector: Empty string
    let expected = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";

    let hash = Sha512::digest(&[]).unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha384_empty() {
    // NIST test vector: Empty string
    let expected = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";

    let hash = Sha384::digest(&[]).unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha512_224_empty() {
    // NIST test vector: Empty string for SHA-512/224
    let expected = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4";

    let hash = Sha512_224::digest(&[]).unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha512_256_empty() {
    // NIST test vector: Empty string for SHA-512/256
    let expected = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a";

    let hash = Sha512_256::digest(&[]).unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha512_224_abc() {
    // NIST test vector: "abc" for SHA-512/224
    let expected = "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa";

    let hash = Sha512_224::digest(b"abc").unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha512_256_abc() {
    // NIST test vector: "abc" for SHA-512/256
    let expected = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23";

    let hash = Sha512_256::digest(b"abc").unwrap();
    assert_eq!(hex::encode(hash.as_ref()), expected);
}

#[test]
fn test_sha2_non_byte_aligned_acvp_vectors() {
    // Repository ACVP-format fixtures. Input bits are stored MSB-first; the
    // fixtures' upstream acquisition provenance is unverified.
    let sha224 =
        Sha224::digest_bits(&hex::decode("7CACC1C2B56D26A96D3A5B7648").unwrap(), 102).unwrap();
    assert_eq!(
        hex::encode(sha224.as_ref()),
        "7b1b888dd4e5657ce7d20a6435b15c19ce2cf090d7928ed028220f44"
    );

    let sha384 = Sha384::digest_bits(&[0x5e], 7).unwrap();
    assert_eq!(
        hex::encode(sha384.as_ref()),
        "2429a641d5826314c9963e9d8e72398f015c86cbb4cce398701a4817d6fec0c687ef1a7b228ac4eb5e2b687bc6aa1fb2"
    );

    let sha512_224 = Sha512_224::digest_bits(&[0x00], 3).unwrap();
    assert_eq!(
        hex::encode(sha512_224.as_ref()),
        "22da154e08a398a7c8c335542c5217e3980a6cfdcfb8c634275698dd"
    );
}

#[test]
fn test_sha2_bit_input_validation_and_byte_equivalence() {
    let byte_digest = Sha256::digest(b"abc").unwrap();
    let bit_digest = Sha256::digest_bits(b"abc", 24).unwrap();
    assert_eq!(byte_digest.as_ref(), bit_digest.as_ref());

    assert!(Sha256::digest_bits(&[0x81], 1).is_err());
    assert!(Sha256::digest_bits(&[], 1).is_err());
    assert!(Sha256::digest_bits(&[0x80, 0x00], 1).is_err());
}

fn padded_bit_message(data: &[u8], bit_len: usize, block_bytes: usize) -> Vec<u8> {
    let length_bytes = block_bytes / 8;
    let padded_bits = (bit_len + 1 + length_bytes * 8).div_ceil(block_bytes * 8) * block_bytes * 8;
    let mut padded = vec![0u8; padded_bits / 8];
    for bit in 0..bit_len {
        if data[bit / 8] & (0x80 >> (bit % 8)) != 0 {
            padded[bit / 8] |= 0x80 >> (bit % 8);
        }
    }
    padded[bit_len / 8] |= 0x80 >> (bit_len % 8);
    let encoded_len = (bit_len as u128).to_be_bytes();
    let start = padded.len() - length_bytes;
    padded[start..].copy_from_slice(&encoded_len[16 - length_bytes..]);
    padded
}

fn reference_sha256_bits(data: &[u8], bit_len: usize) -> Vec<u8> {
    let padded = padded_bit_message(data, bit_len, SHA256_BLOCK_SIZE);
    let mut state = Sha256::init_state();
    for chunk in padded.chunks_exact(SHA256_BLOCK_SIZE) {
        let mut block = [0u8; SHA256_BLOCK_SIZE];
        block.copy_from_slice(chunk);
        Sha256::compress(&mut state, &block).unwrap();
    }
    state.iter().flat_map(|word| word.to_be_bytes()).collect()
}

fn reference_sha512_bits(data: &[u8], bit_len: usize) -> Vec<u8> {
    let padded = padded_bit_message(data, bit_len, SHA512_BLOCK_SIZE);
    let mut state = Sha512::init_state();
    for chunk in padded.chunks_exact(SHA512_BLOCK_SIZE) {
        let mut block = [0u8; SHA512_BLOCK_SIZE];
        block.copy_from_slice(chunk);
        Sha512::compress(&mut state, &block).unwrap();
    }
    state.iter().flat_map(|word| word.to_be_bytes()).collect()
}

#[test]
fn test_sha2_partial_bit_padding_boundaries() {
    for byte_index in [55usize, 56, 63] {
        let bit_len = byte_index * 8 + 3;
        let mut message = vec![0xA5; bit_len.div_ceil(8)];
        *message.last_mut().unwrap() = 0xA0;
        let digest = Sha256::digest_bits(&message, bit_len).unwrap();
        assert_eq!(
            digest.as_ref(),
            reference_sha256_bits(&message, bit_len),
            "SHA-256 partial byte at buffer index {byte_index}"
        );
    }

    for byte_index in [111usize, 112, 127] {
        let bit_len = byte_index * 8 + 3;
        let mut message = vec![0x5A; bit_len.div_ceil(8)];
        *message.last_mut().unwrap() = 0xA0;
        let digest = Sha512::digest_bits(&message, bit_len).unwrap();
        assert_eq!(
            digest.as_ref(),
            reference_sha512_bits(&message, bit_len),
            "SHA-512 partial byte at buffer index {byte_index}"
        );
    }
}

#[test]
fn test_sha2_nist_short_vectors() {
    let dir = vectors_dir();

    // Path to the test vector files
    let sha224_path = dir.join("SHA224ShortMsg.rsp");
    let sha256_path = dir.join("SHA256ShortMsg.rsp");
    let sha384_path = dir.join("SHA384ShortMsg.rsp");
    let sha512_path = dir.join("SHA512ShortMsg.rsp");

    // Check if files exist and provide helpful message if they don't
    for path in [&sha224_path, &sha256_path, &sha384_path, &sha512_path] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }

    // Run the tests
    run_sha2_tests::<Sha224>(sha224_path.to_str().unwrap(), "SHA-224");
    run_sha2_tests::<Sha256>(sha256_path.to_str().unwrap(), "SHA-256");
    run_sha2_tests::<Sha384>(sha384_path.to_str().unwrap(), "SHA-384");
    run_sha2_tests::<Sha512>(sha512_path.to_str().unwrap(), "SHA-512");
}

#[test]
fn test_sha2_nist_long_vectors() {
    let dir = vectors_dir();

    // Path to the long message test vector files
    let sha224_path = dir.join("SHA224LongMsg.rsp");
    let sha256_path = dir.join("SHA256LongMsg.rsp");
    let sha384_path = dir.join("SHA384LongMsg.rsp");
    let sha512_path = dir.join("SHA512LongMsg.rsp");

    // Check if files exist and provide helpful message if they don't
    for path in [&sha224_path, &sha256_path, &sha384_path, &sha512_path] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }

    // Run the same test functions for long messages
    run_sha2_tests::<Sha224>(sha224_path.to_str().unwrap(), "SHA-224");
    run_sha2_tests::<Sha256>(sha256_path.to_str().unwrap(), "SHA-256");
    run_sha2_tests::<Sha384>(sha384_path.to_str().unwrap(), "SHA-384");
    run_sha2_tests::<Sha512>(sha512_path.to_str().unwrap(), "SHA-512");
}

#[derive(Debug)]
struct Sha2TestVector {
    len: usize,  // Bit length
    msg: String, // Hex-encoded message
    md: String,  // Hex-encoded digest (expected hash)
}

fn parse_sha2_test_file(filepath: &str) -> Vec<Sha2TestVector> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    let file = File::open(Path::new(filepath)).expect("Failed to open test vector file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut test_vectors = Vec::new();
    let mut current_vector: Option<Sha2TestVector> = None;

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

            current_vector = Some(Sha2TestVector {
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

fn run_sha2_tests<H: HashFunction>(filepath: &str, name: &str)
where
    H::Output: AsRef<[u8]>,
{
    let test_vectors = parse_sha2_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Check if bit length is 0
        if test.len == 0 {
            // If bit length is 0, use an empty message regardless of what's in the msg field
            let hash = H::digest(&[]).unwrap();

            // Convert expected hash to bytes
            let expected = hex::decode(&test.md)
                .unwrap_or_else(|_| panic!("Invalid hex in expected result {}: {}", i, test.md));

            // Compare byte slices instead of types directly
            assert_eq!(
                hash.as_ref(),
                expected.as_slice(),
                "{} test case {} failed. Input: empty, Expected: {}, Got: {}",
                name,
                i,
                test.md,
                hex::encode(hash.as_ref())
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

                // Compare byte slices instead of types directly
                assert_eq!(
                    hash.as_ref(),
                    expected.as_slice(),
                    "{} test case {} failed. Input: {}, Expected: {}, Got: {}",
                    name,
                    i,
                    test.msg,
                    test.md,
                    hex::encode(hash.as_ref())
                );

                continue;
            }
        }

        // Hash the message
        let hash = H::digest(&msg).unwrap();

        // Convert expected hash to bytes
        let expected = hex::decode(&test.md)
            .unwrap_or_else(|_| panic!("Invalid hex in expected result {}: {}", i, test.md));

        // Compare byte slices instead of types directly
        assert_eq!(
            hash.as_ref(),
            expected.as_slice(),
            "{} test case {} failed. Input: {}, Expected: {}, Got: {}",
            name,
            i,
            test.msg,
            test.md,
            hex::encode(hash.as_ref())
        );
    }
}

#[test]
fn test_sha2_nist_monte_vectors() {
    let dir = vectors_dir();

    // Path to the Monte Carlo test vector files
    let sha224_path = dir.join("SHA224Monte.rsp");
    let sha256_path = dir.join("SHA256Monte.rsp");
    let sha384_path = dir.join("SHA384Monte.rsp");
    let sha512_path = dir.join("SHA512Monte.rsp");

    // Check if files exist and provide helpful message if they don't
    for path in [&sha224_path, &sha256_path, &sha384_path, &sha512_path] {
        assert!(
            path.exists(),
            "Test vector file not found: {}",
            path.display()
        );
    }

    // Run Monte Carlo tests for each SHA-2 variant
    run_sha2_monte_tests::<Sha224>(sha224_path.to_str().unwrap(), "SHA-224");
    run_sha2_monte_tests::<Sha256>(sha256_path.to_str().unwrap(), "SHA-256");
    run_sha2_monte_tests::<Sha384>(sha384_path.to_str().unwrap(), "SHA-384");
    run_sha2_monte_tests::<Sha512>(sha512_path.to_str().unwrap(), "SHA-512");
}

#[derive(Debug)]
struct Sha2MonteTestVector {
    seed: String,     // Initial seed
    count: usize,     // Number of iterations
    expected: String, // Expected final MD value
}

fn parse_sha2_monte_test_file(filepath: &str) -> Vec<Sha2MonteTestVector> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

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
                test_vectors.push(Sha2MonteTestVector {
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
        } else if line.starts_with("MD = ") && count == 1000 {
            // SHA-2 uses 1000 iterations
            current_expected = line.strip_prefix("MD = ").unwrap().to_string();
        }
    }

    // Add the last test vector if present
    if !current_seed.is_empty() && !current_expected.is_empty() {
        test_vectors.push(Sha2MonteTestVector {
            seed: current_seed,
            count,
            expected: current_expected,
        });
    }

    test_vectors
}

// The actual Monte Carlo test procedure for SHA-2
// Modified to remove unnecessary trait bound and fix Vec::from usage
fn run_sha2_monte_tests<H: HashFunction>(filepath: &str, name: &str)
where
    H::Output: AsRef<[u8]>,
{
    let test_vectors = parse_sha2_monte_test_file(filepath);

    for (i, test) in test_vectors.iter().enumerate() {
        // Convert seed to bytes
        let seed_bytes = hex::decode(&test.seed).unwrap_or_else(|_| {
            panic!(
                "{} Monte Carlo test {}: Invalid seed hex: {}",
                name, i, test.seed
            )
        });

        // SHA-2 Monte Carlo test
        // For each j from 0 to 999
        //    Compute MD_j = MD_{j-3} || MD_{j-2} || MD_{j-1}
        //    Compute MD_j = SHA(MD_j)

        // Initialize MD array
        let mut md = Vec::new();
        md.push(seed_bytes.clone()); // MD_0

        let digest1 = H::digest(&seed_bytes).unwrap();
        md.push(digest1.as_ref().to_vec()); // MD_1

        let digest2 = H::digest(md[1].as_slice()).unwrap();
        md.push(digest2.as_ref().to_vec()); // MD_2

        // Perform the specified number of iterations
        for _j in 3..=test.count {
            // Compute MD_j = MD_{j-3} || MD_{j-2} || MD_{j-1}
            let mut input = Vec::new();
            input.extend_from_slice(&md[md.len() - 3]);
            input.extend_from_slice(&md[md.len() - 2]);
            input.extend_from_slice(&md[md.len() - 1]);

            // Compute MD_j = SHA(MD_j)
            let digest = H::digest(&input).unwrap();
            md.push(digest.as_ref().to_vec());
        }

        // Verify the final result matches the expected value
        let expected = hex::decode(&test.expected).unwrap_or_else(|_| {
            panic!(
                "{} Monte Carlo test {}: Invalid expected hex: {}",
                name, i, test.expected
            )
        });

        assert_eq!(
            md[test.count].as_slice(),
            expected.as_slice(),
            "{} Monte Carlo test case {} failed.\nExpected: {}\nGot: {}",
            name,
            i,
            test.expected,
            hex::encode(&md[test.count])
        );
    }
}
