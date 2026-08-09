use super::*;
use hex;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

fn vectors_file() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..") // up to crates/
        .join("..") // up to workspace root
        .join("tests")
        .join("src")
        .join("vectors")
        .join("legacy_rsp")
        .join("blake3")
        .join("blake3_vectors.json")
}

#[derive(Deserialize)]
struct TestCase {
    input_len: usize,
    hash: String,
    keyed_hash: String,
    derive_key: String,
}

#[derive(Deserialize)]
struct TestVectors {
    #[serde(rename = "_comment")]
    comment: String,
    key: String,
    context_string: String,
    cases: Vec<TestCase>,
}

// Function to generate input data with repeating pattern (as specified in test vectors)
fn generate_input(len: usize) -> Vec<u8> {
    // Generate the repeating pattern of 251 bytes: 0, 1, 2, ..., 249, 250, 0, 1, ...
    let mut input = Vec::with_capacity(len);
    for i in 0..len {
        input.push((i % 251) as u8);
    }
    input
}

#[test]
fn test_official_test_vectors() {
    // Load test vectors from JSON file
    let path = vectors_file();
    assert!(
        path.exists(),
        "Test vector file not found: {}",
        path.display()
    );

    let mut file = File::open(&path).expect("Failed to open test vectors file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read test vectors file");

    let vectors: TestVectors =
        serde_json::from_str(&contents).expect("Failed to parse test vectors JSON");

    // Print the comment for debugging purposes
    println!("Test vectors: {}", vectors.comment);

    // Get key and context string as bytes
    let key = vectors.key.as_bytes();
    let context = vectors.context_string.as_bytes();

    // Test each case
    for case in vectors.cases {
        // Generate input according to specified pattern and length
        let input = generate_input(case.input_len);

        // Test regular hash with default length (32 bytes)
        let default_len = 32;
        let result = Blake3Xof::generate(&input, default_len).unwrap();
        assert_eq!(
            hex::encode(result),
            &case.hash[..default_len * 2],
            "Default length hash failed for input_len {}",
            case.input_len
        );

        // Test regular hash with extended length
        let extended_len = case.hash.len() / 2; // Convert hex chars to bytes
        let extended_result = Blake3Xof::generate(&input, extended_len).unwrap();
        assert_eq!(
            hex::encode(extended_result),
            case.hash,
            "Extended length hash failed for input_len {}",
            case.input_len
        );

        // Test keyed hash with default and extended lengths
        let keyed_result = Blake3Xof::keyed_generate(key, &input, default_len).unwrap();
        assert_eq!(
            hex::encode(keyed_result),
            &case.keyed_hash[..default_len * 2],
            "Default length keyed hash failed for input_len {}",
            case.input_len
        );

        let extended_keyed_result = Blake3Xof::keyed_generate(key, &input, extended_len).unwrap();
        assert_eq!(
            hex::encode(extended_keyed_result),
            case.keyed_hash,
            "Extended length keyed hash failed for input_len {}",
            case.input_len
        );

        // Test derive key with default and extended lengths
        let derive_key_result = Blake3Xof::derive_key(context, &input, default_len).unwrap();
        assert_eq!(
            hex::encode(derive_key_result),
            &case.derive_key[..default_len * 2],
            "Default length derive key failed for input_len {}",
            case.input_len
        );

        let extended_derive_key_result =
            Blake3Xof::derive_key(context, &input, extended_len).unwrap();
        assert_eq!(
            hex::encode(extended_derive_key_result),
            case.derive_key,
            "Extended length derive key failed for input_len {}",
            case.input_len
        );
    }
}

#[test]
fn test_blake3_empty() {
    let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    let result = Blake3Xof::generate(&[], 32).unwrap();
    assert_eq!(hex::encode(result), expected);
}

#[test]
fn test_blake3_abc() {
    let expected = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";

    let result = Blake3Xof::generate(b"abc", 32).unwrap();
    assert_eq!(hex::encode(result), expected);
}

#[test]
fn test_blake3_incremental() {
    let expected = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";

    let mut xof = Blake3Xof::new();
    xof.update(b"a").unwrap();
    xof.update(b"b").unwrap();
    xof.update(b"c").unwrap();

    let result = xof.squeeze_into_vec(32).unwrap();
    assert_eq!(hex::encode(result), expected);
}

#[test]
fn test_blake3_keyed() {
    // Test vectors from the official BLAKE3 repo
    let key = b"whats the Elvish word for friend";
    let input = b"";
    let expected = "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26";

    let keyed_result = Blake3Xof::keyed_generate(key, input, 32).unwrap();
    assert_eq!(hex::encode(keyed_result), expected);
}

#[test]
fn test_blake3_derive_key() {
    // Test vectors from the official BLAKE3 repo
    let context = b"BLAKE3 2019-12-27 16:29:52 test vectors context";
    let input = b"";
    let expected = "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d";

    let derive_key_result = Blake3Xof::derive_key(context, input, 32).unwrap();
    assert_eq!(hex::encode(derive_key_result), expected);
}

#[test]
fn test_input_pattern() {
    // Test that our pattern generation works
    let input = generate_input(300);
    assert_eq!(input.len(), 300);
    assert_eq!(input[0], 0);
    assert_eq!(input[250], 250);
    assert_eq!(input[251], 0);
}

#[test]
fn debug_blake3_abc_step_by_step() {
    // This test goes through the entire process of hashing "abc" step by step
    let input = b"abc";

    // Step 1: Initialize the chunk state
    let mut chunk_state = ChunkState::new(&IV, 0, 0);

    // Step 2: Update with the input "abc"
    chunk_state.update(input).unwrap();

    // Step 3: Check block length and data
    assert_eq!(chunk_state.block_len, 3); // "abc" is 3 bytes
    assert_eq!(&chunk_state.block[..3], input);

    // Step 4: Generate output from the chunk state
    let output = chunk_state.output();

    // Step 5: Verify flags
    assert_eq!(output.flags, CHUNK_START | CHUNK_END);

    // Step 6: Generate the final hash with ROOT flag
    let mut result = [0u8; 32];
    output.root_output_bytes(&mut result);

    // Step 7: Verify against expected hash
    let expected = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85";
    assert_eq!(hex::encode(result), expected);
}
