// src/xof/shake/tests.rs

use super::*;
use hex;

fn patterned_bit_string(bit_len: usize) -> Vec<u8> {
    let mut message: Vec<u8> = (0..(bit_len + 7) / 8)
        .map(|index| (index as u8).wrapping_mul(73).wrapping_add(41))
        .collect();
    if bit_len % 8 != 0 {
        *message.last_mut().unwrap() &= 0xff << (8 - bit_len % 8);
    }
    message
}

#[test]
fn test_shake128_empty_output() {
    let mut xof = ShakeXof128::new();
    let result = xof.squeeze_into_vec(0);
    assert!(result.is_err());

    let mut empty_buffer = [];
    let result = xof.squeeze(&mut empty_buffer);
    assert!(result.is_err());
}

#[test]
fn test_shake256_state_errors() {
    let mut xof = ShakeXof256::new();
    xof.finalize().unwrap();

    // Should error when updating after finalization
    let result = xof.update(b"test");
    assert!(matches!(result, Err(Error::Processing { .. })));

    // Should work to squeeze after finalization
    let mut output = [0u8; 32];
    assert!(xof.squeeze(&mut output).is_ok());

    // Should error when updating after squeezing
    let result = xof.update(b"test");
    assert!(matches!(result, Err(Error::Processing { .. })));
}

#[test]
fn test_shake_reset() {
    let mut xof = ShakeXof128::new();
    xof.update(b"test").unwrap();
    xof.finalize().unwrap();

    let mut first_output = [0u8; 32];
    xof.squeeze(&mut first_output).unwrap();

    // Reset should clear all state
    xof.reset().unwrap();

    // Should be able to update again
    assert!(xof.update(b"test").is_ok());
    assert!(!xof.is_finalized);
    assert!(!xof.squeezing);
}

#[test]
fn test_shake128_xof_variable_length() {
    // NIST test vectors for SHAKE-128
    let empty_32_expected = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";

    let mut xof = ShakeXof128::new();
    xof.update(&[]).unwrap();
    let output = xof.squeeze_into_vec(32).unwrap();

    assert_eq!(hex::encode(&output), empty_32_expected);

    // Test generating more output
    let output2 = xof.squeeze_into_vec(32).unwrap();
    assert_ne!(output, output2); // Second 32 bytes should be different

    // Test with longer input
    let abc_32_expected = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8";

    let mut xof = ShakeXof128::new();
    xof.update(b"abc").unwrap();
    let output = xof.squeeze_into_vec(32).unwrap();

    assert_eq!(hex::encode(&output), abc_32_expected);
}

#[test]
fn test_shake_bit_oriented_nist_vectors() {
    let shake128 = ShakeXof128::generate_bits(&[0xc0], 2, 16).unwrap();
    assert_eq!(
        hex::encode(&shake128[..]),
        "f6b6c4093f0a2ceba61b9f2c2fea2ca2"
    );

    let shake256 = ShakeXof256::generate_bits(&[0x80], 2, 32).unwrap();
    assert_eq!(
        hex::encode(&shake256[..]),
        "d93f97bf0211bbd33df10904e7f7ed9cd476eafa7f658f6442f660d2b4520bd1"
    );
}

#[test]
fn test_shake_bit_oriented_api_preserves_byte_input_and_rejects_ambiguity() {
    let mut ordinary = ShakeXof128::new();
    ordinary.update(b"abc").unwrap();
    let ordinary = ordinary.squeeze_into_vec(32).unwrap();
    let bit_oriented = ShakeXof128::generate_bits(b"abc", 24, 32).unwrap();
    assert_eq!(&ordinary[..], &bit_oriented[..]);

    assert!(ShakeXof128::generate_bits(&[0xc1], 2, 16).is_err());
    assert!(ShakeXof128::generate_bits(&[0xc0, 0x00], 2, 16).is_err());
}

#[test]
fn test_shake_bit_suffix_at_and_across_rate_boundary() {
    // Cross-checked against XKCP Keccak_HashUpdate/Final.  1339/1083 input
    // bits plus SHAKE's five-bit delimited suffix exactly fill a rate block;
    // the following lengths exercise the mid-suffix permutation path.
    for (bit_len, expected) in [
        (
            1339,
            "e7ee91cb733ee18991bcdc70a5d86a85089de10af3bb6ce79dd044a943e00949",
        ),
        (
            1340,
            "28d7998d7dbe58d22b05c2124aa5d083f7d4592687da46c068cdccce0cff5fbf",
        ),
    ] {
        let output =
            ShakeXof128::generate_bits(&patterned_bit_string(bit_len), bit_len, 32).unwrap();
        assert_eq!(hex::encode(&output[..]), expected);
    }

    for (bit_len, expected) in [
        (
            1083,
            "351d0f4ee4e56c3ec44b15248b764cf88540a31a78341b59976fa5226b2332cc",
        ),
        (
            1084,
            "3efc9658ff69ec5617e1e25cd877a9e53d134a621e011060cfd081b6201c1b69",
        ),
    ] {
        let output =
            ShakeXof256::generate_bits(&patterned_bit_string(bit_len), bit_len, 32).unwrap();
        assert_eq!(hex::encode(&output[..]), expected);
    }
}

#[test]
fn test_shake256_xof_variable_length() {
    // NIST test vectors for SHAKE-256
    let empty_64_expected = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";

    let mut xof = ShakeXof256::new();
    xof.update(&[]).unwrap();
    let output = xof.squeeze_into_vec(64).unwrap();

    assert_eq!(hex::encode(&output), empty_64_expected);

    // Test generating more output in multiple calls
    let mut xof = ShakeXof256::new();
    xof.update(&[]).unwrap();
    let output1 = xof.squeeze_into_vec(32).unwrap();
    let output2 = xof.squeeze_into_vec(32).unwrap();

    let mut combined = Vec::new();
    combined.extend_from_slice(&output1);
    combined.extend_from_slice(&output2);

    assert_eq!(hex::encode(&combined), empty_64_expected);
}

#[test]
fn test_xof_reuse_error() {
    // Test that attempting to update after finalization fails
    let mut xof = ShakeXof256::new();
    xof.update(b"test").unwrap();
    xof.finalize().unwrap();

    let result = xof.update(b"more data");
    assert!(result.is_err());

    // Test that attempting to update after squeezing fails
    let mut xof = ShakeXof256::new();
    xof.update(b"test").unwrap();
    let _ = xof.squeeze_into_vec(32).unwrap();

    let result = xof.update(b"more data");
    assert!(result.is_err());
}

#[test]
fn test_xof_reset() {
    // Test that reset works correctly
    let mut xof = ShakeXof256::new();
    xof.update(b"test").unwrap();
    let output1 = xof.squeeze_into_vec(32).unwrap();

    // Reset and process same data
    xof.reset().unwrap();
    xof.update(b"test").unwrap();
    let output2 = xof.squeeze_into_vec(32).unwrap();

    // Should get same result after reset
    assert_eq!(output1, output2);
}

#[test]
fn test_shake_xof_incremental_output() {
    // Test that extracting output incrementally gives the same results as all at once
    let test_data = b"test data for incremental output";

    // SHAKE-128
    let mut xof128 = ShakeXof128::new();
    xof128.update(test_data).unwrap();
    xof128.finalize().unwrap();

    // Extract 100 bytes total, in two parts
    let part1_128 = xof128.squeeze_into_vec(50).unwrap();
    let part2_128 = xof128.squeeze_into_vec(50).unwrap();

    // Extract 100 bytes all at once
    let mut xof128_all = ShakeXof128::new();
    xof128_all.update(test_data).unwrap();
    let all_128 = xof128_all.squeeze_into_vec(100).unwrap();

    // Compare
    let mut combined_128 = part1_128.to_vec();
    combined_128.extend_from_slice(&part2_128);
    assert_eq!(
        combined_128.as_slice(),
        all_128.as_slice(),
        "SHAKE-128 incremental output doesn't match combined output"
    );

    // SHAKE-256
    let mut xof256 = ShakeXof256::new();
    xof256.update(test_data).unwrap();
    xof256.finalize().unwrap();

    // Extract 100 bytes total, in two parts
    let part1_256 = xof256.squeeze_into_vec(50).unwrap();
    let part2_256 = xof256.squeeze_into_vec(50).unwrap();

    // Extract 100 bytes all at once
    let mut xof256_all = ShakeXof256::new();
    xof256_all.update(test_data).unwrap();
    let all_256 = xof256_all.squeeze_into_vec(100).unwrap();

    // Compare
    let mut combined_256 = part1_256.to_vec();
    combined_256.extend_from_slice(&part2_256);
    assert_eq!(
        combined_256.as_slice(),
        all_256.as_slice(),
        "SHAKE-256 incremental output doesn't match combined output"
    );
}

#[test]
fn debug_shake_implementation() {
    println!("\nDebugging SHAKE implementation:");

    // Empty input test
    let empty_input: [u8; 0] = [];
    let mut shake128 = ShakeXof128::new();
    shake128.update(&empty_input).unwrap();
    let shake_empty_result = shake128.squeeze_into_vec(32).unwrap();

    println!(
        "SHAKE-128 empty input (actual):   {}",
        hex::encode(&shake_empty_result)
    );
    println!("SHAKE-128 empty input (expected): 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");

    // "abc" input test
    let abc_input = b"abc";
    let mut shake128 = ShakeXof128::new();
    shake128.update(abc_input).unwrap();
    let shake_abc_result = shake128.squeeze_into_vec(32).unwrap();

    println!(
        "SHAKE-128 'abc' input (actual):   {}",
        hex::encode(&shake_abc_result)
    );
    println!("SHAKE-128 'abc' input (expected): 5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");

    // SHAKE-256 tests
    let mut shake256 = ShakeXof256::new();
    shake256.update(&empty_input).unwrap();
    let shake256_empty_result = shake256.squeeze_into_vec(64).unwrap();

    println!(
        "\nSHAKE-256 empty input (actual):   {}",
        hex::encode(&shake256_empty_result)
    );
    println!("SHAKE-256 empty input (expected): 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");

    // For debugging
    println!("\nAnalyzing SHAKE state transitions:");

    // Empty input to SHAKE-128
    let mut debug_shake = ShakeXof128::new();
    debug_shake.update(&empty_input).unwrap();

    // Inspect buffer before finalization
    println!("Before finalize, buffer_idx: {}", debug_shake.buffer_idx);

    debug_shake.finalize().unwrap();

    // Extract raw buffer state for debugging
    if debug_shake.buffer_idx == 0 {
        println!("After finalize:");
        println!(
            "  First byte (should be 0x1F): {:02x}",
            debug_shake.buffer.as_ref()[0]
        );
        println!(
            "  Last byte (should be 0x80): {:02x}",
            debug_shake.buffer.as_ref()[SHAKE128_RATE - 1]
        );
    }
}

// This function handles NIST XOF test vectors with VARIABLE output lengths
fn run_shake_xof_tests<X: ExtendableOutputFunction>(filepath: &str, name: &str) {
    let test_vectors = parse_shake_test_file(filepath);
    println!("Found {} test vectors in {}", test_vectors.len(), filepath);

    let mut tested = 0;
    let mut skipped = 0;

    for (i, test) in test_vectors.iter().enumerate() {
        let bit_len = test.output_len;
        let output_bytes = bit_len.div_ceil(8);

        // Skip zero-length outputs
        if bit_len == 0 || test.output.is_empty() {
            println!(
                "Skipping test case {}: zero-length output ({} bits)",
                i, bit_len
            );
            skipped += 1;
            continue;
        }

        // Verify declared bit length matches hex string length
        let expected_bytes = test.output.len() / 2;
        if output_bytes != expected_bytes {
            println!(
                "Skipping test case {}: declared {} bits → {} bytes, but hex is {} bytes",
                i, bit_len, output_bytes, expected_bytes
            );
            skipped += 1;
            continue;
        }

        // 1) Empty-input case
        if test.len == 0 {
            let mut xof = X::new();
            xof.update(&[]).unwrap();
            let result = xof.squeeze_into_vec(output_bytes).unwrap();
            let expected = hex::decode(&test.output).unwrap();
            let n = result.len().min(expected.len());
            assert_eq!(
                &result[..n],
                &expected[..n],
                "{} test case {} failed (empty input, {} bits)",
                name,
                i,
                bit_len
            );
            tested += 1;
            continue;
        }

        // 2) Partial-bit-length inputs (not a whole number of bytes)
        if test.len % 8 != 0 {
            let bytes = test.len / 8;
            let bits = test.len % 8;
            let msg_bytes = hex::decode(&test.msg).unwrap();
            if bytes < msg_bytes.len() {
                let mut truncated = msg_bytes[..bytes].to_vec();
                if bits > 0 {
                    let mask = (1u8 << bits) - 1;
                    truncated.push(msg_bytes[bytes] & mask);
                }
                let mut xof = X::new();
                xof.update(&truncated).unwrap();
                let result = xof.squeeze_into_vec(output_bytes).unwrap();
                let expected = hex::decode(&test.output).unwrap();
                let m = result.len().min(expected.len());
                assert_eq!(
                    &result[..m],
                    &expected[..m],
                    "{} test case {} failed ({}-bit input, {} bits out)",
                    name,
                    i,
                    test.len,
                    bit_len
                );
                tested += 1;
                continue;
            }
        }

        // 3) Full-byte message case
        let msg = if test.msg.is_empty() {
            Vec::new()
        } else {
            hex::decode(&test.msg).unwrap()
        };
        let mut xof = X::new();
        xof.update(&msg).unwrap();
        let result = xof.squeeze_into_vec(output_bytes).unwrap();
        let expected = hex::decode(&test.output).unwrap();
        let cmp_len = result.len().min(expected.len());
        assert_eq!(
            &result[..cmp_len],
            &expected[..cmp_len],
            "{} test case {} failed ({} bytes in → {} bits out)",
            name,
            i,
            msg.len(),
            bit_len
        );
        tested += 1;
    }

    println!("{} tests: {} passed, {} skipped", name, tested, skipped);
}

#[derive(Debug)]
struct ShakeTestVector {
    len: usize,        // Input length in bits
    msg: String,       // Hex-encoded message
    output_len: usize, // Length of output in bits
    output: String,    // Hex-encoded output (expected hash)
}

fn parse_shake_test_file(filepath: &str) -> Vec<ShakeTestVector> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::path::Path;

    // Attempt to open the file, return empty vector if not found
    let file = match File::open(Path::new(filepath)) {
        Ok(f) => f,
        Err(_) => {
            println!("Test vector file not found: {}", filepath);
            println!("Please ensure the test vectors are in the correct directory.");
            return Vec::new();
        }
    };

    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut test_vectors = Vec::new();
    let mut current_vector: Option<ShakeTestVector> = None;
    let mut in_test_group = false;

    while let Some(Ok(line)) = lines.next() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Detect test group headers like [Keylen = 256]
        if line.starts_with('[') && line.ends_with(']') {
            in_test_group = true;
            continue;
        }

        // Only parse lines that start with specific keys
        if let Some(stripped) = line.strip_prefix("Len = ") {
            // Start of a new test case
            if let Some(vector) = current_vector.take() {
                test_vectors.push(vector);
            }

            // Extract bit length
            let len = match stripped.trim().parse::<usize>() {
                Ok(val) => val,
                Err(_) => {
                    println!("Warning: Invalid length format in line: {}", line);
                    continue;
                }
            };

            current_vector = Some(ShakeTestVector {
                len,
                msg: String::new(),
                output_len: 0, // Will be set later
                output: String::new(),
            });
        } else if let Some(stripped) = line.strip_prefix("OutLen = ") {
            // Extract output length in bits
            if let Some(ref mut vector) = current_vector {
                vector.output_len = match stripped.trim().parse::<usize>() {
                    Ok(val) => val,
                    Err(_) => {
                        println!("Warning: Invalid output length format in line: {}", line);
                        0
                    }
                };
            }
        } else if let Some(ref mut vector) = current_vector {
            // Parse test vector data
            if let Some(stripped) = line.strip_prefix("Msg = ") {
                vector.msg = stripped.trim().to_string();
            } else if let Some(stripped) = line.strip_prefix("Output = ") {
                vector.output = stripped.trim().to_string();

                // If OutLen wasn't specified, derive it from the output hex length
                if vector.output_len == 0 && !vector.output.is_empty() {
                    // Each hex character represents 4 bits
                    vector.output_len = vector.output.len() * 4;
                }
            } else if line.starts_with("Count = ") && in_test_group {
                // NIST-style test vectors often use "Count = N" to start a new test case
                if let Some(old_vector) = current_vector.take() {
                    test_vectors.push(old_vector);
                }

                // Start a new vector with default values
                current_vector = Some(ShakeTestVector {
                    len: 0, // Will be set by specific fields
                    msg: String::new(),
                    output_len: 0,
                    output: String::new(),
                });
            }
        }
    }

    // Add the last test vector if present
    if let Some(vector) = current_vector {
        if !vector.output.is_empty() {
            test_vectors.push(vector);
        }
    }

    test_vectors
}

#[test]
fn test_shake_nist_variable_output() {
    // Path to the test vector files
    let base_path = env!("CARGO_MANIFEST_DIR");
    let vectors_dir = format!("{}/../dcrypt-test/src/vectors", base_path);

    // Path to the variable output test vector files
    let shake128_path = format!("{}/shake/SHAKE128VariableOut.rsp", vectors_dir);
    let shake256_path = format!("{}/shake/SHAKE256VariableOut.rsp", vectors_dir);

    // Run XOF tests - specifically with variable output sizes
    run_shake_xof_tests::<ShakeXof128>(&shake128_path, "SHAKE-128");
    run_shake_xof_tests::<ShakeXof256>(&shake256_path, "SHAKE-256");

    // Also test short message files which have different output lengths
    let shake128_short_path = format!("{}/shake/SHAKE128ShortMsg.rsp", vectors_dir);
    let shake256_short_path = format!("{}/shake/SHAKE256ShortMsg.rsp", vectors_dir);

    run_shake_xof_tests::<ShakeXof128>(&shake128_short_path, "SHAKE-128 (Short)");
    run_shake_xof_tests::<ShakeXof256>(&shake256_short_path, "SHAKE-256 (Short)");
}
