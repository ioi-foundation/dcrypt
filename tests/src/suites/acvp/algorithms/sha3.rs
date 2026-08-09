//! ACVP handlers for SHA-3 hash functions

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{FlexValue, TestCase, TestGroup};
use dcrypt_algorithms::hash::sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use dcrypt_algorithms::hash::HashFunction;
use hex;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

trait AcvpSha3 {
    fn digest_bits(message: &[u8], bit_len: usize) -> Result<Vec<u8>>;
}

macro_rules! impl_acvp_sha3 {
    ($type:ty) => {
        impl AcvpSha3 for $type {
            fn digest_bits(message: &[u8], bit_len: usize) -> Result<Vec<u8>> {
                Ok(<$type>::digest_bits(message, bit_len)?.as_ref().to_vec())
            }
        }
    };
}

impl_acvp_sha3!(Sha3_224);
impl_acvp_sha3!(Sha3_256);
impl_acvp_sha3!(Sha3_384);
impl_acvp_sha3!(Sha3_512);

fn usize_field(value: Option<&FlexValue>, name: &'static str) -> Result<usize> {
    value
        .map(FlexValue::as_string)
        .and_then(|value| value.parse().ok())
        .ok_or(EngineError::MissingField(name))
}

/// Decode ACVP's left-aligned representation of a bit string.  Some older
/// vector sets use a single `00` byte as the sentinel for an empty string.
fn decode_message_bits(encoded: &str, bit_len: usize) -> Result<Vec<u8>> {
    let mut message = hex::decode(encoded)?;
    if bit_len == 0 && message == [0] {
        message.clear();
    }

    let expected_len = bit_len
        .checked_add(7)
        .ok_or_else(|| EngineError::InvalidData("message bit length overflows usize".into()))?
        / 8;
    if message.len() != expected_len {
        return Err(EngineError::InvalidData(format!(
            "{}-bit message requires {} encoded bytes, got {}",
            bit_len,
            expected_len,
            message.len()
        )));
    }
    if bit_len % 8 != 0 {
        let unused_mask = (1u8 << (8 - bit_len % 8)) - 1;
        if message.last().copied().unwrap_or(0) & unused_mask != 0 {
            return Err(EngineError::InvalidData(
                "unused low bits in the final message byte must be zero".into(),
            ));
        }
    }
    Ok(message)
}

fn sha3_digest(group: &TestGroup, message: &[u8], bit_len: usize) -> Result<Vec<u8>> {
    match group.algorithm.as_str() {
        "SHA3-224" | "SHA-3-224" => <Sha3_224 as AcvpSha3>::digest_bits(message, bit_len),
        "SHA3-256" | "SHA-3-256" => <Sha3_256 as AcvpSha3>::digest_bits(message, bit_len),
        "SHA3-384" | "SHA-3-384" => <Sha3_384 as AcvpSha3>::digest_bits(message, bit_len),
        "SHA3-512" | "SHA-3-512" => <Sha3_512 as AcvpSha3>::digest_bits(message, bit_len),
        algorithm => Err(EngineError::InvalidData(format!(
            "Unsupported SHA-3 variant: {}",
            algorithm
        ))),
    }
}

/// SHA-3 Algorithm Family Test (AFT) handler
/// Handles SHA3-224, SHA3-256, SHA3-384, and SHA3-512
pub(crate) fn sha3_aft(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get the message to hash - ACVP uses "msg" field
    let msg_hex = case
        .inputs
        .get("msg")
        .or_else(|| case.inputs.get("message"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("msg"))?;

    let bit_len = usize_field(
        case.inputs.get("len").or_else(|| case.inputs.get("msgLen")),
        "len",
    )?;
    let msg_bytes = decode_message_bits(&msg_hex, bit_len)?;

    // Get expected digest if provided (for validation)
    let expected_md = case
        .inputs
        .get("md")
        .or_else(|| case.inputs.get("digest"))
        .map(|v| v.as_string());

    let digest_hex = hex::encode(sha3_digest(group, &msg_bytes, bit_len)?);

    // Check result if expected value was provided
    if let Some(expected) = expected_md {
        if !super::hex_equal(&digest_hex, &expected) {
            return Err(EngineError::Mismatch {
                expected,
                actual: digest_hex,
            });
        }
    } else {
        // Store result for response generation
        case.outputs.borrow_mut().insert("md".into(), digest_hex);
    }

    Ok(())
}

/// SHA-3 Monte Carlo Test (MCT) handler
pub(crate) fn sha3_mct(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get the initial seed
    let seed_hex = case
        .inputs
        .get("seed")
        .or_else(|| case.inputs.get("msg"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("seed"))?;

    let seed_bit_len = usize_field(
        case.inputs.get("len").or_else(|| case.inputs.get("msgLen")),
        "len",
    )?;
    let seed_bytes = decode_message_bits(&seed_hex, seed_bit_len)?;
    let alternate = group
        .defaults
        .get("mctVersion")
        .map(FlexValue::as_string)
        .unwrap_or_else(|| "standard".into())
        .eq_ignore_ascii_case("alternate");

    let results = match group.algorithm.as_str() {
        "SHA3-224" | "SHA-3-224" => {
            sha3_mct_inner::<Sha3_224>(&seed_bytes, seed_bit_len, alternate)?
        }
        "SHA3-256" | "SHA-3-256" => {
            sha3_mct_inner::<Sha3_256>(&seed_bytes, seed_bit_len, alternate)?
        }
        "SHA3-384" | "SHA-3-384" => {
            sha3_mct_inner::<Sha3_384>(&seed_bytes, seed_bit_len, alternate)?
        }
        "SHA3-512" | "SHA-3-512" => {
            sha3_mct_inner::<Sha3_512>(&seed_bytes, seed_bit_len, alternate)?
        }
        algorithm => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHA-3 variant: {}",
                algorithm
            )))
        }
    };

    if let Some(expected) = case.inputs.get("resultsArray") {
        compare_sha3_mct_results(expected, &results)
    } else {
        let response: Vec<_> = results
            .iter()
            .map(|digest| serde_json::json!({ "md": hex::encode_upper(digest) }))
            .collect();
        case.outputs.borrow_mut().insert(
            "resultsArray".into(),
            serde_json::to_string(&response)
                .map_err(|error| EngineError::InvalidData(error.to_string()))?,
        );
        Ok(())
    }
}

fn normalize_mct_message(message: &[u8], bit_len: usize) -> Vec<u8> {
    let byte_len = (bit_len + 7) / 8;
    let mut normalized = vec![0; byte_len];
    let copied = message.len().min(byte_len);
    normalized[..copied].copy_from_slice(&message[..copied]);
    if bit_len % 8 != 0 {
        normalized[byte_len - 1] &= !((1u8 << (8 - bit_len % 8)) - 1);
    }
    normalized
}

/// FIPS 202 / ACVP SHA-3 MCT: 100 reported iterations, each containing
/// 1000 hashes.  The alternate form truncates or right-zero-pads every inner
/// message back to the original seed length before hashing.
fn sha3_mct_inner<H: AcvpSha3>(
    seed: &[u8],
    seed_bit_len: usize,
    alternate: bool,
) -> Result<Vec<Vec<u8>>> {
    let mut message = seed.to_vec();
    let mut results = Vec::with_capacity(100);
    for _ in 0..100 {
        for _ in 0..1000 {
            let (input, input_bits) = if alternate {
                (normalize_mct_message(&message, seed_bit_len), seed_bit_len)
            } else {
                let bits = message.len().checked_mul(8).ok_or_else(|| {
                    EngineError::InvalidData("MCT message length overflows usize".into())
                })?;
                (message, bits)
            };
            message = H::digest_bits(&input, input_bits)?;
        }
        results.push(message.clone());
    }
    Ok(results)
}

fn compare_sha3_mct_results(expected: &FlexValue, actual: &[Vec<u8>]) -> Result<()> {
    let FlexValue::Array(expected) = expected else {
        return Err(EngineError::InvalidData(
            "resultsArray must be an array".into(),
        ));
    };
    if expected.len() != actual.len() {
        return Err(EngineError::Mismatch {
            expected: format!("{} MCT results", expected.len()),
            actual: format!("{} MCT results", actual.len()),
        });
    }
    for (index, (expected, actual)) in expected.iter().zip(actual).enumerate() {
        let FlexValue::Object(expected) = expected else {
            return Err(EngineError::InvalidData(format!(
                "resultsArray[{}] must be an object",
                index
            )));
        };
        let expected = expected
            .get("md")
            .map(FlexValue::as_string)
            .ok_or(EngineError::MissingField("resultsArray.md"))?;
        let actual = hex::encode(actual);
        if !super::hex_equal(&actual, &expected) {
            return Err(EngineError::Mismatch { expected, actual });
        }
    }
    Ok(())
}

/// Large Data Test (LDT) handler for SHA-3
/// Tests hashing of very large messages
pub(crate) fn sha3_ldt(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Check if this test case uses the largeMsg structure
    if let Some(large_msg_value) = case.inputs.get("largeMsg") {
        // Handle the largeMsg structure
        return handle_large_msg_test(group, case, large_msg_value);
    }

    // Original logic for regular LDT tests

    // Get expansion technique first to determine how to handle the message
    let expansion_technique = case
        .inputs
        .get("expansionTechnique")
        .map(|v| v.as_string().to_lowercase())
        .unwrap_or_else(|| "repeating".to_string());

    // Try to get content length from various possible field names
    let content_len_bits_opt = case
        .inputs
        .get("contentLength")
        .or_else(|| case.inputs.get("contentLen"))
        .or_else(|| case.inputs.get("len"))
        .or_else(|| case.inputs.get("msgLen"))
        .map(|v| v.as_string())
        .and_then(|s| s.parse::<usize>().ok());

    // Helper that converts bits→bytes and validates the multiple-of-8 rule
    let bits_to_bytes = |bits: usize| -> Result<usize> {
        if bits % 8 == 0 {
            Ok(bits / 8)
        } else {
            Err(EngineError::InvalidData(
                "Content length must be multiple of 8 bits".into(),
            ))
        }
    };

    // Generate the full message based on expansion technique
    let full_message = match expansion_technique.as_str() {
        "repeating" => {
            let content_len_bytes = bits_to_bytes(
                content_len_bits_opt.ok_or(EngineError::MissingField("contentLength/len"))?,
            )?;

            let content_hex = case
                .inputs
                .get("content")
                .or_else(|| case.inputs.get("msg"))
                .or_else(|| case.inputs.get("message"))
                .map(|v| v.as_string())
                .unwrap_or_else(|| "".to_string());

            let content_bytes = if content_hex.is_empty() {
                vec![]
            } else {
                hex::decode(&content_hex)?
            };

            return hash_repeating_and_check(group, case, &content_bytes, content_len_bytes);
        }
        "random" => {
            let message_hex = case
                .inputs
                .get("MESSAGE")
                .or_else(|| case.inputs.get("message"))
                .or_else(|| case.inputs.get("msg"))
                .map(|v| v.as_string())
                .ok_or(EngineError::MissingField("MESSAGE for random expansion"))?;

            let msg = hex::decode(&message_hex)?;

            if let Some(bits) = content_len_bits_opt {
                let expected = bits_to_bytes(bits)?;
                if expected != msg.len() {
                    return Err(EngineError::Mismatch {
                        expected: format!("{} bytes", expected),
                        actual: format!("{} bytes", msg.len()),
                    });
                }
            }
            msg
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported expansion technique: {}",
                expansion_technique
            )))
        }
    };

    // Hash the message and check results
    hash_and_check_result(group, case, &full_message)
}

/// Handle test cases with the largeMsg structure
fn handle_large_msg_test(
    group: &TestGroup,
    case: &TestCase,
    large_msg_value: &FlexValue,
) -> Result<()> {
    // Parse the largeMsg object
    let large_msg = match large_msg_value {
        FlexValue::Object(map) => map,
        _ => {
            return Err(EngineError::InvalidData(
                "largeMsg must be an object".into(),
            ))
        }
    };

    // Extract fields from largeMsg
    let content_hex = large_msg
        .get("content")
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("largeMsg.content"))?;

    // Get fullLength - try both as string and number without truncating on
    // targets whose usize cannot represent the vector length.
    let full_length_bits = large_msg
        .get("fullLength")
        .and_then(|v| match v {
            FlexValue::String(s) => s.parse::<usize>().ok(),
            FlexValue::Number(n) => n.as_u64().and_then(|x| usize::try_from(x).ok()),
            _ => None,
        })
        .ok_or(EngineError::MissingField("largeMsg.fullLength"))?;

    let expansion_technique = large_msg
        .get("expansionTechnique")
        .map(|v| v.as_string())
        .unwrap_or_else(|| "repeating".to_string())
        .to_lowercase();

    // Convert bits to bytes
    if full_length_bits % 8 != 0 {
        return Err(EngineError::InvalidData(
            "fullLength must be multiple of 8 bits".into(),
        ));
    }
    let full_length_bytes = full_length_bits / 8;

    // Decode the content pattern
    let content_bytes = hex::decode(&content_hex)?;
    if let Some(content_length) = large_msg.get("contentLength") {
        let content_bits = usize_field(Some(content_length), "largeMsg.contentLength")?;
        if content_bits % 8 != 0 || content_bits / 8 != content_bytes.len() {
            return Err(EngineError::InvalidData(format!(
                "largeMsg contentLength {} bits does not match {} encoded bytes",
                content_bits,
                content_bytes.len()
            )));
        }
    }

    match expansion_technique.as_str() {
        // LDT inputs intentionally reach multiple GiB. Feed a bounded
        // pattern-aligned chunk into the streaming hash instead of
        // materializing the complete message.
        "repeating" => hash_repeating_and_check(group, case, &content_bytes, full_length_bytes),
        _ => Err(EngineError::InvalidData(format!(
            "Unsupported expansion technique in largeMsg: {}",
            expansion_technique
        ))),
    }
}

fn hash_repeating<H>(pattern: &[u8], target_len: usize) -> Result<String>
where
    H: HashFunction,
    H::Output: AsRef<[u8]>,
{
    if target_len != 0 && pattern.is_empty() {
        return Err(EngineError::InvalidData(
            "non-zero length requested but repeating pattern is empty".into(),
        ));
    }

    let mut hash = H::new();
    if target_len != 0 {
        const TARGET_CHUNK: usize = 1024 * 1024;
        let repeats = (TARGET_CHUNK / pattern.len()).max(1);
        let chunk_len = repeats.checked_mul(pattern.len()).ok_or_else(|| {
            EngineError::InvalidData("repeating SHA-3 chunk length overflow".into())
        })?;
        let mut chunk = Vec::with_capacity(chunk_len);
        for _ in 0..repeats {
            chunk.extend_from_slice(pattern);
        }

        let mut remaining = target_len;
        while remaining >= chunk.len() {
            hash.update(&chunk)?;
            remaining -= chunk.len();
        }
        if remaining != 0 {
            hash.update(&chunk[..remaining])?;
        }
    }
    Ok(hex::encode(hash.finalize()?.as_ref()))
}

fn hash_repeating_and_check(
    group: &TestGroup,
    case: &TestCase,
    pattern: &[u8],
    target_len: usize,
) -> Result<()> {
    let digest_hex = match group.algorithm.as_str() {
        "SHA3-224" | "SHA-3-224" => hash_repeating::<Sha3_224>(pattern, target_len)?,
        "SHA3-256" | "SHA-3-256" => hash_repeating::<Sha3_256>(pattern, target_len)?,
        "SHA3-384" | "SHA-3-384" => hash_repeating::<Sha3_384>(pattern, target_len)?,
        "SHA3-512" | "SHA-3-512" => hash_repeating::<Sha3_512>(pattern, target_len)?,
        algorithm => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHA-3 variant: {}",
                algorithm
            )))
        }
    };
    check_digest(case, digest_hex)
}

fn check_digest(case: &TestCase, digest_hex: String) -> Result<()> {
    if let Some(expected) = case.inputs.get("md").map(FlexValue::as_string) {
        if !super::hex_equal(&digest_hex, &expected) {
            return Err(EngineError::Mismatch {
                expected,
                actual: digest_hex,
            });
        }
    } else {
        case.outputs.borrow_mut().insert("md".into(), digest_hex);
    }
    Ok(())
}

/// Common function to hash a message and check the result
fn hash_and_check_result(group: &TestGroup, case: &TestCase, message: &[u8]) -> Result<()> {
    // Determine which SHA-3 variant to use
    let algorithm = &group.algorithm;

    let digest_hex = match algorithm.as_str() {
        "SHA3-224" | "SHA-3-224" => {
            let digest = Sha3_224::digest(message)?;
            hex::encode(digest.as_ref())
        }
        "SHA3-256" | "SHA-3-256" => {
            let digest = Sha3_256::digest(message)?;
            hex::encode(digest.as_ref())
        }
        "SHA3-384" | "SHA-3-384" => {
            let digest = Sha3_384::digest(message)?;
            hex::encode(digest.as_ref())
        }
        "SHA3-512" | "SHA-3-512" => {
            let digest = Sha3_512::digest(message)?;
            hex::encode(digest.as_ref())
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHA-3 variant: {}",
                algorithm
            )))
        }
    };

    check_digest(case, digest_hex)
}

/// Register SHA-3 handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // Register AFT handlers for all SHA-3 variants
    // Include all possible algorithm name variations that ACVP might use
    for algo in &[
        "SHA3-224",
        "SHA-3-224",
        "SHA3-256",
        "SHA-3-256",
        "SHA3-384",
        "SHA-3-384",
        "SHA3-512",
        "SHA-3-512",
    ] {
        insert(map, algo, "AFT", "AFT", sha3_aft);
    }

    // Register MCT handlers for all SHA-3 variants
    for algo in &[
        "SHA3-224",
        "SHA-3-224",
        "SHA3-256",
        "SHA-3-256",
        "SHA3-384",
        "SHA-3-384",
        "SHA3-512",
        "SHA-3-512",
    ] {
        insert(map, algo, "MCT", "MCT", sha3_mct);
    }

    // Register LDT handlers for all SHA-3 variants
    for algo in &[
        "SHA3-224",
        "SHA-3-224",
        "SHA3-256",
        "SHA-3-256",
        "SHA3-384",
        "SHA-3-384",
        "SHA3-512",
        "SHA-3-512",
    ] {
        insert(map, algo, "LDT", "LDT", sha3_ldt);
    }
}
