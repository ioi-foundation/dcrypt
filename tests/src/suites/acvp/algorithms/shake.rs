//! ACVP handlers for SHAKE extendable output functions

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{FlexValue, TestCase, TestGroup};
use dcrypt_algorithms::xof::shake::{ShakeXof128, ShakeXof256};
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use hex;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

trait AcvpShake {
    fn generate_bits(message: &[u8], bit_len: usize, output_len: usize) -> Result<Vec<u8>>;
}

impl AcvpShake for ShakeXof128 {
    fn generate_bits(message: &[u8], bit_len: usize, output_len: usize) -> Result<Vec<u8>> {
        Ok(ShakeXof128::generate_bits(message, bit_len, output_len)?.to_vec())
    }
}

impl AcvpShake for ShakeXof256 {
    fn generate_bits(message: &[u8], bit_len: usize, output_len: usize) -> Result<Vec<u8>> {
        Ok(ShakeXof256::generate_bits(message, bit_len, output_len)?.to_vec())
    }
}

fn usize_field(value: Option<&FlexValue>, name: &'static str) -> Result<usize> {
    value
        .map(FlexValue::as_string)
        .and_then(|value| value.parse().ok())
        .ok_or(EngineError::MissingField(name))
}

/// Decode ACVP's left-aligned representation of an input bit string.  Accept
/// the historical one-byte zero sentinel only for an empty input.
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

fn shake_output(
    group: &TestGroup,
    message: &[u8],
    message_bit_len: usize,
    output_bit_len: usize,
) -> Result<Vec<u8>> {
    if output_bit_len == 0 {
        return Err(EngineError::InvalidData(
            "SHAKE output length must be non-zero".into(),
        ));
    }
    let output_len = output_bit_len
        .checked_add(7)
        .ok_or_else(|| EngineError::InvalidData("output bit length overflows usize".into()))?
        / 8;
    let mut output = match group.algorithm.as_str() {
        "SHAKE-128" | "SHAKE128" => {
            ShakeXof128::generate_bits(message, message_bit_len, output_len)?.to_vec()
        }
        "SHAKE-256" | "SHAKE256" => {
            ShakeXof256::generate_bits(message, message_bit_len, output_len)?.to_vec()
        }
        algorithm => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHAKE variant: {}",
                algorithm
            )))
        }
    };

    // ACVP represents a partial SHAKE output byte with the requested bits in
    // its low positions and the unused high positions cleared.
    if output_bit_len % 8 != 0 {
        *output.last_mut().expect("non-empty output validated above") &=
            (1u8 << (output_bit_len % 8)) - 1;
    }
    Ok(output)
}

fn compare_or_record_output(case: &TestCase, output: &[u8]) -> Result<()> {
    let output_hex = hex::encode(output);
    if let Some(expected) = case
        .inputs
        .get("md")
        .or_else(|| case.inputs.get("output"))
        .map(FlexValue::as_string)
    {
        let expected_bytes = hex::decode(&expected)?;
        if expected_bytes != output {
            return Err(EngineError::Mismatch {
                expected,
                actual: output_hex,
            });
        }
    } else {
        case.outputs.borrow_mut().insert("md".into(), output_hex);
    }
    Ok(())
}

/// SHAKE Algorithm Family Test (AFT) handler
/// Handles SHAKE-128 and SHAKE-256 XOF tests
pub(crate) fn shake_aft(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get the message to hash
    let msg_hex = case
        .inputs
        .get("msg")
        .or_else(|| case.inputs.get("message"))
        .map(|v| v.as_string())
        .ok_or(EngineError::MissingField("msg"))?;

    // Get the output length in bits
    let out_len_bits = case
        .inputs
        .get("outLen")
        .or_else(|| case.inputs.get("outputLen"))
        .map(|v| v.as_string())
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or(EngineError::MissingField("outLen"))?;

    let msg_len_bits = usize_field(
        case.inputs.get("len").or_else(|| case.inputs.get("msgLen")),
        "len",
    )?;
    let msg_bytes = decode_message_bits(&msg_hex, msg_len_bits)?;
    let output = shake_output(group, &msg_bytes, msg_len_bits, out_len_bits)?;
    compare_or_record_output(case, &output)
}

/// SHAKE Variable Output Test (VOT) handler
/// Tests SHAKE with different output lengths
pub(crate) fn shake_vot(group: &TestGroup, case: &TestCase) -> Result<()> {
    // VOT tests are essentially the same as AFT for SHAKE
    // They just emphasize testing different output lengths
    shake_aft(group, case)
}

/// SHAKE Monte Carlo Test (MCT) handler
pub(crate) fn shake_mct(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get the initial seed/message
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
    if seed_bit_len != 128 {
        return Err(EngineError::InvalidData(format!(
            "SHAKE MCT seed must be 128 bits, got {}",
            seed_bit_len
        )));
    }
    let seed_bytes = decode_message_bits(&seed_hex, seed_bit_len)?;
    let min_out_bits = usize_field(group.defaults.get("minOutLen"), "minOutLen")?;
    let max_out_bits = usize_field(group.defaults.get("maxOutLen"), "maxOutLen")?;
    if min_out_bits == 0
        || min_out_bits > max_out_bits
        || min_out_bits % 8 != 0
        || max_out_bits % 8 != 0
    {
        return Err(EngineError::InvalidData(format!(
            "invalid SHAKE MCT output range {}..={} bits",
            min_out_bits, max_out_bits
        )));
    }

    let results = match group.algorithm.as_str() {
        "SHAKE-128" | "SHAKE128" => {
            shake_mct_inner::<ShakeXof128>(&seed_bytes, min_out_bits / 8, max_out_bits / 8)?
        }
        "SHAKE-256" | "SHAKE256" => {
            shake_mct_inner::<ShakeXof256>(&seed_bytes, min_out_bits / 8, max_out_bits / 8)?
        }
        algorithm => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHAKE variant: {}",
                algorithm
            )))
        }
    };

    if let Some(expected) = case.inputs.get("resultsArray") {
        compare_shake_mct_results(expected, &results)
    } else {
        let response: Vec<_> = results
            .iter()
            .map(|(out_len, digest)| {
                serde_json::json!({
                    "md": hex::encode_upper(digest),
                    "outLen": out_len * 8,
                })
            })
            .collect();
        case.outputs.borrow_mut().insert(
            "resultsArray".into(),
            serde_json::to_string(&response)
                .map_err(|error| EngineError::InvalidData(error.to_string()))?,
        );
        Ok(())
    }
}

/// ACVP SHAKE MCT: each of 100 reported iterations contains 1000 SHAKE
/// operations.  Every input is the leftmost 128 output bits (right-zero-padded
/// when necessary), and the next output length is selected from the rightmost
/// 16 output bits.
fn shake_mct_inner<X: AcvpShake>(
    seed: &[u8],
    min_out_len: usize,
    max_out_len: usize,
) -> Result<Vec<(usize, Vec<u8>)>> {
    let range = max_out_len - min_out_len + 1;
    let mut message = seed.to_vec();
    let mut out_len = max_out_len;
    let mut results = Vec::with_capacity(100);

    for _ in 0..100 {
        let mut digest = Vec::new();
        let mut digest_out_len = out_len;
        for _ in 0..1000 {
            digest_out_len = out_len;
            digest = X::generate_bits(&message, 128, out_len)?;

            let last = digest.len();
            let selector = u16::from_be_bytes([digest[last - 2], digest[last - 1]]) as usize;
            out_len = min_out_len + selector % range;

            message.clear();
            message.extend_from_slice(&digest[..digest.len().min(16)]);
            message.resize(16, 0);
        }
        results.push((digest_out_len, digest));
    }
    Ok(results)
}

fn compare_shake_mct_results(expected: &FlexValue, actual: &[(usize, Vec<u8>)]) -> Result<()> {
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

    for (index, (expected, (actual_out_len, actual_digest))) in
        expected.iter().zip(actual).enumerate()
    {
        let FlexValue::Object(expected) = expected else {
            return Err(EngineError::InvalidData(format!(
                "resultsArray[{}] must be an object",
                index
            )));
        };
        let expected_md = expected
            .get("md")
            .map(FlexValue::as_string)
            .ok_or(EngineError::MissingField("resultsArray.md"))?;
        let expected_out_len = usize_field(expected.get("outLen"), "resultsArray.outLen")?;
        let actual_md = hex::encode(actual_digest);
        if expected_out_len != actual_out_len * 8 || !super::hex_equal(&actual_md, &expected_md) {
            return Err(EngineError::Mismatch {
                expected: format!("{} bits: {}", expected_out_len, expected_md),
                actual: format!("{} bits: {}", actual_out_len * 8, actual_md),
            });
        }
    }
    Ok(())
}

/// Large Data Test (LDT) handler for SHAKE
/// Tests XOF with very large messages
pub(crate) fn shake_ldt(group: &TestGroup, case: &TestCase) -> Result<()> {
    let out_len_bits = usize_field(
        case.inputs
            .get("outLen")
            .or_else(|| case.inputs.get("outputLen")),
        "outLen",
    )?;

    let (pattern, target_len, expansion_technique) =
        if let Some(FlexValue::Object(large_msg)) = case.inputs.get("largeMsg") {
            let content = large_msg
                .get("content")
                .map(FlexValue::as_string)
                .ok_or(EngineError::MissingField("largeMsg.content"))?;
            let pattern = hex::decode(content)?;
            if let Some(content_length) = large_msg.get("contentLength") {
                let content_bits = usize_field(Some(content_length), "largeMsg.contentLength")?;
                if content_bits % 8 != 0 || content_bits / 8 != pattern.len() {
                    return Err(EngineError::InvalidData(format!(
                        "largeMsg contentLength {} bits does not match {} encoded bytes",
                        content_bits,
                        pattern.len()
                    )));
                }
            }
            let full_length = usize_field(large_msg.get("fullLength"), "largeMsg.fullLength")?;
            if full_length % 8 != 0 {
                return Err(EngineError::InvalidData(
                    "largeMsg.fullLength must be byte-aligned".into(),
                ));
            }
            let expansion = large_msg
                .get("expansionTechnique")
                .map(FlexValue::as_string)
                .unwrap_or_else(|| "repeating".into())
                .to_lowercase();
            (pattern, full_length / 8, expansion)
        } else if case.inputs.contains_key("largeMsg") {
            return Err(EngineError::InvalidData(
                "largeMsg must be an object".into(),
            ));
        } else {
            let target_bits = usize_field(
                case.inputs
                    .get("contentLength")
                    .or_else(|| case.inputs.get("contentLen"))
                    .or_else(|| case.inputs.get("len")),
                "contentLength",
            )?;
            if target_bits % 8 != 0 {
                return Err(EngineError::InvalidData(
                    "content length must be byte-aligned".into(),
                ));
            }
            let content = case
                .inputs
                .get("content")
                .or_else(|| case.inputs.get("msg"))
                .map(FlexValue::as_string)
                .unwrap_or_default();
            let expansion = case
                .inputs
                .get("expansionTechnique")
                .map(FlexValue::as_string)
                .unwrap_or_else(|| "repeating".into())
                .to_lowercase();
            (hex::decode(content)?, target_bits / 8, expansion)
        };

    if expansion_technique != "repeating" {
        return Err(EngineError::InvalidData(format!(
            "Unsupported SHAKE LDT expansion technique: {}",
            expansion_technique
        )));
    }
    let output = match group.algorithm.as_str() {
        "SHAKE-128" | "SHAKE128" => {
            shake_repeating::<ShakeXof128>(&pattern, target_len, out_len_bits)?
        }
        "SHAKE-256" | "SHAKE256" => {
            shake_repeating::<ShakeXof256>(&pattern, target_len, out_len_bits)?
        }
        algorithm => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHAKE variant: {}",
                algorithm
            )))
        }
    };
    compare_or_record_output(case, &output)
}

fn shake_repeating<X: ExtendableOutputFunction>(
    pattern: &[u8],
    target_len: usize,
    output_bit_len: usize,
) -> Result<Vec<u8>> {
    if target_len != 0 && pattern.is_empty() {
        return Err(EngineError::InvalidData(
            "non-zero length requested but repeating pattern is empty".into(),
        ));
    }
    if output_bit_len == 0 {
        return Err(EngineError::InvalidData(
            "SHAKE output length must be non-zero".into(),
        ));
    }

    let mut xof = X::new();
    if target_len != 0 {
        const TARGET_CHUNK: usize = 1024 * 1024;
        let repeats = (TARGET_CHUNK / pattern.len()).max(1);
        let chunk_len = repeats.checked_mul(pattern.len()).ok_or_else(|| {
            EngineError::InvalidData("repeating SHAKE chunk length overflow".into())
        })?;
        let mut chunk = Vec::with_capacity(chunk_len);
        for _ in 0..repeats {
            chunk.extend_from_slice(pattern);
        }

        let mut remaining = target_len;
        while remaining >= chunk.len() {
            xof.update(&chunk)?;
            remaining -= chunk.len();
        }
        if remaining != 0 {
            xof.update(&chunk[..remaining])?;
        }
    }

    let output_len = output_bit_len
        .checked_add(7)
        .ok_or_else(|| EngineError::InvalidData("output bit length overflows usize".into()))?
        / 8;
    let mut output = xof.squeeze_into_vec(output_len)?.to_vec();
    if output_bit_len % 8 != 0 {
        *output.last_mut().expect("non-empty output validated above") &=
            (1u8 << (output_bit_len % 8)) - 1;
    }
    Ok(output)
}

/// Register SHAKE handlers
pub fn register(map: &mut std::collections::HashMap<DispatchKey, HandlerFn>) {
    // Register AFT handlers for SHAKE variants
    for algo in &["SHAKE-128", "SHAKE128", "SHAKE-256", "SHAKE256"] {
        insert(map, algo, "AFT", "AFT", shake_aft);
    }

    // Register VOT (Variable Output Test) handlers
    for algo in &["SHAKE-128", "SHAKE128", "SHAKE-256", "SHAKE256"] {
        insert(map, algo, "VOT", "VOT", shake_vot);
    }

    // Register MCT handlers
    for algo in &["SHAKE-128", "SHAKE128", "SHAKE-256", "SHAKE256"] {
        insert(map, algo, "MCT", "MCT", shake_mct);
    }

    // Register LDT handlers
    for algo in &["SHAKE-128", "SHAKE128", "SHAKE-256", "SHAKE256"] {
        insert(map, algo, "LDT", "LDT", shake_ldt);
    }
}
