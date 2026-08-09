//! ACVP handlers for SHAKE extendable output functions

use crate::suites::acvp::error::{EngineError, Result};
use crate::suites::acvp::model::{TestCase, TestGroup};
use dcrypt_algorithms::xof::shake::{ShakeXof128, ShakeXof256};
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use hex;

use super::super::dispatcher::{insert, DispatchKey, HandlerFn};

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

    // Decode the message from hex
    let msg_bytes = hex::decode(&msg_hex)?;

    // Get expected output if provided (for validation)
    let expected_out = case
        .inputs
        .get("md")
        .or_else(|| case.inputs.get("output"))
        .map(|v| v.as_string());

    // For bit-oriented outputs, we need to handle them specially
    if out_len_bits % 8 != 0 {
        // Calculate how many full bytes we need plus the partial byte
        let full_bytes = out_len_bits / 8;
        let partial_bits = out_len_bits % 8;
        let total_bytes = full_bytes + if partial_bits > 0 { 1 } else { 0 };

        // Generate the output
        let algorithm = &group.algorithm;
        let mut output = match algorithm.as_str() {
            "SHAKE-128" | "SHAKE128" => {
                let mut xof = ShakeXof128::new();
                xof.update(&msg_bytes)?;
                xof.squeeze_into_vec(total_bytes)?
            }
            "SHAKE-256" | "SHAKE256" => {
                let mut xof = ShakeXof256::new();
                xof.update(&msg_bytes)?;
                xof.squeeze_into_vec(total_bytes)?
            }
            _ => {
                return Err(EngineError::InvalidData(format!(
                    "Unsupported SHAKE variant: {}",
                    algorithm
                )))
            }
        };

        // Mask the last byte if we have partial bits
        if partial_bits > 0 {
            let mask = (1u8 << partial_bits) - 1;
            if let Some(last_byte) = output.last_mut() {
                *last_byte &= mask;
            }
        }

        let output_hex = hex::encode(&output);

        // Check result if expected value was provided
        if let Some(expected) = expected_out {
            // For bit-oriented outputs, we need to compare only the relevant bits
            let expected_bytes = hex::decode(&expected)?;

            // Compare full bytes
            for i in 0..full_bytes {
                if i < output.len() && i < expected_bytes.len() {
                    if output[i] != expected_bytes[i] {
                        return Err(EngineError::Mismatch {
                            expected: expected.clone(),
                            actual: output_hex,
                        });
                    }
                }
            }

            // Compare partial byte if present
            if partial_bits > 0 && full_bytes < output.len() && full_bytes < expected_bytes.len() {
                let mask = (1u8 << partial_bits) - 1;
                if (output[full_bytes] & mask) != (expected_bytes[full_bytes] & mask) {
                    return Err(EngineError::Mismatch {
                        expected: expected.clone(),
                        actual: output_hex,
                    });
                }
            }
        } else {
            // Store result for response generation
            // Truncate to exact bit length in hex representation
            let hex_chars = (out_len_bits + 3) / 4; // Round up bits to hex chars
            let truncated_hex = &output_hex[..hex_chars];
            case.outputs
                .borrow_mut()
                .insert("md".into(), truncated_hex.to_string());
        }
    } else {
        // Byte-aligned output - standard processing
        let out_len_bytes = out_len_bits / 8;

        let algorithm = &group.algorithm;
        let output_hex = match algorithm.as_str() {
            "SHAKE-128" | "SHAKE128" => {
                let mut xof = ShakeXof128::new();
                xof.update(&msg_bytes)?;
                let output = xof.squeeze_into_vec(out_len_bytes)?;
                hex::encode(&output)
            }
            "SHAKE-256" | "SHAKE256" => {
                let mut xof = ShakeXof256::new();
                xof.update(&msg_bytes)?;
                let output = xof.squeeze_into_vec(out_len_bytes)?;
                hex::encode(&output)
            }
            _ => {
                return Err(EngineError::InvalidData(format!(
                    "Unsupported SHAKE variant: {}",
                    algorithm
                )))
            }
        };

        // Check result if expected value was provided
        if let Some(expected) = expected_out {
            if output_hex != expected {
                return Err(EngineError::Mismatch {
                    expected,
                    actual: output_hex,
                });
            }
        } else {
            // Store result for response generation
            case.outputs.borrow_mut().insert("md".into(), output_hex);
        }
    }

    Ok(())
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

    // Get the output length in bits - check multiple locations including group defaults and params
    let out_len_bits = case
        .inputs
        .get("outLen")
        .or_else(|| case.inputs.get("outputLen"))
        .or_else(|| case.inputs.get("outlen")) // lowercase variant
        .or_else(|| group.defaults.get("outLen"))
        .or_else(|| group.defaults.get("outputLen"))
        .or_else(|| group.defaults.get("outlen"))
        .map(|v| v.as_string())
        .or_else(|| {
            // Check in group params if it exists
            group
                .params
                .as_ref()
                .and_then(|p| p.as_object())
                .and_then(|obj| {
                    obj.get("outLen")
                        .or_else(|| obj.get("outputLen"))
                        .or_else(|| obj.get("outlen"))
                })
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .or_else(|| {
            // For SHAKE MCT, sometimes the output length is fixed based on the algorithm
            // SHAKE-128 MCT often uses 128 bits (16 bytes)
            // SHAKE-256 MCT often uses 256 bits (32 bytes)
            match group.algorithm.as_str() {
                "SHAKE-128" | "SHAKE128" => Some("128".to_string()),
                "SHAKE-256" | "SHAKE256" => Some("256".to_string()),
                _ => None,
            }
        })
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or(EngineError::MissingField("outLen"))?;

    // For MCT, we typically work with byte-aligned outputs
    if out_len_bits % 8 != 0 {
        return Err(EngineError::InvalidData(format!(
            "MCT requires byte-aligned output length, got {} bits",
            out_len_bits
        )));
    }
    let out_len_bytes = out_len_bits / 8;

    let seed_bytes = hex::decode(&seed_hex)?;

    // Get expected final output if provided
    let expected_md = case.inputs.get("md").map(|v| v.as_string());

    // Determine which SHAKE variant to use
    let algorithm = &group.algorithm;

    // SHAKE Monte Carlo test procedure (similar to other hash MCTs):
    // MD[0] = Seed
    // For j = 0 to 99:
    //   MSG = MD[j]
    //   MD[j+1] = SHAKE(MSG, outLen)
    // Output MD[100]

    let final_output = match algorithm.as_str() {
        "SHAKE-128" | "SHAKE128" => {
            shake_mct_inner::<ShakeXof128>(&seed_bytes, out_len_bytes, 100)?
        }
        "SHAKE-256" | "SHAKE256" => {
            shake_mct_inner::<ShakeXof256>(&seed_bytes, out_len_bytes, 100)?
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported SHAKE variant: {}",
                algorithm
            )))
        }
    };

    let output_hex = hex::encode(&final_output);

    // Check result if expected value was provided
    if let Some(expected) = expected_md {
        if output_hex != expected {
            return Err(EngineError::Mismatch {
                expected,
                actual: output_hex,
            });
        }
    } else {
        // Store result for response generation
        case.outputs.borrow_mut().insert("md".into(), output_hex);
    }

    Ok(())
}

/// Inner function for Monte Carlo Test implementation
fn shake_mct_inner<X: ExtendableOutputFunction>(
    seed: &[u8],
    out_len: usize,
    iterations: usize,
) -> Result<Vec<u8>> {
    let mut md = seed.to_vec();

    for _ in 0..iterations {
        let mut xof = X::new();
        xof.update(&md)?;
        // The Monte Carlo digest is public test-vector state.
        md = xof.squeeze_into_vec(out_len)?.to_vec();
    }

    Ok(md)
}

/// Large Data Test (LDT) handler for SHAKE
/// Tests XOF with very large messages
pub(crate) fn shake_ldt(group: &TestGroup, case: &TestCase) -> Result<()> {
    // Get expansion technique
    let expansion_technique = case
        .inputs
        .get("expansionTechnique")
        .map(|v| v.as_string().to_lowercase())
        .unwrap_or_else(|| "repeating".to_string());

    // Get output length in bits
    let out_len_bits = case
        .inputs
        .get("outLen")
        .or_else(|| case.inputs.get("outputLen"))
        .map(|v| v.as_string())
        .and_then(|s| s.parse::<usize>().ok())
        .ok_or(EngineError::MissingField("outLen"))?;

    // Get content length
    let content_len_bits_opt = case
        .inputs
        .get("contentLength")
        .or_else(|| case.inputs.get("contentLen"))
        .or_else(|| case.inputs.get("len"))
        .map(|v| v.as_string())
        .and_then(|s| s.parse::<usize>().ok());

    // Generate the full message based on expansion technique
    let full_message = match expansion_technique.as_str() {
        "repeating" => {
            let content_len_bits =
                content_len_bits_opt.ok_or(EngineError::MissingField("contentLength"))?;

            if content_len_bits % 8 != 0 {
                return Err(EngineError::InvalidData(
                    "Content length must be multiple of 8 bits".into(),
                ));
            }
            let content_len_bytes = content_len_bits / 8;

            let content_hex = case
                .inputs
                .get("content")
                .or_else(|| case.inputs.get("msg"))
                .map(|v| v.as_string())
                .unwrap_or_else(|| "".to_string());

            let content_bytes = if content_hex.is_empty() {
                vec![]
            } else {
                hex::decode(&content_hex)?
            };

            build_repeating(&content_bytes, content_len_bytes)?
        }
        _ => {
            return Err(EngineError::InvalidData(format!(
                "Unsupported expansion technique: {}",
                expansion_technique
            )))
        }
    };

    // Process with SHAKE - handle both byte-aligned and bit-oriented outputs
    let algorithm = &group.algorithm;

    // For bit-oriented outputs
    if out_len_bits % 8 != 0 {
        let full_bytes = out_len_bits / 8;
        let partial_bits = out_len_bits % 8;
        let total_bytes = full_bytes + if partial_bits > 0 { 1 } else { 0 };

        let mut output = match algorithm.as_str() {
            "SHAKE-128" | "SHAKE128" => {
                let mut xof = ShakeXof128::new();
                xof.update(&full_message)?;
                xof.squeeze_into_vec(total_bytes)?
            }
            "SHAKE-256" | "SHAKE256" => {
                let mut xof = ShakeXof256::new();
                xof.update(&full_message)?;
                xof.squeeze_into_vec(total_bytes)?
            }
            _ => {
                return Err(EngineError::InvalidData(format!(
                    "Unsupported SHAKE variant: {}",
                    algorithm
                )))
            }
        };

        // Mask the last byte
        if partial_bits > 0 {
            let mask = (1u8 << partial_bits) - 1;
            if let Some(last_byte) = output.last_mut() {
                *last_byte &= mask;
            }
        }

        let output_hex = hex::encode(&output);

        // Check result if expected value was provided
        if let Some(expected) = case.inputs.get("md").map(|v| v.as_string()) {
            let expected_bytes = hex::decode(&expected)?;

            // Compare full bytes
            for i in 0..full_bytes {
                if i < output.len() && i < expected_bytes.len() {
                    if output[i] != expected_bytes[i] {
                        return Err(EngineError::Mismatch {
                            expected: expected.clone(),
                            actual: output_hex,
                        });
                    }
                }
            }

            // Compare partial byte
            if partial_bits > 0 && full_bytes < output.len() && full_bytes < expected_bytes.len() {
                let mask = (1u8 << partial_bits) - 1;
                if (output[full_bytes] & mask) != (expected_bytes[full_bytes] & mask) {
                    return Err(EngineError::Mismatch {
                        expected: expected.clone(),
                        actual: output_hex,
                    });
                }
            }
        } else {
            // Store result - truncate hex to exact bit length
            let hex_chars = (out_len_bits + 3) / 4;
            let truncated_hex = &output_hex[..hex_chars];
            case.outputs
                .borrow_mut()
                .insert("md".into(), truncated_hex.to_string());
        }
    } else {
        // Byte-aligned output
        let out_len_bytes = out_len_bits / 8;

        let output_hex = match algorithm.as_str() {
            "SHAKE-128" | "SHAKE128" => {
                let mut xof = ShakeXof128::new();
                xof.update(&full_message)?;
                let output = xof.squeeze_into_vec(out_len_bytes)?;
                hex::encode(&output)
            }
            "SHAKE-256" | "SHAKE256" => {
                let mut xof = ShakeXof256::new();
                xof.update(&full_message)?;
                let output = xof.squeeze_into_vec(out_len_bytes)?;
                hex::encode(&output)
            }
            _ => {
                return Err(EngineError::InvalidData(format!(
                    "Unsupported SHAKE variant: {}",
                    algorithm
                )))
            }
        };

        // Check result if expected value was provided
        if let Some(expected) = case.inputs.get("md").map(|v| v.as_string()) {
            if output_hex != expected {
                return Err(EngineError::Mismatch {
                    expected,
                    actual: output_hex,
                });
            }
        } else {
            // Store result for response generation
            case.outputs.borrow_mut().insert("md".into(), output_hex);
        }
    }

    Ok(())
}

/// Build a message by repeating a pattern to reach target length
fn build_repeating(pattern: &[u8], target_len: usize) -> Result<Vec<u8>> {
    if target_len == 0 {
        return Ok(vec![]);
    }

    if pattern.is_empty() {
        return Err(EngineError::InvalidData(
            "Non-zero length requested but pattern is empty".into(),
        ));
    }

    let mut message = Vec::with_capacity(target_len);
    while message.len() < target_len {
        let remaining = target_len - message.len();
        if remaining >= pattern.len() {
            message.extend_from_slice(pattern);
        } else {
            message.extend_from_slice(&pattern[..remaining]);
        }
    }

    Ok(message)
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
