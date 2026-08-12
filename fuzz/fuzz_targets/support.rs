#![forbid(unsafe_code)]
#![allow(dead_code)]

use dcrypt_symmetric::ChaCha20Rng;

const SEMANTIC_TRAILER: &[u8] = b":DCRYPT:END:V1:";

/// Accept only an explicitly framed semantic seed or a mutation that retains
/// both framing sentinels. This keeps the fixed 1,000-iteration PR smoke
/// bounded while persistent campaigns can mutate the payload between them.
pub fn semantic_payload<'a>(input: &'a [u8], target_magic: &[u8]) -> Option<&'a [u8]> {
    let input = input.strip_suffix(b"\n").unwrap_or(input);
    input
        .strip_prefix(target_magic)?
        .strip_suffix(SEMANTIC_TRAILER)
}

pub fn selector(byte: u8, states: usize) -> usize {
    let value = if byte.is_ascii_digit() {
        byte - b'0'
    } else {
        byte
    };
    usize::from(value) % states
}

/// Derive a deterministic, domain-separated seed from one bounded fuzz input.
pub fn seed(input: &[u8], domain: u8) -> [u8; 32] {
    let mut output = [0u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let source = input
            .get(index % input.len().max(1))
            .copied()
            .unwrap_or(domain);
        *byte = source
            .wrapping_add(domain)
            .wrapping_add((index as u8).wrapping_mul(0x3d));
    }
    for (index, source) in input.iter().enumerate() {
        let slot = index % output.len();
        output[slot] = output[slot]
            .rotate_left((index & 7) as u32)
            .wrapping_add(*source ^ domain);
    }
    output
}

pub fn rng(input: &[u8], domain: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(seed(input, domain))
}

pub fn tamper(bytes: &[u8], selector: usize) -> Vec<u8> {
    let mut output = bytes.to_vec();
    if output.is_empty() {
        output.push(1);
    } else {
        let index = selector % output.len();
        output[index] ^= 1 << (selector & 7);
    }
    output
}

pub fn message(input: &[u8], offset: usize, maximum: usize) -> &[u8] {
    input
        .get(offset..)
        .unwrap_or_default()
        .get(..input.len().saturating_sub(offset).min(maximum))
        .unwrap_or_default()
}
