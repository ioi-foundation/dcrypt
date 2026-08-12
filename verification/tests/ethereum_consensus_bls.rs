//! Ethereum consensus BLS adapter checks against the repository corpus.
//!
//! These fixtures are excluded from the published workspace. A claimed upstream
//! commit, paths, and Git blob identifiers are recorded beside the corpus in
//! `vectors/ethereum_consensus_spec_tests/PROVENANCE.md`, but no independently
//! verified acquisition archive or download digest is available.

#![forbid(unsafe_code)]

use dcrypt_sign::bls::{Bls12381PublicKey, Bls12381Signature, Eth2Bls12381G2PopV4};
use std::fs;
use std::path::{Path, PathBuf};

const VECTOR_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/vectors/ethereum_consensus_spec_tests/altair/bls"
);

struct AggregatePublicKeysVector {
    input: Vec<String>,
    output: Option<String>,
}

struct FastAggregateVerifyVector {
    input: FastAggregateVerifyInput,
    output: bool,
}

struct FastAggregateVerifyInput {
    pubkeys: Vec<String>,
    message: String,
    signature: String,
}

fn fixture_files(suite: &str) -> Vec<PathBuf> {
    let directory = Path::new(VECTOR_ROOT).join(suite).join("bls");
    let mut files: Vec<_> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("failed to read vector entry: {error}"))
                .path()
                .join("data.yaml")
        })
        .collect();
    files.sort();
    files
}

fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], String> {
    let encoded = encoded
        .strip_prefix("0x")
        .ok_or_else(|| "hex value is missing its 0x prefix".to_owned())?;
    if encoded.len() != N * 2 {
        return Err(format!(
            "hex value has {} digits; expected {}",
            encoded.len(),
            N * 2
        ));
    }

    let mut decoded = [0u8; N];
    for (destination, pair) in decoded.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        *destination = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn decode_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex digit 0x{value:02x}")),
    }
}

fn parse_public_keys(values: &[String]) -> Result<Vec<Bls12381PublicKey>, String> {
    values
        .iter()
        .map(|value| {
            let bytes = decode_hex::<48>(value)?;
            Bls12381PublicKey::from_bytes(&bytes).map_err(|error| format!("{error:?}"))
        })
        .collect()
}

fn quoted_value(value: &str) -> Result<String, String> {
    value
        .trim()
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
        .map(str::to_owned)
        .ok_or_else(|| format!("expected a single-quoted YAML scalar, got {value:?}"))
}

fn parse_aggregate_public_keys(yaml: &str) -> Result<AggregatePublicKeysVector, String> {
    let mut input = Vec::new();
    let mut saw_input = false;
    let mut output = None;
    for line in yaml.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line == "input:" || line == "input: []" {
            saw_input = true;
        } else if let Some(value) = line.strip_prefix("- ") {
            input.push(quoted_value(value)?);
        } else if let Some(value) = line.strip_prefix("output: ") {
            if output.is_some() {
                return Err("duplicate output field".to_owned());
            }
            output = Some(if value == "null" {
                None
            } else {
                Some(quoted_value(value)?)
            });
        } else {
            return Err(format!(
                "unexpected aggregate-public-key YAML line: {line:?}"
            ));
        }
    }
    if !saw_input {
        return Err("missing input field".to_owned());
    }
    Ok(AggregatePublicKeysVector {
        input,
        output: output.ok_or_else(|| "missing output field".to_owned())?,
    })
}

fn parse_fast_aggregate_verify(yaml: &str) -> Result<FastAggregateVerifyVector, String> {
    let mut pubkeys = Vec::new();
    let mut saw_input = false;
    let mut saw_pubkeys = false;
    let mut message = None;
    let mut signature = None;
    let mut output = None;
    for line in yaml.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line == "input:" {
            saw_input = true;
        } else if line == "pubkeys:" || line == "pubkeys: []" {
            saw_pubkeys = true;
        } else if let Some(value) = line.strip_prefix("- ") {
            pubkeys.push(quoted_value(value)?);
        } else if let Some(value) = line.strip_prefix("message: ") {
            if message.replace(quoted_value(value)?).is_some() {
                return Err("duplicate message field".to_owned());
            }
        } else if let Some(value) = line.strip_prefix("signature: ") {
            if signature.replace(quoted_value(value)?).is_some() {
                return Err("duplicate signature field".to_owned());
            }
        } else if let Some(value) = line.strip_prefix("output: ") {
            let value = match value {
                "true" => true,
                "false" => false,
                _ => return Err(format!("invalid Boolean output: {value:?}")),
            };
            if output.replace(value).is_some() {
                return Err("duplicate output field".to_owned());
            }
        } else {
            return Err(format!("unexpected fast-aggregate YAML line: {line:?}"));
        }
    }
    if !saw_input || !saw_pubkeys {
        return Err("missing input or pubkeys field".to_owned());
    }
    Ok(FastAggregateVerifyVector {
        input: FastAggregateVerifyInput {
            pubkeys,
            message: message.ok_or_else(|| "missing message field".to_owned())?,
            signature: signature.ok_or_else(|| "missing signature field".to_owned())?,
        },
        output: output.ok_or_else(|| "missing output field".to_owned())?,
    })
}

#[test]
fn repository_eth_aggregate_pubkeys_vectors() {
    let files = fixture_files("eth_aggregate_pubkeys");
    assert_eq!(
        files.len(),
        8,
        "repository aggregate-public-key corpus changed"
    );

    for path in files {
        let yaml = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let vector = parse_aggregate_public_keys(&yaml)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        let expected = vector
            .output
            .as_deref()
            .map(decode_hex::<48>)
            .transpose()
            .unwrap_or_else(|error| panic!("invalid output in {}: {error}", path.display()));
        let actual = parse_public_keys(&vector.input)
            .and_then(|public_keys| {
                Eth2Bls12381G2PopV4::aggregate_public_keys(&public_keys)
                    .map_err(|error| format!("{error:?}"))
            })
            .map(|public_key| public_key.to_bytes())
            .ok();

        assert_eq!(actual, expected, "vector {}", path.display());
    }
}

#[test]
fn repository_eth_fast_aggregate_verify_vectors() {
    let files = fixture_files("eth_fast_aggregate_verify");
    assert_eq!(files.len(), 12, "repository fast-aggregate corpus changed");

    for path in files {
        let yaml = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let vector = parse_fast_aggregate_verify(&yaml)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        let actual = (|| -> Result<(), String> {
            let public_keys = parse_public_keys(&vector.input.pubkeys)?;
            let message = decode_hex::<32>(&vector.input.message)?;
            let signature_bytes = decode_hex::<96>(&vector.input.signature)?;
            let signature = Bls12381Signature::from_bytes(&signature_bytes)
                .map_err(|error| format!("{error:?}"))?;
            Eth2Bls12381G2PopV4::fast_aggregate_verify(&public_keys, &message, &signature)
                .map_err(|error| format!("{error:?}"))
        })()
        .is_ok();

        assert_eq!(actual, vector.output, "vector {}", path.display());
    }
}
