#![no_main]
#![forbid(unsafe_code)]

use dcrypt_api::traits::{Serialize, SerializeSecret};
use dcrypt_api::Signature;
use dcrypt_hybrid::sign::EcdsaMlDsa65Hybrid;
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 16 * 1024;
const PUBLIC_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/public/v2";
const SECRET_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/secret/v2";
const SIGNATURE_LABEL: &[u8] = b"dcrypt-hybrid-sig/ecdsa-p384+ml-dsa-65/signature/v2";

type PublicKey = <EcdsaMlDsa65Hybrid as Signature>::PublicKey;
type SecretKey = <EcdsaMlDsa65Hybrid as Signature>::SecretKey;
type SignatureData = <EcdsaMlDsa65Hybrid as Signature>::SignatureData;

fn with_valid_label(label: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(1 + label.len() + tail.len());
    framed.push(label.len() as u8);
    framed.extend_from_slice(label);
    framed.extend_from_slice(tail);
    framed
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];

    // Raw input covers malformed/mismatched version labels.
    let _ = <PublicKey as Serialize>::from_bytes(input);
    let _ = <SecretKey as SerializeSecret>::from_bytes(input);
    let _ = <SignatureData as Serialize>::from_bytes(input);

    // Valid labels force the decoder into its checked u32 component-length
    // arithmetic with arbitrary, possibly truncated, tails.
    let _ = <PublicKey as Serialize>::from_bytes(&with_valid_label(PUBLIC_LABEL, input));
    let _ = <SecretKey as SerializeSecret>::from_bytes(&with_valid_label(SECRET_LABEL, input));
    let _ = <SignatureData as Serialize>::from_bytes(&with_valid_label(SIGNATURE_LABEL, input));
});
