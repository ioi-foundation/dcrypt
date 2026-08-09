#![no_main]

use dcrypt_algorithms::ec::bls12_381::{
    Bls12_381Scalar, G1Affine, G1Projective, G2Affine, G2Projective,
};
use libfuzzer_sys::fuzz_target;

const INPUT_MAX: usize = 4 * 1024;

fn fixed<const N: usize>(input: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0u8; N];
    if input.is_empty() {
        return output;
    }
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = input[(offset + index) % input.len()];
    }
    output
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(INPUT_MAX)];

    // Variable-length checked entry points cover truncation and trailing data.
    let _ = G1Projective::from_bytes_validated(input);
    let _ = G2Projective::from_bytes_validated(input);

    // Fixed-width forms force canonical field, flag, curve, subgroup, and
    // identity checks for both compressed and uncompressed encodings.
    let g1_compressed = fixed::<48>(input, 1);
    let g1_uncompressed = fixed::<96>(input, 7);
    let g2_compressed = fixed::<96>(input, 13);
    let g2_uncompressed = fixed::<192>(input, 29);
    let scalar = fixed::<32>(input, 47);
    let wide_scalar = fixed::<64>(input, 61);

    let _ = G1Affine::from_compressed(&g1_compressed);
    let _ = G1Affine::from_uncompressed(&g1_uncompressed);
    let _ = G1Projective::from_bytes(&g1_compressed);
    let _ = G2Affine::from_compressed(&g2_compressed);
    let _ = G2Affine::from_uncompressed(&g2_uncompressed);
    let _ = G2Projective::from_bytes(&g2_compressed);
    let _ = Bls12_381Scalar::from_bytes(&scalar);
    let _ = Bls12_381Scalar::from_bytes_wide(&wide_scalar);
});
