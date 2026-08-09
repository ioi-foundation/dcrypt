//! FIPS 203 K-PKE algorithms used internally by ML-KEM.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use dcrypt_algorithms::error::{Error, Result};
use dcrypt_algorithms::hash::sha3::Sha3_512;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_algorithms::xof::shake::{ShakeXof128, ShakeXof256};
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_internal::zeroing::Zeroizing;

use super::params::{
    compressed_polyvec_bytes, pke_secret_key_bytes, MlKemParameterSet, N, POLY_BYTES, SYM_BYTES,
};
use super::poly::{
    compress, decode, decode_12_checked, decode_12_mod_q, decompress, encode, Poly, PolyVec,
};

type Matrix = [[Poly; 4]; 4];

fn primitive_error(operation: &'static str) -> Error {
    Error::Processing {
        operation,
        details: "owned SHA3/SHAKE primitive failed",
    }
}

fn hash_g_parts(first: &[u8], second: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let mut hash = Zeroizing::new(Sha3_512::new());
    hash.update(first)
        .map_err(|_| primitive_error("ML-KEM G"))?;
    hash.update(second)
        .map_err(|_| primitive_error("ML-KEM G"))?;
    let digest = Zeroizing::new(hash.finalize().map_err(|_| primitive_error("ML-KEM G"))?);
    let mut output = Zeroizing::new([0u8; 64]);
    output.copy_from_slice(digest.as_ref());
    Ok(output)
}

fn sample_ntt(seed: &[u8; SYM_BYTES], x: u8, y: u8) -> Result<Poly> {
    let mut xof = ShakeXof128::new();
    xof.update(seed)
        .map_err(|_| primitive_error("ML-KEM SampleNTT"))?;
    xof.update(&[x, y])
        .map_err(|_| primitive_error("ML-KEM SampleNTT"))?;

    let mut result = Poly::zero();
    let mut count = 0usize;
    let mut bytes = Zeroizing::new([0u8; 3]);
    while count < N {
        xof.squeeze(bytes.as_mut())
            .map_err(|_| primitive_error("ML-KEM SampleNTT"))?;
        let first = u16::from(bytes[0]) | ((u16::from(bytes[1]) & 0x0f) << 8);
        let second = (u16::from(bytes[1]) >> 4) | (u16::from(bytes[2]) << 4);
        if first < 3_329 {
            result.coeffs[count] = first as i16;
            count += 1;
        }
        if count < N && second < 3_329 {
            result.coeffs[count] = second as i16;
            count += 1;
        }
    }
    Ok(result)
}

fn generate_matrix<P: MlKemParameterSet>(
    rho: &[u8; SYM_BYTES],
    transposed: bool,
) -> Result<Matrix> {
    let mut matrix: Matrix = core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero()));
    for (row, matrix_row) in matrix.iter_mut().enumerate().take(P::K) {
        for (column, entry) in matrix_row.iter_mut().enumerate().take(P::K) {
            let (x, y) = if transposed {
                (row as u8, column as u8)
            } else {
                (column as u8, row as u8)
            };
            *entry = sample_ntt(rho, x, y)?;
        }
    }
    Ok(matrix)
}

fn sample_cbd(seed: &[u8; SYM_BYTES], nonce: u8, eta: usize) -> Result<Zeroizing<Poly>> {
    let mut xof = ShakeXof256::new();
    xof.update(seed)
        .map_err(|_| primitive_error("ML-KEM PRF"))?;
    xof.update(&[nonce])
        .map_err(|_| primitive_error("ML-KEM PRF"))?;
    let mut bytes = Zeroizing::new(vec![0u8; eta * 64].into_boxed_slice());
    xof.squeeze(&mut bytes[..])
        .map_err(|_| primitive_error("ML-KEM PRF"))?;

    let mut result = Zeroizing::new(Poly::zero());
    let mut bit_offset = 0usize;
    for coefficient in &mut result.coeffs {
        let mut first = 0i16;
        let mut second = 0i16;
        for _ in 0..eta {
            first += i16::from((bytes[bit_offset >> 3] >> (bit_offset & 7)) & 1);
            bit_offset += 1;
        }
        for _ in 0..eta {
            second += i16::from((bytes[bit_offset >> 3] >> (bit_offset & 7)) & 1);
            bit_offset += 1;
        }
        *coefficient = first - second;
    }
    Ok(result)
}

fn sample_vector(
    seed: &[u8; SYM_BYTES],
    first_nonce: u8,
    eta: usize,
    k: usize,
) -> Result<Zeroizing<PolyVec>> {
    let mut result = Zeroizing::new(PolyVec::zero());
    for (index, polynomial) in result.polys.iter_mut().enumerate().take(k) {
        let sample = sample_cbd(seed, first_nonce + index as u8, eta)?;
        polynomial.coeffs.copy_from_slice(&sample.coeffs);
    }
    Ok(result)
}

fn pointwise_accumulate(left: &PolyVec, right: &PolyVec, k: usize) -> Zeroizing<Poly> {
    let mut result = Poly::base_mul(&left.polys[0], &right.polys[0]);
    for index in 1..k {
        let product = Poly::base_mul(&left.polys[index], &right.polys[index]);
        result.add_assign(&product);
    }
    result
}

fn matrix_vector_product(matrix: &Matrix, vector: &PolyVec, k: usize) -> Zeroizing<PolyVec> {
    let mut result = Zeroizing::new(PolyVec::zero());
    for (row, output) in result.polys.iter_mut().enumerate().take(k) {
        let matrix_row = PolyVec {
            polys: core::array::from_fn(|column| matrix[row][column].clone()),
        };
        let product = pointwise_accumulate(&matrix_row, vector, k);
        output.coeffs.copy_from_slice(&product.coeffs);
    }
    result
}

fn encode_polyvec_12(vector: &PolyVec, k: usize, output: &mut [u8]) {
    debug_assert_eq!(output.len(), k * POLY_BYTES);
    for (index, polynomial) in vector.polys.iter().enumerate().take(k) {
        encode(
            polynomial,
            12,
            &mut output[index * POLY_BYTES..(index + 1) * POLY_BYTES],
        );
    }
}

fn decode_polyvec_12_checked(input: &[u8], k: usize) -> Option<Zeroizing<PolyVec>> {
    if input.len() != k * POLY_BYTES {
        return None;
    }
    let mut result = Zeroizing::new(PolyVec::zero());
    for (index, polynomial) in result.polys.iter_mut().enumerate().take(k) {
        *polynomial = decode_12_checked(&input[index * POLY_BYTES..(index + 1) * POLY_BYTES])?;
    }
    Some(result)
}

fn decode_polyvec_12_mod_q(input: &[u8], k: usize) -> Option<PolyVec> {
    if input.len() != k * POLY_BYTES {
        return None;
    }
    let mut result = PolyVec::zero();
    for (index, polynomial) in result.polys.iter_mut().enumerate().take(k) {
        *polynomial = decode_12_mod_q(&input[index * POLY_BYTES..(index + 1) * POLY_BYTES]);
    }
    Some(result)
}

pub(crate) fn public_key_is_canonical<P: MlKemParameterSet>(public_key: &[u8]) -> bool {
    if public_key.len() != P::ENCAPSULATION_KEY_BYTES {
        return false;
    }
    decode_polyvec_12_checked(&public_key[..P::K * POLY_BYTES], P::K).is_some()
}

pub(crate) fn keygen<P: MlKemParameterSet>(
    d: &[u8; SYM_BYTES],
) -> Result<(Vec<u8>, Zeroizing<Box<[u8]>>)> {
    let domain = [P::K as u8];
    let seeds = hash_g_parts(d, &domain)?;
    let mut rho = [0u8; SYM_BYTES];
    rho.copy_from_slice(&seeds[..SYM_BYTES]);
    let mut sigma = Zeroizing::new([0u8; SYM_BYTES]);
    sigma.copy_from_slice(&seeds[SYM_BYTES..]);

    let matrix = generate_matrix::<P>(&rho, false)?;
    let mut secret = sample_vector(&sigma, 0, P::ETA1, P::K)?;
    let mut error = sample_vector(&sigma, P::K as u8, P::ETA1, P::K)?;
    secret.ntt(P::K);
    error.ntt(P::K);

    let mut public = matrix_vector_product(&matrix, &secret, P::K);
    for (output, noise) in public.polys.iter_mut().zip(error.polys.iter()).take(P::K) {
        output.to_montgomery();
        output.add_assign(noise);
    }
    public.reduce(P::K);
    secret.reduce(P::K);

    let mut encapsulation_key = vec![0u8; P::ENCAPSULATION_KEY_BYTES];
    encode_polyvec_12(&public, P::K, &mut encapsulation_key[..P::K * POLY_BYTES]);
    encapsulation_key[P::K * POLY_BYTES..].copy_from_slice(&rho);

    let mut decapsulation_key =
        Zeroizing::new(vec![0u8; pke_secret_key_bytes::<P>()].into_boxed_slice());
    encode_polyvec_12(&secret, P::K, &mut decapsulation_key[..]);
    Ok((encapsulation_key, decapsulation_key))
}

pub(crate) fn encrypt<P: MlKemParameterSet>(
    public_key: &[u8],
    message: &[u8; SYM_BYTES],
    randomness: &[u8; SYM_BYTES],
) -> Result<Zeroizing<Box<[u8]>>> {
    debug_assert_eq!(public_key.len(), P::ENCAPSULATION_KEY_BYTES);
    // External encapsulation keys have already passed the FIPS modulus check.
    // During decapsulation, however, Algorithm 18 re-encrypts with the embedded
    // byte string after only the Section 7.3 hash check. ByteDecode_12 therefore
    // has to reduce arbitrary 12-bit coefficients modulo q here.
    let public_vector = decode_polyvec_12_mod_q(&public_key[..P::K * POLY_BYTES], P::K)
        .ok_or_else(|| primitive_error("ML-KEM K-PKE public-key decode"))?;
    let mut rho = [0u8; SYM_BYTES];
    rho.copy_from_slice(&public_key[P::K * POLY_BYTES..]);
    let transposed_matrix = generate_matrix::<P>(&rho, true)?;

    let mut ephemeral = sample_vector(randomness, 0, P::ETA1, P::K)?;
    let error_vector = sample_vector(randomness, P::K as u8, P::ETA2, P::K)?;
    let error_scalar = sample_cbd(randomness, (2 * P::K) as u8, P::ETA2)?;
    ephemeral.ntt(P::K);

    let mut u = matrix_vector_product(&transposed_matrix, &ephemeral, P::K);
    let mut v = pointwise_accumulate(&public_vector, &ephemeral, P::K);
    u.inv_ntt_tomont(P::K);
    v.inv_ntt_tomont();
    for (output, noise) in u.polys.iter_mut().zip(error_vector.polys.iter()).take(P::K) {
        output.add_assign(noise);
    }
    v.add_assign(&error_scalar);

    let mut message_encoded = Zeroizing::new(Poly::zero());
    for (index, coefficient) in message_encoded.coeffs.iter_mut().enumerate() {
        let bit = (message[index >> 3] >> (index & 7)) & 1;
        *coefficient = i16::from(bit) * 1_665;
    }
    v.add_assign(&message_encoded);
    u.reduce(P::K);
    v.reduce();

    let u_bytes = compressed_polyvec_bytes::<P>();
    let mut ciphertext = Zeroizing::new(vec![0u8; P::CIPHERTEXT_BYTES].into_boxed_slice());
    for (index, polynomial) in u.polys.iter().enumerate().take(P::K) {
        let compressed = Zeroizing::new(compress(polynomial, P::DU));
        let start = index * N * P::DU / 8;
        let end = start + N * P::DU / 8;
        encode(&compressed, P::DU, &mut ciphertext[start..end]);
    }
    let compressed_v = Zeroizing::new(compress(&v, P::DV));
    encode(&compressed_v, P::DV, &mut ciphertext[u_bytes..]);
    Ok(ciphertext)
}

pub(crate) fn decrypt<P: MlKemParameterSet>(
    pke_secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SYM_BYTES]>> {
    debug_assert_eq!(pke_secret_key.len(), pke_secret_key_bytes::<P>());
    debug_assert_eq!(ciphertext.len(), P::CIPHERTEXT_BYTES);
    let secret = Zeroizing::new(
        decode_polyvec_12_mod_q(pke_secret_key, P::K)
            .ok_or_else(|| primitive_error("ML-KEM K-PKE secret-key decode"))?,
    );

    let mut u = Zeroizing::new(PolyVec::zero());
    for (index, polynomial) in u.polys.iter_mut().enumerate().take(P::K) {
        let start = index * N * P::DU / 8;
        let end = start + N * P::DU / 8;
        *polynomial = decompress(&decode(&ciphertext[start..end], P::DU), P::DU);
    }
    let u_bytes = compressed_polyvec_bytes::<P>();
    let mut v = Zeroizing::new(decompress(&decode(&ciphertext[u_bytes..], P::DV), P::DV));

    u.ntt(P::K);
    let mut product = pointwise_accumulate(&secret, &u, P::K);
    product.inv_ntt_tomont();
    v.sub_assign(&product);
    v.reduce();
    let compressed_message = Zeroizing::new(compress(&v, 1));
    let mut message = Zeroizing::new([0u8; SYM_BYTES]);
    encode(&compressed_message, 1, message.as_mut());
    Ok(message)
}

#[cfg(test)]
pub(crate) fn ntt_roundtrip(polynomial: &Poly) -> Poly {
    let mut result = polynomial.clone();
    result.ntt();
    result.inv_ntt_tomont();
    result.reduce();
    result
}
