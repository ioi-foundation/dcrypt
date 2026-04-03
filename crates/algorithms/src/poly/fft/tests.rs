// Path: dcrypt/crates/algorithms/src/poly/fft/tests.rs
//! Tests for the BLS12-381 Scalar Field FFT/NTT.

use super::*;
use crate::ec::bls12_381::Bls12_381Scalar as Scalar;
use rand::rngs::OsRng;
use rand::RngCore;

/// Tests the fundamental roundtrip property: IFFT(FFT(P)) = P.
#[test]
fn test_fft_ifft_roundtrip() {
    let mut rng = OsRng;
    let mut poly = (0..FFT_SIZE)
        .map(|i| Scalar::from(rng.next_u64() + i as u64))
        .collect::<Vec<_>>();
    let original = poly.clone();

    fft(&mut poly).unwrap();
    assert_ne!(poly, original);
    ifft(&mut poly).unwrap();
    assert_eq!(poly, original);
}

/// Tests the linearity property: FFT(a) + FFT(b) = FFT(a + b).
#[test]
fn test_fft_linearity() {
    let mut rng = OsRng;
    let poly_a = (0..FFT_SIZE)
        .map(|i| Scalar::from(rng.next_u64() + i as u64))
        .collect::<Vec<_>>();
    let poly_b = (0..FFT_SIZE)
        .map(|i| Scalar::from(rng.next_u64() + i as u64))
        .collect::<Vec<_>>();

    let mut poly_sum = poly_a
        .iter()
        .zip(poly_b.iter())
        .map(|(a, b)| *a + *b)
        .collect::<Vec<_>>();

    let mut fft_a = poly_a.clone();
    let mut fft_b = poly_b.clone();
    fft(&mut fft_a).unwrap();
    fft(&mut fft_b).unwrap();

    let fft_sum_manual = fft_a
        .iter()
        .zip(fft_b.iter())
        .map(|(a, b)| *a + *b)
        .collect::<Vec<_>>();

    fft(&mut poly_sum).unwrap();

    assert_eq!(fft_sum_manual, poly_sum);
}

/// Tests the convolution theorem for NEGACYCLIC convolution.
#[test]
fn test_negacyclic_convolution_theorem() {
    let mut poly_a = vec![Scalar::zero(); FFT_SIZE];
    poly_a[0] = Scalar::from(1);
    poly_a[1] = Scalar::from(2);

    let mut poly_b = vec![Scalar::zero(); FFT_SIZE];
    poly_b[0] = Scalar::from(3);
    poly_b[1] = Scalar::from(4);

    let mut expected = vec![Scalar::zero(); FFT_SIZE];
    expected[0] = Scalar::from(3);
    expected[1] = Scalar::from(10);
    expected[2] = Scalar::from(8);

    let mut fft_a = poly_a.clone();
    let mut fft_b = poly_b.clone();
    fft_negacyclic(&mut fft_a).unwrap();
    fft_negacyclic(&mut fft_b).unwrap();

    let mut fft_c = fft_a
        .iter()
        .zip(fft_b.iter())
        .map(|(a, b)| *a * *b)
        .collect::<Vec<_>>();

    ifft_negacyclic(&mut fft_c).unwrap();

    assert_eq!(fft_c, expected);
}

#[test]
fn test_bit_reversal() {
    let mut data = vec![0, 1, 2, 3, 4, 5, 6, 7];
    bit_reverse_permutation(&mut data);
    assert_eq!(data, vec![0, 4, 2, 6, 1, 5, 3, 7]);
}

#[test]
fn check_roots_consistency() {
    let w_n = *super::get_fft_n_root();
    let g = *super::get_primitive_2n_root();

    assert_eq!(
        g.square(),
        w_n,
        "primitive_2N_root^2 must equal the derived N-th root"
    );

    let mut p = w_n;
    for _ in 0..super::FFT_SIZE.trailing_zeros() {
        p = p.square();
    }
    assert_eq!(p, Scalar::one(), "w_N^N must be 1");

    let mut h = w_n;
    for _ in 0..(super::FFT_SIZE.trailing_zeros() - 1) {
        h = h.square();
    }
    assert_eq!(h, -Scalar::one(), "w_N^(N/2) must be -1");

    let mut gn = g;
    for _ in 0..super::FFT_SIZE.trailing_zeros() {
        gn = gn.square();
    }
    assert_eq!(gn, -Scalar::one(), "primitive_2N_root^N must be -1");
}

#[test]
fn negacyclic_roundtrip_random() {
    let mut rng = OsRng;
    let mut a = (0..FFT_SIZE)
        .map(|_| Scalar::from(rng.next_u64()))
        .collect::<Vec<_>>();
    let orig = a.clone();
    fft_negacyclic(&mut a).unwrap();
    ifft_negacyclic(&mut a).unwrap();
    assert_eq!(a, orig);
}
