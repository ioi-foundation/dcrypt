//! sampling.rs - Cryptographic sampling algorithms

use super::params::Modulus;
use super::polynomial::Polynomial;
use crate::error::{Error, Result};
use dcrypt_internal::random::{try_fill_bytes_zeroing_on_error, CryptoRng, RngCore};
use dcrypt_internal::zeroing::Zeroizing;

/// Trait for sampling polynomials uniformly at random
pub trait UniformSampler<M: Modulus> {
    /// Samples a polynomial with coefficients uniformly random in [0, Q-1]
    fn sample_uniform<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Polynomial<M>>;
}

/// Trait for sampling polynomials from a Centered Binomial Distribution (CBD)
pub trait CbdSampler<M: Modulus> {
    /// Samples a polynomial with coefficients from CBD(eta)
    fn sample_cbd<R: RngCore + CryptoRng>(rng: &mut R, eta: u8) -> Result<Polynomial<M>>;
}

/// Default implementation of cryptographic samplers
pub struct DefaultSamplers;

impl<M: Modulus> UniformSampler<M> for DefaultSamplers {
    fn sample_uniform<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Polynomial<M>> {
        let mut poly = Polynomial::<M>::zero();
        let q = M::Q;

        // Handle different modulus sizes
        if q <= (1 << 16) {
            // For small moduli, use rejection sampling with u16
            sample_uniform_small::<M, R>(rng, &mut poly)?;
        } else if q <= (1 << 24) {
            // For medium moduli, use rejection sampling with u32
            sample_uniform_medium::<M, R>(rng, &mut poly)?;
        } else {
            // For large moduli up to 2^31
            sample_uniform_large::<M, R>(rng, &mut poly)?;
        }

        Ok(poly)
    }
}

/// Rejection sampling for small moduli (Q <= 2^16)
fn sample_uniform_small<M: Modulus, R: RngCore + CryptoRng>(
    rng: &mut R,
    poly: &mut Polynomial<M>,
) -> Result<()> {
    let q = M::Q;
    let n = M::N;

    // Find the largest multiple of q that fits in u16
    let threshold = ((1u32 << 16) / q) * q;

    for i in 0..n {
        loop {
            let mut bytes = Zeroizing::new([0u8; 2]);
            try_fill_bytes_zeroing_on_error(rng, &mut bytes[..])?;
            let sample = u32::from(bytes[0]) | (u32::from(bytes[1]) << 8);

            // Rejection sampling for uniform distribution
            if sample < threshold {
                poly.coeffs[i] = sample % q;
                break;
            }
        }
    }

    Ok(())
}

/// Rejection sampling for medium moduli (2^16 < Q <= 2^24)
fn sample_uniform_medium<M: Modulus, R: RngCore + CryptoRng>(
    rng: &mut R,
    poly: &mut Polynomial<M>,
) -> Result<()> {
    let q = M::Q;
    let n = M::N;

    // Use 3 bytes for sampling
    let threshold = ((1u32 << 24) / q) * q;

    for i in 0..n {
        loop {
            let mut bytes = Zeroizing::new([0u8; 3]);
            try_fill_bytes_zeroing_on_error(rng, &mut bytes[..])?;
            let sample =
                u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16);

            if sample < threshold {
                poly.coeffs[i] = sample % q;
                break;
            }
        }
    }

    Ok(())
}

/// Rejection sampling for large moduli (2^24 < Q <= 2^31)
fn sample_uniform_large<M: Modulus, R: RngCore + CryptoRng>(
    rng: &mut R,
    poly: &mut Polynomial<M>,
) -> Result<()> {
    let q = M::Q;
    let n = M::N;

    // Use full u32 with MSB clear to ensure < 2^31
    let threshold = ((1u32 << 31) / q) * q;

    for i in 0..n {
        loop {
            let mut bytes = Zeroizing::new([0u8; 4]);
            try_fill_bytes_zeroing_on_error(rng, &mut bytes[..])?;
            bytes[3] &= 0x7F; // Clear MSB
            let sample = u32::from(bytes[0])
                | (u32::from(bytes[1]) << 8)
                | (u32::from(bytes[2]) << 16)
                | (u32::from(bytes[3]) << 24);

            if sample < threshold {
                poly.coeffs[i] = sample % q;
                break;
            }
        }
    }

    Ok(())
}

impl<M: Modulus> CbdSampler<M> for DefaultSamplers {
    fn sample_cbd<R: RngCore + CryptoRng>(rng: &mut R, eta: u8) -> Result<Polynomial<M>> {
        if eta == 0 || eta > 16 {
            return Err(Error::Parameter {
                name: "CBD sampling".into(),
                reason: format!("eta must be in range [1, 16], got {}", eta).into(),
            });
        }

        let mut poly = Polynomial::<M>::zero();
        let n = M::N;
        let q = M::Q;

        // CBD(eta): sample 2*eta bits, compute sum of first eta bits minus sum of second eta bits
        let bytes_per_sample = (2 * eta as usize).div_ceil(8); // FIXED: Use div_ceil
        let mut buffer = Zeroizing::new([0u8; 4]); // Max 32 bits for eta=16

        for i in 0..n {
            try_fill_bytes_zeroing_on_error(rng, &mut buffer[..bytes_per_sample])?;

            let mut a = 0i32;
            let mut b = 0i32;

            // Extract eta bits for positive contribution
            for j in 0..eta {
                let byte_idx = j as usize / 8;
                let bit_idx = j as usize % 8;
                a += ((buffer[byte_idx] >> bit_idx) & 1) as i32;
            }

            // Extract eta bits for negative contribution
            for j in 0..eta {
                let bit_pos = (eta + j) as usize;
                let byte_idx = bit_pos / 8;
                let bit_idx = bit_pos % 8;
                b += ((buffer[byte_idx] >> bit_idx) & 1) as i32;
            }

            // CBD sample is in range [-eta, eta]
            let sample = a - b;

            // Convert to [0, q) range
            poly.coeffs[i] = ((sample + q as i32) % q as i32) as u32;
        }

        Ok(poly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcrypt_internal::random::ChaCha20Rng;

    #[derive(Clone)]
    struct TestModulus;
    impl Modulus for TestModulus {
        const Q: u32 = 3329;
        const N: usize = 256;
    }

    #[test]
    fn test_uniform_sampling() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let poly =
            <DefaultSamplers as UniformSampler<TestModulus>>::sample_uniform(&mut rng).unwrap();

        // Check all coefficients are in valid range
        for &coeff in poly.as_coeffs_slice() {
            assert!(coeff < TestModulus::Q);
        }
    }

    #[test]
    fn test_cbd_sampling() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        for eta in 1..=8 {
            let poly =
                <DefaultSamplers as CbdSampler<TestModulus>>::sample_cbd(&mut rng, eta).unwrap();

            // Check all coefficients are in valid range
            for &coeff in poly.as_coeffs_slice() {
                assert!(coeff < TestModulus::Q);
            }
        }
    }

    #[test]
    fn test_cbd_distribution() {
        // Simple statistical test for CBD
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let eta = 2;
        let num_samples = 10000;
        let mut histogram = vec![0u32; (2 * eta + 1) as usize];

        for _ in 0..num_samples {
            let poly =
                <DefaultSamplers as CbdSampler<TestModulus>>::sample_cbd(&mut rng, eta).unwrap();

            // Check first coefficient distribution
            let coeff = poly.coeffs[0];
            let centered = (coeff as i32 + eta as i32) % TestModulus::Q as i32;
            if centered <= 2 * eta as i32 {
                histogram[centered as usize] += 1;
            }
        }

        // CBD(2) should have distribution:
        // P(X = -2) = 1/16, P(X = -1) = 4/16, P(X = 0) = 6/16,
        // P(X = 1) = 4/16, P(X = 2) = 1/16
        let expected = [625, 2500, 3750, 2500, 625]; // Out of 10000

        // Chi-squared test with reasonable tolerance
        let mut chi_squared = 0.0;
        for i in 0..histogram.len() {
            let observed = histogram[i] as f64;
            let expected_val = expected[i] as f64;
            chi_squared += (observed - expected_val).powi(2) / expected_val;
        }

        // Degrees of freedom = 4, critical value at 0.05 significance ≈ 9.488
        assert!(
            chi_squared < 15.0,
            "Chi-squared test failed: {}",
            chi_squared
        );
    }
}
