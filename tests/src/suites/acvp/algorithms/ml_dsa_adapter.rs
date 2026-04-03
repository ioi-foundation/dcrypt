//! Test-only adapter for handling ACVP's non-standard secret key format
//!
//! This module provides conversion between ACVP format (no tr, different padding)
//! and standard FIPS 204 format.

use dcrypt_algorithms::hash::sha3::Sha3_256;
use dcrypt_algorithms::hash::HashFunction;
use dcrypt_algorithms::poly::params::DilithiumParams;
use dcrypt_algorithms::poly::params::Modulus;
use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_algorithms::poly::serialize::{
    CoefficientPacker, CoefficientUnpacker, DefaultCoefficientSerde,
};
use dcrypt_algorithms::xof::shake::ShakeXof128;
use dcrypt_algorithms::xof::ExtendableOutputFunction;
use dcrypt_params::pqc::dilithium::{
    Dilithium2Params, Dilithium3Params, Dilithium5Params, DilithiumSchemeParams, DILITHIUM_N,
};
use dcrypt_sign::dilithium::DilithiumSecretKey;
use dcrypt_sign::error::Error as SignError;

/// Adapter for handling ACVP's non-standard secret key format
pub struct AcvpSecretKeyAdapter;

// We need to define the polyvec types here since they're not exported
#[derive(Debug)]
struct PolyVecL<P: DilithiumSchemeParams> {
    polys: Vec<Polynomial<DilithiumParams>>,
    _phantom: std::marker::PhantomData<P>,
}

#[derive(Debug)]
struct PolyVecK<P: DilithiumSchemeParams> {
    polys: Vec<Polynomial<DilithiumParams>>,
    _phantom: std::marker::PhantomData<P>,
}

// Manual Clone implementations
impl<P: DilithiumSchemeParams> Clone for PolyVecL<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: DilithiumSchemeParams> Clone for PolyVecK<P> {
    fn clone(&self) -> Self {
        Self {
            polys: self.polys.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: DilithiumSchemeParams> PolyVecL<P> {
    fn zero() -> Self {
        let mut polys = Vec::with_capacity(P::L_DIM);
        for _ in 0..P::L_DIM {
            polys.push(Polynomial::<DilithiumParams>::zero());
        }
        Self {
            polys,
            _phantom: std::marker::PhantomData,
        }
    }

    fn ntt_inplace(&mut self) -> Result<(), SignError> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace().map_err(|e| SignError::from(e))?;
        }
        Ok(())
    }
}

impl<P: DilithiumSchemeParams> PolyVecK<P> {
    fn zero() -> Self {
        let mut polys = Vec::with_capacity(P::K_DIM);
        for _ in 0..P::K_DIM {
            polys.push(Polynomial::<DilithiumParams>::zero());
        }
        Self {
            polys,
            _phantom: std::marker::PhantomData,
        }
    }

    fn ntt_inplace(&mut self) -> Result<(), SignError> {
        for p in self.polys.iter_mut() {
            p.ntt_inplace().map_err(|e| SignError::from(e))?;
        }
        Ok(())
    }

    fn add(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..P::K_DIM {
            res.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        res
    }

    fn inv_ntt_inplace(&mut self) -> Result<(), SignError> {
        for p in self.polys.iter_mut() {
            p.from_ntt_inplace().map_err(|e| SignError::from(e))?;
        }
        Ok(())
    }
}

impl AcvpSecretKeyAdapter {
    /// Parse ACVP format secret key and convert to standard DilithiumSecretKey
    ///
    /// ACVP format omits 'tr' and uses all bytes for polynomial data (no padding)
    pub fn from_acvp_bytes(bytes: &[u8], param_set: &str) -> Result<DilithiumSecretKey, SignError> {
        match param_set {
            "Dilithium2" => Self::parse_dilithium2_acvp(bytes),
            "Dilithium3" => Self::parse_dilithium3_acvp(bytes),
            "Dilithium5" => Self::parse_dilithium5_acvp(bytes),
            _ => Err(SignError::Deserialization(format!(
                "Unknown parameter set: {}",
                param_set
            ))),
        }
    }

    /// Convert standard DilithiumSecretKey to ACVP format
    pub fn to_acvp_bytes(sk: &DilithiumSecretKey, param_set: &str) -> Result<Vec<u8>, SignError> {
        match param_set {
            "Dilithium2" => Self::serialize_dilithium2_acvp(sk),
            "Dilithium3" => Self::serialize_dilithium3_acvp(sk),
            "Dilithium5" => Self::serialize_dilithium5_acvp(sk),
            _ => Err(SignError::Deserialization(format!(
                "Unknown parameter set: {}",
                param_set
            ))),
        }
    }

    fn parse_dilithium2_acvp(bytes: &[u8]) -> Result<DilithiumSecretKey, SignError> {
        Self::parse_acvp_generic::<Dilithium2Params>(bytes)
    }

    fn parse_dilithium3_acvp(bytes: &[u8]) -> Result<DilithiumSecretKey, SignError> {
        Self::parse_acvp_generic::<Dilithium3Params>(bytes)
    }

    fn parse_dilithium5_acvp(bytes: &[u8]) -> Result<DilithiumSecretKey, SignError> {
        Self::parse_acvp_generic::<Dilithium5Params>(bytes)
    }

    fn parse_acvp_generic<P: DilithiumSchemeParams>(
        bytes: &[u8],
    ) -> Result<DilithiumSecretKey, SignError> {
        // Calculate expected component sizes
        let eta_bits = if P::ETA_S1S2 == 2 { 3 } else { 4 };
        let bytes_per_s_poly = DILITHIUM_N * eta_bits / 8;
        let bytes_per_t0_poly = DILITHIUM_N * P::D_PARAM as usize / 8;

        let s1_size = P::L_DIM * bytes_per_s_poly;
        let s2_size = P::K_DIM * bytes_per_s_poly;
        let t0_size = P::K_DIM * bytes_per_t0_poly;

        // ACVP format: ρ || K || s1 || s2 || t0 (no tr, no padding)
        let expected_size = 64 + s1_size + s2_size + t0_size;

        if bytes.len() != expected_size {
            return Err(SignError::Deserialization(format!(
                "Invalid ACVP secret key size for {}: expected {}, got {}",
                P::NAME,
                expected_size,
                bytes.len()
            )));
        }

        let mut offset = 0;

        // Extract components
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes[offset..offset + 32]);
        offset += 32;

        let s1_bytes = &bytes[offset..offset + s1_size];
        offset += s1_size;

        let s2_bytes = &bytes[offset..offset + s2_size];
        offset += s2_size;

        let t0_bytes = &bytes[offset..offset + t0_size];

        // Parse polynomial vectors
        let s1_vec = Self::unpack_polyvecl::<P>(s1_bytes, P::ETA_S1S2)?;
        let s2_vec = Self::unpack_polyveck::<P>(s2_bytes, P::ETA_S1S2)?;
        let t0_vec = Self::unpack_polyveck_t0::<P>(t0_bytes)?;

        // Reconstruct public key to compute tr
        let pk_bytes = Self::reconstruct_public_key::<P>(&rho, &s1_vec, &s2_vec)?;

        // Compute tr = H(pk)
        let mut hasher = Sha3_256::new();
        hasher
            .update(&pk_bytes)
            .map_err(|e| SignError::Serialization(e.to_string()))?;
        let digest = hasher
            .finalize()
            .map_err(|e| SignError::Serialization(e.to_string()))?;
        let mut tr = [0u8; 32];
        tr.copy_from_slice(&digest);

        // Pack into FIPS 204 format
        let sk_bytes = Self::pack_secret_key::<P>(&rho, &k, &tr, &s1_vec, &s2_vec, &t0_vec)?;

        DilithiumSecretKey::from_bytes(&sk_bytes)
    }

    fn serialize_dilithium2_acvp(sk: &DilithiumSecretKey) -> Result<Vec<u8>, SignError> {
        Self::serialize_acvp_generic::<Dilithium2Params>(sk)
    }

    fn serialize_dilithium3_acvp(sk: &DilithiumSecretKey) -> Result<Vec<u8>, SignError> {
        Self::serialize_acvp_generic::<Dilithium3Params>(sk)
    }

    fn serialize_dilithium5_acvp(sk: &DilithiumSecretKey) -> Result<Vec<u8>, SignError> {
        Self::serialize_acvp_generic::<Dilithium5Params>(sk)
    }

    fn serialize_acvp_generic<P: DilithiumSchemeParams>(
        sk: &DilithiumSecretKey,
    ) -> Result<Vec<u8>, SignError> {
        // For now, we'll just strip the tr and padding from the FIPS 204 format
        let sk_bytes = sk.as_ref();

        // Calculate expected component sizes
        let eta_bits = if P::ETA_S1S2 == 2 { 3 } else { 4 };
        let bytes_per_s_poly = DILITHIUM_N * eta_bits / 8;
        let bytes_per_t0_poly = DILITHIUM_N * P::D_PARAM as usize / 8;

        let s1_size = P::L_DIM * bytes_per_s_poly;
        let s2_size = P::K_DIM * bytes_per_s_poly;
        let t0_size = P::K_DIM * bytes_per_t0_poly;

        // ACVP format: ρ || K || s1 || s2 || t0 (no tr, no padding)
        let acvp_size = 64 + s1_size + s2_size + t0_size;
        let mut acvp_bytes = Vec::with_capacity(acvp_size);

        // Copy ρ and K
        acvp_bytes.extend_from_slice(&sk_bytes[0..64]);

        // Skip tr (32 bytes at offset 64)
        let offset = 96; // After ρ, K, and tr

        // Copy s1, s2, t0
        let remaining_size = s1_size + s2_size + t0_size;
        acvp_bytes.extend_from_slice(&sk_bytes[offset..offset + remaining_size]);

        Ok(acvp_bytes)
    }

    // Helper functions for polynomial packing/unpacking

    fn unpack_polyvecl<P: DilithiumSchemeParams>(
        packed: &[u8],
        eta: u32,
    ) -> Result<PolyVecL<P>, SignError> {
        let eta_bits = if eta == 2 { 3 } else { 4 };
        let bytes_per_poly = DILITHIUM_N * eta_bits / 8;

        let mut vec = PolyVecL::<P>::zero();
        let mut offset = 0;

        for i in 0..P::L_DIM {
            let poly_bytes = &packed[offset..offset + bytes_per_poly];
            let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, eta_bits)
                .map_err(|e| SignError::Serialization(e.to_string()))?;

            // Map from [0, 2η] back to [-η, η]
            for c in temp_poly.coeffs.iter_mut() {
                let signed = (*c as i32) - (eta as i32);
                if signed < 0 {
                    *c = (signed + dcrypt_algorithms::poly::params::DilithiumParams::Q as i32)
                        as u32;
                } else {
                    *c = signed as u32;
                }
            }

            vec.polys[i] = temp_poly;
            offset += bytes_per_poly;
        }

        Ok(vec)
    }

    fn unpack_polyveck<P: DilithiumSchemeParams>(
        packed: &[u8],
        eta: u32,
    ) -> Result<PolyVecK<P>, SignError> {
        let eta_bits = if eta == 2 { 3 } else { 4 };
        let bytes_per_poly = DILITHIUM_N * eta_bits / 8;

        let mut vec = PolyVecK::<P>::zero();
        let mut offset = 0;

        for i in 0..P::K_DIM {
            let poly_bytes = &packed[offset..offset + bytes_per_poly];
            let mut temp_poly = DefaultCoefficientSerde::unpack_coeffs(poly_bytes, eta_bits)
                .map_err(|e| SignError::Serialization(e.to_string()))?;

            // Map from [0, 2η] back to [-η, η]
            for c in temp_poly.coeffs.iter_mut() {
                let signed = (*c as i32) - (eta as i32);
                if signed < 0 {
                    *c = (signed + dcrypt_algorithms::poly::params::DilithiumParams::Q as i32)
                        as u32;
                } else {
                    *c = signed as u32;
                }
            }

            vec.polys[i] = temp_poly;
            offset += bytes_per_poly;
        }

        Ok(vec)
    }

    fn unpack_polyveck_t0<P: DilithiumSchemeParams>(
        packed: &[u8],
    ) -> Result<PolyVecK<P>, SignError> {
        let bytes_per_poly = DILITHIUM_N * P::D_PARAM as usize / 8;
        let t0_offset = 1 << (P::D_PARAM - 1);

        let mut vec = PolyVecK::<P>::zero();
        let mut offset = 0;

        for i in 0..P::K_DIM {
            let poly_bytes = &packed[offset..offset + bytes_per_poly];
            let mut temp_poly =
                DefaultCoefficientSerde::unpack_coeffs(poly_bytes, P::D_PARAM as usize)
                    .map_err(|e| SignError::Serialization(e.to_string()))?;

            for c in temp_poly.coeffs.iter_mut() {
                let signed = (*c as i32) - t0_offset;
                *c = ((signed + dcrypt_algorithms::poly::params::DilithiumParams::Q as i32)
                    % dcrypt_algorithms::poly::params::DilithiumParams::Q as i32)
                    as u32;
            }

            vec.polys[i] = temp_poly;
            offset += bytes_per_poly;
        }

        Ok(vec)
    }

    fn reconstruct_public_key<P: DilithiumSchemeParams>(
        rho: &[u8; 32],
        s1_vec: &PolyVecL<P>,
        s2_vec: &PolyVecK<P>,
    ) -> Result<Vec<u8>, SignError> {
        // Expand matrix A from rho
        let matrix_a = Self::expand_matrix_a::<P>(rho)?;

        // Convert to NTT domain - clone the vectors since we need to mutate them
        let mut matrix_a_hat = Vec::with_capacity(P::K_DIM);
        for row in matrix_a {
            let mut row_ntt = row;
            row_ntt.ntt_inplace()?;
            matrix_a_hat.push(row_ntt);
        }

        // Clone the vectors to avoid borrowing issues
        let mut s1_hat = s1_vec.clone();
        s1_hat.ntt_inplace()?;

        let mut s2_hat = s2_vec.clone();
        s2_hat.ntt_inplace()?;

        // t = As1 + s2
        let mut t_hat = Self::matrix_polyvecl_mul(&matrix_a_hat, &s1_hat);
        t_hat = t_hat.add(&s2_hat);

        // Convert back to standard domain
        let mut t = t_hat;
        t.inv_ntt_inplace()?;

        // Get t1 using Power2Round
        let (_, t1) = Self::power2round_polyvec(&t, P::D_PARAM);

        // Pack public key
        Self::pack_public_key::<P>(rho, &t1)
    }

    fn expand_matrix_a<P: DilithiumSchemeParams>(
        rho_seed: &[u8; 32],
    ) -> Result<Vec<PolyVecL<P>>, SignError> {
        let mut matrix_a = Vec::with_capacity(P::K_DIM);

        for i in 0..P::K_DIM {
            let mut row = PolyVecL::<P>::zero();
            for j in 0..P::L_DIM {
                let mut xof = ShakeXof128::new();
                xof.update(rho_seed)
                    .map_err(|e| SignError::Serialization(e.to_string()))?;
                xof.update(&[j as u8])
                    .map_err(|e| SignError::Serialization(e.to_string()))?;
                xof.update(&[i as u8])
                    .map_err(|e| SignError::Serialization(e.to_string()))?;

                let mut poly = Polynomial::<DilithiumParams>::zero();
                let mut ctr = 0;
                let mut temp_buf = [0u8; 3];

                while ctr < DilithiumParams::N {
                    xof.squeeze(&mut temp_buf)
                        .map_err(|e| SignError::Serialization(e.to_string()))?;
                    // Extract two 12-bit values from 3 bytes
                    let d1 = (temp_buf[0] as u32) | (((temp_buf[1] as u32) & 0x0F) << 8);
                    let d2 = ((temp_buf[1] as u32) >> 4) | ((temp_buf[2] as u32) << 4);

                    if d1 < DilithiumParams::Q {
                        poly.coeffs[ctr] = d1;
                        ctr += 1;
                    }
                    if ctr < DilithiumParams::N && d2 < DilithiumParams::Q {
                        poly.coeffs[ctr] = d2;
                        ctr += 1;
                    }
                }

                row.polys[j] = poly;
            }
            matrix_a.push(row);
        }
        Ok(matrix_a)
    }

    fn matrix_polyvecl_mul<P: DilithiumSchemeParams>(
        matrix_a_hat: &[PolyVecL<P>],
        vector_l_hat: &PolyVecL<P>,
    ) -> PolyVecK<P> {
        let mut result_veck = PolyVecK::<P>::zero();

        for (i, row) in matrix_a_hat.iter().enumerate() {
            let mut acc = Polynomial::<DilithiumParams>::zero();
            for j in 0..P::L_DIM {
                let prod = row.polys[j].ntt_mul(&vector_l_hat.polys[j]);
                acc = acc.add(&prod);
            }
            result_veck.polys[i] = acc;
        }

        result_veck
    }

    fn power2round_polyvec<P: DilithiumSchemeParams>(
        pv: &PolyVecK<P>,
        d_param: u32,
    ) -> (PolyVecK<P>, PolyVecK<P>) {
        let mut pv0 = PolyVecK::<P>::zero();
        let mut pv1 = PolyVecK::<P>::zero();

        for i in 0..P::K_DIM {
            for j in 0..DilithiumParams::N {
                let (r0_signed, r1) = Self::power2round(pv.polys[i].coeffs[j], d_param);
                // Store r0 as positive representative in [0, Q-1]
                pv0.polys[i].coeffs[j] =
                    ((r0_signed + DilithiumParams::Q as i32) % DilithiumParams::Q as i32) as u32;
                pv1.polys[i].coeffs[j] = r1;
            }
        }

        (pv0, pv1)
    }

    fn power2round(r: u32, d: u32) -> (i32, u32) {
        let q = DilithiumParams::Q;
        let r_plus = r % q;
        let half = 1 << (d - 1);

        let mut r1 = (r_plus + half) >> d;
        let mut r0 = r_plus as i32 - (r1 as i32) * (1 << d);

        if r_plus == q - 1 {
            r0 = 0;
            r1 = (q - 1) >> d;
        }
        if r0 == half as i32 {
            r0 = -(half as i32);
            r1 = r1.wrapping_add(1);
        }
        (r0, r1)
    }

    fn pack_public_key<P: DilithiumSchemeParams>(
        rho_seed: &[u8; 32],
        t1_vec: &PolyVecK<P>,
    ) -> Result<Vec<u8>, SignError> {
        let mut pk_bytes = Vec::with_capacity(P::PUBLIC_KEY_BYTES);

        // Pack ρ
        pk_bytes.extend_from_slice(rho_seed);

        // Pack t1 (each coefficient uses 10 bits for all parameter sets)
        for i in 0..P::K_DIM {
            let packed_poly = DefaultCoefficientSerde::pack_coeffs(&t1_vec.polys[i], 10)
                .map_err(|e| SignError::Serialization(e.to_string()))?;
            pk_bytes.extend_from_slice(&packed_poly);
        }

        Ok(pk_bytes)
    }

    fn pack_secret_key<P: DilithiumSchemeParams>(
        rho_seed: &[u8; 32],
        k_seed: &[u8; 32],
        tr_hash: &[u8; 32],
        s1_vec: &PolyVecL<P>,
        s2_vec: &PolyVecK<P>,
        t0_vec: &PolyVecK<P>,
    ) -> Result<Vec<u8>, SignError> {
        let mut sk_bytes = Vec::with_capacity(P::SECRET_KEY_BYTES);

        // Pack ρ, K, tr
        sk_bytes.extend_from_slice(rho_seed);
        sk_bytes.extend_from_slice(k_seed);
        sk_bytes.extend_from_slice(tr_hash);

        // Calculate bits needed for s1, s2 encoding
        let eta_bits = if P::ETA_S1S2 == 2 { 3 } else { 4 };

        // Pack s1 (coefficients in [-η, η])
        for i in 0..P::L_DIM {
            let mut temp_poly = s1_vec.polys[i].clone();
            // Map from [-η, η] to [0, 2η]
            for c in temp_poly.coeffs.iter_mut() {
                let centered = (*c as i64)
                    .rem_euclid(dcrypt_params::pqc::dilithium::DILITHIUM_Q as i64)
                    as i32;
                let adjusted = if centered > (dcrypt_params::pqc::dilithium::DILITHIUM_Q / 2) as i32
                {
                    centered - dcrypt_params::pqc::dilithium::DILITHIUM_Q as i32
                } else {
                    centered
                };
                *c = (adjusted + P::ETA_S1S2 as i32) as u32;
            }
            let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, eta_bits)
                .map_err(|e| SignError::Serialization(e.to_string()))?;
            sk_bytes.extend_from_slice(&packed);
        }

        // Pack s2 (same as s1)
        for i in 0..P::K_DIM {
            let mut temp_poly = s2_vec.polys[i].clone();
            for c in temp_poly.coeffs.iter_mut() {
                let centered = (*c as i64)
                    .rem_euclid(dcrypt_params::pqc::dilithium::DILITHIUM_Q as i64)
                    as i32;
                let adjusted = if centered > (dcrypt_params::pqc::dilithium::DILITHIUM_Q / 2) as i32
                {
                    centered - dcrypt_params::pqc::dilithium::DILITHIUM_Q as i32
                } else {
                    centered
                };
                *c = (adjusted + P::ETA_S1S2 as i32) as u32;
            }
            let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, eta_bits)
                .map_err(|e| SignError::Serialization(e.to_string()))?;
            sk_bytes.extend_from_slice(&packed);
        }

        // Pack t0 (coefficients in (-2^(d-1), 2^(d-1)])
        let t0_offset = 1 << (P::D_PARAM - 1);
        for i in 0..P::K_DIM {
            let mut temp_poly = t0_vec.polys[i].clone();
            for c in temp_poly.coeffs.iter_mut() {
                let centered = (*c as i64)
                    .rem_euclid(dcrypt_params::pqc::dilithium::DILITHIUM_Q as i64)
                    as i32;
                let adjusted = if centered > (dcrypt_params::pqc::dilithium::DILITHIUM_Q / 2) as i32
                {
                    centered - dcrypt_params::pqc::dilithium::DILITHIUM_Q as i32
                } else {
                    centered
                };
                *c = (adjusted + t0_offset) as u32;
            }
            let packed = DefaultCoefficientSerde::pack_coeffs(&temp_poly, P::D_PARAM as usize)
                .map_err(|e| SignError::Serialization(e.to_string()))?;
            sk_bytes.extend_from_slice(&packed);
        }

        // FIPS 204: Add padding if needed to match the specification size
        if sk_bytes.len() < P::SECRET_KEY_BYTES {
            sk_bytes.resize(P::SECRET_KEY_BYTES, 0u8);
        }

        Ok(sk_bytes)
    }
}
