// tests/mod.rs
//
// FIPS 204 UseHint Direction Rules:
//
// The final FIPS 204 specification (13-Aug-2024) defines UseHint Algorithm 40 as:
//
// Step 3: "if h = 1 and r₀ > 0 return (r₁ + 1) mod m"     [POSITIVE → UP]
// Step 4: "if h = 1 and r₀ ≤ 0 return (r₁ − 1) mod m"    [ZERO/NEGATIVE → DOWN]
// Step 5: "return r₁"                                     [NO HINT → IDENTITY]
//
// Source: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf

use super::arithmetic::{
    challenge_poly_mul, // Added this import
    check_norm_poly,
    decompose,
    highbits,
    lowbits,
    power2round,
    schoolbook_mul_generic,
    use_hint_coeff,
    w1_encode_gamma,
};
use super::encoding::{
    pack_public_key, pack_secret_key, pack_signature, unpack_public_key, unpack_secret_key,
    unpack_signature,
};
use super::polyvec::{expand_matrix_a, PolyVecK, PolyVecL};
use super::sampling::{sample_challenge_c, sample_poly_cbd_eta, sample_polyvecl_uniform_gamma1};
use super::*;
use dcrypt_algorithms::poly::ntt::montgomery_reduce;
use dcrypt_algorithms::poly::params::DilithiumParams; // Removed unused Modulus trait import
use dcrypt_algorithms::poly::polynomial::Polynomial;
use dcrypt_params::pqc::dilithium::{
    Dilithium2Params, Dilithium3Params, Dilithium5Params, DilithiumSchemeParams, DILITHIUM_N,
    DILITHIUM_Q, FIPS204_SIGN_INTERNAL_MIN_LOOP_LIMIT,
};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const TEST_MESSAGE: &[u8] = b"test message for dilithium signatures";

// Constants for Dilithium2
const GAMMA2: u32 = (DILITHIUM_Q - 1) / 88;
const GAMMA2_MODE5: u32 = (DILITHIUM_Q - 1) / 32;

// ===== TEST HELPER FUNCTIONS =====
// These functions were moved from the main modules since they're only used in tests

// Test helper: multiply two values modulo q
fn mul_q(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % DILITHIUM_Q as u64) as u32
}

// Test helper: make hint for a single coefficient
fn make_hint_coeff(z_coeff: i32, r_coeff: u32, alpha: u32) -> bool {
    let (_, r1) = decompose(r_coeff, alpha);

    // Ensure r+z is in [0, q) before decompose
    let r_plus_z = ((r_coeff as i64 + z_coeff as i64).rem_euclid(DILITHIUM_Q as i64)) as u32;
    let (_, v1) = decompose(r_plus_z, alpha);

    r1 != v1
}

// Test helper: encode w1 coefficient
fn w1_encode_coeff<P: DilithiumSchemeParams>(r_coeff: u32) -> u32 {
    let (_, r1) = decompose(r_coeff, 2 * P::GAMMA2_PARAM);
    w1_encode_gamma(r1)
}

// Test helper: centered schoolbook multiplication
fn schoolbook_mul_centered(
    c: &Polynomial<DilithiumParams>,
    t0: &Polynomial<DilithiumParams>,
) -> Polynomial<DilithiumParams> {
    // Use generic function with both operands centered
    schoolbook_mul_generic(c, t0, true, true)
}

// Test helper: centered multiplication for eta-bounded coefficients
fn schoolbook_mul_eta_centered(
    c: &Polynomial<DilithiumParams>,
    s_eta: &Polynomial<DilithiumParams>,
) -> Polynomial<DilithiumParams> {
    // Use generic function with both operands centered
    schoolbook_mul_generic(c, s_eta, true, true)
}

// ===== END TEST HELPERS =====

// Rest of the test file content remains the same...
#[test]
fn test_dilithium2_sign_verify() {
    use super::arithmetic::{highbits_polyvec, make_hint_polyveck, use_hint_polyveck};
    use super::encoding::{
        pack_polyveck_w1, unpack_public_key, unpack_secret_key, unpack_signature,
    };
    use super::polyvec::{expand_matrix_a, matrix_polyvecl_mul};
    use super::sampling::sample_challenge_c;
    use super::*;
    use dcrypt_algorithms::poly::params::Modulus;
    use dcrypt_algorithms::xof::shake::ShakeXof256;
    use dcrypt_algorithms::xof::ExtendableOutputFunction;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const TEST_MESSAGE: &[u8] = b"Test message for Dilithium2";

    // Step 1: Generate keypair
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();

    // Step 2: Sign the message
    let sig = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();

    // Step 3: We'll assert full verification after the deeper algebraic checks so
    // any mismatch is easier to localize during debugging.
    let verify_result = Dilithium2::verify(TEST_MESSAGE, &sig, &pk);

    // Step 4: Deep algebraic verification using the ACTUAL challenge from the signature

    // Unpack all components - use as_ref() to get bytes
    let unpacked_sk = unpack_secret_key::<Dilithium2Params>(sk.as_ref()).unwrap();
    let (rho_seed, tr_hash) = (unpacked_sk.0, unpacked_sk.2);
    let (s1_vec, s2_vec, t0_vec) = (unpacked_sk.3, unpacked_sk.4, unpacked_sk.5);
    let (_, t1_vec) = unpack_public_key::<Dilithium2Params>(pk.as_ref()).unwrap();

    // Extract & reuse the real challenge from the signature
    let (c_tilde_sig, z_vec, h_hint_poly) =
        unpack_signature::<Dilithium2Params>(sig.as_ref()).unwrap();

    let c =
        sample_challenge_c::<Dilithium2Params>(&c_tilde_sig, Dilithium2Params::TAU_PARAM as u32)
            .unwrap();

    // Expand matrix A
    let matrix_a = expand_matrix_a::<Dilithium2Params>(&rho_seed).unwrap();
    let mut matrix_a_hat = Vec::new();
    for row in matrix_a {
        let mut row_ntt = row;
        row_ntt.ntt_inplace().unwrap();
        matrix_a_hat.push(row_ntt);
    }

    // Step 5: Recover y = z - c·s1
    let mut y_vec = z_vec.clone();
    for i in 0..Dilithium2Params::L_DIM {
        let cs1_i = c.schoolbook_mul(&s1_vec.polys[i]);
        y_vec.polys[i] = y_vec.polys[i].sub(&cs1_i);
    }

    // Step 6: Compute w = A·y
    let mut y_hat = y_vec.clone();
    y_hat.ntt_inplace().unwrap();
    let mut w_hat = matrix_polyvecl_mul(&matrix_a_hat, &y_hat);
    w_hat.inv_ntt_inplace().unwrap();
    let w = w_hat.clone();
    // Note: inv_ntt_inplace() already outputs coefficients in standard domain per FIPS 204

    // Step 7: Compute w1 = HighBits(w, 2γ2)
    let w1_original = highbits_polyvec(&w, 2 * Dilithium2Params::GAMMA2_PARAM);

    // Step 8: Verify hint generation

    // Compute c·s2 and c·t0 using the SAME challenge
    let mut cs2_vec = PolyVecK::<Dilithium2Params>::zero();
    let mut ct0_vec = PolyVecK::<Dilithium2Params>::zero();
    for i in 0..Dilithium2Params::K_DIM {
        // Use centered multiplication for s2 (coefficients in [-η, η])
        cs2_vec.polys[i] = schoolbook_mul_eta_centered(&c, &s2_vec.polys[i]);
        // Use centered multiplication for t0 (coefficients in (-2^(d-1), 2^(d-1)])
        ct0_vec.polys[i] = schoolbook_mul_centered(&c, &t0_vec.polys[i]);
    }

    // FIPS 204 Algorithm 7 computes h = MakeHint(-ct0, w - cs2 + ct0).
    let w_minus_cs2 = w.sub(&cs2_vec);
    let w_prime_approx = w_minus_cs2.add(&ct0_vec);
    let neg_ct0 = ct0_vec.neg_mod_q();
    let (h_recomputed, hint_count) =
        make_hint_polyveck::<Dilithium2Params>(&neg_ct0, &w_prime_approx).unwrap();

    // Verify hint count is within bounds (can be up to omega=80 for Dilithium2)
    assert!(
        hint_count <= Dilithium2Params::OMEGA_PARAM as usize,
        "Too many hints generated: {} > {}",
        hint_count,
        Dilithium2Params::OMEGA_PARAM
    );

    // Verify hints match
    let mut hint_matches = true;
    for i in 0..Dilithium2Params::K_DIM {
        for j in 0..DILITHIUM_N {
            if h_hint_poly.polys[i].coeffs[j] != h_recomputed.polys[i].coeffs[j] {
                hint_matches = false;
                break;
            }
        }
    }
    assert!(hint_matches, "Hints don't match");

    // Step 9: Simulate verifier's computation

    // Compute w' = Az - c·t1·2^d
    let mut z_hat = z_vec.clone();
    z_hat.ntt_inplace().unwrap();
    let mut az_hat = matrix_polyvecl_mul(&matrix_a_hat, &z_hat);
    az_hat.inv_ntt_inplace().unwrap();
    let mut w_prime = az_hat.clone();
    // Note: inv_ntt_inplace() already outputs coefficients in standard domain per FIPS 204

    // The public key stores t1, NOT t1·2^d
    // We must scale t1 by 2^d before multiplication
    let two_d = 1u32 << Dilithium2Params::D_PARAM;
    let mut t1_scaled = t1_vec.clone();
    for poly in t1_scaled.polys.iter_mut() {
        for coeff in poly.coeffs.iter_mut() {
            *coeff = ((*coeff as u64 * two_d as u64) % DilithiumParams::Q as u64) as u32;
        }
    }

    // Now subtract c·t1·2^d using the SCALED t1
    for i in 0..Dilithium2Params::K_DIM {
        let ct1 = challenge_poly_mul(&c, &t1_scaled.polys[i]);
        w_prime.polys[i] = w_prime.polys[i].sub(&ct1);
    }

    // Step 10: Apply UseHint to recover w1
    let w1_reconstructed = use_hint_polyveck::<Dilithium2Params>(&h_hint_poly, &w_prime).unwrap();

    // Verify w1 reconstruction matches original
    let mut w1_matches = true;
    for i in 0..Dilithium2Params::K_DIM {
        for j in 0..DILITHIUM_N {
            if w1_original.polys[i].coeffs[j] != w1_reconstructed.polys[i].coeffs[j] {
                w1_matches = false;
            }
        }
    }

    assert!(w1_matches, "W1 reconstruction failed");

    // Step 11: Verify challenge computation round-trip

    // Pack w1
    let w1_packed = pack_polyveck_w1::<Dilithium2Params>(&w1_reconstructed).unwrap();

    // Compute μ = H(tr || M)
    let mut xof_mu = ShakeXof256::new();
    xof_mu.update(&tr_hash).unwrap();
    xof_mu.update(TEST_MESSAGE).unwrap();
    let mut mu = vec![0u8; 64];
    xof_mu.squeeze(&mut mu).unwrap();

    // Compute c̃ = H(μ || w1)
    let mut xof_c = ShakeXof256::new();
    xof_c.update(&mu).unwrap();
    xof_c.update(&w1_packed).unwrap();
    let mut c_tilde_recomputed = vec![0u8; Dilithium2Params::CHALLENGE_BYTES];
    xof_c.squeeze(&mut c_tilde_recomputed).unwrap();

    assert_eq!(
        c_tilde_sig, c_tilde_recomputed,
        "Challenge seeds don't match"
    );

    // Step 12: Verify algebraic identities

    // Verify: w' = w + ct0 - cs2
    let w_plus_ct0_minus_cs2 = w.add(&ct0_vec).sub(&cs2_vec);
    let mut identity_holds = true;
    for i in 0..Dilithium2Params::K_DIM {
        for j in 0..DILITHIUM_N {
            if w_prime.polys[i].coeffs[j] != w_plus_ct0_minus_cs2.polys[i].coeffs[j] {
                identity_holds = false;
                break;
            }
        }
    }
    assert!(
        identity_holds,
        "Algebraic identity w' = w + ct0 - cs2 doesn't hold"
    );

    assert!(verify_result.is_ok(), "Basic verification should pass");
}

#[test]
fn test_dilithium3_sign_verify() {
    let mut rng = ChaCha20Rng::from_seed([43u8; 32]);
    let (pk, sk) = Dilithium3::keypair(&mut rng).unwrap();

    let sig = Dilithium3::sign(TEST_MESSAGE, &sk).unwrap();
    assert!(Dilithium3::verify(TEST_MESSAGE, &sig, &pk).is_ok());
}

#[test]
fn test_dilithium5_sign_verify() {
    let mut rng = ChaCha20Rng::from_seed([44u8; 32]);
    let (pk, sk) = Dilithium5::keypair(&mut rng).unwrap();

    let sig = Dilithium5::sign(TEST_MESSAGE, &sk).unwrap();
    assert!(Dilithium5::verify(TEST_MESSAGE, &sig, &pk).is_ok());
}

#[test]
fn test_power2round() {
    // Test with d = 13 (Dilithium standard)
    let d = 13;

    // Test case 1: r = 0
    let (r0, r1) = power2round(0, d);
    assert_eq!(r0, 0);
    assert_eq!(r1, 0);

    // Test case 2: r = 2^12 (exactly at boundary)
    let (r0, r1) = power2round(4096, d);
    assert_eq!(r0, -4096); // Tie goes to negative
    assert_eq!(r1, 1);

    // Test case 3: r = q-1 (special case)
    let (r0, r1) = power2round(DILITHIUM_Q - 1, d);
    assert_eq!(r0, 0);
    assert_eq!(r1, 1023); // (q-1) / 2^13

    // Test case 4: General case
    let (r0, r1) = power2round(12345, d);
    assert_eq!(r0, -4039); // 12345 - 2*8192 = -4039
    assert_eq!(r1, 2); // floor((12345 + 4096) / 8192) = 2
}

#[test]
fn test_decompose() {
    // Test for Dilithium2/3 parameters
    let alpha = 2 * GAMMA2;

    // Test case 1: a = 0
    let (a0, a1) = decompose(0, alpha);
    assert_eq!(a0, 0);
    assert_eq!(a1, 0);

    // Test case 2: Positive value
    let a = 1000000;
    let (a0, a1) = decompose(a, alpha);
    assert!(a0 > -(GAMMA2 as i32) && a0 <= GAMMA2 as i32);
    assert_eq!(
        (a1 as i32 * alpha as i32 + a0) % DILITHIUM_Q as i32,
        (a % DILITHIUM_Q) as i32
    );

    // Test case 3: Boundary case (a such that a - a0 = q - 1)
    // This triggers the special case in decompose
    let test_val = DILITHIUM_Q - 1 + 47616; // Constructs a case where a - a0 = q - 1
    let (a0, a1) = decompose(test_val, alpha);
    assert_eq!(a1, 0); // Should set a1 = 0
    assert_eq!(a0, 47615); // Should be original a0 - 1
}

#[test]
fn test_highbits_lowbits_consistency() {
    let alpha = 2 * GAMMA2;

    for _ in 0..100 {
        let r = rand::random::<u32>() % DILITHIUM_Q;
        let r1 = highbits(r, alpha);
        let r0 = lowbits(r, alpha);

        // Check reconstruction
        let reconstructed =
            (((r1 as i64 * alpha as i64) + r0 as i64).rem_euclid(DILITHIUM_Q as i64)) as u32;
        assert_eq!(reconstructed, r % DILITHIUM_Q);

        // Check ranges
        assert!(r0 > -(GAMMA2 as i32) && r0 <= GAMMA2 as i32);
    }
}

#[test]
fn test_make_hint_boundary() {
    // FIPS 204 final: At γ₂ boundary, hint should be true
    assert!(
        make_hint_coeff(1, GAMMA2, 2 * GAMMA2),
        "Dilithium2: make_hint_coeff(1, γ₂) should be true per FIPS 204"
    );

    // Other boundary cases
    assert!(
        !make_hint_coeff(0, GAMMA2, 2 * GAMMA2),
        "Dilithium2: make_hint_coeff(0, γ₂) should be false"
    );

    assert!(
        make_hint_coeff(-1, GAMMA2 + 1, 2 * GAMMA2),
        "Dilithium2: make_hint_coeff(-1, γ₂+1) should be true"
    );
}

#[test]
fn test_check_norm_poly() {
    let mut poly = Polynomial::<DilithiumParams>::zero();

    // All zeros should pass any bound
    assert!(check_norm_poly(&poly, 100));

    // Set one coefficient to exactly the bound
    poly.coeffs[0] = 100;
    assert!(!check_norm_poly(&poly, 100));

    // Set one coefficient above the bound
    poly.coeffs[0] = 101;
    assert!(!check_norm_poly(&poly, 100));

    // Test with negative values (represented as q - value)
    poly.coeffs[0] = DILITHIUM_Q - 100; // -100 mod q
    assert!(!check_norm_poly(&poly, 100));

    poly.coeffs[0] = DILITHIUM_Q - 101; // -101 mod q
    assert!(!check_norm_poly(&poly, 100));
}

#[test]
fn test_sample_poly_cbd_eta() {
    let seed = [42u8; 32];
    let nonce = 0;

    // Test CBD with eta = 2
    let poly2 = sample_poly_cbd_eta::<Dilithium2Params>(&seed, nonce, 2).unwrap();
    for &coeff in &poly2.coeffs {
        let centered = if coeff > DILITHIUM_Q / 2 {
            coeff as i32 - DILITHIUM_Q as i32
        } else {
            coeff as i32
        };
        assert!((-2..=2).contains(&centered));
    }

    // Test CBD with eta = 4
    let poly4 = sample_poly_cbd_eta::<Dilithium5Params>(&seed, nonce, 4).unwrap();
    for &coeff in &poly4.coeffs {
        let centered = if coeff > DILITHIUM_Q / 2 {
            coeff as i32 - DILITHIUM_Q as i32
        } else {
            coeff as i32
        };
        assert!((-4..=4).contains(&centered));
    }
}

#[test]
fn test_sample_challenge() {
    // Test for different tau values
    let test_cases = vec![
        (39, 32), // Dilithium2
        (49, 48), // Dilithium3
        (60, 64), // Dilithium5
    ];

    for (tau, seed_size) in test_cases {
        let c_tilde_seed = vec![42u8; seed_size];
        let c_poly = sample_challenge_c::<Dilithium2Params>(&c_tilde_seed, tau).unwrap();

        // Count non-zero coefficients
        let non_zero_count = c_poly.coeffs.iter().filter(|&&c| c != 0).count();
        assert_eq!(non_zero_count, tau as usize);

        // Check that non-zero coefficients are ±1
        for &coeff in &c_poly.coeffs {
            assert!(coeff == 0 || coeff == 1 || coeff == DILITHIUM_Q - 1);
        }
    }
}

#[test]
fn test_sample_uniform_gamma1() {
    let seed = [42u8; 32];
    let kappa = 0;

    // Test for Dilithium2 (gamma1 = 2^17)
    let gamma1 = 1 << 17;
    let pv = sample_polyvecl_uniform_gamma1::<Dilithium2Params>(&seed, kappa, gamma1).unwrap();

    for poly in &pv.polys {
        for &coeff in &poly.coeffs {
            let centered = if coeff > DILITHIUM_Q / 2 {
                coeff as i32 - DILITHIUM_Q as i32
            } else {
                coeff as i32
            };
            // Check bounds: ExpandMask produces coefficients in [-γ1 + 1, γ1]
            let lower = -(gamma1 as i32) + 1;
            let upper = gamma1 as i32;
            assert!(centered >= lower && centered <= upper);
        }
    }
}

#[test]
fn test_ntt_challenge_products_match_schoolbook() {
    let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
    let (_, sk) = Dilithium2::keypair(&mut rng).unwrap();
    let (_, _, _, s1_vec, s2_vec, t0_vec) =
        unpack_secret_key::<Dilithium2Params>(sk.as_ref()).unwrap();

    let c_tilde_seed = vec![0xA5; Dilithium2Params::CHALLENGE_BYTES];
    let c_poly =
        sample_challenge_c::<Dilithium2Params>(&c_tilde_seed, Dilithium2Params::TAU_PARAM as u32)
            .unwrap();

    let mut c_hat = c_poly.clone();
    c_hat.ntt_inplace().unwrap();

    let mut s1_hat = s1_vec.clone();
    s1_hat.ntt_inplace().unwrap();
    let mut s2_hat = s2_vec.clone();
    s2_hat.ntt_inplace().unwrap();
    let mut t0_hat = t0_vec.clone();
    t0_hat.ntt_inplace().unwrap();

    let mut s1_ntt = PolyVecL::<Dilithium2Params>::zero();
    for i in 0..Dilithium2Params::L_DIM {
        s1_ntt.polys[i] = c_hat.ntt_mul(&s1_hat.polys[i]);
    }
    s1_ntt.inv_ntt_inplace().unwrap();

    let mut s2_ntt = PolyVecK::<Dilithium2Params>::zero();
    for i in 0..Dilithium2Params::K_DIM {
        s2_ntt.polys[i] = c_hat.ntt_mul(&s2_hat.polys[i]);
    }
    s2_ntt.inv_ntt_inplace().unwrap();

    let mut t0_ntt = PolyVecK::<Dilithium2Params>::zero();
    for i in 0..Dilithium2Params::K_DIM {
        t0_ntt.polys[i] = c_hat.ntt_mul(&t0_hat.polys[i]);
    }
    t0_ntt.inv_ntt_inplace().unwrap();

    for i in 0..Dilithium2Params::L_DIM {
        let schoolbook = schoolbook_mul_generic(&c_poly, &s1_vec.polys[i], true, true);
        assert_eq!(schoolbook.coeffs, s1_ntt.polys[i].coeffs);
    }

    for i in 0..Dilithium2Params::K_DIM {
        let s2_schoolbook = schoolbook_mul_generic(&c_poly, &s2_vec.polys[i], true, true);
        assert_eq!(s2_schoolbook.coeffs, s2_ntt.polys[i].coeffs);

        let t0_schoolbook = schoolbook_mul_generic(&c_poly, &t0_vec.polys[i], true, true);
        assert_eq!(t0_schoolbook.coeffs, t0_ntt.polys[i].coeffs);
    }
}

#[test]
fn test_matrix_expansion() {
    let rho_seed = [42u8; 32];

    // Test matrix expansion is deterministic
    let matrix_a1 = expand_matrix_a::<Dilithium2Params>(&rho_seed).unwrap();
    let matrix_a2 = expand_matrix_a::<Dilithium2Params>(&rho_seed).unwrap();

    // Check dimensions
    assert_eq!(matrix_a1.len(), Dilithium2Params::K_DIM);
    assert_eq!(matrix_a1[0].polys.len(), Dilithium2Params::L_DIM);

    // Check determinism
    for i in 0..Dilithium2Params::K_DIM {
        for j in 0..Dilithium2Params::L_DIM {
            for k in 0..DILITHIUM_N {
                assert_eq!(
                    matrix_a1[i].polys[j].coeffs[k],
                    matrix_a2[i].polys[j].coeffs[k]
                );
            }
        }
    }
}

#[test]
fn test_polyvec_add_sub() {
    let mut pv1 = PolyVecK::<Dilithium2Params>::zero();
    let mut pv2 = PolyVecK::<Dilithium2Params>::zero();

    // Set some test values
    pv1.polys[0].coeffs[0] = 100;
    pv2.polys[0].coeffs[0] = 200;

    // Test addition
    let sum = pv1.add(&pv2);
    assert_eq!(sum.polys[0].coeffs[0], 300);

    // Test subtraction
    let diff = pv2.sub(&pv1);
    assert_eq!(diff.polys[0].coeffs[0], 100);
}

#[test]
fn test_power2round_properties() {
    let d = 13;

    // Property: For all r, we have r = r1 * 2^d + r0 (mod q)
    for _ in 0..1000 {
        let r = rand::random::<u32>() % DILITHIUM_Q;
        let (r0, r1) = power2round(r, d);

        let reconstructed =
            (((r1 as i64) * (1i64 << d) + (r0 as i64)).rem_euclid(DILITHIUM_Q as i64)) as u32;
        assert_eq!(reconstructed, r % DILITHIUM_Q);

        // Check range: r0 in (-2^(d-1), 2^(d-1)]
        assert!(r0 >= -(1 << (d - 1)) && r0 <= (1 << (d - 1)));
    }
}

#[test]
fn test_decompose_properties() {
    let alpha = 2 * GAMMA2;

    // Property: For all a, we have a = a1 * alpha + a0 (mod q)
    for _ in 0..1000 {
        let a = rand::random::<u32>() % DILITHIUM_Q;
        let (a0, a1) = decompose(a, alpha);

        let reconstructed =
            (((a1 as i64) * (alpha as i64) + (a0 as i64)).rem_euclid(DILITHIUM_Q as i64)) as u32;
        assert_eq!(reconstructed, a % DILITHIUM_Q);

        // Check range: a0 in (-gamma2, gamma2]
        assert!(a0 > -(GAMMA2 as i32) && a0 <= GAMMA2 as i32);
    }
}

#[test]
fn test_montgomery_reduction() {
    // Test Montgomery reduction properties
    // R = 2^32 mod q = 4193792
    let r = 4193792u32; // This is 2^32 mod q for Dilithium

    // Property: montgomery_reduce(a * R) = a (mod q)
    for _ in 0..100 {
        let a = rand::random::<u32>() % DILITHIUM_Q;
        let a_mont = mul_q(a, r); // a * R mod q
        let a_reduced = montgomery_reduce::<DilithiumParams>(a_mont as u64);
        assert_eq!(a_reduced, a);
    }
}

#[test]
fn test_secret_key_serialization_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Generate a keypair
    let (_, sk) = Dilithium2::keypair(&mut rng).unwrap();

    // Unpack and repack - use as_ref() to get bytes
    let (rho, k, tr, s1, s2, t0) = unpack_secret_key::<Dilithium2Params>(sk.as_ref()).unwrap();
    let sk_repacked = pack_secret_key::<Dilithium2Params>(&rho, &k, &tr, &s1, &s2, &t0).unwrap();

    // Compare (accounting for potential padding)
    let content_size = sk_repacked.len().min(sk.as_ref().len()) - 32; // Exclude padding
    assert_eq!(&sk.as_ref()[..content_size], &sk_repacked[..content_size]);
}

#[test]
fn test_public_key_serialization_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Generate a keypair
    let (pk, _) = Dilithium2::keypair(&mut rng).unwrap();

    // Unpack and repack - use as_ref() to get bytes
    let (rho, t1) = unpack_public_key::<Dilithium2Params>(pk.as_ref()).unwrap();
    let pk_repacked = pack_public_key::<Dilithium2Params>(&rho, &t1).unwrap();

    assert_eq!(pk.as_ref(), &pk_repacked[..]);
}

#[test]
fn test_signature_serialization_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (_, sk) = Dilithium2::keypair(&mut rng).unwrap();

    let sig = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();

    // Unpack and repack - use as_ref() to get bytes
    let (c_tilde, z, h) = unpack_signature::<Dilithium2Params>(sig.as_ref()).unwrap();
    let sig_repacked = pack_signature::<Dilithium2Params>(&c_tilde, &z, &h).unwrap();

    assert_eq!(sig.as_ref(), &sig_repacked[..]);
}

#[test]
fn test_multiple_signatures_same_key() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();

    // Sign the same message multiple times
    for i in 0..5 {
        let msg = format!("test message {}", i).into_bytes();
        let sig = Dilithium2::sign(&msg, &sk).unwrap();
        assert!(Dilithium2::verify(&msg, &sig, &pk).is_ok());
    }
}

#[test]
fn test_deterministic_signatures() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (_, sk) = Dilithium2::keypair(&mut rng).unwrap();

    // Sign the same message twice
    let sig1 = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();
    let sig2 = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();

    // Signatures should be deterministic
    assert_eq!(sig1.as_ref(), sig2.as_ref());
}

#[test]
fn test_modified_message_fails() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();

    let sig = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();

    // Modify the message
    let mut modified_msg = TEST_MESSAGE.to_vec();
    modified_msg[0] ^= 1;

    assert!(Dilithium2::verify(&modified_msg, &sig, &pk).is_err());
}

#[test]
fn test_modified_signature_fails() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();

    let sig = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();

    // Create a modified signature by cloning and modifying
    let mut sig_bytes = sig.as_ref().to_vec();
    sig_bytes[0] ^= 1;
    let modified_sig = DilithiumSignatureData::from_bytes(&sig_bytes).unwrap();

    assert!(Dilithium2::verify(TEST_MESSAGE, &modified_sig, &pk).is_err());
}

#[test]
fn test_wrong_signature_fails() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let sk1 = Dilithium2::keypair(&mut rng).unwrap().1;
    let (pk2, _) = Dilithium2::keypair(&mut rng).unwrap();

    let sig = Dilithium2::sign(TEST_MESSAGE, &sk1).unwrap();

    // Try to verify with wrong public key
    assert!(Dilithium2::verify(TEST_MESSAGE, &sig, &pk2).is_err());
}

#[test]
fn test_invalid_public_key_size() {
    let invalid_pk_bytes = vec![0u8; 100]; // Wrong size
    let result = DilithiumPublicKey::from_bytes(&invalid_pk_bytes);
    assert!(result.is_err());
}

#[test]
fn test_invalid_secret_key_size() {
    // Test creating with invalid size
    let result = DilithiumSecretKey::from_bytes(&vec![0u8; 100]);
    assert!(result.is_err());
}

#[test]
fn test_invalid_signature_size() {
    let invalid_sig_bytes = vec![0u8; 100]; // Wrong size
    let result = DilithiumSignatureData::from_bytes(&invalid_sig_bytes);
    assert!(result.is_err());
}

#[test]
fn test_polyvec_zeroization() {
    let mut pv = PolyVecK::<Dilithium2Params>::zero();

    // Set some non-zero values
    pv.polys[0].coeffs[0] = 12345;
    pv.polys[0].coeffs[1] = 67890;

    // Zeroize
    pv.zeroize();

    // Check all coefficients are zero
    for poly in &pv.polys {
        for &coeff in &poly.coeffs {
            assert_eq!(coeff, 0);
        }
    }
}

#[test]
fn test_secret_key_zeroization() {
    let sk_bytes = vec![42u8; 2560]; // Valid Dilithium2 size
    let mut sk = DilithiumSecretKey::from_bytes(&sk_bytes).unwrap();
    let ptr = sk.as_ref().as_ptr();

    // Zeroize
    sk.zeroize();

    // Check memory is zeroed (carefully, as the memory might be reused)
    unsafe {
        // Only check up to the actual length
        for i in 0..sk.as_ref().len() {
            assert_eq!(*ptr.add(i), 0);
        }
    }
}

#[test]
fn test_gamma2_boundary_behavior() {
    // Test behavior exactly at the γ₂ boundary
    let alpha = 2 * GAMMA2;

    // Test decompose at boundary
    // r = γ₂ gives r₀ = γ₂, r₁ = 0
    let (r0, r1) = decompose(GAMMA2, alpha);
    assert_eq!(r0, GAMMA2 as i32);
    assert_eq!(r1, 0);

    // Test decompose just below boundary
    let (r0, _) = decompose(GAMMA2 - 1, alpha);
    assert_eq!(r0, (GAMMA2 - 1) as i32);

    // Test decompose just above boundary
    let (r0, _) = decompose(GAMMA2 + 1, alpha);
    assert_eq!(r0, -((GAMMA2 - 1) as i32));
}

#[test]
fn test_decompose_gamma2_exact() {
    // When r = γ₂, we get r₀ = γ₂, r₁ = 0 per FIPS 204
    let gamma2 = GAMMA2;
    let alpha = 2 * gamma2;

    let (r0, r1) = decompose(gamma2, alpha);
    assert_eq!(r0, gamma2 as i32);
    assert_eq!(r1, 0);

    // For Dilithium5
    let gamma2_5 = GAMMA2_MODE5;
    let alpha_5 = 2 * gamma2_5;

    let (r0, r1) = decompose(gamma2_5, alpha_5);
    assert_eq!(r0, gamma2_5 as i32);
    assert_eq!(r1, 0);
}

#[test]
fn test_q_minus_one_decompose_fips204() {
    // Test the special case handling for q-1
    let alpha = 2 * GAMMA2;

    // Direct test of q-1
    let (r0, r1) = decompose(DILITHIUM_Q - 1, alpha);
    assert_eq!(r1, 0);
    assert_eq!(r0, -1); // FIPS-204: q-1 special case gives r₀ = -1
}

#[test]
fn test_use_hint_fips204_algorithm_40() {
    // FIPS 204 Algorithm 40 (final specification test):
    //   Step 3: "if h = 1 and r₀ > 0 return (r₁ + 1) mod m"     [rotate UP when positive]
    //   Step 4: "if h = 1 and r₀ ≤ 0 return (r₁ − 1) mod m"     [rotate DOWN when zero/negative]

    let gamma2 = 95_232; // GAMMA2 for Dilithium2
    let alpha = 2 * gamma2; // 2 γ₂
    let m = 44u32; // number of non-special high-bit buckets for Dilithium2

    // Case 0: hint = 0 → identity (Step 5)
    let r = 1_234_567u32 % DILITHIUM_Q; // arbitrary coefficient
    let (_, r1) = decompose(r, alpha);
    assert_eq!(
        use_hint_coeff::<Dilithium2Params>(false, r),
        r1,
        "hint = 0 must return HighBits(r)"
    );

    // Case 1: r₀ > 0 → rotate UP (Step 3)
    // Choose r = α + 1 so that r₀ = 1, r₁ = 1
    let r_pos = alpha + 1; // 2 γ₂ + 1
    let (r0_pos, r1_pos) = decompose(r_pos, alpha);
    assert!(r0_pos > 0);
    let expected_up = (r1_pos + 1) % m; // FIPS 204: r₀ > 0 → UP
    assert_eq!(
        use_hint_coeff::<Dilithium2Params>(true, r_pos),
        expected_up,
        "FIPS 204 Step 3: r₀ > 0 must rotate UP"
    );

    // Case 2: r₀ = 0 → rotate DOWN (Step 4: r₀ ≤ 0)
    // Any exact multiple of α gives r₀ = 0
    let r_zero = alpha * 7; // r₁ = 7, r₀ = 0
    let (r0_zero, r1_zero) = decompose(r_zero, alpha);
    assert_eq!(r0_zero, 0);
    let expected_up0 = (r1_zero + m - 1) % m; // FIPS 204: r₀ ≤ 0 → DOWN
    assert_eq!(
        use_hint_coeff::<Dilithium2Params>(true, r_zero),
        expected_up0,
        "FIPS 204 Step 4: r₀ = 0 must rotate DOWN"
    );

    // Case 3: r₀ < 0 → rotate DOWN (Step 4: r₀ ≤ 0)
    // Choose r = α − 1 so that r₀ = −1
    let r_neg = alpha - 1; // 2 γ₂ − 1
    let (r0_neg, r1_neg) = decompose(r_neg, alpha);
    assert!(r0_neg < 0);
    let expected_down = (r1_neg + m - 1) % m; // FIPS 204: r₀ < 0 → DOWN
    assert_eq!(
        use_hint_coeff::<Dilithium2Params>(true, r_neg),
        expected_down,
        "FIPS 204 Step 4: r₀ < 0 must rotate DOWN"
    );
}

#[test]
fn test_make_use_hint_property() {
    // FIPS 204 property: UseHint(MakeHint(z, r), r+z) = HighBits(r)
    // This is guaranteed only for |z| < γ₂

    let alpha = 2 * GAMMA2;

    // Test vectors including edge cases
    let test_vectors: Vec<(u32, i32)> = vec![
        (8280417, 95232),  // z = γ₂ (edge case)
        (1234567, 1000),   // Normal case
        (7654321, -1000),  // Normal negative z
        (100000, 50000),   // Larger z but still < γ₂
        (8000000, -50000), // Large negative z
    ];

    for (r, z) in test_vectors {
        // Skip the edge case where |z| >= γ₂
        if z.abs() < GAMMA2 as i32 {
            let hint = make_hint_coeff(z, r, alpha);
            let r_plus_z = ((r as i64 + z as i64).rem_euclid(DILITHIUM_Q as i64)) as u32;
            let recovered = use_hint_coeff::<Dilithium2Params>(hint, r_plus_z);
            assert_eq!(
                recovered,
                highbits(r, alpha),
                "Dilithium2: UseHint property failed for r={}, z={}",
                r,
                z
            );
        }
    }
}

#[test]
fn test_hint_system_complete() {
    // Test the complete hint system with carefully designed test vectors
    // This test verifies that MakeHint/UseHint correctly handle boundary crossings
    // and can reconstruct the original high bits when given the perturbed value.
    //
    // The test creates specific z values that force r₀ to cross the ±γ₂ boundaries,
    // which should generate hints. The hint system should then be able to recover
    // the original high bits exactly.

    let mut pv_r = PolyVecK::<Dilithium2Params>::zero();
    let mut pv_z = PolyVecK::<Dilithium2Params>::zero();

    const ALPHA: u32 = 2 * GAMMA2; // 190,464 - full bucket width

    // Helper function to create a minimal z value that forces r₀ to cross boundary
    // Returns z such that |z| < γ₂ when possible
    fn create_boundary_crossing_z(r: u32, alpha: u32, gamma2: u32, cross_positive: bool) -> u32 {
        let (r0, _) = decompose(r, alpha);

        if cross_positive {
            // We want to push r₀ from positive to negative (cross +γ₂)
            if r0 > 0 {
                // Need to add just enough to exceed γ₂
                (gamma2 as i32 - r0 + 1) as u32
            } else {
                // r₀ is already negative/zero, need to wrap around
                // Add just enough to reach γ₂ + 1 from current position
                let to_zero = r0.unsigned_abs();
                (to_zero + gamma2 + 1) % DILITHIUM_Q
            }
        } else {
            // We want to push r₀ from negative to positive (cross -γ₂)
            if r0 <= 0 {
                // Need to subtract just enough to go below -γ₂
                DILITHIUM_Q.wrapping_sub((gamma2 as i32 + r0.abs() + 1) as u32)
            } else {
                // r₀ is already positive, need to wrap around
                // Subtract enough to reach -(γ₂ + 1) from current position
                DILITHIUM_Q.wrapping_sub(r0 as u32 + gamma2 + 1)
            }
        }
    }

    // Test case 1: Force crossing +γ₂ boundary
    pv_r.polys[0].coeffs[0] = 1234567 % DILITHIUM_Q;
    pv_z.polys[0].coeffs[0] =
        create_boundary_crossing_z(pv_r.polys[0].coeffs[0], ALPHA, GAMMA2, true);

    // Test case 2: Force crossing -γ₂ boundary
    pv_r.polys[0].coeffs[1] = 7654321 % DILITHIUM_Q;
    pv_z.polys[0].coeffs[1] =
        create_boundary_crossing_z(pv_r.polys[0].coeffs[1], ALPHA, GAMMA2, false);

    // Test case 3: Small change that won't cross boundary
    pv_r.polys[0].coeffs[2] = 42;
    pv_z.polys[0].coeffs[2] = 10; // Small change, no boundary crossing

    // All other coefficients: no change (z = 0)
    for i in 3..DILITHIUM_N {
        pv_r.polys[0].coeffs[i] = 42;
        pv_z.polys[0].coeffs[i] = 0;
    }

    // Compute r + z (component-wise)
    let pv_v = pv_r.add(&pv_z);

    // Generate hints
    let (hint_vec, hint_count) =
        super::arithmetic::make_hint_polyveck::<Dilithium2Params>(&pv_z, &pv_r)
            .expect("make_hint_polyveck must succeed");

    // We expect exactly 2 hints (positions 0 and 1 where we forced boundary crossings)
    assert_eq!(hint_count, 2, "Expected exactly 2 boundary-crossing hints");
    assert!(
        hint_count <= Dilithium2Params::OMEGA_PARAM as usize,
        "Hint count exceeds ω"
    );

    // Verify hints at expected positions
    assert_eq!(
        hint_vec.polys[0].coeffs[0], 1,
        "Position 0 should have hint (crossed +γ₂)"
    );
    assert_eq!(
        hint_vec.polys[0].coeffs[1], 1,
        "Position 1 should have hint (crossed -γ₂)"
    );
    assert_eq!(
        hint_vec.polys[0].coeffs[2], 0,
        "Position 2 should not have hint (no crossing)"
    );

    // Apply hints to recover high bits
    let recovered = super::arithmetic::use_hint_polyveck::<Dilithium2Params>(&hint_vec, &pv_v)
        .expect("use_hint_polyveck must succeed");

    // Expected high bits from original r vector
    let expected = super::arithmetic::highbits_polyvec::<Dilithium2Params>(&pv_r, ALPHA);

    // The hint system should recover the original high bits exactly
    let mut mismatches = 0;
    for k in 0..Dilithium2Params::K_DIM {
        for j in 0..DILITHIUM_N {
            let got = recovered.polys[k].coeffs[j];
            let want = expected.polys[k].coeffs[j];

            if got != want {
                mismatches += 1;
            }
        }
    }

    assert_eq!(
        mismatches, 0,
        "Found {} mismatches in hint recovery",
        mismatches
    );
}

#[test]
fn test_hint_system_marks_large_gaps_per_algorithm_39() {
    let mut pv_r = PolyVecK::<Dilithium2Params>::zero();
    let mut pv_z = PolyVecK::<Dilithium2Params>::zero();

    const ALPHA: u32 = 2 * GAMMA2; // 190,464 - full bucket width

    // Create a case that causes a multi-bucket jump (7 buckets)
    pv_r.polys[0].coeffs[0] = 1234567;
    pv_z.polys[0].coeffs[0] = 7 * ALPHA; // This would jump 7 buckets!

    let (hint_vec, hint_count) =
        super::arithmetic::make_hint_polyveck::<Dilithium2Params>(&pv_z, &pv_r)
            .expect("make_hint_polyveck must succeed");

    assert_eq!(hint_count, 1, "Algorithm 39 should set one hint bit");
    assert_eq!(
        hint_vec.polys[0].coeffs[0], 1,
        "large gap still yields a hint"
    );
}

#[test]
fn test_hint_bitpack_format() {
    // Test that hint packing produces correct size output
    let mut h = PolyVecK::<Dilithium2Params>::zero();

    // Set some hint bits
    h.polys[0].coeffs[10] = 1;
    h.polys[0].coeffs[20] = 1;
    h.polys[1].coeffs[30] = 1;

    // Test through the signature packing interface
    let z_vec = PolyVecL::<Dilithium2Params>::zero();
    let c_tilde = vec![0u8; Dilithium2Params::CHALLENGE_BYTES];

    let sig = pack_signature::<Dilithium2Params>(&c_tilde, &z_vec, &h).unwrap();

    // Check total signature size
    assert_eq!(sig.len(), Dilithium2Params::SIGNATURE_SIZE);

    // The hint section should be at the end, with size ω + K
    let hint_section_size = Dilithium2Params::OMEGA_PARAM as usize + Dilithium2Params::K_DIM;
    let hint_offset = sig.len() - hint_section_size;

    // Basic sanity checks on the hint section
    assert!(hint_offset < sig.len());
}

#[test]
fn test_hint_bitpack_edge_cases() {
    // Test maximum hints through signature interface
    let mut h = PolyVecK::<Dilithium2Params>::zero();

    // Set exactly ω hints
    for i in 0..Dilithium2Params::OMEGA_PARAM as usize {
        h.polys[0].coeffs[i] = 1;
    }

    let z_vec = PolyVecL::<Dilithium2Params>::zero();
    let c_tilde = vec![0u8; Dilithium2Params::CHALLENGE_BYTES];

    // Should succeed with exactly ω hints
    let sig = pack_signature::<Dilithium2Params>(&c_tilde, &z_vec, &h);
    assert!(sig.is_ok());

    // Try to exceed ω hints
    h.polys[0].coeffs[Dilithium2Params::OMEGA_PARAM as usize] = 1;
    let sig_fail = pack_signature::<Dilithium2Params>(&c_tilde, &z_vec, &h);
    assert!(sig_fail.is_err());
}

#[test]
fn test_corrupted_hint_encoding() {
    // Test that corrupted signatures fail to unpack
    let mut h = PolyVecK::<Dilithium2Params>::zero();
    h.polys[0].coeffs[10] = 1;
    h.polys[0].coeffs[20] = 1;

    let z_vec = PolyVecL::<Dilithium2Params>::zero();
    let c_tilde = vec![0u8; Dilithium2Params::CHALLENGE_BYTES];

    let mut sig = pack_signature::<Dilithium2Params>(&c_tilde, &z_vec, &h).unwrap();

    // Corrupt the signature by modifying hint section
    let counter_offset = sig.len() - Dilithium2Params::K_DIM;
    sig[counter_offset] = 100; // Claims 100 hints but only 2 present

    // Should fail to unpack
    assert!(unpack_signature::<Dilithium2Params>(&sig).is_err());
}

#[test]
fn test_w1_encode_consistency() {
    // Test that w1_encode produces correct values for both parameter sets

    // Dilithium2/3: γ₂ = 95232, bucket count = 45
    let test_r = 1234567u32;
    let encoded = w1_encode_coeff::<Dilithium2Params>(test_r);
    assert!(encoded < 45);

    // Dilithium5: γ₂ = 261888, bucket count = 16
    let test_r5 = 2345678u32;
    let encoded5 = w1_encode_coeff::<Dilithium5Params>(test_r5);
    assert!(encoded5 < 16);
}

#[test]
fn test_w1_encode_edge_cases() {
    // Test w1_encode at boundaries

    // At γ₂
    let encoded = w1_encode_coeff::<Dilithium2Params>(GAMMA2);
    assert_eq!(encoded, 0); // decompose(γ₂) gives (γ₂, 0) per FIPS 204

    // At multiples of α
    let alpha = 2 * GAMMA2;
    for i in 1..5 {
        let r = i * alpha;
        let encoded = w1_encode_coeff::<Dilithium2Params>(r);
        assert_eq!(encoded, i);
    }
}

#[test]
fn test_signature_size_bounds() {
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    // Test all parameter sets
    let test_cases = vec![
        (Dilithium2Params::SIGNATURE_SIZE, {
            let (_, sk) = Dilithium2::keypair(&mut rng).unwrap();
            Dilithium2::sign(TEST_MESSAGE, &sk).unwrap()
        }),
        (Dilithium3Params::SIGNATURE_SIZE, {
            let (_, sk) = Dilithium3::keypair(&mut rng).unwrap();
            Dilithium3::sign(TEST_MESSAGE, &sk).unwrap()
        }),
        (Dilithium5Params::SIGNATURE_SIZE, {
            let (_, sk) = Dilithium5::keypair(&mut rng).unwrap();
            Dilithium5::sign(TEST_MESSAGE, &sk).unwrap()
        }),
    ];

    for (expected_size, sig) in test_cases {
        assert_eq!(sig.as_ref().len(), expected_size);
    }
}

#[test]
fn test_signature_exact_size() {
    // Verify exact signature component sizes
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    let (_, sk) = Dilithium2::keypair(&mut rng).unwrap();
    let sig = Dilithium2::sign(TEST_MESSAGE, &sk).unwrap();

    let (c_tilde, z, h) = unpack_signature::<Dilithium2Params>(sig.as_ref()).unwrap();

    // Check c_tilde size
    assert_eq!(c_tilde.len(), Dilithium2Params::CHALLENGE_BYTES);

    // Check that z coefficients are in valid range
    for poly in &z.polys {
        for &coeff in &poly.coeffs {
            let centered = if coeff > DILITHIUM_Q / 2 {
                coeff as i32 - DILITHIUM_Q as i32
            } else {
                coeff as i32
            };
            let bound = (Dilithium2Params::GAMMA1_PARAM - Dilithium2Params::BETA_PARAM) as i32;
            assert!(centered >= -bound && centered <= bound);
        }
    }

    // Verify hint polynomial structure
    let mut total_hints = 0;
    for poly in &h.polys {
        for &coeff in &poly.coeffs {
            assert!(
                coeff == 0 || coeff == 1,
                "Invalid hint coefficient: {}",
                coeff
            );
            total_hints += coeff as usize;
        }
    }
    assert!(
        total_hints <= Dilithium2Params::OMEGA_PARAM as usize,
        "Too many hints in signature: {} > {}",
        total_hints,
        Dilithium2Params::OMEGA_PARAM
    );
}

#[test]
fn test_decompose_reference_implementation() {
    // Test vectors that match reference implementation behavior
    let alpha = 2 * GAMMA2;

    // Standard cases
    let test_cases = vec![
        (0, (0, 0)),
        (95232, (95232, 0)),    // r = γ₂ gives (γ₂, 0) per FIPS 204
        (95233, (-95231, 1)),   // r = γ₂ + 1
        (190464, (0, 1)),       // r = 2γ₂
        (4190208, (0, 22)),     // r = 22α
        (8285184, (95232, 43)), // Restored original expectation
    ];

    for (input, (expected_r0, expected_r1)) in test_cases {
        let (r0, r1) = decompose(input, alpha);
        assert_eq!(r0, expected_r0, "decompose({}) r0 mismatch", input);
        assert_eq!(r1, expected_r1, "decompose({}) r1 mismatch", input);
    }
}

#[test]
fn test_signature_hint_encoding_compatibility() {
    // Test that hint encoding/decoding works with various signature sizes
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

    for msg_len in [0, 1, 13, 100, 1000] {
        let message = vec![42u8; msg_len];
        let (pk, sk) = Dilithium2::keypair(&mut rng).unwrap();
        let sig = Dilithium2::sign(&message, &sk).unwrap();

        // Should verify successfully
        assert!(
            Dilithium2::verify(&message, &sig, &pk).is_ok(),
            "Failed to verify signature for message of length {}",
            msg_len
        );
    }
}

#[test]
fn test_hint_identity_comprehensive() {
    // Comprehensive check of the FIPS-204 hint identity:
    //
    //     UseHint( MakeHint(z, r) ,  r + z )  ==  HighBits(r)
    //
    // IMPORTANT: This identity only holds when |z| is small enough that the high bits
    // change by at most ±1 bucket. Large values of z that cause multi-bucket jumps
    // cannot be corrected by the hint system.

    let alpha = 2 * GAMMA2; // 190 464

    // Use only small z values that don't cause large bucket jumps
    let cases = vec![
        (1_234_567u32, 1i32, "small +z"),
        (1_234_567u32, -1i32, "small -z"),
        (GAMMA2, 10, "boundary +z"),
        (GAMMA2, -10, "boundary -z"),
        (alpha, 1, "r₀=0, small +z"),
        (alpha, -1, "r₀=0, small -z"),
        (alpha + 1, 5, "r₀>0, small +z"),
        (alpha - 1, -5, "r₀<0, small -z"),
        (GAMMA2 * 3, 20, "larger r, small z"),
        (DILITHIUM_Q - 100, -1, "near q-1"),
    ];

    for (r, z, label) in cases {
        // Only test cases where z is small enough for hint system to work
        if z.abs() >= 100 {
            continue;
        } // Much smaller constraint than γ₂

        let r_plus_z = ((r as i64 + z as i64).rem_euclid(DILITHIUM_Q as i64)) as u32;

        let hint = make_hint_coeff(z, r, alpha);
        let recovered = use_hint_coeff::<Dilithium2Params>(hint, r_plus_z);
        let expected = highbits(r, alpha);

        // Check if high bits actually changed to validate the test
        let original_highbits = highbits(r, alpha);
        let new_highbits = highbits(r_plus_z, alpha);
        let highbits_changed = original_highbits != new_highbits;

        // Skip cases where hint=true but high bits changed by more than 1
        if hint && highbits_changed {
            let bucket_diff = (new_highbits as i32 - original_highbits as i32).abs();
            if bucket_diff > 1 {
                continue;
            }
        }

        assert_eq!(
            recovered, expected,
            "Hint identity failure for {} (r={}, z={}): {} != {}",
            label, r, z, recovered, expected
        );
    }
}

#[test]
fn test_make_use_hint_consistency_at_boundary() {
    // Test that MakeHint and UseHint are consistent at the r0=0 boundary
    let gamma2 = GAMMA2;
    let alpha = 2 * gamma2;

    // Test several multiples of alpha where r0 = 0
    for k in 1..10 {
        let r = alpha * k;
        let (r0, _) = decompose(r, alpha);
        assert_eq!(r0, 0, "r0 should be 0 for r = {}*alpha", k);

        // Test with small positive and negative z values
        let z_values: [i32; 6] = [-100, -50, -1, 1, 50, 100];
        for &z in z_values.iter() {
            if z.abs() < gamma2 as i32 {
                let hint = make_hint_coeff(z, r, alpha);
                let r_plus_z = ((r as i64 + z as i64).rem_euclid(DILITHIUM_Q as i64)) as u32;
                let recovered = use_hint_coeff::<Dilithium2Params>(hint, r_plus_z);
                let expected = highbits(r, alpha);

                // The key property: UseHint(MakeHint(z, r), r+z) = HighBits(r)
                assert_eq!(
                    recovered, expected,
                    "UseHint property failed for r={} ({}*alpha), z={}",
                    r, k, z
                );
            }
        }
    }
}

#[test]
fn test_hint_identity_valid_cases() {
    // Test the FIPS 204 hint identity with realistic, valid cases
    // UseHint(MakeHint(z, r), r+z) = HighBits(r)
    //
    // The hint system can only correct ±1 bucket changes, so we test
    // with small z values that don't cause massive high-bit jumps.

    let alpha = 2 * GAMMA2;

    // Valid test cases with small z values
    let test_cases = vec![
        (GAMMA2, 1i32),         // At boundary with tiny change
        (GAMMA2, -1i32),        // At boundary with tiny negative change
        (alpha, 1i32),          // r₀=0 with small positive z
        (alpha, -1i32),         // r₀=0 with small negative z
        (alpha + 1, 5i32),      // r₀>0 with small positive z
        (alpha - 1, -5i32),     // r₀<0 with small negative z
        (1_000_000u32, 10i32),  // Random case with small z
        (5_000_000u32, -15i32), // Another random case
    ];

    for (r, z) in test_cases {
        let r_plus_z = ((r as i64 + z as i64).rem_euclid(DILITHIUM_Q as i64)) as u32;

        let hint = make_hint_coeff(z, r, alpha);
        let recovered = use_hint_coeff::<Dilithium2Params>(hint, r_plus_z);
        let expected = highbits(r, alpha);

        // Verify this is a reasonable test case (high bits don't jump wildly)
        let original_highbits = highbits(r, alpha);
        let new_highbits = highbits(r_plus_z, alpha);
        let bucket_diff = (new_highbits as i32 - original_highbits as i32).abs();

        // Only test cases where bucket change is reasonable (≤1 for hint system)
        if hint && bucket_diff > 1 {
            continue; // Skip invalid test cases
        }

        assert_eq!(
            recovered, expected,
            "FIPS 204 hint identity failed for r={}, z={} (bucket_diff={})",
            r, z, bucket_diff
        );
    }
}

fn collect_signing_attempts<P>(num_keys: usize, messages_per_key: usize) -> Vec<u16>
where
    P: DilithiumSchemeParams + Send + Sync + 'static,
{
    let mut seed = [0u8; 32];
    for (idx, byte) in P::NAME.as_bytes().iter().enumerate() {
        seed[idx % seed.len()] ^= *byte;
    }

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut attempts = Vec::with_capacity(num_keys * messages_per_key);

    for key_idx in 0..num_keys {
        let (_, sk) = Dilithium::<P>::keypair(&mut rng).unwrap();

        for message_idx in 0..messages_per_key {
            let message = format!(
                "{}-window-profile-key-{}-message-{}",
                P::NAME,
                key_idx,
                message_idx
            );
            let attempt = super::sign::first_valid_signing_attempt_internal::<P>(
                message.as_bytes(),
                sk.as_ref(),
            )
            .unwrap()
            .unwrap_or_else(|| panic!("{} exceeded {}", P::NAME, P::MAX_SIGN_ABORTS));
            attempts.push(attempt);
        }
    }

    attempts
}

fn percentile(sorted: &[u16], numerator: usize, denominator: usize) -> u16 {
    let idx = (sorted.len() - 1) * numerator / denominator;
    sorted[idx]
}

fn assert_signing_window_covers_sample<P>(num_keys: usize, messages_per_key: usize)
where
    P: DilithiumSchemeParams + Send + Sync + 'static,
{
    let attempts = collect_signing_attempts::<P>(num_keys, messages_per_key);
    let max_attempt = *attempts.iter().max().unwrap();

    assert!(
        max_attempt <= P::FIXED_SIGNING_WINDOW,
        "{} fixed signing window {} did not cover deterministic sample max {}",
        P::NAME,
        P::FIXED_SIGNING_WINDOW,
        max_attempt
    );
}

#[test]
fn test_dilithium_fixed_signing_windows_cover_regression_sample() {
    assert_signing_window_covers_sample::<Dilithium2Params>(4, 8);
    assert_signing_window_covers_sample::<Dilithium3Params>(4, 8);
    assert_signing_window_covers_sample::<Dilithium5Params>(4, 8);
}

#[test]
fn test_dilithium_fixed_signing_windows_meet_fips_appendix_c_bound() {
    assert!(
        Dilithium2Params::FIXED_SIGNING_WINDOW >= FIPS204_SIGN_INTERNAL_MIN_LOOP_LIMIT,
        "Dilithium2 fixed signing window fell below the FIPS 204 Appendix C minimum"
    );
    assert!(
        Dilithium3Params::FIXED_SIGNING_WINDOW >= FIPS204_SIGN_INTERNAL_MIN_LOOP_LIMIT,
        "Dilithium3 fixed signing window fell below the FIPS 204 Appendix C minimum"
    );
    assert!(
        Dilithium5Params::FIXED_SIGNING_WINDOW >= FIPS204_SIGN_INTERNAL_MIN_LOOP_LIMIT,
        "Dilithium5 fixed signing window fell below the FIPS 204 Appendix C minimum"
    );
}

#[test]
#[ignore = "profiling helper for selecting fixed constant-time signing windows"]
fn profile_dilithium_fixed_signing_windows() {
    fn print_stats<P>(num_keys: usize, messages_per_key: usize)
    where
        P: DilithiumSchemeParams + Send + Sync + 'static,
    {
        let mut attempts = collect_signing_attempts::<P>(num_keys, messages_per_key);
        attempts.sort_unstable();

        let min = attempts[0];
        let median = percentile(&attempts, 1, 2);
        let p90 = percentile(&attempts, 9, 10);
        let p99 = percentile(&attempts, 99, 100);
        let max = *attempts.last().unwrap();

        eprintln!(
            "{} attempt profile over {} samples: min={}, median={}, p90={}, p99={}, max={}",
            P::NAME,
            attempts.len(),
            min,
            median,
            p90,
            p99,
            max
        );
    }

    print_stats::<Dilithium2Params>(16, 32);
    print_stats::<Dilithium3Params>(16, 32);
    print_stats::<Dilithium5Params>(16, 32);
}
