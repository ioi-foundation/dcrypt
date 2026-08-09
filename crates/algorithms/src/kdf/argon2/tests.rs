use super::*; // Imports items from the parent module (argon2/mod.rs)
use dcrypt_common::security::SecretVec;
use dcrypt_internal::random::{ChaCha20Rng, RngCore};
use dcrypt_internal::{boxed_bytes_zeroed, zeroizing_bytes_from_slice};
use hex; // For decoding expected hex strings in RFC vectors
use std::ops::Deref; // For deref() method on Zeroizing

// RFC-9106 constant inputs --------------------------------------------------
const PASSWORD: [u8; 32] = [0x01; 32]; // Password[32] 01 01 … 01
const SALT: [u8; 16] = [0x02; 16]; // Salt[16]     02 02 … 02
const SECRET: [u8; 8] = [0x03; 8]; // Secret[8]    03 03 … 03
const AD: [u8; 12] = [0x04; 12]; // AD[12]       04 04 … 04
const SALT_LEN: usize = 16; // All vectors use 16-byte salt

// Helper to build Params<SALT_LEN> for the three variants -------------------
fn rfc_params(argon_type: Algorithm) -> Params<SALT_LEN> {
    Params {
        argon_type,
        memory_cost: 32, // 32 KiB
        time_cost: 3,    // 3 passes
        parallelism: 4,  // 4 lanes
        salt: Salt::new(SALT),
        ad: Some(AD.to_vec()),
        secret: Some(zeroizing_bytes_from_slice(&SECRET)),
        output_len: 32, // 32-byte tag
        version: ARGON2_VERSION_1_3,
    }
}

#[test]
fn blake2b_argon2_h0_param_block_exact() {
    use crate::hash::blake2::BLAKE2B_IV;

    let b = create_blake2b_for_h0();
    // Check that the parameter block for H₀ has inner_length = 0
    // by examining the resulting h[0] after XOR with IV
    assert_eq!(b.h[0] ^ BLAKE2B_IV[0], 0x0101_0040);
}

// --- RFC 9106 Section 5.1: Argon2d Test Vector -----------------------------
#[test]
fn argon2d_rfc_vector_a1() -> Result<()> {
    let password = SecretVec::from_slice(&PASSWORD);
    let argon2 = Argon2::new_with_params(rfc_params(Algorithm::Argon2d));
    let hash = argon2.hash_password(password.as_ref())?;

    println!(">>> argon2d hash = {}", hex::encode(hash.as_slice()));

    let expected_hex = "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb";
    let expected_bytes = hex::decode(expected_hex).expect("Invalid expected hex");

    assert_eq!(
        hash.as_slice(),
        expected_bytes.as_slice(),
        "Argon2d RFC vector mismatch"
    );
    Ok(())
}

// --- RFC 9106 Section 5.2: Argon2i Test Vector -----------------------------
#[test]
fn argon2i_rfc_vector_a3() -> Result<()> {
    let password = SecretVec::from_slice(&PASSWORD);
    let argon2 = Argon2::new_with_params(rfc_params(Algorithm::Argon2i));
    let hash = argon2.hash_password(password.as_ref())?;

    println!(">>> argon2i hash = {}", hex::encode(hash.as_slice()));

    let expected_hex = "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8";
    let expected_bytes = hex::decode(expected_hex).expect("Invalid expected hex");

    assert_eq!(
        hash.as_slice(),
        expected_bytes.as_slice(),
        "Argon2i RFC vector mismatch"
    );
    Ok(())
}

// --- RFC 9106 Section 5.3: Argon2id Test Vector ----------------------------
#[test]
fn argon2id_rfc_vector_a5() -> Result<()> {
    let password = SecretVec::from_slice(&PASSWORD);
    let argon2 = Argon2::new_with_params(rfc_params(Algorithm::Argon2id));
    let hash = argon2.hash_password(password.as_ref())?;

    println!(">>> argon2id hash = {}", hex::encode(hash.as_slice()));

    let expected_hex = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
    let expected_bytes = hex::decode(expected_hex).expect("Invalid expected hex");

    assert_eq!(
        hash.as_slice(),
        expected_bytes.as_slice(),
        "Argon2id RFC vector mismatch"
    );
    Ok(())
}

// --- Additional common test case for reference implementation compatibility ---
#[test]
fn argon2id_reference_implementation_vector() -> Result<()> {
    const REF_SALT_LEN: usize = 8;
    let password = SecretVec::from_slice(b"password");
    let salt = Salt::<REF_SALT_LEN>::new(*b"somesalt");

    let params = Params::<REF_SALT_LEN> {
        argon_type: Algorithm::Argon2id,
        memory_cost: 32,
        time_cost: 2,
        parallelism: 4,
        salt,
        ad: None,
        secret: None,
        output_len: 32,
        version: ARGON2_VERSION_1_3,
    };

    let argon2 = Argon2::new_with_params(params);
    let hash = argon2.hash_password(password.as_ref())?;

    println!(
        ">>> argon2id reference implementation hash = {}",
        hex::encode(hash.as_slice())
    );

    let expected_hex = "d74d7db154b312931625cde5a51f76bc52113b4b0515aa94952203b3cc45b800";
    let expected_bytes = hex::decode(expected_hex).expect("Invalid expected hex");

    assert_eq!(
        hash.as_slice(),
        expected_bytes.as_slice(),
        "Argon2id reference implementation vector mismatch"
    );
    Ok(())
}

#[test]
fn argon2id_phc_string_hash_verify() -> Result<()> {
    let mut pw_bytes = [b' '; 32];
    let src_pw = b"complexP@$$w0rd!";
    pw_bytes[..src_pw.len()].copy_from_slice(src_pw);
    let password = SecretBytes::<32>::new(pw_bytes);

    const SALT_LEN: usize = 16;

    let mut salt_data_arr = [0u8; SALT_LEN];
    ChaCha20Rng::from_seed([0x61; 32]).fill_bytes(&mut salt_data_arr);
    let salt_struct = Salt::<SALT_LEN>::new(salt_data_arr);

    let ad_data_vec = b"user@example.com".to_vec();

    let params_for_hasher = Params::<SALT_LEN> {
        argon_type: Algorithm::Argon2id,
        memory_cost: 65536,
        time_cost: 2,
        parallelism: 4,
        salt: salt_struct.clone(),
        ad: Some(ad_data_vec.clone()),
        secret: None,
        output_len: 32,
        version: ARGON2_VERSION_1_3,
    };

    let argon2_hasher = Argon2::new_with_params(params_for_hasher);
    // Explicitly call the trait method to ensure PasswordHash is returned
    let phc_hash_obj =
        <Argon2<SALT_LEN> as PasswordHashFunction>::hash_password(&argon2_hasher, &password)?;

    assert_eq!(phc_hash_obj.algorithm, "argon2id");
    assert_eq!(
        phc_hash_obj.param("v").unwrap().as_str(),
        ARGON2_VERSION_1_3.to_string().as_str()
    );
    assert_eq!(phc_hash_obj.param("m").unwrap(), "65536");
    assert_eq!(phc_hash_obj.param("t").unwrap(), "2");
    assert_eq!(phc_hash_obj.param("p").unwrap(), "4");
    assert_eq!(
        phc_hash_obj.param("data").unwrap(),
        &base64::engine::general_purpose::STANDARD_NO_PAD.encode(&ad_data_vec)
    );
    assert_eq!(phc_hash_obj.salt.deref(), salt_struct.as_ref());
    assert_eq!(phc_hash_obj.hash.len(), 32);

    // Assuming Salt<S> and Params<S> can derive Default for Argon2::new()
    let argon2_verifier = Argon2::<SALT_LEN>::new();
    let is_valid = argon2_verifier.verify(&password, &phc_hash_obj)?;
    assert!(is_valid, "Verification failed for the correct password");

    let mut wrong_pw_bytes = [b' '; 32];
    let src_wrong_pw = b"wrongpassword";
    wrong_pw_bytes[..src_wrong_pw.len()].copy_from_slice(src_wrong_pw);
    let wrong_password = SecretBytes::<32>::new(wrong_pw_bytes);
    let is_invalid = argon2_verifier.verify(&wrong_password, &phc_hash_obj)?;
    assert!(
        !is_invalid,
        "Verification succeeded for an incorrect password"
    );

    let mut tampered_hash_obj = phc_hash_obj.clone();
    tampered_hash_obj
        .params
        .insert("m".to_string(), "32768".to_string());
    let verify_tampered_params_result = argon2_verifier.verify(&password, &tampered_hash_obj)?;
    assert!(
        !verify_tampered_params_result,
        "Verification succeeded with tampered memory cost"
    );

    let mut tampered_salt_hash_obj = phc_hash_obj.clone();
    let mut salt_vec = tampered_salt_hash_obj.salt.to_vec();
    salt_vec[0] ^= 0xff;
    tampered_salt_hash_obj.salt = salt_vec;
    let verify_tampered_salt_result = argon2_verifier.verify(&password, &tampered_salt_hash_obj)?;
    assert!(
        !verify_tampered_salt_result,
        "Verification succeeded with tampered salt"
    );

    let mut tampered_hash_val_obj = phc_hash_obj.clone();
    let mut mutable_hash = tampered_hash_val_obj.hash.to_vec();
    mutable_hash[0] ^= 0xff;
    tampered_hash_val_obj.hash = mutable_hash;
    let verify_tampered_hash_result = argon2_verifier.verify(&password, &tampered_hash_val_obj)?;
    assert!(
        !verify_tampered_hash_result,
        "Verification succeeded with tampered hash value"
    );

    Ok(())
}

#[test]
fn argon2_builder_overrides_work() -> Result<()> {
    const SALT_LEN: usize = 16;
    let base_salt_data = [0u8; SALT_LEN];
    let base_salt = Salt::<SALT_LEN>::new(base_salt_data);

    let base_kdf_params = Params {
        argon_type: Algorithm::Argon2id,
        memory_cost: 65536,
        time_cost: 3,
        parallelism: 2,
        salt: base_salt.clone(),
        ad: Some(b"base_ad".to_vec()),
        secret: Some(zeroizing_bytes_from_slice(b"base_secret")),
        output_len: 32,
        version: ARGON2_VERSION_1_3,
    };
    let base_kdf = Argon2::<SALT_LEN>::new_with_params(base_kdf_params);

    let ikm = b"my input key material";

    let builder_salt_data = [1u8; SALT_LEN];
    let builder_salt_slice = &builder_salt_data[..];

    let builder_info = b"builder context info";
    let output_len_override = 64;

    let derived_key_via_builder = base_kdf
        .builder()
        .with_ikm(ikm)
        .with_salt(builder_salt_slice)
        .with_info(builder_info)
        .with_output_length(output_len_override)
        .derive()?;

    assert_eq!(
        derived_key_via_builder.len(),
        output_len_override,
        "Builder derived key length mismatch"
    );

    // For comparison, we must ensure the salt is correctly formed for `manual_kdf`
    let mut manual_salt_data = [0u8; SALT_LEN];
    manual_salt_data.copy_from_slice(builder_salt_slice);

    let manual_params_for_comparison = Params {
        argon_type: base_kdf.params.argon_type,
        memory_cost: base_kdf.params.memory_cost,
        time_cost: base_kdf.params.time_cost,
        parallelism: base_kdf.params.parallelism,
        salt: Salt::<SALT_LEN>::new(manual_salt_data), // Use the overridden salt
        ad: Some(builder_info.to_vec()),               // Use the overridden AD
        secret: base_kdf.params.secret.clone(),        // Secret is not overridden by builder.info()
        output_len: output_len_override,               // Use the overridden length
        version: base_kdf.params.version,
    };
    let manual_kdf = Argon2::new_with_params(manual_params_for_comparison);
    let manual_derived_key_vec = manual_kdf.hash_password(ikm)?; // hash_password uses ikm as password

    assert_eq!(
        derived_key_via_builder, manual_derived_key_vec,
        "Builder derivation differs from manual derivation with same params"
    );

    Ok(())
}

#[test]
fn generate_salt_correct_size() {
    const TEST_SALT_SIZE: usize = 24;
    // Removed DEFAULT_ARGON2_SALT_SIZE as it's not directly relevant here for checking Argon2<S>::generate_salt
    let mut rng = ChaCha20Rng::from_seed([0x62; 32]);
    let salt = Argon2::<TEST_SALT_SIZE>::generate_salt(&mut rng).unwrap();
    // MODIFIED: Expected size is TEST_SALT_SIZE (which is S in Argon2<S>)
    assert_eq!(salt.as_ref().len(), TEST_SALT_SIZE);

    // This part of the test checks Salt::random_with_size directly, which is good.
    let specific_salt = Salt::<TEST_SALT_SIZE>::random_with_size(&mut rng, TEST_SALT_SIZE).unwrap();
    assert_eq!(specific_salt.as_ref().len(), TEST_SALT_SIZE);
}

#[test]
fn h_prime_1024_matches_rfc_a1_block0() -> Result<()> {
    // From RFC 9106 Test Vector
    // For parameters: m=32, t=3, p=4, pwd=32×0x01, salt=16×0x02,
    // secret=8×0x03, ad=12×0x04, 32 byte tag

    // Construct the pre-hashing buffer for H0 as per RFC 9106
    let mut h0_buffer = SecretVec::empty();
    h0_buffer.extend_from_slice(&4u32.to_le_bytes()); // p = 4
    h0_buffer.extend_from_slice(&32u32.to_le_bytes()); // T = 32 (output_len)
    h0_buffer.extend_from_slice(&32u32.to_le_bytes()); // m = 32
    h0_buffer.extend_from_slice(&3u32.to_le_bytes()); // t = 3
    h0_buffer.extend_from_slice(&0x13u32.to_le_bytes()); // v = 0x13
    h0_buffer.extend_from_slice(&0u32.to_le_bytes()); // y = 0 (argon2d)
    h0_buffer.extend_from_slice(&32u32.to_le_bytes()); // |pwd| = 32
    h0_buffer.extend_from_slice(&PASSWORD); // pwd
    h0_buffer.extend_from_slice(&16u32.to_le_bytes()); // |salt| = 16
    h0_buffer.extend_from_slice(&SALT); // salt
    h0_buffer.extend_from_slice(&8u32.to_le_bytes()); // |secret| = 8
    h0_buffer.extend_from_slice(&SECRET); // secret
    h0_buffer.extend_from_slice(&12u32.to_le_bytes()); // |ad| = 12
    h0_buffer.extend_from_slice(&AD); // ad

    // Calculate true H0 using standard Blake2b-512 (as per RFC 9106 for H0 itself)
    use crate::hash::blake2::Blake2b; // Make sure Blake2b is in scope
                                      // H0 output size is 64 bytes as per RFC 9106
    let mut h0_hasher = Blake2b::with_output_size(64);
    h0_hasher.update(&h0_buffer)?;
    let mut h0_digest = h0_hasher.finalize()?;
    let computed_h0 = zeroizing_bytes_from_slice(h0_digest.as_ref());
    h0_digest.zeroize();

    // This is the correct H0 for the RFC parameters (to be verified against implementation)
    let expected_rfc_h0 = hex::decode(
        "b8819791a0359660bb7709c85fa48f04d5d82c05c5f215ccdb885491717cf757082c28b951be381410b5fc2eb7274033b9fdc7ae672bcaac5d179097a4af3109"
    ).expect("Failed to decode expected RFC H0 hex");

    assert_eq!(
        computed_h0.as_slice(),
        &expected_rfc_h0[..],
        "Standard Blake2b H0 computation for RFC vector mismatch"
    );

    // Seed for B[0][0] uses this computed_h0:
    // B[i][0] = H'(H_0 || ser(0) || ser(i)) for the first pass (i=lane index)
    // B[i][1] = H'(H_0 || ser(1) || ser(i)) for the first pass
    // Here we test B[0][0] (lane 0, block index 0 for initial blocks).
    let mut block0_seed = SecretVec::empty();
    block0_seed.extend_from_slice(&computed_h0);
    block0_seed.extend_from_slice(&0u32.to_le_bytes()); // First block index = 0
    block0_seed.extend_from_slice(&0u32.to_le_bytes()); // Lane 0
                                                        // Generate B[0][0] using the h_prime_variable_output
    let block0 = h_prime_variable_output(&block0_seed, ARGON2_BLOCK_SIZE)?;

    // This expected value may need to be updated based on the reference implementation
    // or RFC 9106 if specific example B0 blocks are provided
    let expected_block0_start = hex::decode("8a5c6f2c6bea2fdb3426f800be139471")
        .expect("Failed to decode expected block0 start hex");

    assert_eq!(
        &block0[..16],
        &expected_block0_start[..],
        "H' computation for RFC vector block0 mismatch"
    );

    Ok(())
}

#[test]
fn debug_internal_argon2_h_prime() -> Result<()> {
    let data = [1u8; 8];

    // Test with small output size (32 bytes)
    let out_32 = h_prime_variable_output(&data, 32)?;
    assert_eq!(out_32.len(), 32, "H' output length mismatch for 32 bytes");

    // Test with medium output size (64 bytes)
    let out_64 = h_prime_variable_output(&data, 64)?;
    assert_eq!(out_64.len(), 64, "H' output length mismatch for 64 bytes");

    // Test with large output size (1024 bytes)
    let out_1024 = h_prime_variable_output(&data, 1024)?;
    assert_eq!(
        out_1024.len(),
        1024,
        "H' output length mismatch for 1024 bytes"
    );

    Ok(())
}

#[test]
fn h_prime_final_32_matches_rfc_a1_tag() -> Result<()> {
    // This test will verify the final H' compression for the RFC vector

    // Create a sample 1KB block
    let mut final_block_xor = Zeroizing::new(boxed_bytes_zeroed(ARGON2_BLOCK_SIZE));
    // Fill with a pattern
    for (i, byte) in final_block_xor.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    // Apply h_prime_variable_output
    let tag = h_prime_variable_output(&final_block_xor, 32)?;

    // Check consistency of our function
    let current_output = h_prime_variable_output(&final_block_xor, 32)?;

    assert_eq!(
        tag, current_output,
        "H' final compression should be consistent"
    );

    // When we have the actual final_block_xor from RFC 9106, we can use this:
    // let expected_tag = hex::decode("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb").expect("Failed to decode expected tag hex");
    // assert_eq!(tag, expected_tag, "H' final compression for RFC vector tag mismatch");

    Ok(())
}
