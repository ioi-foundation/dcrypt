// tests/acvp_tests.rs
use dcrypt_tests::suites::acvp::{engine::DcryptEngine, loader, runner::Runner};

#[test]
fn test_aes_cbc_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ACVP-AES-CBC-1.0")
        .expect("Failed to load ACVP-AES-CBC-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("ACVP tests failed");
}

#[test]
fn test_aes_ctr_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ACVP-AES-CTR-1.0")
        .expect("Failed to load ACVP-AES-CTR-1.0 suite");

    // DEBUG: Print what's actually in the group defaults
    // println!("DEBUG ▶ first-group defaults = {:#?}", suite.groups[0].defaults);

    // DEBUG: Print what's in the first test case
    // println!("DEBUG ▶ first test raw = {:#?}", suite.groups[0].tests[0].inputs);

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("ACVP tests failed");
}

#[test]
fn test_aes_gcm_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ACVP-AES-GCM-1.0")
        .expect("Failed to load ACVP-AES-GCM-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     if let Some(direction) = &first_group.direction {
    //         println!("First group direction: {}", direction);
    //     }

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    // Run the test suite
    r.run_suite(&suite).expect("ACVP GCM tests failed");
}

#[test]
fn test_sha256_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHA2-256-1.0").expect("Failed to load SHA2-256-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA-256 ACVP tests failed");
}

#[test]
fn test_sha224_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHA2-224-1.0").expect("Failed to load SHA2-224-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA-224 ACVP tests failed");
}

#[test]
fn test_sha384_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHA2-384-1.0").expect("Failed to load SHA2-384-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA-384 ACVP tests failed");
}

#[test]
fn test_sha512_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHA2-512-1.0").expect("Failed to load SHA2-512-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA-512 ACVP tests failed");
}

#[test]
fn test_sha512_224_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("SHA2-512-224-1.0")
        .expect("Failed to load SHA2-512-224-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA-512/224 ACVP tests failed");
}

#[test]
fn test_sha512_256_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("SHA2-512-256-1.0")
        .expect("Failed to load SHA2-512-256-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA-512/256 ACVP tests failed");
}

// Add these test functions to tests/tests/acvp_tests.rs

#[test]
fn test_sha3_224_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHA3-224-2.0").expect("Failed to load SHA3-224-2.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA3-224 ACVP tests failed");
}

#[test]
fn test_sha3_256_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHA3-256-2.0").expect("Failed to load SHA3-256-2.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHA3-256 ACVP tests failed");
}

// Note: SHA3-384 and SHA3-512 ACVP test vectors are not available in the test vector directory.
// The SHA3-384 and SHA3-512 implementations are tested via the NIST test vectors in the unit tests.
// If ACVP test vectors for these variants become available, uncomment the tests below:

// #[test]
// #[ignore = "ACVP test vectors not available"]
// fn test_sha3_384_acvp() {
//     let engine = DcryptEngine;
//     let suite = loader::load_suite_by_name("SHA3-384-2.0")
//         .expect("Failed to load SHA3-384-2.0 suite");
//
//     let r = Runner::new(&engine);
//
//     println!("Running ACVP test suite: {}", suite.suite_name);
//     r.run_suite(&suite).expect("SHA3-384 ACVP tests failed");
// }

// #[test]
// #[ignore = "ACVP test vectors not available"]
// fn test_sha3_512_acvp() {
//     let engine = DcryptEngine;
//     let suite = loader::load_suite_by_name("SHA3-512-2.0")
//         .expect("Failed to load SHA3-512-2.0 suite");
//
//     let r = Runner::new(&engine);
//
//     println!("Running ACVP test suite: {}", suite.suite_name);
//     r.run_suite(&suite).expect("SHA3-512 ACVP tests failed");
// }

#[test]
fn test_shake128_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHAKE-128-1.0").expect("Failed to load SHAKE-128-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHAKE-128 ACVP tests failed");
}

#[test]
fn test_shake256_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("SHAKE-256-1.0").expect("Failed to load SHAKE-256-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: {}", suite.suite_name);
    r.run_suite(&suite).expect("SHAKE-256 ACVP tests failed");
}

#[test]
fn test_hmac_sha256_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HMAC-SHA2-256-1.0")
        .expect("Failed to load HMAC-SHA2-256-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HMAC-SHA2-256");
    r.run_suite(&suite)
        .expect("HMAC-SHA2-256 ACVP tests failed");
}

#[test]
fn test_hmac_sha384_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HMAC-SHA2-384-1.0")
        .expect("Failed to load HMAC-SHA2-384-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HMAC-SHA2-384");
    r.run_suite(&suite)
        .expect("HMAC-SHA2-384 ACVP tests failed");
}

#[test]
fn test_hmac_sha512_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HMAC-SHA2-512-1.0")
        .expect("Failed to load HMAC-SHA2-512-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HMAC-SHA2-512");
    r.run_suite(&suite)
        .expect("HMAC-SHA2-512 ACVP tests failed");
}

#[test]
fn test_hmac_sha3_256_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HMAC-SHA3-256-1.0")
        .expect("Failed to load HMAC-SHA3-256-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HMAC-SHA3-256");
    r.run_suite(&suite)
        .expect("HMAC-SHA3-256 ACVP tests failed");
}

#[test]
fn test_hkdf_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("HKDF-1.0").expect("Failed to load HKDF-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: HKDF-1.0");
    r.run_suite(&suite).expect("HKDF ACVP tests failed");
}

#[test]
fn test_pbkdf2_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("PBKDF-1.0").expect("Failed to load PBKDF-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: PBKDF-1.0");
    r.run_suite(&suite).expect("PBKDF2 ACVP tests failed");
}

#[test]
fn test_ecdh_component_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("KAS-ECC-CDH-Component-1.0")
        .expect("Failed to load KAS-ECC-CDH-Component-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: KAS-ECC-CDH-Component-1.0");
    r.run_suite(&suite).expect("ECDH Component tests failed");
}

#[test]
fn test_ecdh_kas_ecc_acvp() {
    let engine = DcryptEngine;
    let suite =
        loader::load_suite_by_name("KAS-ECC-1.0").expect("Failed to load KAS-ECC-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: KAS-ECC-1.0");
    r.run_suite(&suite).expect("KAS-ECC tests failed");
}

#[test]
fn test_ecdsa_keygen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ECDSA-KeyGen-FIPS186-5")
        .expect("Failed to load ECDSA-KeyGen-FIPS186-5 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ECDSA-KeyGen-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    r.run_suite(&suite).expect("ACVP ECDSA KeyGen tests failed");
}

#[test]
fn test_ecdsa_keyver_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ECDSA-KeyVer-FIPS186-5")
        .expect("Failed to load ECDSA-KeyVer-FIPS186-5 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ECDSA-KeyVer-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    r.run_suite(&suite).expect("ACVP ECDSA KeyVer tests failed");
}

#[test]
fn test_ecdsa_siggen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ECDSA-SigGen-FIPS186-5")
        .expect("Failed to load ECDSA-SigGen-FIPS186-5 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ECDSA-SigGen-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    r.run_suite(&suite).expect("ACVP ECDSA SigGen tests failed");
}

#[test]
fn test_ecdsa_sigver_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ECDSA-SigVer-FIPS186-5")
        .expect("Failed to load ECDSA-SigVer-FIPS186-5 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ECDSA-SigVer-FIPS186-5");
    // println!("Number of test groups: {}", suite.groups.len());

    // Debug: Print the first test group to understand structure
    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type);
    //     println!("First group defaults: {:?}", first_group.defaults);

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    r.run_suite(&suite).expect("ACVP ECDSA SigVer tests failed");
}

#[test]
fn test_eddsa_keygen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("EDDSA-KeyGen-1.0")
        .expect("Failed to load EDDSA-KeyGen-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: EDDSA-KeyGen-1.0");
    r.run_suite(&suite).expect("ACVP EdDSA KeyGen tests failed");
}

#[test]
fn test_eddsa_keyver_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("EDDSA-KeyVer-1.0")
        .expect("Failed to load EDDSA-KeyVer-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: EDDSA-KeyVer-1.0");
    r.run_suite(&suite).expect("ACVP EdDSA KeyVer tests failed");
}

#[test]
fn test_eddsa_siggen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("EDDSA-SigGen-1.0")
        .expect("Failed to load EDDSA-SigGen-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: EDDSA-SigGen-1.0");
    r.run_suite(&suite).expect("ACVP EdDSA SigGen tests failed");
}

#[test]
fn test_eddsa_sigver_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("EDDSA-SigVer-1.0")
        .expect("Failed to load EDDSA-SigVer-1.0 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: EDDSA-SigVer-1.0");
    r.run_suite(&suite).expect("ACVP EdDSA SigVer tests failed");
}

#[test]
fn test_ml_kem_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-KEM-encapDecap-FIPS203")
        .expect("Failed to load ML-KEM-encapDecap-FIPS203 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-KEM-encapDecap-FIPS203");
    // println!("Number of test groups: {}", suite.groups.len());

    // if let Some(first_group) = suite.groups.first() {
    //     println!("First group algorithm: {}", first_group.algorithm);
    //     println!("First group test type: {}", first_group.test_type); // Should be "AFT"
    //     // For KEMs, the "direction" is more like a "function"
    //     if let Some(function) = first_group.defaults.get("function").map(|v| v.as_string()) {
    //          println!("First group function: {}", function);
    //     } else if let Some(function) = first_group.direction.as_ref() {
    //         println!("First group function (from direction): {}", function);
    //     }
    //      println!("First group parameterSet: {:?}", first_group.defaults.get("parameterSet").map(|v| v.as_string()));

    //     if let Some(first_test) = first_group.tests.first() {
    //         println!("First test inputs: {:?}", first_test.inputs);
    //     }
    // }

    r.run_suite(&suite).expect("ACVP ML-KEM tests failed");
}

#[test]
fn test_ml_kem_keygen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-KEM-keyGen-FIPS203")
        .expect("Failed to load ML-KEM-keyGen-FIPS203 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-KEM-keyGen-FIPS203");
    r.run_suite(&suite)
        .expect("ACVP ML-KEM keyGen tests failed");
}

#[test]
fn test_ml_dsa_keygen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-DSA-keyGen-FIPS204")
        .expect("Failed to load ML-DSA-keyGen-FIPS204 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-DSA-keyGen-FIPS204");
    r.run_suite(&suite)
        .expect("ACVP ML-DSA KeyGen tests failed");
}

#[test]
fn test_ml_dsa_siggen_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-DSA-sigGen-FIPS204")
        .expect("Failed to load ML-DSA-sigGen-FIPS204 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-DSA-sigGen-FIPS204");
    r.run_suite(&suite)
        .expect("ACVP ML-DSA SigGen tests failed");
}

#[test]
fn test_ml_dsa_sigver_acvp() {
    let engine = DcryptEngine;
    let suite = loader::load_suite_by_name("ML-DSA-sigVer-FIPS204")
        .expect("Failed to load ML-DSA-sigVer-FIPS204 suite");

    let r = Runner::new(&engine);

    println!("Running ACVP test suite: ML-DSA-sigVer-FIPS204");
    r.run_suite(&suite)
        .expect("ACVP ML-DSA SigVer tests failed");
}

#[test]
fn full_stack_sha256_suite() {
    let engine = DcryptEngine;
    let suites = loader::load_all_suites();
    let r = Runner::new(&engine);

    // SHA-256 tests would need to be loaded separately
    // For now, this test is disabled as we're focusing on AES-CBC

    /*
    let sha256 = suites.iter()
        .find(|s| s.suite_name.contains("SHA2-256"))
        .expect("suite not found");

    r.run_suite(sha256).unwrap();
    */
}
