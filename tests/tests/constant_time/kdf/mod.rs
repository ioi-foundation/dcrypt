// tests/constant_time/kdf/mod.rs
// Module declarations for KDF constant time tests

// Declare test modules
pub mod argon2;
pub mod hkdf;
pub mod pbkdf2;

use dcrypt_tests::suites::constant_time::tester::TimingAnalysis;

pub(super) fn measure_hkdf_constant_time() -> Result<TimingAnalysis, String> {
    hkdf::measure_hkdf_constant_time()
}

pub(super) fn measure_pbkdf2_constant_time() -> Result<TimingAnalysis, String> {
    pbkdf2::measure_pbkdf2_constant_time()
}

pub(super) fn measure_argon2id_verify_constant_time() -> Result<TimingAnalysis, String> {
    argon2::measure_argon2id_verify_constant_time()
}

pub(super) fn measure_argon2_constant_time_compare() -> Result<TimingAnalysis, String> {
    argon2::measure_argon2_constant_time_compare()
}
