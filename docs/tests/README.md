# dcrypt Tests (`dcrypt-tests`)

The `dcrypt-tests` crate is a dedicated workspace member for housing integration tests, ACVP validation, and the constant-time verification suite for the dcrypt library. Keeping this logic in a separate workspace crate allows more elaborate harness code and dependencies without polluting the main library crates.

## Purpose

-   **Integration Testing**: Verify that different components of the dcrypt library (e.g., `algorithms`, `symmetric`, `kem`, `sign`, `hybrid`) work together correctly.
-   **Cross-Implementation Testing**: Compare dcrypt outputs against known-answer vectors and compatibility adapters where applicable.
-   **Constant-Time Verification**: Statistically analyze timing behavior of security-sensitive operations using the custom harness in `tests/src/suites/constant_time/`. The current blocking suite prepares equal-public-metadata A/B inputs into one reusable same-address state outside the clock, follows an exactly balanced paired schedule, and assigns one fixed-seed paired-randomization p-value to each of exactly 29 cases. One suite-wide Holm correction controls family alpha at 0.01; a case blocks only when Holm rejects and its absolute paired mean difference exceeds its unchanged practical threshold. Paired-bootstrap confidence intervals, Welch-style mean-shift checks, and Kolmogorov-Smirnov tests are descriptive only.
-   **Test Vector Management**: Centralize and manage test vectors for various algorithms, possibly loaded from JSON or other formats (indicated by `vectors` directory and files like `blake3_vectors.json`).
-   **Hybrid Scheme Testing**: Specifically test the combined functionality of hybrid KEMs and signature schemes (`hybrid_tests.rs`).
-   **KEM Specific Tests**: Detailed tests for Key Encapsulation Mechanisms (`kem_tests.rs`).

## Structure

The `dcrypt-tests` crate has the following notable structure:

-   **`src/lib.rs`**: The main library file for the test crate. It likely pulls in modules for different test categories.
-   **`src/suites/constant_time/`**:
    *   `config.rs`: Configuration for sampling, descriptive-CI alpha, unchanged practical thresholds, and paired-v1 noise settings. The blocking family alpha is fixed by the suite contract in `tester.rs`.
    *   `mod.rs`: Module declaration.
    *   `profile.rs`: Stores comparable environment baselines in the versioned `paired-v1` namespace; legacy-harness keys are not consumed.
    *   `stats.rs`: Implements the fixed-seed paired randomization primary test, suite-wide Holm correction, and descriptive bootstrap / KS / Welch helpers.
    *   `tester.rs`: Builds the balanced schedule, prepares both classes outside the clock, records raw paired evidence, and gates materially noisy environments.
-   **`src/vectors/`**: Directory for storing and managing test vectors.
    *   Subdirectories for specific algorithms (e.g., `cbc`, `chacha`, `ctr`, `gcm`, `sha2`, `sha3`, `shake`).
    *   `blake3_vectors.json`: Example of test vectors in JSON format.
    *   `custom.rs`, `fips.rs`, `nist_pqc.rs`: Rust modules potentially for parsing or generating test vectors from different sources or for specific standards.
-   **`tests/`**: This is where the actual integration test binaries live, using the `#[test]` attribute.
    *   `acvp_tests.rs`: Runs the NIST-style ACVP validation suites.
    *   `constant_time_tests.rs`: Collects every one of the 29 blocking cases before applying one aggregate familywise verdict; ML-DSA public-input timing remains a separate nonblocking diagnostic.
    *   `cross_implementation_tests.rs`: For comparing dcrypt outputs.
    *   `hybrid_tests.rs`: For testing hybrid cryptographic schemes.
    *   `integration_tests.rs`: General integration tests.
    *   `kem_tests.rs`: Specific tests for KEMs.

## Dependencies

The `Cargo.toml` for `dcrypt-tests` depends on the major dcrypt workspace members (`algorithms`, `api`, `common`, `hybrid`, `internal`, `kem`, `sign`, `symmetric`) so it can validate end-to-end behavior. It also includes statistical and deterministic-test dependencies such as `rand_chacha`.

## Running Tests

Tests are typically run from the workspace root:

```bash
# Core integration and ACVP harness
cargo test -p dcrypt-tests

# Constant-time harness/assembly guards and the aggregate timing suite
cargo test -p dcrypt-tests --lib --all-features
cargo test -p dcrypt-tests --test constant_time_tests -- \
    --test-threads=1 --nocapture

# ACVP ML-DSA coverage in release mode
cargo test --release -p dcrypt-tests --test acvp_tests test_ml_dsa_ -- --nocapture

# Downstream v4 error API replacement fixture
cargo test -p dcrypt-tests --test error_api_v4_migration

# Public error and secret-buffer APIs under Miri
cargo +nightly-2026-08-07 miri test -p dcrypt-api --lib --all-features
cargo +nightly-2026-08-07 miri test -p dcrypt-common --lib --all-features

# Compile the attacker-controlled decoder fuzz targets
cargo +nightly-2026-08-07 fuzz build
```

The pull-request security workflow also runs workspace-wide `cargo-audit` and
`cargo-deny` checks after generating the intentionally untracked lockfile. Fuzz
targets and their exact coverage are documented in `fuzz/README.md`; ordinary
CI compiles them, while sustained fuzz campaigns remain a separate release
operation.

## Key Test Areas

-   **Correctness**: Verifying algorithm outputs against known-answer tests (KATs) and official test vectors.
-   **Security Properties**: Statistical timing-regression checks for selected sensitive operations, including ML-DSA verification.
-   **Parameter Handling**: Correct handling of keys, nonces, and other cryptographic parameters.
-   **Error Handling**: Proper behavior for invalid inputs and failure conditions.
-   **API Usability**: Ensuring the public APIs are ergonomic and function as documented.
-   **Interoperability** (Cross-Implementation): Ensuring that dcrypt can, for example, verify signatures or decrypt ciphertexts generated by other standard implementations (if applicable test vectors are used).
-   **Hybrid Scheme Logic**: Verifying that the combination logic in hybrid schemes is correct and that they achieve the intended combined security properties (at least structurally).

This dedicated test crate is a core part of maintaining the correctness, side-channel assurance, and release confidence of the dcrypt library.
