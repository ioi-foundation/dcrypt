// tests/src/suites/constant_time/config.rs

use std::path::{Path, PathBuf};

const PAIRED_NOISE_PROFILE_FILE: &str = "ct_noise_profile_paired_v1.json";

/// Resolve the paired-harness profile against the workspace rather than the
/// process cwd. Cargo runs this crate's integration binaries from `tests/`, so
/// a relative `target/...` path would silently select `tests/target`.
pub fn paired_noise_profile_path() -> PathBuf {
    if let Some(configured) = std::env::var_os("DCRYPT_CT_NOISE_PROFILE") {
        let path = PathBuf::from(configured);
        assert!(
            path.is_absolute(),
            "DCRYPT_CT_NOISE_PROFILE must be an absolute path"
        );
        return path;
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dcrypt-tests must remain directly inside the workspace")
        .join("target")
        .join(PAIRED_NOISE_PROFILE_FILE)
}

/// Configuration parameters for constant-time execution testing.
///
/// The blocking gate uses one paired-randomization p-value per case, a single
/// suite-wide Holm correction, and a predeclared practical threshold. Confidence
/// intervals, Welch output, and KS output are descriptive only.
#[derive(Debug, Clone)]
pub struct TestConfig {
    // --- Statistical Parameters ---
    /// Significance level (alpha) for the descriptive confidence interval.
    /// The blocking family alpha is fixed separately by the suite contract.
    /// Default: 0.01 (99% confidence).
    pub significance_level: f64,

    /// Number of bootstrap resamples to perform for CI calculation.
    /// Higher = more accurate tails, but slower.
    pub bootstrap_iterations: usize,

    /// Practical Significance Threshold (nanoseconds).
    /// A family-adjusted rejection blocks only when the absolute paired mean
    /// difference also exceeds this value.
    /// This filters out differences below the predeclared practical threshold.
    /// Default: 0.5ns.
    pub practical_significance_threshold: f64,

    /// Legacy Dudect-style Welch t-statistic threshold retained for
    /// configuration/API compatibility. Welch output is descriptive and never
    /// gates the suite.
    pub welch_t_threshold: f64,

    // --- Sampling Configuration ---
    /// Number of warmup iterations to characterize environment noise.
    pub num_warmup: usize,

    /// Number of distinct sample batches to collect.
    pub num_samples: usize,

    /// Number of iterations per sample batch.
    pub num_iterations: usize,

    // --- Versioned paired-harness noise profiling ---
    /// If true, loads/saves noise profiles to disk to detect environment degradation.
    pub use_noise_profile: bool,

    /// If true, excessive profile drift aborts the timing case. The open
    /// simulation laboratory records uncontrolled host drift observationally;
    /// both complete statistical family passes still gate.
    pub enforce_noise_profile: bool,

    /// Path to the noise profile store (JSON).
    pub noise_profile_path: PathBuf,

    /// Allowed degradation factor.
    /// If current_noise > baseline_noise * factor, the test is marked inconclusive/noisy
    /// rather than failing.
    pub noise_tolerance_factor: f64,
}

impl Default for TestConfig {
    fn default() -> Self {
        let enforce_noise_profile = match std::env::var("DCRYPT_CT_NOISE_POLICY") {
            Ok(value) if value == "observe" => false,
            Ok(value) if value == "enforce" => true,
            Ok(value) => panic!("unsupported DCRYPT_CT_NOISE_POLICY value: {value}"),
            Err(std::env::VarError::NotPresent) => true,
            Err(std::env::VarError::NotUnicode(_)) => {
                panic!("DCRYPT_CT_NOISE_POLICY must be valid Unicode")
            }
        };
        Self {
            significance_level: 0.01, // 99% Confidence
            // Fixed paired-bootstrap budget. This is large enough for stable
            // 99% descriptive intervals and is never increased after seeing
            // a result.
            bootstrap_iterations: 100_000,
            practical_significance_threshold: 0.5, // 0.5ns tolerance
            welch_t_threshold: 4.5,

            num_warmup: 2000,
            num_samples: 100,    // Increased samples for better distribution shape
            num_iterations: 500, // Lower iterations/sample to catch interruptions

            use_noise_profile: true,
            enforce_noise_profile,
            // The paired-v1 harness is statistically incomparable with the
            // legacy independent-sample engine and must not consume its keys.
            noise_profile_path: paired_noise_profile_path(),
            noise_tolerance_factor: 3.0, // Abort if noise is 3x historical baseline
        }
    }
}

// Helper constructors for specific primitive types
impl TestConfig {
    pub fn for_block_cipher() -> Self {
        Self {
            // Block ciphers are extremely fast; minimal tolerance.
            practical_significance_threshold: 0.2,
            num_iterations: 1000,
            ..Self::default()
        }
    }

    pub fn for_aead() -> Self {
        Self::default()
    }

    pub fn for_chacha_poly() -> Self {
        Self::default()
    }

    pub fn for_hash() -> Self {
        Self::default()
    }

    pub fn for_xof() -> Self {
        Self::default()
    }

    pub fn for_blake3_xof() -> Self {
        Self::default()
    }

    pub fn for_mac() -> Self {
        Self::default()
    }

    pub fn for_stream() -> Self {
        Self::default()
    }

    pub fn for_hkdf() -> Self {
        Self::default()
    }

    pub fn for_pbkdf2() -> Self {
        Self {
            // PBKDF2 is slow; adjust sampling
            num_warmup: 50,
            num_samples: 40,
            num_iterations: 10,
            practical_significance_threshold: 5.0, // Higher tolerance for slower op
            ..Self::default()
        }
    }

    pub fn for_pqc_kem() -> Self {
        Self {
            // MlKem has higher variance; rely heavily on robust stats.
            practical_significance_threshold: 1.0,
            num_warmup: 3000,
            ..Self::default()
        }
    }

    pub fn for_pqc_sign() -> Self {
        Self {
            num_samples: 200,
            practical_significance_threshold: 2.0,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_paired_v1_noise_namespace() {
        if std::env::var_os("DCRYPT_CT_NOISE_PROFILE").is_some() {
            return;
        }
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let expected = workspace_root
            .join("target")
            .join(PAIRED_NOISE_PROFILE_FILE);
        let configured = TestConfig::default().noise_profile_path;

        assert!(configured.is_absolute());
        assert_eq!(
            configured, expected,
            "the default profile must not resolve relative to integration-test cwd"
        );
    }
}
