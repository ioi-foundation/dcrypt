// tests/src/suites/constant_time/config.rs

use std::path::PathBuf;

/// Configuration parameters for constant-time execution testing.
///
/// This configuration moves away from heuristic scoring (T-stat > 5.0) and towards
/// statistical inference (Confidence Intervals) and adaptive noise profiling.
#[derive(Debug, Clone)]
pub struct TestConfig {
    // --- Statistical Parameters ---

    /// Significance level (alpha) for the confidence interval.
    /// Default: 0.01 (99% confidence).
    pub significance_level: f64,

    /// Number of bootstrap resamples to perform for CI calculation.
    /// Higher = more accurate tails, but slower.
    pub bootstrap_iterations: usize,

    /// Practical Significance Threshold (nanoseconds).
    /// Even if a difference is statistically significant (p < alpha),
    /// we ignore it if the magnitude of the difference is less than this value.
    /// This filters out architectural biases that are real but exploitable.
    /// Default: 1.0ns (approx 3-4 cycles on modern CPUs).
    pub practical_significance_threshold: f64,

    // --- Sampling Configuration ---

    /// Number of warmup iterations to characterize environment noise.
    pub num_warmup: usize,

    /// Number of distinct sample batches to collect.
    pub num_samples: usize,

    /// Number of iterations per sample batch.
    pub num_iterations: usize,

    // --- Noise Profiling (DTS Gen 2) ---

    /// If true, loads/saves noise profiles to disk to detect environment degradation.
    pub use_noise_profile: bool,

    /// Path to the noise profile store (JSON).
    pub noise_profile_path: PathBuf,

    /// Allowed degradation factor.
    /// If current_noise > baseline_noise * factor, the test is marked inconclusive/noisy
    /// rather than failing.
    pub noise_tolerance_factor: f64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            significance_level: 0.01,    // 99% Confidence
            bootstrap_iterations: 10_000,
            practical_significance_threshold: 0.5, // 0.5ns tolerance

            num_warmup: 2000,
            num_samples: 100,            // Increased samples for better distribution shape
            num_iterations: 500,         // Lower iterations/sample to catch interruptions

            use_noise_profile: true,
            noise_profile_path: PathBuf::from("target/ct_noise_profile.json"),
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
            // Kyber has higher variance; rely heavily on robust stats.
            // We relax the practical threshold slightly to account for
            // complex memory patterns.
            practical_significance_threshold: 2.0,
            num_warmup: 3000,
            ..Self::default()
        }
    }

    pub fn for_pqc_sign() -> Self {
        Self {
            // Dilithium rejection sampling creates massive variance.
            // We need a lot of samples to average that out.
            num_samples: 200,
            // High threshold because rejection loops dominate timing
            practical_significance_threshold: 5.0, 
            ..Self::default()
        }
    }
}