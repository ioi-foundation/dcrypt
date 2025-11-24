// tests/src/suites/constant_time/tester.rs

use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use std::time::Instant;
use crate::suites::constant_time::config::TestConfig;
use crate::suites::constant_time::stats;
use crate::suites::constant_time::profile::ProfileStore;

#[derive(Debug)]
pub struct TimingAnalysis {
    // Stats
    pub mean_a: f64,
    pub mean_b: f64,
    pub mean_diff: f64,
    pub mad_a: f64,
    pub mad_b: f64,
    pub cohens_d: f64,
    pub ks_stat: f64,

    // Inference & P-values
    pub ci_lower: f64,
    pub ci_upper: f64,
    pub zero_in_ci: bool,
    pub p_ci: f64,  // Bootstrap p-value for mean diff
    pub p_ks: f64,  // KS test p-value for distribution shape
    
    // Multi-signal Correction (Holm-Bonferroni)
    pub holm_reject_ci: bool, // Did mean diff survive Holm?
    pub holm_reject_ks: bool, // Did KS stat survive Holm?

    pub practical_threshold: f64,
    
    // Environment
    pub noise_floor_mad: f64,
    pub environment_status: String,

    // Verdict
    pub is_constant_time: bool,
}

pub struct TimingTester {
    pub num_samples: usize,
    pub num_iterations: usize,
}

impl TimingTester {
    pub fn new(num_samples: usize, num_iterations: usize) -> Self {
        Self {
            num_samples,
            num_iterations,
        }
    }

    /// Calculate metrics, check profile, and determine pass/fail.
    /// Returns `Err` if the environment is too noisy to run a valid test.
    pub fn calibrate_and_measure<W, M>(
        &self,
        mut warmup_op: W,
        mut measurement_op: M,
        config: &TestConfig,
        name: &str
    ) -> Result<TimingAnalysis, String>
    where
        W: FnMut(),
        M: FnMut(bool) -> (),
    {
        // --- 1. Warmup & Noise Profiling ---
        let mut warmup_times = Vec::with_capacity(config.num_warmup);
        for _ in 0..config.num_warmup {
            let start = Instant::now();
            warmup_op();
            let end = Instant::now();
            warmup_times.push((end - start).as_nanos() as f64);
        }

        let current_mad = stats::robust_mad(&warmup_times);
        let mut env_status = "Clean".to_string();

        // Profile Check & Gating
        if config.use_noise_profile {
            let mut store = ProfileStore::load_or_create(&config.noise_profile_path);
            
            if let Some(baseline) = store.get_baseline(name) {
                // Check if noise is drastically worse than history
                if current_mad > baseline * config.noise_tolerance_factor {
                    // GATING: Abort the test if the environment is too noisy.
                    return Err(format!(
                        "TEST ABORTED: Environment too noisy. Current MAD {:.2}ns > {:.1}x Baseline {:.2}ns", 
                        current_mad, config.noise_tolerance_factor, baseline
                    ));
                }
                
                // Warn if noise is elevated but within tolerance
                if current_mad > baseline * 1.5 {
                    env_status = format!("Elevated Noise (MAD {:.2} > Baseline {:.2})", current_mad, baseline);
                }
            }
            
            store.update(name, current_mad);
            store.save(&config.noise_profile_path);
        }

        // --- 2. Interleaved Measurement ---
        let mut times_a = Vec::with_capacity(self.num_samples);
        let mut times_b = Vec::with_capacity(self.num_samples);
        let mut rng = thread_rng();

        // Pre-heat
        measurement_op(false);
        measurement_op(true);

        for _ in 0..self.num_samples {
            let run_a_first = rng.gen_bool(0.5);

            let mut measure = |op_arg: bool| {
                let start = Instant::now();
                for _ in 0..self.num_iterations {
                    measurement_op(op_arg);
                }
                let end = Instant::now();
                // Return avg ns per op
                ((end - start).as_nanos() as f64) / (self.num_iterations as f64)
            };

            if run_a_first {
                times_a.push(measure(false));
                times_b.push(measure(true));
            } else {
                let b = measure(true);
                let a = measure(false);
                times_b.push(b);
                times_a.push(a);
            }
        }

        self.analyze(&times_a, &times_b, config, current_mad, env_status)
    }

    fn analyze(
        &self,
        a: &[f64],
        b: &[f64],
        config: &TestConfig,
        noise_mad: f64,
        env_status: String,
    ) -> Result<TimingAnalysis, String> {
        // 1. Pairwise Differences
        let diffs: Vec<f64> = a.iter().zip(b).map(|(x, y)| x - y).collect();
        let mean_diff = diffs.iter().sum::<f64>() / diffs.len() as f64;

        // 2. Bootstrap Confidence Interval & P-Value (Metric 1: Mean Diff)
        let (ci_low, ci_high, p_ci) = stats::bootstrap_ci_and_p(
            &diffs, 
            config.bootstrap_iterations, 
            config.significance_level
        );

        // 3. Kolmogorov-Smirnov Test (Metric 2: Distribution Shape)
        let ks_stat = stats::ks_statistic(a, b);
        let p_ks = stats::ks_pvalue(ks_stat, a.len(), b.len());

        // 4. Holm-Bonferroni Correction
        // We are testing two hypotheses:
        // H0_1: Mean diff = 0
        // H0_2: Distributions are identical
        // We want to control FWER at `significance_level`
        let pvals = vec![p_ci, p_ks];
        let holm_decisions = stats::holm_adjust(&pvals, config.significance_level);
        
        let holm_reject_ci = holm_decisions[0];
        let holm_reject_ks = holm_decisions[1];
        
        // 5. Other Diagnostics
        let mean_a = a.iter().sum::<f64>() / a.len() as f64;
        let mean_b = b.iter().sum::<f64>() / b.len() as f64;
        let mad_a = stats::robust_mad(a);
        let mad_b = stats::robust_mad(b);
        let cohens_d = stats::cohens_d(a, b);

        // 6. Decision Logic
        // A. Confidence Interval Check (Primary Signal)
        // Note: zero_excluded matches holm_reject_ci in theory (same test), but 
        // we track both explicitly.
        let zero_excluded = ci_low > 0.0 || ci_high < 0.0;
        
        // B. Practical Significance (Magnitude)
        let thr = config.practical_significance_threshold;
        let is_practical = ci_low > thr || ci_high < -thr;

        // C. Multi-signal Confirmation
        // We only flag a failure if:
        // 1. The difference is statistically significant (CI doesn't touch zero)
        // 2. The difference is practically significant (outside threshold)
        // 3. The hypothesis test survives Holm correction (controls false positive rate)
        //
        // Note: We use holm_reject_ci as the gatekeeper. KS provides shape info.
        let leak_detected = zero_excluded && is_practical && holm_reject_ci;

        Ok(TimingAnalysis {
            mean_a,
            mean_b,
            mean_diff,
            mad_a,
            mad_b,
            cohens_d,
            ks_stat,
            ci_lower: ci_low,
            ci_upper: ci_high,
            zero_in_ci: !zero_excluded,
            p_ci,
            p_ks,
            holm_reject_ci,
            holm_reject_ks,
            practical_threshold: config.practical_significance_threshold,
            noise_floor_mad: noise_mad,
            environment_status: env_status,
            is_constant_time: !leak_detected,
        })
    }
}

pub fn generate_test_insights(
    analysis: &TimingAnalysis,
    _config: &TestConfig,
    primitive_name: &str,
) -> String {
    let mut s = String::new();
    
    let status_icon = if analysis.is_constant_time { "✅" } else { "❌" };
    
    s.push_str(&format!("{} Result: {}\n", status_icon, primitive_name));
    s.push_str(&format!("   Environment: {}\n", analysis.environment_status));
    s.push_str(&format!("   Noise Floor (MAD): {:.3} ns\n", analysis.noise_floor_mad));
    
    s.push_str("   --- Statistics ---\n");
    s.push_str(&format!("   Mean Diff:   {:.3} ns\n", analysis.mean_diff));
    s.push_str(&format!("   99% CI:      [{:.3}, {:.3}] ns\n", analysis.ci_lower, analysis.ci_upper));
    s.push_str(&format!("   Cohen's d:   {:.3} (Effect Size)\n", analysis.cohens_d));
    
    s.push_str("   --- Hypothesis Tests (Holm-Adjusted) ---\n");
    s.push_str(&format!("   Mean Diff P: {:.1e} (Reject: {})\n", analysis.p_ci, analysis.holm_reject_ci));
    s.push_str(&format!("   KS Stat P:   {:.1e} (Reject: {})\n", analysis.p_ks, analysis.holm_reject_ks));
    
    if !analysis.is_constant_time {
        s.push_str("\n   ⚠️  FAILURE DIAGNOSIS:\n");
        
        if analysis.holm_reject_ci {
             s.push_str("   - Statistically significant mean difference detected (p < alpha).\n");
        }
        
        if analysis.ci_lower > analysis.practical_threshold {
             s.push_str(&format!("   - Positive bias exceeds practical threshold (+{:.1} ns)\n", analysis.practical_threshold));
        } else if analysis.ci_upper < -analysis.practical_threshold {
             s.push_str(&format!("   - Negative bias exceeds practical threshold (-{:.1} ns)\n", analysis.practical_threshold));
        }
        
        if analysis.holm_reject_ks {
             s.push_str("   - Distribution shapes differ significantly (suggests branching).\n");
        } else {
             s.push_str("   - Distributions similar shape, offset implies data-dependent operands.\n");
        }
    }

    s
}