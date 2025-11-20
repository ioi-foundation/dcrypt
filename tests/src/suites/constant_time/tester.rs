// tests/src/suites/constant_time/tester.rs

use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use statrs::distribution::{ContinuousCDF, StudentsT};
use std::time::Instant;

use crate::suites::constant_time::config::TestConfig;

// Structure to hold the results of timing analysis
#[derive(Debug)]
pub struct TimingAnalysis {
    // Basic Stats
    pub mean_a: f64,
    pub mean_b: f64,
    pub std_dev_a: f64,
    pub std_dev_b: f64,
    
    // Advanced Stats
    pub mad_a: f64,               // Median Absolute Deviation A
    pub mad_b: f64,               // Median Absolute Deviation B
    pub ks_statistic: f64,        // Kolmogorov-Smirnov statistic (distribution shape)
    pub bootstrap_p_value: f64,   // P-value from permutation test (robustness)
    
    // Comparisons
    pub mean_ratio: f64,
    pub t_statistic: f64,
    pub degrees_of_freedom: f64,
    pub p_value: f64,             // Analytical T-test p-value
    
    // Scoring
    pub combined_score: f64,
    pub is_constant_time: bool,
    
    // Interpretations
    pub cohens_d: f64,
    pub effect_size_interpretation: String,
    pub confidence_interval: (f64, f64),
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

    // Generic measure function that takes any FnMut
    pub fn measure<F>(&self, mut f: F) -> Vec<u128>
    where
        F: FnMut(),
    {
        let mut times = Vec::with_capacity(self.num_samples);
        // Run once to warm up instruction cache
        f();
        
        for _ in 0..self.num_samples {
            let start = Instant::now();
            for _ in 0..self.num_iterations {
                f();
            }
            let end = Instant::now();
            let avg = (end - start).as_nanos() / self.num_iterations as u128;
            times.push(avg);
        }
        times
    }

    /// Calculate the Robust Coefficient of Variation (RCV)
    /// J = MAD / Median
    ///
    /// This metric is less sensitive to outliers (like OS interrupts) than standard CV (std/mean).
    fn calculate_noise_floor(times: &[u128]) -> f64 {
        if times.is_empty() { return 0.0; }
        
        let median = Self::median(times);
        if median <= 1e-9 { return 0.0; } // Avoid div by zero
        
        let mad = Self::median_absolute_deviation(times);
        
        mad / median
    }

    /// Master method: Warmup -> Calibrate -> Measure -> Analyze
    ///
    /// 1. Runs `warmup_op` repeatedly to characterize environment noise.
    /// 2. Calculates Noise Floor (J).
    /// 3. Scales thresholds based on noise level.
    /// 4. Runs `measurement_op` toggling between A (false) and B (true) in interleaved order.
    /// 5. Performs statistical analysis with adjusted thresholds.
    pub fn calibrate_and_measure<W, M>(
        &self,
        mut warmup_op: W,
        mut measurement_op: M,
        config: &TestConfig
    ) -> Result<TimingAnalysis, String>
    where
        W: FnMut(),             // Operation to run during warmup (input independent)
        M: FnMut(bool) -> (),   // Operation to measure (bool toggles input A/B)
    {
        // --- Phase 1: Warmup & Calibration ---
        let mut warmup_times = Vec::with_capacity(config.num_warmup);
        
        // Run warmup loop and capture individual times
        for _ in 0..config.num_warmup {
            let start = Instant::now();
            warmup_op();
            let end = Instant::now();
            warmup_times.push((end - start).as_nanos());
        }

        // Calculate Noise Floor (J)
        let noise_floor = Self::calculate_noise_floor(&warmup_times);

        // --- Phase 2: Threshold Adjustment (Three Regimes) ---
        let multiplier = if !config.enable_dynamic_scaling {
            1.0
        } else {
            // Check if noise exceeds hard floor
            let effective_noise = if noise_floor > config.noise_hard_floor {
                // If noise is very high, warn but proceed with capped scaling to prevent
                // total test failure in noisy CI environments (e.g., GitHub Actions)
                if std::env::var("VERBOSE").is_ok() {
                    println!("WARNING: Noise floor {:.2}% exceeds hard limit {:.2}%. Proceeding with capped scaling.", 
                        noise_floor * 100.0, config.noise_hard_floor * 100.0);
                }
                config.noise_hard_floor
            } else {
                noise_floor
            };

            if effective_noise <= config.noise_soft_floor {
                // Regime 1: Clean Environment -> Strict thresholds
                1.0
            } else {
                // Regime 2: Noisy -> Dynamic Scaling
                // Multiplier = 1 + alpha * tanh(beta * noise)
                let factor = (config.noise_sensitivity * effective_noise).tanh();
                1.0 + (config.noise_scale_factor * factor)
            }
        };

        let adj_t_threshold = config.t_stat_threshold * multiplier;
        let adj_combined_threshold = config.combined_score_threshold * multiplier;

        // Log calibration if verbose
        if std::env::var("VERBOSE").is_ok() {
            println!("[CT-Harness] Calibration Report:");
            println!("  Noise Floor (RCV): {:.4}%", noise_floor * 100.0);
            println!("  Multiplier:        {:.3}x", multiplier);
            println!("  Adj T-Stat Limit:  {:.2} -> {:.2}", config.t_stat_threshold, adj_t_threshold);
            println!("  Adj Score Limit:   {:.2} -> {:.2}", config.combined_score_threshold, adj_combined_threshold);
        }

        // --- Phase 3: Interleaved Measurement ---
        // Instead of measuring all A then all B (which is vulnerable to drift),
        // we interleave A and B execution.
        let mut times_a = Vec::with_capacity(self.num_samples);
        let mut times_b = Vec::with_capacity(self.num_samples);

        let mut rng = thread_rng();

        // Warm up the measurement op with both inputs
        measurement_op(false);
        measurement_op(true);

        for _ in 0..self.num_samples {
            // Randomize order within the pair to mitigate periodic noise
            let run_a_first = rng.gen_bool(0.5);

            let mut measure = |op_arg: bool| {
                let start = Instant::now();
                for _ in 0..self.num_iterations {
                    measurement_op(op_arg);
                }
                let end = Instant::now();
                (end - start).as_nanos() / self.num_iterations as u128
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

        // --- Phase 4: Analysis ---
        self.analyze_constant_time(
            &times_a,
            &times_b,
            config.mean_ratio_max,
            adj_t_threshold,
            adj_combined_threshold,
        )
    }

    pub fn mean(times: &[u128]) -> f64 {
        if times.is_empty() { return 0.0; }
        let sum: u128 = times.iter().sum();
        sum as f64 / times.len() as f64
    }

    pub fn variance(times: &[u128], mean: f64) -> f64 {
        if times.len() < 2 { return 0.0; }
        let ss: f64 = times
            .iter()
            .map(|&t| {
                let d = t as f64 - mean;
                d * d
            })
            .sum();
        ss / (times.len() as f64 - 1.0)
    }

    /// Calculate Median
    pub fn median(times: &[u128]) -> f64 {
        if times.is_empty() { return 0.0; }
        let mut sorted = times.to_vec();
        sorted.sort_unstable();
        let mid = sorted.len() / 2;
        if sorted.len() % 2 == 0 {
            (sorted[mid - 1] + sorted[mid]) as f64 / 2.0
        } else {
            sorted[mid] as f64
        }
    }

    /// Calculate Median Absolute Deviation (MAD)
    /// Robust measure of variability, less affected by OS spikes than StdDev.
    pub fn median_absolute_deviation(times: &[u128]) -> f64 {
        let med = Self::median(times);
        let mut abs_devs: Vec<u128> = times
            .iter()
            .map(|&t| (t as f64 - med).abs() as u128)
            .collect();
        abs_devs.sort_unstable();
        // Constant k for consistency with StdDev (1.4826 for normal distributions)
        1.4826 * Self::median(&abs_devs)
    }

    /// Kolmogorov-Smirnov Test Statistic
    /// Non-parametric test to compare the shapes of two distributions.
    /// Returns the maximum distance between the empirical CDFs.
    pub fn ks_statistic(times_a: &[u128], times_b: &[u128]) -> f64 {
        let mut sorted_a = times_a.to_vec();
        let mut sorted_b = times_b.to_vec();
        sorted_a.sort_unstable();
        sorted_b.sort_unstable();

        let n_a = sorted_a.len();
        let n_b = sorted_b.len();
        
        let mut i = 0;
        let mut j = 0;
        let mut max_diff = 0.0;

        while i < n_a && j < n_b {
            let val_a = sorted_a[i];
            let val_b = sorted_b[j];

            let cdf_a = (i as f64) / (n_a as f64);
            let cdf_b = (j as f64) / (n_b as f64);
            
            let diff = (cdf_a - cdf_b).abs();
            if diff > max_diff {
                max_diff = diff;
            }

            if val_a <= val_b {
                i += 1;
            } else {
                j += 1;
            }
        }
        max_diff
    }

    /// Permutation (Bootstrap) Test
    /// Shuffles the combined data to determine if the observed mean difference
    /// is significant compared to random noise in THIS SPECIFIC environment.
    /// This makes the test robust against noisy CI runners.
    pub fn permutation_test_p_value(times_a: &[u128], times_b: &[u128], observed_diff: f64) -> f64 {
        let n_a = times_a.len();
        let combined: Vec<u128> = [times_a, times_b].concat();
        let iterations = 1000;
        let mut better_counts = 0;
        let mut rng = thread_rng();

        for _ in 0..iterations {
            let mut shuffled = combined.clone();
            shuffled.shuffle(&mut rng);
            
            let (sample_a, sample_b) = shuffled.split_at(n_a);
            let mean_a = Self::mean(sample_a);
            let mean_b = Self::mean(sample_b);
            let diff = (mean_a - mean_b).abs();

            if diff >= observed_diff {
                better_counts += 1;
            }
        }

        better_counts as f64 / iterations as f64
    }

    // Remove outliers using IQR method
    pub fn remove_outliers(times: &[u128]) -> Vec<u128> {
        if times.len() < 4 {
            return times.to_vec();
        }

        let mut sorted = times.to_vec();
        sorted.sort_unstable();

        let q1_pos = (sorted.len() as f64 * 0.25) as usize;
        let q3_pos = (sorted.len() as f64 * 0.75) as usize;

        let q1 = sorted[q1_pos] as f64;
        let q3 = sorted[q3_pos] as f64;

        let iqr = q3 - q1;
        // Use slightly looser bounds (2.0) to keep more signal
        let lower_bound = q1 - 2.0 * iqr;
        let upper_bound = q3 + 2.0 * iqr;

        times
            .iter()
            .filter(|&&t| (t as f64) >= lower_bound && (t as f64) <= upper_bound)
            .copied()
            .collect()
    }

    pub fn t_statistic(times_a: &[u128], times_b: &[u128]) -> f64 {
        let mean_a = Self::mean(times_a);
        let mean_b = Self::mean(times_b);
        let var_a = Self::variance(times_a, mean_a);
        let var_b = Self::variance(times_b, mean_b);
        let n_a = times_a.len() as f64;
        let n_b = times_b.len() as f64;

        // Avoid division by zero
        if var_a + var_b < 1e-9 { return 0.0; }

        (mean_a - mean_b).abs() / ((var_a / n_a + var_b / n_b).sqrt())
    }

    pub fn p_value(t_stat: f64, df: f64) -> f64 {
        if df < 1.0 || !df.is_finite() {
            return 0.5; 
        }

        match StudentsT::new(0.0, 1.0, df) {
            Ok(dist) => {
                let p = 2.0 * (1.0 - dist.cdf(t_stat.abs()));
                p.max(0.0).min(1.0)
            }
            Err(_) => 0.5,
        }
    }

    pub fn degrees_of_freedom(times_a: &[u128], times_b: &[u128]) -> f64 {
        let mean_a = Self::mean(times_a);
        let mean_b = Self::mean(times_b);
        let var_a = Self::variance(times_a, mean_a);
        let var_b = Self::variance(times_b, mean_b);
        let n_a = times_a.len() as f64;
        let n_b = times_b.len() as f64;

        let term_a = var_a / n_a;
        let term_b = var_b / n_b;

        if term_a + term_b < 1e-9 { return n_a + n_b - 2.0; }

        (term_a + term_b).powi(2) / (term_a.powi(2) / (n_a - 1.0) + term_b.powi(2) / (n_b - 1.0))
    }

    pub fn cohens_d(times_a: &[u128], times_b: &[u128]) -> f64 {
        let mean_a = Self::mean(times_a);
        let mean_b = Self::mean(times_b);
        let var_a = Self::variance(times_a, mean_a);
        let var_b = Self::variance(times_b, mean_b);
        let n_a = times_a.len() as f64;
        let n_b = times_b.len() as f64;

        let pooled_std_dev =
            ((var_a * (n_a - 1.0) + var_b * (n_b - 1.0)) / (n_a + n_b - 2.0)).sqrt();

        if pooled_std_dev < 1e-9 { return 0.0; }

        (mean_a - mean_b).abs() / pooled_std_dev
    }

    pub fn interpret_effect_size(d: f64) -> String {
        match d {
            d if d < 0.2 => "Negligible".to_string(),
            d if d < 0.5 => "Small".to_string(),
            d if d < 0.8 => "Medium".to_string(),
            d if d < 1.2 => "Large".to_string(),
            _ => "Very large".to_string(),
        }
    }

    // Helper function to get t-critical values
    pub fn t_critical_value(df: f64, confidence_level: f64) -> f64 {
        match StudentsT::new(0.0, 1.0, df) {
            Ok(dist) => {
                let alpha = 1.0 - confidence_level;
                dist.inverse_cdf(1.0 - alpha / 2.0)
            }
            Err(_) => 1.96, // Fallback for ~infinite degrees of freedom
        }
    }

    // Robust scoring that penalizes only when multiple signals agree
    pub fn combined_score(
        &self,
        mean_ratio: f64,
        t_stat: f64,
        ks_stat: f64,
        bootstrap_p: f64,
        rel_std_dev_max: f64,
    ) -> f64 {
        // Weights - Adjusted to be less sensitive to noise
        const W_RATIO: f64 = 0.60; // Increased weight on mean difference (the most critical metric)
        const W_TSTAT: f64 = 0.10; // Reduced weight on T-stat (high T-stat is common with large N)
        const W_KS: f64 = 0.15;    // Reduced weight on distribution shape
        const W_NOISE: f64 = 0.15; // Reduced weight on variance

        // Normalize inputs
        // Use a quadratic penalty for mean ratio to ignore small fluctuations but punish large ones heavily
        let ratio_diff = (mean_ratio - 1.0).abs();
        let ratio_score = if ratio_diff < 0.05 {
            ratio_diff * 2.0 // Linear penalty for small diffs (< 5%)
        } else {
            ratio_diff * 10.0 // Heavy penalty for large diffs (> 5%)
        };

        let t_score = (t_stat / 20.0).min(1.0); // Cap t-stat influence, require t > 20 to max out
        
        // KS stat is typically 0.0 - 1.0. 
        // Only penalize if distributions are significantly different (> 0.2)
        let ks_score = if ks_stat > 0.2 { ks_stat * 2.0 } else { 0.0 };
        
        let noise_penalty = rel_std_dev_max.min(1.0);

        let mut score = 1.0 + 
            (ratio_score * W_RATIO) + 
            (t_score * W_TSTAT) + 
            (ks_score * W_KS) + 
            (noise_penalty * W_NOISE);

        // Robustness Check: 
        // If bootstrap p-value is high (>0.05), the difference is likely noise.
        if bootstrap_p > 0.05 {
             // Reduce penalty significantly if it looks like noise
            score = 1.0 + (score - 1.0) * 0.1;
        } else if bootstrap_p > 0.01 {
            // Weak significance
            score = 1.0 + (score - 1.0) * 0.5;
        }

        score
    }

    pub fn analyze_constant_time(
        &self,
        times_a: &[u128],
        times_b: &[u128],
        _mean_ratio_max: f64,
        t_stat_threshold: f64,
        combined_score_threshold: f64,
    ) -> Result<TimingAnalysis, String> {
        // 1. Outlier Removal
        let clean_a = Self::remove_outliers(times_a);
        let clean_b = Self::remove_outliers(times_b);

        if clean_a.is_empty() || clean_b.is_empty() {
            return Err("Insufficient data after outlier removal".to_string());
        }

        // 2. Basic Stats
        let mean_a = Self::mean(&clean_a);
        let mean_b = Self::mean(&clean_b);
        let var_a = Self::variance(&clean_a, mean_a);
        let var_b = Self::variance(&clean_b, mean_b);
        let std_dev_a = var_a.sqrt();
        let std_dev_b = var_b.sqrt();
        let n_a = clean_a.len() as f64;
        let n_b = clean_b.len() as f64;

        // 3. Advanced Stats (New)
        let mad_a = Self::median_absolute_deviation(&clean_a);
        let mad_b = Self::median_absolute_deviation(&clean_b);
        let ks_stat = Self::ks_statistic(&clean_a, &clean_b);
        
        let mean_diff = (mean_a - mean_b).abs();
        let bootstrap_p = Self::permutation_test_p_value(&clean_a, &clean_b, mean_diff);

        // 4. Comparisons
        let mean_ratio = if mean_a > mean_b {
            mean_a / mean_b
        } else {
            mean_b / mean_a
        };

        let t_stat = Self::t_statistic(&clean_a, &clean_b);
        let df = Self::degrees_of_freedom(&clean_a, &clean_b);
        let p_value = Self::p_value(t_stat, df);

        let rel_std_dev_a = std_dev_a / mean_a;
        let rel_std_dev_b = std_dev_b / mean_b;
        let max_rel_std_dev = f64::max(rel_std_dev_a, rel_std_dev_b);

        // 5. Scoring
        let combined_score = self.combined_score(
            mean_ratio, 
            t_stat, 
            ks_stat, 
            bootstrap_p, 
            max_rel_std_dev
        );

        // 6. Meta info
        let cohens_d = Self::cohens_d(&clean_a, &clean_b);
        let effect = Self::interpret_effect_size(cohens_d);

        let t_crit = Self::t_critical_value(df, 0.95);
        let std_err = ((var_a / n_a) + (var_b / n_b)).sqrt();
        let margin = t_crit * std_err;
        let conf_interval = ((mean_diff - margin).max(0.0), mean_diff + margin);

        // Use adjusted thresholds passed from calibrate_and_measure
        let is_constant_time = combined_score <= combined_score_threshold && t_stat <= t_stat_threshold;

        Ok(TimingAnalysis {
            mean_a, mean_b,
            std_dev_a, std_dev_b,
            mad_a, mad_b,
            ks_statistic: ks_stat,
            bootstrap_p_value: bootstrap_p,
            mean_ratio,
            t_statistic: t_stat,
            degrees_of_freedom: df,
            p_value,
            combined_score,
            is_constant_time,
            cohens_d,
            effect_size_interpretation: effect,
            confidence_interval: conf_interval,
        })
    }
}

/// Generates detailed insights for constant-time test results
pub fn generate_test_insights(
    analysis: &TimingAnalysis,
    _config: &crate::suites::constant_time::config::TestConfig,
    primitive_name: &str,
) -> String {
    let mut insights = String::new();

    let mean_diff = (analysis.mean_a - analysis.mean_b).abs();
    let diff_pct = (mean_diff / f64::min(analysis.mean_a, analysis.mean_b)) * 100.0;

    if analysis.is_constant_time {
        insights.push_str(&format!("✅ PASS: {} is constant-time.\n", primitive_name));
        return insights;
    }

    insights.push_str(&format!("❌ FAIL: {} timing vulnerability detected.\n", primitive_name));
    insights.push_str(&format!("   Score: {:.2} (Diff: {:.2}%)\n", analysis.combined_score, diff_pct));
    
    insights.push_str("\n📊 STATISTICAL EVIDENCE:\n");
    insights.push_str(&format!("   T-Statistic: {:.2} (p={:.1e})\n", analysis.t_statistic, analysis.p_value));
    insights.push_str(&format!("   Bootstrap P: {:.3} (Probability diff is noise)\n", analysis.bootstrap_p_value));
    insights.push_str(&format!("   KS-Stat:     {:.3} (Distribution shape diff)\n", analysis.ks_statistic));
    insights.push_str(&format!("   MAD Ratio:   {:.3} (Variability diff)\n", analysis.mad_a / analysis.mad_b));

    insights.push_str("\n🔍 DIAGNOSIS:\n");
    
    if analysis.bootstrap_p_value > 0.05 {
        insights.push_str("   ⚠️  FALSE POSITIVE LIKELY: Bootstrap test suggests difference is noise.\n");
        insights.push_str("       Try increasing sample count or isolating system load.\n");
    } else if analysis.ks_statistic > 0.15 {
        insights.push_str("   🔴 DISTRIBUTION MISMATCH: Execution paths likely differ structurally.\n");
        insights.push_str("       (e.g., Early return, different loop counts)\n");
    } else if analysis.mean_ratio > 1.1 {
        insights.push_str("   🔴 MAGNITUDE LEAK: Significant constant-factor difference.\n");
        insights.push_str("       (e.g., different math operations chosen based on secret)\n");
    } else if analysis.t_statistic > 5.0 {
        insights.push_str("   🟠 SUBTLE LEAK: Small but statistically consistent difference.\n");
        insights.push_str("       (e.g., cache bank conflicts, operand-dependent instructions)\n");
    }

    insights
}