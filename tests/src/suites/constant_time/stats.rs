// tests/src/suites/constant_time/stats.rs

use rand::prelude::*;
use rand::thread_rng;

/// Calculates the median of a dataset.
pub fn median(data: &[f64]) -> f64 {
    let mut sorted = data.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

/// Calculates Median Absolute Deviation (MAD).
/// Scale factor 1.4826 makes it consistent with StdDev for normal distributions.
pub fn robust_mad(data: &[f64]) -> f64 {
    let med = median(data);
    let abs_devs: Vec<f64> = data.iter().map(|&x| (x - med).abs()).collect();
    1.4826 * median(&abs_devs)
}

/// Calculates Robust Coefficient of Variation (RCV).
pub fn robust_cv(data: &[f64]) -> f64 {
    let med = median(data);
    if med.abs() < 1e-9 {
        0.0
    } else {
        robust_mad(data) / med
    }
}

/// Generates bootstrap distribution of means
pub fn bootstrap_mean_distribution(diffs: &[f64], iterations: usize) -> Vec<f64> {
    let n = diffs.len();
    let mut rng = thread_rng();
    let mut means = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let mut sum = 0.0;
        for _ in 0..n {
            // Resample differences with replacement
            let idx = rng.gen_range(0..n);
            sum += diffs[idx];
        }
        means.push(sum / n as f64);
    }

    means.sort_by(|a, b| a.partial_cmp(b).unwrap());
    means
}

/// Performs Percentile Bootstrap to calculate CI and p-value.
///
/// Returns (lower_bound, upper_bound, p_value).
pub fn bootstrap_ci_and_p(
    diffs: &[f64], 
    iterations: usize, 
    alpha: f64
) -> (f64, f64, f64) {
    let means = bootstrap_mean_distribution(diffs, iterations);

    let lower_idx = ((iterations as f64) * (alpha / 2.0)) as usize;
    let upper_idx = ((iterations as f64) * (1.0 - (alpha / 2.0))) as usize;

    // Clamp indices
    let lower = means[lower_idx.min(iterations - 1)];
    let upper = means[upper_idx.min(iterations - 1)];

    // Calculate "Percentile P-value" for H0: mu = 0.
    // This represents the probability that the bootstrap distribution crosses 0.
    // It aligns perfectly with the CI: if 99% CI excludes 0, then p < 0.01.
    let count_below_zero = means.iter().filter(|&&m| m < 0.0).count();
    let p_one_sided = count_below_zero as f64 / iterations as f64;
    // Two-sided p-value
    let p = 2.0 * p_one_sided.min(1.0 - p_one_sided);

    (lower, upper, p.max(1.0 / iterations as f64))
}

/// Asymptotic Kolmogorov-Smirnov p-value approximation.
///
/// Uses the standard Kolmogorov distribution tail approximation:
/// P(D_n >= d) ≈ 2 * Σ_{k=1..∞} (-1)^(k-1) * e^(-2 k^2 λ^2)
pub fn ks_pvalue(stat: f64, n_a: usize, n_b: usize) -> f64 {
    if stat <= 0.0 { return 1.0; }
    
    let n_eff = (n_a * n_b) as f64 / (n_a + n_b) as f64;
    // Stephens approximation for lambda
    let lambda = (n_eff.sqrt() + 0.12 + 0.11 / n_eff.sqrt()) * stat;

    let mut sum = 0.0;
    for k in 1..100 {
        let k_f = k as f64;
        let term = (-2.0 * k_f * k_f * lambda * lambda).exp();
        let sign = if (k - 1) % 2 == 0 { 1.0 } else { -1.0 };
        
        sum += sign * term;
        
        if term < 1e-12 { break; }
    }
    
    let p = 2.0 * sum;
    p.max(0.0).min(1.0)
}

/// Holm-Bonferroni step-down method for multiple hypothesis testing.
///
/// Controls Family-Wise Error Rate (FWER).
/// Returns a boolean vector corresponding to the input p-values, 
/// where `true` indicates the null hypothesis is rejected (significant result).
pub fn holm_adjust(pvals: &[f64], alpha: f64) -> Vec<bool> {
    let m = pvals.len();
    // Store (original_index, p_value)
    let mut indexed: Vec<(usize, f64)> = pvals
        .iter()
        .cloned()
        .enumerate()
        .collect();

    // Sort by p-value ascending (smallest first)
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut decisions = vec![false; m];
    
    for (i, (original_idx, p)) in indexed.into_iter().enumerate() {
        // Holm threshold: alpha / (m - rank + 1)
        // Here rank is i+1 (1-based), so denominator is m - i
        let threshold = alpha / (m - i) as f64;
        
        if p <= threshold {
            decisions[original_idx] = true;
        } else {
            // Step-down: once we fail to reject, we stop and fail to reject all remaining
            break;
        }
    }

    decisions
}

/// Calculates Cohen's d (Effect Size)
pub fn cohens_d(a: &[f64], b: &[f64]) -> f64 {
    let mean_a = a.iter().sum::<f64>() / a.len() as f64;
    let mean_b = b.iter().sum::<f64>() / b.len() as f64;
    
    // Pooled variance
    let var_a = variance(a, mean_a);
    let var_b = variance(b, mean_b);
    let pooled_std = ((var_a + var_b) / 2.0).sqrt();

    if pooled_std < 1e-9 { 0.0 } else { (mean_a - mean_b).abs() / pooled_std }
}

fn variance(data: &[f64], mean: f64) -> f64 {
    let sum_sq_diff: f64 = data.iter().map(|x| (x - mean).powi(2)).sum();
    sum_sq_diff / (data.len() as f64 - 1.0)
}

/// Kolmogorov-Smirnov Test Statistic
/// Returns max distance between CDFs.
pub fn ks_statistic(a: &[f64], b: &[f64]) -> f64 {
    let mut sorted_a = a.to_vec();
    let mut sorted_b = b.to_vec();
    sorted_a.sort_by(|x, y| x.partial_cmp(y).unwrap());
    sorted_b.sort_by(|x, y| x.partial_cmp(y).unwrap());

    let n_a = sorted_a.len();
    let n_b = sorted_b.len();
    
    let mut i = 0;
    let mut j = 0;
    let mut max_diff = 0.0;

    while i < n_a && j < n_b {
        let val_a = sorted_a[i];
        let val_b = sorted_b[j];
        
        let cdf_a = i as f64 / n_a as f64;
        let cdf_b = j as f64 / n_b as f64;
        
        let diff = (cdf_a - cdf_b).abs();
        if diff > max_diff { max_diff = diff; }

        if val_a <= val_b { i += 1; } else { j += 1; }
    }
    max_diff
}