// tests/src/suites/constant_time/stats.rs

use rand::prelude::*;
use rand::seq::SliceRandom;
use rand_chacha::ChaCha20Rng;

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

fn validate_finite_nonempty(values: &[f64], label: &str) -> Result<(), String> {
    if values.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if values.iter().any(|value| !value.is_finite()) {
        return Err(format!("{label} contains a non-finite value"));
    }
    Ok(())
}

/// Reconstruct A-B differences from the measured first/second batches and the
/// predeclared within-pair assignment.
pub fn paired_differences(
    first: &[f64],
    second: &[f64],
    a_first: &[bool],
) -> Result<Vec<f64>, String> {
    if first.len() != second.len() || first.len() != a_first.len() {
        return Err("paired timing vectors have different lengths".to_string());
    }
    validate_finite_nonempty(first, "first timings")?;
    validate_finite_nonempty(second, "second timings")?;

    Ok(first
        .iter()
        .zip(second)
        .zip(a_first)
        .map(|((&first_time, &second_time), &class_a_first)| {
            if class_a_first {
                first_time - second_time
            } else {
                second_time - first_time
            }
        })
        .collect())
}

fn validate_balanced_assignment(a_first: &[bool]) -> Result<(), String> {
    if a_first.len() < 2 || a_first.len() % 2 != 0 {
        return Err("paired randomization requires a nonzero even sample count".to_string());
    }
    let a_first_count = a_first.iter().filter(|&&value| value).count();
    if a_first_count * 2 != a_first.len() {
        return Err("paired assignment is not exactly balanced".to_string());
    }
    Ok(())
}

/// Two-sided paired randomization test for the balanced A-first/B-first design.
///
/// The sharp-null distribution reassigns exactly half of the measured first
/// and second batches to class A. `iterations` and `seed` are fixed before any
/// observations are collected. The add-one correction prevents a zero p-value.
pub fn balanced_paired_randomization_p_value(
    first: &[f64],
    second: &[f64],
    observed_a_first: &[bool],
    iterations: usize,
    seed: u64,
) -> Result<f64, String> {
    if iterations == 0 {
        return Err("paired randomization iteration count must be positive".to_string());
    }
    validate_balanced_assignment(observed_a_first)?;
    let observed_diffs = paired_differences(first, second, observed_a_first)?;
    let observed_stat = observed_diffs.iter().sum::<f64>().abs();

    let mut assignment = vec![false; observed_a_first.len()];
    assignment[..observed_a_first.len() / 2].fill(true);
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut extreme = 0usize;

    for _ in 0..iterations {
        assignment.shuffle(&mut rng);
        let candidate_sum = first
            .iter()
            .zip(second)
            .zip(&assignment)
            .map(|((&first_time, &second_time), &class_a_first)| {
                if class_a_first {
                    first_time - second_time
                } else {
                    second_time - first_time
                }
            })
            .sum::<f64>()
            .abs();
        if candidate_sum >= observed_stat {
            extreme += 1;
        }
    }

    Ok((extreme as f64 + 1.0) / (iterations as f64 + 1.0))
}

/// Generates a deterministic paired-bootstrap distribution of mean A-B
/// differences. The seed and iteration budget are fixed before measurement.
pub fn bootstrap_mean_distribution(
    diffs: &[f64],
    iterations: usize,
    seed: u64,
) -> Result<Vec<f64>, String> {
    validate_finite_nonempty(diffs, "paired differences")?;
    if iterations == 0 {
        return Err("bootstrap iteration count must be positive".to_string());
    }
    let n = diffs.len();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
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
    Ok(means)
}

/// Performs a deterministic percentile bootstrap for a descriptive paired CI.
/// It deliberately returns no p-value; the paired randomization test is the
/// suite's only primary inference.
pub fn bootstrap_ci(
    diffs: &[f64],
    iterations: usize,
    alpha: f64,
    seed: u64,
) -> Result<(f64, f64), String> {
    if !(0.0 < alpha && alpha < 1.0) {
        return Err("bootstrap alpha must be between zero and one".to_string());
    }
    let means = bootstrap_mean_distribution(diffs, iterations, seed)?;

    let lower_idx = ((iterations as f64) * (alpha / 2.0)) as usize;
    let upper_idx = ((iterations as f64) * (1.0 - (alpha / 2.0))) as usize;

    // Clamp indices
    let lower = means[lower_idx.min(iterations - 1)];
    let upper = means[upper_idx.min(iterations - 1)];

    Ok((lower, upper))
}

/// Welch's t-test statistic and a large-sample two-sided p-value approximation.
pub fn welch_t_statistic(a: &[f64], b: &[f64]) -> (f64, f64) {
    let mean_a = a.iter().sum::<f64>() / a.len() as f64;
    let mean_b = b.iter().sum::<f64>() / b.len() as f64;
    let var_a = variance(a, mean_a);
    let var_b = variance(b, mean_b);

    let denom = (var_a / a.len() as f64 + var_b / b.len() as f64).sqrt();
    if denom < 1e-12 {
        return (0.0, 1.0);
    }

    let t = (mean_a - mean_b) / denom;
    let p = 2.0 * (1.0 - normal_cdf(t.abs()));
    (t, p.clamp(0.0, 1.0))
}

/// Asymptotic Kolmogorov-Smirnov p-value approximation.
///
/// Uses the standard Kolmogorov distribution tail approximation:
/// P(D_n >= d) ≈ 2 * Σ_{k=1..∞} (-1)^(k-1) * e^(-2 k^2 λ^2)
pub fn ks_pvalue(stat: f64, n_a: usize, n_b: usize) -> f64 {
    if stat <= 0.0 {
        return 1.0;
    }

    let n_eff = (n_a * n_b) as f64 / (n_a + n_b) as f64;
    // Stephens approximation for lambda
    let lambda = (n_eff.sqrt() + 0.12 + 0.11 / n_eff.sqrt()) * stat;

    let mut sum = 0.0;
    for k in 1..100 {
        let k_f = k as f64;
        let term = (-2.0 * k_f * k_f * lambda * lambda).exp();
        let sign = if (k - 1) % 2 == 0 { 1.0 } else { -1.0 };

        sum += sign * term;

        if term < 1e-12 {
            break;
        }
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
    let mut indexed: Vec<(usize, f64)> = pvals.iter().cloned().enumerate().collect();

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

    if pooled_std < 1e-9 {
        0.0
    } else {
        (mean_a - mean_b).abs() / pooled_std
    }
}

fn variance(data: &[f64], mean: f64) -> f64 {
    let sum_sq_diff: f64 = data.iter().map(|x| (x - mean).powi(2)).sum();
    sum_sq_diff / (data.len() as f64 - 1.0)
}

fn normal_cdf(x: f64) -> f64 {
    0.5 * (1.0 + erf_approx(x / core::f64::consts::SQRT_2))
}

fn erf_approx(x: f64) -> f64 {
    // Abramowitz and Stegun 7.1.26
    let sign = if x < 0.0 { -1.0 } else { 1.0 };
    let x = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let y = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * (-x * x).exp();
    sign * y
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paired_differences_reconstruct_a_minus_b() {
        let diffs = paired_differences(
            &[11.0, 3.0, 15.0, 7.0],
            &[1.0, 13.0, 5.0, 17.0],
            &[true, false, true, false],
        )
        .unwrap();
        assert_eq!(diffs, vec![10.0; 4]);
    }

    #[test]
    fn balanced_randomization_has_predeclared_resolution_and_known_null() {
        let assignment: Vec<bool> = (0..40).map(|index| index % 2 == 0).collect();
        let identical = vec![7.0; assignment.len()];
        assert_eq!(
            balanced_paired_randomization_p_value(
                &identical,
                &identical,
                &assignment,
                100_000,
                17,
            )
            .unwrap(),
            1.0
        );

        let first: Vec<f64> = assignment
            .iter()
            .map(|&a_first| if a_first { 10.0 } else { 0.0 })
            .collect();
        let second: Vec<f64> = assignment
            .iter()
            .map(|&a_first| if a_first { 0.0 } else { 10.0 })
            .collect();
        let p = balanced_paired_randomization_p_value(&first, &second, &assignment, 100_000, 17)
            .unwrap();
        assert_eq!(p, 1.0 / 100_001.0);
        assert!(p < 0.01 / 29.0);
    }

    #[test]
    fn paired_randomization_rejects_malformed_evidence() {
        assert!(balanced_paired_randomization_p_value(
            &[1.0, 2.0],
            &[1.0, 2.0],
            &[true, true],
            100,
            1,
        )
        .is_err());
        assert!(paired_differences(&[f64::NAN], &[1.0], &[true]).is_err());
    }

    #[test]
    fn paired_bootstrap_is_deterministic() {
        let first = bootstrap_ci(&[-2.0, -1.0, 1.0, 2.0], 1_000, 0.01, 99).unwrap();
        let second = bootstrap_ci(&[-2.0, -1.0, 1.0, 2.0], 1_000, 0.01, 99).unwrap();
        assert_eq!(first, second);
    }
}
