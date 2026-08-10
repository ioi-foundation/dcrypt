// tests/src/suites/constant_time/tester.rs

use crate::suites::constant_time::config::TestConfig;
use crate::suites::constant_time::profile::ProfileStore;
use crate::suites::constant_time::stats;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeSet;
use std::hint::black_box;
use std::sync::atomic::{compiler_fence, Ordering};
use std::sync::Mutex;
use std::time::Instant;

static TIMING_MEASUREMENT_LOCK: Mutex<()> = Mutex::new(());

pub const PRIMARY_RANDOMIZATION_ITERATIONS: usize = 100_000;
pub const MIN_BOOTSTRAP_ITERATIONS: usize = 100_000;
pub const BLOCKING_FAMILY_ALPHA: f64 = 0.01;
pub const EXPECTED_BLOCKING_CASES: usize = 29;

const SCHEDULE_SEED: u64 = 0x4454_5353_4348_4544;
const RANDOMIZATION_SEED: u64 = 0x4454_5352_414e_444f;
const BOOTSTRAP_SEED: u64 = 0x4454_5342_4f4f_5453;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimingClass {
    A = 0,
    B = 1,
}

/// Replace a reusable byte buffer without a class-correlated branch or
/// class-selected template read immediately before the timed interval.
/// Both equal-length templates are read on every call.
pub fn prepare_bytes(current: &mut [u8], class_a: &[u8], class_b: &[u8], class: TimingClass) {
    assert_eq!(current.len(), class_a.len());
    assert_eq!(current.len(), class_b.len());
    let class_b_mask = 0u8.wrapping_sub(class as u8);
    let class_a_mask = !class_b_mask;
    for ((destination, &a), &b) in current.iter_mut().zip(class_a).zip(class_b) {
        *destination = (a & class_a_mask) | (b & class_b_mask);
    }
}

#[derive(Debug)]
pub struct TimingAnalysis {
    pub name: String,

    // Raw paired evidence. `a_first[index]` describes which class occupied
    // `first_times[index]`; every schedule is exactly balanced.
    pub first_times: Vec<f64>,
    pub second_times: Vec<f64>,
    pub a_first: Vec<bool>,
    pub times_a: Vec<f64>,
    pub times_b: Vec<f64>,
    pub paired_diffs: Vec<f64>,

    // Primary inference. This is the only per-case p-value admitted to the
    // blocking family and is not itself a verdict.
    pub primary_p_value: f64,
    pub randomization_iterations: usize,
    pub schedule_seed: u64,
    pub randomization_seed: u64,

    // Descriptive statistics only.
    pub mean_a: f64,
    pub mean_b: f64,
    pub mean_diff: f64,
    pub mad_a: f64,
    pub mad_b: f64,
    pub cohens_d: f64,
    pub ks_stat: f64,
    pub ks_p_value: f64,
    pub welch_t: f64,
    pub welch_p_value: f64,
    pub ci_lower: f64,
    pub ci_upper: f64,
    pub bootstrap_iterations: usize,
    pub bootstrap_seed: u64,

    pub practical_threshold: f64,
    pub noise_floor_mad: f64,
    pub environment_status: String,
}

#[derive(Debug)]
pub struct FamilyCaseDecision {
    pub name: String,
    pub primary_p_value: f64,
    pub holm_reject: bool,
    pub exceeds_practical_threshold: bool,
    pub blocks_release: bool,
}

#[derive(Debug)]
pub struct FamilywiseAnalysis {
    pub alpha: f64,
    pub decisions: Vec<FamilyCaseDecision>,
}

impl FamilywiseAnalysis {
    pub fn blocking_cases(&self) -> impl Iterator<Item = &FamilyCaseDecision> {
        self.decisions
            .iter()
            .filter(|decision| decision.blocks_release)
    }

    pub fn passes(&self) -> bool {
        self.blocking_cases().next().is_none()
    }
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

    /// Measure two classes through one reusable state and one class-free timed
    /// call site.
    ///
    /// `prepare_op` runs outside every `Instant` interval and must update
    /// `state` in place. `measurement_op` receives no class selector, which
    /// makes an A/B branch inside the measured API impossible by construction.
    /// The state object must stay at the same address for the entire run;
    /// Vec-backed states must additionally enforce stable pointer/length/
    /// capacity invariants in their preparation function.
    pub fn calibrate_and_measure_prepared<S, P, M>(
        &self,
        state: &mut S,
        mut prepare_op: P,
        mut measurement_op: M,
        config: &TestConfig,
        name: &str,
    ) -> Result<TimingAnalysis, String>
    where
        P: FnMut(&mut S, TimingClass),
        M: FnMut(&S),
    {
        if self.num_samples < 2 || self.num_samples % 2 != 0 {
            return Err("timing samples must be a nonzero even count".to_string());
        }
        if self.num_iterations == 0 || config.num_warmup == 0 {
            return Err("timing warmup and batch iteration counts must be positive".to_string());
        }
        if config.bootstrap_iterations < MIN_BOOTSTRAP_ITERATIONS {
            return Err(format!(
                "paired bootstrap requires at least {MIN_BOOTSTRAP_ITERATIONS} fixed iterations"
            ));
        }
        if !(0.0 < config.significance_level && config.significance_level < 1.0) {
            return Err("timing significance level must be between zero and one".to_string());
        }

        let _measurement_guard = TIMING_MEASUREMENT_LOCK
            .lock()
            .map_err(|_| "timing measurement lock poisoned".to_string())?;
        let state_address = std::ptr::from_ref(&*state).addr();

        let schedule_seed = derived_seed(SCHEDULE_SEED, name);
        let randomization_seed = derived_seed(RANDOMIZATION_SEED, name);
        let bootstrap_seed = derived_seed(BOOTSTRAP_SEED, name);
        let a_first = balanced_schedule(self.num_samples, schedule_seed)?;

        // Warm up and characterize only the measured operation. Class
        // preparation stays outside the interval on every iteration.
        let mut warmup_times = Vec::with_capacity(config.num_warmup);
        for _ in 0..config.num_warmup {
            prepare_checked(state, TimingClass::A, state_address, &mut prepare_op)?;
            compiler_fence(Ordering::SeqCst);
            black_box(&*state);
            let start = Instant::now();
            measurement_op(black_box(&*state));
            compiler_fence(Ordering::SeqCst);
            let end = Instant::now();
            ensure_state_address(state, state_address)?;
            warmup_times.push((end - start).as_nanos() as f64);
        }

        let current_mad = stats::robust_mad(&warmup_times);
        if !current_mad.is_finite() {
            return Err("warmup noise estimate is non-finite".to_string());
        }
        let mut environment_status = "Clean".to_string();

        if config.use_noise_profile {
            let mut store = ProfileStore::load_or_create(&config.noise_profile_path);
            if let Some(baseline) = store.get_baseline(name) {
                if current_mad > baseline * config.noise_tolerance_factor {
                    return Err(format!(
                        "TEST ABORTED: Environment too noisy. Current MAD {:.2}ns > {:.1}x Baseline {:.2}ns",
                        current_mad, config.noise_tolerance_factor, baseline
                    ));
                }
                if current_mad > baseline * 1.5 {
                    environment_status = format!(
                        "Elevated Noise (MAD {:.2} > Baseline {:.2})",
                        current_mad, baseline
                    );
                }
            }
            store.update(name, current_mad);
            store.save(&config.noise_profile_path);
        }

        // Preheat both prepared classes through the same measured closure.
        prepare_checked(state, TimingClass::A, state_address, &mut prepare_op)?;
        measurement_op(black_box(&*state));
        prepare_checked(state, TimingClass::B, state_address, &mut prepare_op)?;
        measurement_op(black_box(&*state));
        ensure_state_address(state, state_address)?;

        let mut first_times = Vec::with_capacity(self.num_samples);
        let mut second_times = Vec::with_capacity(self.num_samples);

        for &class_a_first in &a_first {
            let (first_class, second_class) = if class_a_first {
                (TimingClass::A, TimingClass::B)
            } else {
                (TimingClass::B, TimingClass::A)
            };
            first_times.push(measure_batch(
                state,
                first_class,
                state_address,
                self.num_iterations,
                &mut prepare_op,
                &mut measurement_op,
            )?);
            second_times.push(measure_batch(
                state,
                second_class,
                state_address,
                self.num_iterations,
                &mut prepare_op,
                &mut measurement_op,
            )?);
        }

        self.analyze(
            name,
            first_times,
            second_times,
            a_first,
            config,
            current_mad,
            environment_status,
            schedule_seed,
            randomization_seed,
            bootstrap_seed,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze(
        &self,
        name: &str,
        first_times: Vec<f64>,
        second_times: Vec<f64>,
        a_first: Vec<bool>,
        config: &TestConfig,
        noise_mad: f64,
        environment_status: String,
        schedule_seed: u64,
        randomization_seed: u64,
        bootstrap_seed: u64,
    ) -> Result<TimingAnalysis, String> {
        let paired_diffs = stats::paired_differences(&first_times, &second_times, &a_first)?;
        let mut times_a = Vec::with_capacity(self.num_samples);
        let mut times_b = Vec::with_capacity(self.num_samples);
        for ((&first, &second), &class_a_first) in
            first_times.iter().zip(&second_times).zip(&a_first)
        {
            if class_a_first {
                times_a.push(first);
                times_b.push(second);
            } else {
                times_a.push(second);
                times_b.push(first);
            }
        }

        let primary_p_value = stats::balanced_paired_randomization_p_value(
            &first_times,
            &second_times,
            &a_first,
            PRIMARY_RANDOMIZATION_ITERATIONS,
            randomization_seed,
        )?;
        let (ci_lower, ci_upper) = stats::bootstrap_ci(
            &paired_diffs,
            config.bootstrap_iterations,
            config.significance_level,
            bootstrap_seed,
        )?;
        let mean_a = mean(&times_a)?;
        let mean_b = mean(&times_b)?;
        let mean_diff = mean(&paired_diffs)?;
        let ks_stat = stats::ks_statistic(&times_a, &times_b);
        let ks_p_value = stats::ks_pvalue(ks_stat, times_a.len(), times_b.len());
        let (welch_t, welch_p_value) = stats::welch_t_statistic(&times_a, &times_b);

        let finite_diagnostics = [
            primary_p_value,
            ci_lower,
            ci_upper,
            mean_a,
            mean_b,
            mean_diff,
            ks_stat,
            ks_p_value,
            welch_t,
            welch_p_value,
        ];
        if finite_diagnostics.iter().any(|value| !value.is_finite()) {
            return Err("timing analysis produced a non-finite value".to_string());
        }

        Ok(TimingAnalysis {
            name: name.to_string(),
            first_times,
            second_times,
            a_first,
            times_a: times_a.clone(),
            times_b: times_b.clone(),
            paired_diffs,
            primary_p_value,
            randomization_iterations: PRIMARY_RANDOMIZATION_ITERATIONS,
            schedule_seed,
            randomization_seed,
            mean_a,
            mean_b,
            mean_diff,
            mad_a: stats::robust_mad(&times_a),
            mad_b: stats::robust_mad(&times_b),
            cohens_d: stats::cohens_d(&times_a, &times_b),
            ks_stat,
            ks_p_value,
            welch_t,
            welch_p_value,
            ci_lower,
            ci_upper,
            bootstrap_iterations: config.bootstrap_iterations,
            bootstrap_seed,
            practical_threshold: config.practical_significance_threshold,
            noise_floor_mad: noise_mad,
            environment_status,
        })
    }
}

fn prepare_checked<S, P>(
    state: &mut S,
    class: TimingClass,
    expected_address: usize,
    prepare_op: &mut P,
) -> Result<(), String>
where
    P: FnMut(&mut S, TimingClass),
{
    ensure_state_address(state, expected_address)?;
    prepare_op(state, class);
    compiler_fence(Ordering::SeqCst);
    black_box(&*state);
    ensure_state_address(state, expected_address)
}

fn measure_batch<S, P, M>(
    state: &mut S,
    class: TimingClass,
    expected_address: usize,
    iterations: usize,
    prepare_op: &mut P,
    measurement_op: &mut M,
) -> Result<f64, String>
where
    P: FnMut(&mut S, TimingClass),
    M: FnMut(&S),
{
    prepare_checked(state, class, expected_address, prepare_op)?;
    compiler_fence(Ordering::SeqCst);
    let start = Instant::now();
    for _ in 0..iterations {
        measurement_op(black_box(&*state));
        compiler_fence(Ordering::SeqCst);
    }
    let end = Instant::now();
    compiler_fence(Ordering::SeqCst);
    ensure_state_address(state, expected_address)?;
    let average = (end - start).as_nanos() as f64 / iterations as f64;
    if !average.is_finite() {
        return Err("timing batch produced a non-finite duration".to_string());
    }
    Ok(average)
}

fn ensure_state_address<S>(state: &S, expected: usize) -> Result<(), String> {
    if std::ptr::from_ref(state).addr() != expected {
        return Err("prepared timing state moved during measurement".to_string());
    }
    Ok(())
}

fn balanced_schedule(samples: usize, seed: u64) -> Result<Vec<bool>, String> {
    if samples < 2 || samples % 2 != 0 {
        return Err("balanced schedule requires a nonzero even sample count".to_string());
    }
    let mut schedule = vec![false; samples];
    schedule[..samples / 2].fill(true);
    schedule.shuffle(&mut ChaCha20Rng::seed_from_u64(seed));
    Ok(schedule)
}

fn derived_seed(base: u64, name: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    base ^ hash
}

fn mean(values: &[f64]) -> Result<f64, String> {
    if values.is_empty() || values.iter().any(|value| !value.is_finite()) {
        return Err("cannot compute a timing mean from empty/non-finite data".to_string());
    }
    Ok(values.iter().sum::<f64>() / values.len() as f64)
}

pub fn analyze_blocking_family(
    cases: &[TimingAnalysis],
    expected_names: &[&str],
) -> Result<FamilywiseAnalysis, String> {
    if expected_names.len() != EXPECTED_BLOCKING_CASES {
        return Err(format!(
            "family contract expected {EXPECTED_BLOCKING_CASES} names, got {}",
            expected_names.len()
        ));
    }
    if cases.len() != EXPECTED_BLOCKING_CASES {
        return Err(format!(
            "blocking timing family expected {EXPECTED_BLOCKING_CASES} cases, got {}",
            cases.len()
        ));
    }

    let expected: BTreeSet<&str> = expected_names.iter().copied().collect();
    if expected.len() != EXPECTED_BLOCKING_CASES {
        return Err("blocking timing contract contains duplicate expected names".to_string());
    }
    let observed: BTreeSet<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    if observed.len() != EXPECTED_BLOCKING_CASES {
        return Err("blocking timing evidence contains duplicate case names".to_string());
    }
    if observed != expected {
        let missing: Vec<_> = expected.difference(&observed).copied().collect();
        let unexpected: Vec<_> = observed.difference(&expected).copied().collect();
        return Err(format!(
            "blocking timing case-set mismatch; missing={missing:?}, unexpected={unexpected:?}"
        ));
    }

    let mut ordered = Vec::with_capacity(EXPECTED_BLOCKING_CASES);
    for &name in expected_names {
        let case = cases
            .iter()
            .find(|case| case.name == name)
            .ok_or_else(|| format!("missing blocking timing case {name}"))?;
        validate_case(case)?;
        ordered.push(case);
    }
    let p_values: Vec<f64> = ordered.iter().map(|case| case.primary_p_value).collect();
    let holm_rejections = stats::holm_adjust(&p_values, BLOCKING_FAMILY_ALPHA);
    let decisions = ordered
        .into_iter()
        .zip(holm_rejections)
        .map(|(case, holm_reject)| {
            let exceeds_practical_threshold = case.mean_diff.abs() > case.practical_threshold;
            FamilyCaseDecision {
                name: case.name.clone(),
                primary_p_value: case.primary_p_value,
                holm_reject,
                exceeds_practical_threshold,
                blocks_release: holm_reject && exceeds_practical_threshold,
            }
        })
        .collect();

    Ok(FamilywiseAnalysis {
        alpha: BLOCKING_FAMILY_ALPHA,
        decisions,
    })
}

fn validate_case(case: &TimingAnalysis) -> Result<(), String> {
    if !case.primary_p_value.is_finite()
        || !(0.0..=1.0).contains(&case.primary_p_value)
        || !case.mean_diff.is_finite()
        || !case.practical_threshold.is_finite()
        || case.practical_threshold < 0.0
    {
        return Err(format!("{} contains invalid family evidence", case.name));
    }
    if case.randomization_iterations != PRIMARY_RANDOMIZATION_ITERATIONS {
        return Err(format!(
            "{} used {} primary permutations instead of {}",
            case.name, case.randomization_iterations, PRIMARY_RANDOMIZATION_ITERATIONS
        ));
    }
    if case.bootstrap_iterations < MIN_BOOTSTRAP_ITERATIONS {
        return Err(format!(
            "{} used too few paired bootstrap iterations",
            case.name
        ));
    }
    if case.first_times.len() != case.second_times.len()
        || case.first_times.len() != case.a_first.len()
        || case.first_times.len() != case.paired_diffs.len()
        || case.first_times.len() != case.times_a.len()
        || case.first_times.len() != case.times_b.len()
        || case.a_first.iter().filter(|&&value| value).count() * 2 != case.a_first.len()
    {
        return Err(format!("{} has malformed paired evidence", case.name));
    }
    if case
        .first_times
        .iter()
        .chain(&case.second_times)
        .any(|value| !value.is_finite())
        || case
            .times_a
            .iter()
            .chain(&case.times_b)
            .any(|value| !value.is_finite())
        || case.paired_diffs.iter().any(|value| !value.is_finite())
    {
        return Err(format!("{} has non-finite raw timing evidence", case.name));
    }

    let reconstructed_diffs =
        stats::paired_differences(&case.first_times, &case.second_times, &case.a_first)?;
    let mut reconstructed_a = Vec::with_capacity(case.first_times.len());
    let mut reconstructed_b = Vec::with_capacity(case.first_times.len());
    for ((&first, &second), &a_first) in case
        .first_times
        .iter()
        .zip(&case.second_times)
        .zip(&case.a_first)
    {
        if a_first {
            reconstructed_a.push(first);
            reconstructed_b.push(second);
        } else {
            reconstructed_a.push(second);
            reconstructed_b.push(first);
        }
    }
    if reconstructed_diffs != case.paired_diffs
        || reconstructed_a != case.times_a
        || reconstructed_b != case.times_b
        || mean(&reconstructed_diffs)? != case.mean_diff
        || mean(&reconstructed_a)? != case.mean_a
        || mean(&reconstructed_b)? != case.mean_b
    {
        return Err(format!(
            "{} has inconsistent derived timing evidence",
            case.name
        ));
    }
    if case.schedule_seed != derived_seed(SCHEDULE_SEED, &case.name)
        || case.randomization_seed != derived_seed(RANDOMIZATION_SEED, &case.name)
        || case.bootstrap_seed != derived_seed(BOOTSTRAP_SEED, &case.name)
    {
        return Err(format!(
            "{} has an invalid predeclared seed binding",
            case.name
        ));
    }
    if case.a_first != balanced_schedule(case.a_first.len(), case.schedule_seed)? {
        return Err(format!(
            "{} does not match its predeclared balanced schedule",
            case.name
        ));
    }

    let diagnostics = [
        case.mad_a,
        case.mad_b,
        case.cohens_d,
        case.ks_stat,
        case.ks_p_value,
        case.welch_t,
        case.welch_p_value,
        case.ci_lower,
        case.ci_upper,
        case.noise_floor_mad,
    ];
    if diagnostics.iter().any(|value| !value.is_finite()) {
        return Err(format!("{} has non-finite diagnostic evidence", case.name));
    }
    Ok(())
}

pub fn generate_test_insights(
    analysis: &TimingAnalysis,
    _config: &TestConfig,
    primitive_name: &str,
) -> String {
    let schedule: String = analysis
        .a_first
        .iter()
        .map(|&a_first| if a_first { 'A' } else { 'B' })
        .collect();
    format!(
        "Timing diagnostics: {primitive_name}\n\
         Environment: {}\n\
         Noise floor MAD: {:.3} ns\n\
         Mean A-B: {:.3} ns\n\
         99% paired-bootstrap CI (descriptive): [{:.3}, {:.3}] ns\n\
         Practical threshold: {:.3} ns\n\
         Primary balanced-randomization p (unadjusted): {:.8}\n\
         Primary permutations: {} seed={:#018x}\n\
         Balanced schedule seed={:#018x} A-first pattern={}\n\
         Diagnostic Cohen's d: {:.3}\n\
         Diagnostic Welch t/p: {:.3} / {:.3e}\n\
         Diagnostic KS statistic/p: {:.3} / {:.3e}\n\
         Paired bootstrap: {} seed={:#018x}\n\
         Raw first ns/op: {:?}\n\
         Raw second ns/op: {:?}\n\
         Raw paired A-B ns/op: {:?}",
        analysis.environment_status,
        analysis.noise_floor_mad,
        analysis.mean_diff,
        analysis.ci_lower,
        analysis.ci_upper,
        analysis.practical_threshold,
        analysis.primary_p_value,
        analysis.randomization_iterations,
        analysis.randomization_seed,
        analysis.schedule_seed,
        schedule,
        analysis.cohens_d,
        analysis.welch_t,
        analysis.welch_p_value,
        analysis.ks_stat,
        analysis.ks_p_value,
        analysis.bootstrap_iterations,
        analysis.bootstrap_seed,
        analysis.first_times,
        analysis.second_times,
        analysis.paired_diffs,
    )
}

pub fn generate_familywise_insights(family: &FamilywiseAnalysis) -> String {
    let mut output = format!(
        "Blocking timing family: {} cases, Holm FWER alpha={}\n",
        family.decisions.len(),
        family.alpha
    );
    for decision in &family.decisions {
        output.push_str(&format!(
            "  {}: primary_p={:.8}, holm_reject={}, practical={}, blocks={}\n",
            decision.name,
            decision.primary_p_value,
            decision.holm_reject,
            decision.exceeds_practical_threshold,
            decision.blocks_release,
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn balanced_schedule_is_deterministic_and_exact() {
        let first = balanced_schedule(100, 7).unwrap();
        let second = balanced_schedule(100, 7).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.iter().filter(|&&value| value).count(), 50);
        assert!(balanced_schedule(99, 7).is_err());
    }

    #[test]
    fn prepared_bytes_select_each_class_in_place() {
        let class_a = [0x00, 0x55, 0xaa, 0xff];
        let class_b = [0xff, 0xaa, 0x55, 0x00];
        let mut current = [0u8; 4];
        let address = current.as_ptr();
        prepare_bytes(&mut current, &class_a, &class_b, TimingClass::A);
        assert_eq!(current, class_a);
        assert_eq!(current.as_ptr(), address);
        prepare_bytes(&mut current, &class_a, &class_b, TimingClass::B);
        assert_eq!(current, class_b);
        assert_eq!(current.as_ptr(), address);
    }

    #[test]
    fn prepared_api_uses_one_address_and_prepares_once_per_batch() {
        #[derive(Debug)]
        struct State(u8);

        let mut config = TestConfig::default();
        config.num_warmup = 2;
        config.num_samples = 2;
        config.num_iterations = 3;
        config.use_noise_profile = false;
        let tester = TimingTester::new(config.num_samples, config.num_iterations);
        let mut state = State(0);
        let address = std::ptr::from_ref(&state).addr();
        let prepare_count = Cell::new(0usize);
        let measure_count = Cell::new(0usize);

        let analysis = tester
            .calibrate_and_measure_prepared(
                &mut state,
                |current, class| {
                    assert_eq!(std::ptr::from_ref(current).addr(), address);
                    current.0 = u8::from(class == TimingClass::B);
                    prepare_count.set(prepare_count.get() + 1);
                },
                |current| {
                    assert_eq!(std::ptr::from_ref(current).addr(), address);
                    black_box(current.0);
                    measure_count.set(measure_count.get() + 1);
                },
                &config,
                "prepared-api-self-test",
            )
            .unwrap();

        // warmups + two preheats + two classes for each paired sample
        assert_eq!(prepare_count.get(), 2 + 2 + 2 * 2);
        assert_eq!(measure_count.get(), 2 + 2 + 2 * 2 * 3);
        assert_eq!(analysis.a_first.iter().filter(|&&value| value).count(), 1);
    }

    fn synthetic_case(name: &str, p_value: f64, mean_diff: f64) -> TimingAnalysis {
        let schedule_seed = derived_seed(SCHEDULE_SEED, name);
        let a_first = balanced_schedule(2, schedule_seed).unwrap();
        let first_times: Vec<f64> = a_first
            .iter()
            .map(|&class_a_first| if class_a_first { 1.0 + mean_diff } else { 1.0 })
            .collect();
        let second_times: Vec<f64> = a_first
            .iter()
            .map(|&class_a_first| if class_a_first { 1.0 } else { 1.0 + mean_diff })
            .collect();
        TimingAnalysis {
            name: name.to_string(),
            first_times,
            second_times,
            a_first,
            times_a: vec![1.0 + mean_diff, 1.0 + mean_diff],
            times_b: vec![1.0, 1.0],
            paired_diffs: vec![mean_diff, mean_diff],
            primary_p_value: p_value,
            randomization_iterations: PRIMARY_RANDOMIZATION_ITERATIONS,
            schedule_seed,
            randomization_seed: derived_seed(RANDOMIZATION_SEED, name),
            mean_a: 1.0 + mean_diff,
            mean_b: 1.0,
            mean_diff,
            mad_a: 0.0,
            mad_b: 0.0,
            cohens_d: 0.0,
            ks_stat: 1.0,
            ks_p_value: 0.1,
            welch_t: 0.0,
            welch_p_value: 1.0,
            ci_lower: 1.0,
            ci_upper: 1.0,
            bootstrap_iterations: MIN_BOOTSTRAP_ITERATIONS,
            bootstrap_seed: derived_seed(BOOTSTRAP_SEED, name),
            practical_threshold: 0.5,
            noise_floor_mad: 0.0,
            environment_status: "Synthetic".to_string(),
        }
    }

    #[test]
    fn blocking_family_is_exact_fail_closed_and_uses_one_holm_pass() {
        let names: Vec<String> = (0..EXPECTED_BLOCKING_CASES)
            .map(|index| format!("case-{index:02}"))
            .collect();
        let expected: Vec<&str> = names.iter().map(String::as_str).collect();
        let mut cases: Vec<TimingAnalysis> = expected
            .iter()
            .map(|name| synthetic_case(name, 1.0, 0.0))
            .collect();

        cases[0] = synthetic_case(expected[0], 0.000_01, 0.75);
        cases[1] = synthetic_case(expected[1], 0.000_02, 0.25);
        let family = analyze_blocking_family(&cases, &expected).unwrap();
        assert!(family.decisions[0].holm_reject);
        assert!(family.decisions[0].blocks_release);
        assert!(family.decisions[1].holm_reject);
        assert!(!family.decisions[1].blocks_release);

        cases.pop();
        assert!(analyze_blocking_family(&cases, &expected).is_err());

        cases.push(synthetic_case(expected[0], 1.0, 0.0));
        assert!(analyze_blocking_family(&cases, &expected).is_err());

        cases[EXPECTED_BLOCKING_CASES - 1] =
            synthetic_case(expected[EXPECTED_BLOCKING_CASES - 1], f64::NAN, 0.0);
        assert!(analyze_blocking_family(&cases, &expected).is_err());
    }
}
