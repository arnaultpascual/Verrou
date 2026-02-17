//! Timing side-channel validation for constant-time operations (Layer 5).
//!
//! Uses Welch's t-test to verify that TOTP validation timing does not
//! leak information about whether a code matches. The test compares timing
//! distributions for matching vs non-matching codes and asserts that the
//! t-statistic stays below a threshold (|t| < 4.5), indicating no
//! statistically significant timing difference.
//!
//! **Methodology:** This is a simplified dudect-style analysis. We:
//! 1. Generate a valid TOTP code (class A — match) and an invalid code (class B — mismatch)
//! 2. Time N iterations of `validate_totp` for each class
//! 3. Compute Welch's t-statistic on the two timing distributions
//! 4. Assert |t| < 4.5 (no detectable timing difference)
//!
//! A |t| > 4.5 would suggest timing leakage at >99.999% confidence.
//!
//! **Caveat:** This is a statistical test. In rare cases, system scheduling
//! noise may cause false positives. The test uses 10,000+ iterations and
//! black-box barriers to minimize this risk.

use std::time::Instant;

use verrou_crypto_core::totp::{generate_totp, validate_totp, OtpAlgorithm, OtpDigits};

/// Number of timing samples per class.
const SAMPLES: usize = 10_000;

/// Welch's t-test threshold. |t| < 4.5 means no detectable timing difference.
const T_THRESHOLD: f64 = 4.5;

/// Black-box hint to prevent the compiler from optimizing away a value.
///
/// Uses `std::hint::black_box` (stabilized in Rust 1.66) to ensure the
/// result is actually computed and not elided by the optimizer.
#[inline(never)]
fn black_box_validate(
    secret: &[u8],
    time: u64,
    code: &str,
    digits: OtpDigits,
    period: u32,
    algorithm: OtpAlgorithm,
) -> bool {
    let result = validate_totp(secret, time, code, digits, period, algorithm)
        .expect("validate_totp should not error during timing test");
    std::hint::black_box(result)
}

/// Compute Welch's t-statistic for two independent samples.
///
/// `t = (mean_a - mean_b) / sqrt(var_a/n_a + var_b/n_b)`
///
/// Returns `f64::NAN` if either variance computation would divide by zero.
#[allow(clippy::cast_precision_loss)]
fn welch_t_statistic(a: &[f64], b: &[f64]) -> f64 {
    if a.len() < 2 || b.len() < 2 {
        return f64::NAN;
    }

    let n_a = a.len() as f64;
    let n_b = b.len() as f64;

    let mean_a: f64 = a.iter().sum::<f64>() / n_a;
    let mean_b: f64 = b.iter().sum::<f64>() / n_b;

    let var_a: f64 = a.iter().map(|x| (x - mean_a).powi(2)).sum::<f64>() / (n_a - 1.0);
    let var_b: f64 = b.iter().map(|x| (x - mean_b).powi(2)).sum::<f64>() / (n_b - 1.0);

    let denominator = (var_a / n_a + var_b / n_b).sqrt();
    if denominator == 0.0 {
        return 0.0; // Both distributions are constant — no timing difference.
    }

    (mean_a - mean_b) / denominator
}

/// Validate that `validate_totp` does not exhibit timing side-channels.
///
/// Compares timing of matching codes (class A) vs non-matching codes (class B).
/// If the constant-time comparison in `validate_totp` works correctly,
/// both distributions should be statistically indistinguishable.
#[test]
fn validate_totp_constant_time_no_timing_leak() {
    let secret = b"12345678901234567890";
    let time = 1_234_567_890u64;
    let digits = OtpDigits::Six;
    let period = 30;
    let algorithm = OtpAlgorithm::Sha1;

    // Class A: matching code.
    let valid_code =
        generate_totp(secret, time, digits, period, algorithm).expect("generate valid code");

    // Class B: non-matching code (same length, different value).
    let invalid_code = if valid_code == "000000" {
        "111111".to_owned()
    } else {
        "000000".to_owned()
    };

    // Warm up to stabilize JIT/cache effects.
    for _ in 0..100 {
        black_box_validate(secret, time, &valid_code, digits, period, algorithm);
        black_box_validate(secret, time, &invalid_code, digits, period, algorithm);
    }

    // Collect timing samples, interleaving A and B to cancel out drift.
    let mut times_a = Vec::with_capacity(SAMPLES);
    let mut times_b = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        // Class A: matching code.
        let start = Instant::now();
        let _ = black_box_validate(secret, time, &valid_code, digits, period, algorithm);
        let elapsed_a = start.elapsed().as_nanos();

        // Class B: non-matching code.
        let start = Instant::now();
        let _ = black_box_validate(secret, time, &invalid_code, digits, period, algorithm);
        let elapsed_b = start.elapsed().as_nanos();

        #[allow(clippy::cast_precision_loss)]
        {
            times_a.push(elapsed_a as f64);
            times_b.push(elapsed_b as f64);
        }
    }

    let t = welch_t_statistic(&times_a, &times_b);
    let abs_t = t.abs();

    eprintln!(
        "Timing side-channel test: |t| = {abs_t:.2} (threshold: {T_THRESHOLD}), \
         samples = {SAMPLES} per class"
    );

    assert!(
        abs_t < T_THRESHOLD,
        "Timing side-channel detected: |t| = {abs_t:.2} exceeds threshold {T_THRESHOLD}. \
         This suggests validate_totp leaks timing information about code correctness."
    );
}

/// Verify the Welch t-test implementation with known distributions.
///
/// Two identical constant distributions should yield t = 0.
#[test]
fn welch_t_test_identical_distributions() {
    let a = vec![1.0; 100];
    let b = vec![1.0; 100];
    let t = welch_t_statistic(&a, &b);
    assert!(
        t.abs() < 0.001,
        "identical distributions should yield t ≈ 0, got {t}"
    );
}

/// Verify Welch t-test detects clearly different distributions.
///
/// Mean 100 vs mean 200 with low variance should produce |t| >> 4.5.
#[test]
fn welch_t_test_different_distributions() {
    let a: Vec<f64> = (0..1000).map(|i| 100.0 + f64::from(i % 3)).collect();
    let b: Vec<f64> = (0..1000).map(|i| 200.0 + f64::from(i % 3)).collect();
    let t = welch_t_statistic(&a, &b);
    assert!(
        t.abs() > 100.0,
        "clearly different distributions should yield |t| >> 4.5, got {t:.2}"
    );
}
