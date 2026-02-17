#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Property-based tests for TOTP/HOTP generation engine.

use proptest::prelude::*;
use verrou_crypto_core::totp::{generate_hotp, generate_totp, OtpAlgorithm, OtpDigits};

/// Strategy for `OtpDigits`.
fn digits_strategy() -> impl Strategy<Value = OtpDigits> {
    prop_oneof![Just(OtpDigits::Six), Just(OtpDigits::Eight),]
}

/// Strategy for `OtpAlgorithm`.
fn algorithm_strategy() -> impl Strategy<Value = OtpAlgorithm> {
    prop_oneof![
        Just(OtpAlgorithm::Sha1),
        Just(OtpAlgorithm::Sha256),
        Just(OtpAlgorithm::Sha512),
    ]
}

proptest! {
    /// TOTP output length always equals the digit count.
    #[test]
    fn totp_output_length_matches_digits(
        secret in proptest::collection::vec(any::<u8>(), 1..64),
        time in any::<u64>(),
        digits in digits_strategy(),
        algorithm in algorithm_strategy(),
    ) {
        let code = generate_totp(&secret, time, digits, 30, algorithm)
            .expect("TOTP generation should succeed");
        let expected_len = usize::from(digits.value());
        prop_assert_eq!(
            code.len(),
            expected_len,
            "TOTP output length {} does not match digits {}",
            code.len(),
            expected_len
        );
    }

    /// HOTP output length always equals the digit count.
    #[test]
    fn hotp_output_length_matches_digits(
        secret in proptest::collection::vec(any::<u8>(), 1..64),
        counter in any::<u64>(),
        digits in digits_strategy(),
        algorithm in algorithm_strategy(),
    ) {
        let code = generate_hotp(&secret, counter, digits, algorithm)
            .expect("HOTP generation should succeed");
        let expected_len = usize::from(digits.value());
        prop_assert_eq!(
            code.len(),
            expected_len,
            "HOTP output length {} does not match digits {}",
            code.len(),
            expected_len
        );
    }

    /// Same inputs always produce the same output (deterministic).
    #[test]
    fn totp_is_deterministic(
        secret in proptest::collection::vec(any::<u8>(), 1..64),
        time in any::<u64>(),
        digits in digits_strategy(),
        algorithm in algorithm_strategy(),
    ) {
        let code1 = generate_totp(&secret, time, digits, 30, algorithm)
            .expect("first generation");
        let code2 = generate_totp(&secret, time, digits, 30, algorithm)
            .expect("second generation");
        prop_assert_eq!(code1, code2, "TOTP must be deterministic");
    }

    /// TOTP at time T equals HOTP at counter T/period.
    #[test]
    fn totp_equals_hotp_at_time_step(
        secret in proptest::collection::vec(any::<u8>(), 1..64),
        time in any::<u64>(),
        digits in digits_strategy(),
        algorithm in algorithm_strategy(),
    ) {
        let period = 30u32;
        let totp_code = generate_totp(&secret, time, digits, period, algorithm)
            .expect("TOTP generation");
        // Compute the same time step manually.
        // period is constant 30 (non-zero), division is safe.
        let period_u64 = u64::from(period);
        #[allow(clippy::arithmetic_side_effects)]
        let time_step = time / period_u64;
        let hotp_code = generate_hotp(&secret, time_step, digits, algorithm)
            .expect("HOTP generation");
        prop_assert_eq!(
            totp_code,
            hotp_code,
            "TOTP at time {} should equal HOTP at counter {}",
            time,
            time_step
        );
    }
}
