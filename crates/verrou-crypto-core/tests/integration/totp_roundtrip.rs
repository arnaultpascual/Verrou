//! Integration tests for TOTP/HOTP generation engine.
//!
//! Tests the full OTP lifecycle: generate → validate, cross-algorithm
//! differentiation, and time-window boundary behavior.

use verrou_crypto_core::totp::{
    generate_hotp, generate_totp, validate_totp, OtpAlgorithm, OtpDigits,
};

const SECRET_20: &[u8] = b"12345678901234567890";
const SECRET_64: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

/// Generate → validate at same time succeeds.
#[test]
fn generate_then_validate_same_time() {
    let time = 1_700_000_000u64;
    let code =
        generate_totp(SECRET_20, time, OtpDigits::Six, 30, OtpAlgorithm::Sha1).expect("generate");
    let valid = validate_totp(
        SECRET_20,
        time,
        &code,
        OtpDigits::Six,
        30,
        OtpAlgorithm::Sha1,
    )
    .expect("validate");
    assert!(valid, "code should be valid at same time");
}

/// Generate → validate at T+period succeeds (within ±1 window).
#[test]
fn generate_then_validate_one_step_later() {
    let time = 1_700_000_000u64;
    let code =
        generate_totp(SECRET_20, time, OtpDigits::Six, 30, OtpAlgorithm::Sha1).expect("generate");
    let valid = validate_totp(
        SECRET_20,
        time.wrapping_add(30),
        &code,
        OtpDigits::Six,
        30,
        OtpAlgorithm::Sha1,
    )
    .expect("validate");
    assert!(valid, "code should be valid one step later");
}

/// Generate → validate at T+3*period fails (outside ±1 window).
#[test]
fn generate_then_validate_three_steps_later_fails() {
    let time = 1_700_000_000u64;
    let code =
        generate_totp(SECRET_20, time, OtpDigits::Six, 30, OtpAlgorithm::Sha1).expect("generate");
    let valid = validate_totp(
        SECRET_20,
        time.wrapping_add(90),
        &code,
        OtpDigits::Six,
        30,
        OtpAlgorithm::Sha1,
    )
    .expect("validate");
    assert!(!valid, "code should be invalid three steps later");
}

/// All three algorithms produce valid but different codes for same inputs.
#[test]
fn cross_algorithm_differentiation() {
    let time = 1_234_567_890u64;

    let sha1 =
        generate_totp(SECRET_64, time, OtpDigits::Eight, 30, OtpAlgorithm::Sha1).expect("sha1");
    let sha256 =
        generate_totp(SECRET_64, time, OtpDigits::Eight, 30, OtpAlgorithm::Sha256).expect("sha256");
    let sha512 =
        generate_totp(SECRET_64, time, OtpDigits::Eight, 30, OtpAlgorithm::Sha512).expect("sha512");

    // Each code must be valid under its own algorithm.
    assert!(
        validate_totp(
            SECRET_64,
            time,
            &sha1,
            OtpDigits::Eight,
            30,
            OtpAlgorithm::Sha1
        )
        .expect("validate sha1"),
        "SHA1 code must validate under SHA1"
    );
    assert!(
        validate_totp(
            SECRET_64,
            time,
            &sha256,
            OtpDigits::Eight,
            30,
            OtpAlgorithm::Sha256,
        )
        .expect("validate sha256"),
        "SHA256 code must validate under SHA256"
    );
    assert!(
        validate_totp(
            SECRET_64,
            time,
            &sha512,
            OtpDigits::Eight,
            30,
            OtpAlgorithm::Sha512,
        )
        .expect("validate sha512"),
        "SHA512 code must validate under SHA512"
    );

    // At least two must differ.
    let all_same = sha1 == sha256 && sha256 == sha512;
    assert!(
        !all_same,
        "different algorithms should produce different codes"
    );
}

/// HOTP and TOTP consistency: TOTP(secret, t) == HOTP(secret, t/period).
#[test]
fn totp_hotp_consistency() {
    let time = 2_000_000_000u64;
    let period = 60u32;

    let totp_code = generate_totp(
        SECRET_20,
        time,
        OtpDigits::Six,
        period,
        OtpAlgorithm::Sha256,
    )
    .expect("totp");

    let time_step = time / u64::from(period);
    let hotp_code =
        generate_hotp(SECRET_20, time_step, OtpDigits::Six, OtpAlgorithm::Sha256).expect("hotp");

    assert_eq!(
        totp_code, hotp_code,
        "TOTP must equal HOTP at same time step"
    );
}

/// 60-second period works correctly.
#[test]
fn sixty_second_period() {
    let time = 1_700_000_000u64;
    let code =
        generate_totp(SECRET_20, time, OtpDigits::Six, 60, OtpAlgorithm::Sha1).expect("generate");
    let valid = validate_totp(
        SECRET_20,
        time,
        &code,
        OtpDigits::Six,
        60,
        OtpAlgorithm::Sha1,
    )
    .expect("validate");
    assert!(valid, "60s period code should be valid");

    // One step later (60s) should still be valid.
    let valid_next = validate_totp(
        SECRET_20,
        time.wrapping_add(60),
        &code,
        OtpDigits::Six,
        60,
        OtpAlgorithm::Sha1,
    )
    .expect("validate next");
    assert!(valid_next, "code should be valid one 60s step later");
}
