//! RFC 6238 TOTP and RFC 4226 HOTP generation engine.
//!
//! Provides standards-compliant one-time password generation using
//! `ring::hmac` for HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512.

use ring::hmac;

use crate::CryptoError;

/// Constant-time byte comparison for OTP codes.
///
/// Returns `true` iff both slices have equal length and identical contents.
/// Uses bitwise OR accumulation to avoid short-circuit timing leaks.
///
/// Note: The early return on length mismatch is acceptable for OTP codes
/// because the expected digit count (6 or 8) is public information — it is
/// not secret. The constant-time property protects the *code value*, not
/// its length.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Constants ───────────────────────────────────────────────────────

/// Default TOTP period in seconds (RFC 6238 §4).
pub const DEFAULT_PERIOD: u32 = 30;

/// Time-step window for TOTP validation (±1 step per RFC 6238 §5.2, NFR43).
pub const TOTP_WINDOW: u32 = 1;

// ── Types ───────────────────────────────────────────────────────────

/// HMAC algorithm used for OTP generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpAlgorithm {
    /// HMAC-SHA1 (default for most authenticator apps).
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl OtpAlgorithm {
    /// Map to the corresponding `ring::hmac::Algorithm`.
    fn to_ring_algorithm(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
            Self::Sha512 => hmac::HMAC_SHA512,
        }
    }
}

/// Number of digits in an OTP code (6 or 8 only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtpDigits {
    /// 6-digit code (standard).
    Six,
    /// 8-digit code.
    Eight,
}

impl OtpDigits {
    /// Return the numeric digit count.
    #[must_use]
    pub const fn value(self) -> u8 {
        match self {
            Self::Six => 6,
            Self::Eight => 8,
        }
    }

    /// Return the modulus value (10^digits) for truncation.
    #[must_use]
    const fn modulus(self) -> u32 {
        match self {
            Self::Six => 1_000_000,
            Self::Eight => 100_000_000,
        }
    }
}

// ── HOTP (RFC 4226) ────────────────────────────────────────────────

/// Generate an HOTP code per RFC 4226.
///
/// # Arguments
/// - `secret`: Shared secret key bytes (from `SecretBuffer::expose()`)
/// - `counter`: 8-byte counter value (big-endian per RFC 4226 §5.2)
/// - `digits`: Number of output digits (6 or 8)
/// - `algorithm`: HMAC algorithm to use
///
/// # Errors
/// Returns `CryptoError::Otp` if the secret is empty.
#[must_use = "OTP code should be used or stored"]
pub fn generate_hotp(
    secret: &[u8],
    counter: u64,
    digits: OtpDigits,
    algorithm: OtpAlgorithm,
) -> Result<String, CryptoError> {
    if secret.is_empty() {
        return Err(CryptoError::Otp("secret must not be empty".to_owned()));
    }

    // HMAC(K, C) where C is counter as 8-byte big-endian (RFC 4226 §5.2).
    let key = hmac::Key::new(algorithm.to_ring_algorithm(), secret);
    let counter_bytes = counter.to_be_bytes();
    let tag = hmac::sign(&key, &counter_bytes);
    let hmac_result = tag.as_ref();

    // Dynamic Truncation (RFC 4226 §5.3).
    // offset = low-order 4 bits of last byte.
    let offset = usize::from(hmac_result[hmac_result.len().wrapping_sub(1)] & 0x0F);

    // Extract 4 bytes starting at offset, mask high bit (0x7FFFFFFF).
    let binary_code = u32::from_be_bytes([
        hmac_result[offset] & 0x7F,
        hmac_result[offset.wrapping_add(1)],
        hmac_result[offset.wrapping_add(2)],
        hmac_result[offset.wrapping_add(3)],
    ]);

    // code = binary_code mod 10^digits.
    // modulus is always 1_000_000 or 100_000_000 (never zero).
    let modulus = digits.modulus();
    #[allow(clippy::arithmetic_side_effects)]
    let code = binary_code % modulus;
    let width = usize::from(digits.value());

    Ok(format!("{code:0>width$}"))
}

// ── TOTP (RFC 6238) ────────────────────────────────────────────────

/// Generate a TOTP code per RFC 6238.
///
/// # Arguments
/// - `secret`: Shared secret key bytes
/// - `time`: Unix timestamp in seconds
/// - `digits`: Number of output digits (6 or 8)
/// - `period`: Time step in seconds (typically 30)
/// - `algorithm`: HMAC algorithm to use
///
/// # Errors
/// Returns `CryptoError::Otp` if `period` is 0 or secret is empty.
#[must_use = "OTP code should be used or stored"]
pub fn generate_totp(
    secret: &[u8],
    time: u64,
    digits: OtpDigits,
    period: u32,
    algorithm: OtpAlgorithm,
) -> Result<String, CryptoError> {
    if period == 0 {
        return Err(CryptoError::Otp("period must be > 0".to_owned()));
    }

    // T = floor(time / period) per RFC 6238 §4.
    // period is validated non-zero above.
    let period_u64 = u64::from(period);
    #[allow(clippy::arithmetic_side_effects)]
    let time_step = time / period_u64;
    generate_hotp(secret, time_step, digits, algorithm)
}

/// Validate a TOTP code with ±1 time step window (NFR43, RFC 6238 §5.2).
///
/// Checks the code against T-1, T, and T+1 time steps using
/// constant-time string comparison.
///
/// # Arguments
/// - `secret`: Shared secret key bytes
/// - `time`: Unix timestamp in seconds
/// - `code`: The code to validate
/// - `digits`: Number of output digits
/// - `period`: Time step in seconds
/// - `algorithm`: HMAC algorithm to use
///
/// # Errors
/// Returns `CryptoError::Otp` if `period` is 0 or secret is empty.
#[must_use = "validation result should be checked"]
pub fn validate_totp(
    secret: &[u8],
    time: u64,
    code: &str,
    digits: OtpDigits,
    period: u32,
    algorithm: OtpAlgorithm,
) -> Result<bool, CryptoError> {
    if period == 0 {
        return Err(CryptoError::Otp("period must be > 0".to_owned()));
    }

    // period is validated non-zero above.
    let period_u64 = u64::from(period);
    #[allow(clippy::arithmetic_side_effects)]
    let time_step = time / period_u64;

    // Check T-1, T, T+1 (±TOTP_WINDOW steps).
    // Use saturating arithmetic to avoid wrapping around u64 boundaries.
    // At time_step=0, start saturates to 0 (not u64::MAX).
    let mut valid = false;

    let start = time_step.saturating_sub(u64::from(TOTP_WINDOW));
    let end = time_step.saturating_add(u64::from(TOTP_WINDOW));

    // Iterate through window: start..=end
    let mut step = start;
    loop {
        let expected = generate_hotp(secret, step, digits, algorithm)?;
        // Constant-time comparison to prevent timing attacks.
        if constant_time_eq(expected.as_bytes(), code.as_bytes()) {
            valid = true;
        }
        if step == end {
            break;
        }
        step = step.wrapping_add(1);
    }

    Ok(valid)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── RFC 4226 Appendix D test vectors ────────────────────────────
    // Secret: "12345678901234567890" (ASCII), SHA1, 6 digits.
    const RFC4226_SECRET: &[u8] = b"12345678901234567890";

    const RFC4226_EXPECTED: [&str; 10] = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];

    #[test]
    fn hotp_rfc4226_appendix_d_vectors() {
        for (counter, expected) in RFC4226_EXPECTED.iter().enumerate() {
            let code = generate_hotp(
                RFC4226_SECRET,
                u64::try_from(counter).expect("counter fits u64"),
                OtpDigits::Six,
                OtpAlgorithm::Sha1,
            )
            .expect("HOTP generation should succeed");
            assert_eq!(
                &code, expected,
                "HOTP mismatch at counter {counter}: got {code}, expected {expected}"
            );
        }
    }

    // ── RFC 6238 Appendix B test vectors ────────────────────────────
    // SHA1 secret:   "12345678901234567890"              (20 bytes)
    // SHA256 secret: "12345678901234567890123456789012"   (32 bytes)
    // SHA512 secret: "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
    const RFC6238_SECRET_SHA1: &[u8] = b"12345678901234567890";
    const RFC6238_SECRET_SHA256: &[u8] = b"12345678901234567890123456789012";
    const RFC6238_SECRET_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    struct Rfc6238Vector {
        time: u64,
        sha1: &'static str,
        sha256: &'static str,
        sha512: &'static str,
    }

    const RFC6238_VECTORS: [Rfc6238Vector; 6] = [
        Rfc6238Vector {
            time: 59,
            sha1: "94287082",
            sha256: "46119246",
            sha512: "90693936",
        },
        Rfc6238Vector {
            time: 1_111_111_109,
            sha1: "07081804",
            sha256: "68084774",
            sha512: "25091201",
        },
        Rfc6238Vector {
            time: 1_111_111_111,
            sha1: "14050471",
            sha256: "67062674",
            sha512: "99943326",
        },
        Rfc6238Vector {
            time: 1_234_567_890,
            sha1: "89005924",
            sha256: "91819424",
            sha512: "93441116",
        },
        Rfc6238Vector {
            time: 2_000_000_000,
            sha1: "69279037",
            sha256: "90698825",
            sha512: "38618901",
        },
        Rfc6238Vector {
            time: 20_000_000_000,
            sha1: "65353130",
            sha256: "77737706",
            sha512: "47863826",
        },
    ];

    #[test]
    fn totp_rfc6238_appendix_b_sha1() {
        for v in &RFC6238_VECTORS {
            let code = generate_totp(
                RFC6238_SECRET_SHA1,
                v.time,
                OtpDigits::Eight,
                30,
                OtpAlgorithm::Sha1,
            )
            .expect("TOTP generation should succeed");
            assert_eq!(
                &code, v.sha1,
                "TOTP SHA1 mismatch at time {}: got {code}, expected {}",
                v.time, v.sha1
            );
        }
    }

    #[test]
    fn totp_rfc6238_appendix_b_sha256() {
        for v in &RFC6238_VECTORS {
            let code = generate_totp(
                RFC6238_SECRET_SHA256,
                v.time,
                OtpDigits::Eight,
                30,
                OtpAlgorithm::Sha256,
            )
            .expect("TOTP generation should succeed");
            assert_eq!(
                &code, v.sha256,
                "TOTP SHA256 mismatch at time {}: got {code}, expected {}",
                v.time, v.sha256
            );
        }
    }

    #[test]
    fn totp_rfc6238_appendix_b_sha512() {
        for v in &RFC6238_VECTORS {
            let code = generate_totp(
                RFC6238_SECRET_SHA512,
                v.time,
                OtpDigits::Eight,
                30,
                OtpAlgorithm::Sha512,
            )
            .expect("TOTP generation should succeed");
            assert_eq!(
                &code, v.sha512,
                "TOTP SHA512 mismatch at time {}: got {code}, expected {}",
                v.time, v.sha512
            );
        }
    }

    // ── Validation window tests ─────────────────────────────────────

    #[test]
    fn validate_totp_accepts_current_step() {
        let secret = b"12345678901234567890";
        let time = 1_234_567_890u64;
        let code =
            generate_totp(secret, time, OtpDigits::Six, 30, OtpAlgorithm::Sha1).expect("generate");
        let valid = validate_totp(secret, time, &code, OtpDigits::Six, 30, OtpAlgorithm::Sha1)
            .expect("validate");
        assert!(valid, "code at same time step should be valid");
    }

    #[test]
    fn validate_totp_accepts_previous_step() {
        let secret = b"12345678901234567890";
        let time = 1_234_567_890u64;
        // Generate code at T, validate at T+period (so T is T-1 relative to validation time).
        let code =
            generate_totp(secret, time, OtpDigits::Six, 30, OtpAlgorithm::Sha1).expect("generate");
        let valid = validate_totp(
            secret,
            time.wrapping_add(30),
            &code,
            OtpDigits::Six,
            30,
            OtpAlgorithm::Sha1,
        )
        .expect("validate");
        assert!(valid, "code from T-1 step should be valid within ±1 window");
    }

    #[test]
    fn validate_totp_accepts_next_step() {
        let secret = b"12345678901234567890";
        let time = 1_234_567_890u64;
        // Generate code at T+period, validate at T (so generated code is T+1 relative to validation).
        let code = generate_totp(
            secret,
            time.wrapping_add(30),
            OtpDigits::Six,
            30,
            OtpAlgorithm::Sha1,
        )
        .expect("generate");
        let valid = validate_totp(secret, time, &code, OtpDigits::Six, 30, OtpAlgorithm::Sha1)
            .expect("validate");
        assert!(valid, "code from T+1 step should be valid within ±1 window");
    }

    #[test]
    fn validate_totp_rejects_two_steps_away() {
        let secret = b"12345678901234567890";
        let time = 1_234_567_890u64;
        let code =
            generate_totp(secret, time, OtpDigits::Six, 30, OtpAlgorithm::Sha1).expect("generate");
        // Validate at T+2*period (2 steps ahead).
        let valid = validate_totp(
            secret,
            time.wrapping_add(60),
            &code,
            OtpDigits::Six,
            30,
            OtpAlgorithm::Sha1,
        )
        .expect("validate");
        assert!(!valid, "code from T-2 steps should be rejected");
    }

    #[test]
    fn validate_totp_rejects_two_steps_behind() {
        let secret = b"12345678901234567890";
        let time = 1_234_567_890u64;
        // Generate code at T+2*period, validate at T.
        let code = generate_totp(
            secret,
            time.wrapping_add(60),
            OtpDigits::Six,
            30,
            OtpAlgorithm::Sha1,
        )
        .expect("generate");
        let valid = validate_totp(secret, time, &code, OtpDigits::Six, 30, OtpAlgorithm::Sha1)
            .expect("validate");
        assert!(!valid, "code from T+2 steps should be rejected");
    }

    // ── Digit length tests ──────────────────────────────────────────

    #[test]
    fn six_digit_output_length() {
        let code =
            generate_hotp(b"secret", 0, OtpDigits::Six, OtpAlgorithm::Sha1).expect("generate");
        assert_eq!(code.len(), 6, "6-digit code should have length 6");
    }

    #[test]
    fn eight_digit_output_length() {
        let code =
            generate_hotp(b"secret", 0, OtpDigits::Eight, OtpAlgorithm::Sha1).expect("generate");
        assert_eq!(code.len(), 8, "8-digit code should have length 8");
    }

    #[test]
    fn leading_zeros_preserved() {
        // Find a counter that produces leading zeros for this secret.
        // We brute-force a few to find one; if none in 10000, skip.
        let secret = b"12345678901234567890";
        let mut found_leading_zero = false;
        for counter in 0u64..10_000 {
            let code = generate_hotp(secret, counter, OtpDigits::Six, OtpAlgorithm::Sha1)
                .expect("generate");
            if code.starts_with('0') {
                assert_eq!(code.len(), 6, "leading-zero code must still be 6 chars");
                found_leading_zero = true;
                break;
            }
        }
        assert!(
            found_leading_zero,
            "should find at least one leading-zero code in 10000 iterations"
        );
    }

    // ── Error handling tests ────────────────────────────────────────

    #[test]
    fn empty_secret_returns_error() {
        let result = generate_hotp(&[], 0, OtpDigits::Six, OtpAlgorithm::Sha1);
        assert!(
            matches!(result, Err(CryptoError::Otp(_))),
            "empty secret should yield CryptoError::Otp, got: {result:?}"
        );
    }

    #[test]
    fn period_zero_returns_error() {
        let result = generate_totp(b"secret", 1_000_000, OtpDigits::Six, 0, OtpAlgorithm::Sha1);
        assert!(
            matches!(result, Err(CryptoError::Otp(_))),
            "period=0 should yield CryptoError::Otp, got: {result:?}"
        );
    }

    #[test]
    fn validate_totp_period_zero_returns_error() {
        let result = validate_totp(
            b"secret",
            1_000_000,
            "123456",
            OtpDigits::Six,
            0,
            OtpAlgorithm::Sha1,
        );
        assert!(
            matches!(result, Err(CryptoError::Otp(_))),
            "validate with period=0 should yield CryptoError::Otp, got: {result:?}"
        );
    }

    // ── Edge case: time=0 ─────────────────────────────────────────

    #[test]
    fn validate_totp_at_time_zero() {
        let secret = b"12345678901234567890";
        // time=0, period=30 → time_step=0. Window should check steps 0 and 1 only (not u64::MAX).
        let code = generate_totp(secret, 0, OtpDigits::Six, 30, OtpAlgorithm::Sha1)
            .expect("generate at time 0");
        let valid = validate_totp(secret, 0, &code, OtpDigits::Six, 30, OtpAlgorithm::Sha1)
            .expect("validate at time 0");
        assert!(valid, "code at time 0 should be valid");
    }

    // ── Edge case: wrong-length code ────────────────────────────────

    #[test]
    fn validate_totp_rejects_wrong_length_code() {
        let secret = b"12345678901234567890";
        let time = 1_234_567_890u64;
        // 5-digit code when expecting 6 digits.
        let valid = validate_totp(
            secret,
            time,
            "12345",
            OtpDigits::Six,
            30,
            OtpAlgorithm::Sha1,
        )
        .expect("validate");
        assert!(!valid, "wrong-length code should be rejected");
    }

    // ── Algorithm differentiation ───────────────────────────────────

    #[test]
    fn different_algorithms_produce_different_codes() {
        let secret = b"12345678901234567890123456789012345678901234567890123456789012345678";
        let time = 1_234_567_890u64;

        let sha1 =
            generate_totp(secret, time, OtpDigits::Six, 30, OtpAlgorithm::Sha1).expect("sha1");
        let sha256 =
            generate_totp(secret, time, OtpDigits::Six, 30, OtpAlgorithm::Sha256).expect("sha256");
        let sha512 =
            generate_totp(secret, time, OtpDigits::Six, 30, OtpAlgorithm::Sha512).expect("sha512");

        // At least two should differ (extremely unlikely all three match by chance).
        let all_same = sha1 == sha256 && sha256 == sha512;
        assert!(
            !all_same,
            "different algorithms should produce different codes: SHA1={sha1}, SHA256={sha256}, SHA512={sha512}"
        );
    }

    // ── Performance test ────────────────────────────────────────────

    #[test]
    fn performance_under_10ms_per_code() {
        let secret = b"12345678901234567890";
        let start = std::time::Instant::now();
        for i in 0u64..1_000 {
            let _ = generate_totp(
                secret,
                i.wrapping_mul(30),
                OtpDigits::Six,
                30,
                OtpAlgorithm::Sha1,
            );
        }
        let elapsed = start.elapsed();
        // 1000 codes should complete well under 10 seconds (10ms each).
        assert!(
            elapsed.as_secs() < 10,
            "1000 TOTP generations took {elapsed:?}, expected < 10s"
        );
    }
}
