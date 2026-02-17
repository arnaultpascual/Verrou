//! RFC 6238 TOTP and RFC 4226 HOTP Known Answer Test vectors.

use verrou_crypto_core::totp::{generate_hotp, generate_totp, OtpAlgorithm, OtpDigits};

// ── RFC 4226 Appendix D — HOTP test vectors ────────────────────────
// Secret: "12345678901234567890" (ASCII, 20 bytes)
// Algorithm: SHA1, Digits: 6
const HOTP_SECRET: &[u8] = b"12345678901234567890";

const HOTP_EXPECTED: [(u64, &str); 10] = [
    (0, "755224"),
    (1, "287082"),
    (2, "359152"),
    (3, "969429"),
    (4, "338314"),
    (5, "254676"),
    (6, "287922"),
    (7, "162583"),
    (8, "399871"),
    (9, "520489"),
];

#[test]
fn rfc4226_appendix_d_hotp_sha1() {
    for (counter, expected) in &HOTP_EXPECTED {
        let code = generate_hotp(HOTP_SECRET, *counter, OtpDigits::Six, OtpAlgorithm::Sha1)
            .expect("HOTP generation should succeed");
        assert_eq!(
            &code, expected,
            "RFC 4226 HOTP mismatch at counter {counter}"
        );
    }
}

// ── RFC 6238 Appendix B — TOTP test vectors ────────────────────────
// SHA1 secret:   20 bytes ("12345678901234567890")
// SHA256 secret: 32 bytes ("12345678901234567890123456789012")
// SHA512 secret: 64 bytes
// Period: 30s, Digits: 8

const TOTP_SHA1_SECRET: &[u8] = b"12345678901234567890";
const TOTP_SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
const TOTP_SHA512_SECRET: &[u8] =
    b"1234567890123456789012345678901234567890123456789012345678901234";

struct TotpVector {
    time: u64,
    sha1: &'static str,
    sha256: &'static str,
    sha512: &'static str,
}

const TOTP_VECTORS: [TotpVector; 6] = [
    TotpVector {
        time: 59,
        sha1: "94287082",
        sha256: "46119246",
        sha512: "90693936",
    },
    TotpVector {
        time: 1_111_111_109,
        sha1: "07081804",
        sha256: "68084774",
        sha512: "25091201",
    },
    TotpVector {
        time: 1_111_111_111,
        sha1: "14050471",
        sha256: "67062674",
        sha512: "99943326",
    },
    TotpVector {
        time: 1_234_567_890,
        sha1: "89005924",
        sha256: "91819424",
        sha512: "93441116",
    },
    TotpVector {
        time: 2_000_000_000,
        sha1: "69279037",
        sha256: "90698825",
        sha512: "38618901",
    },
    TotpVector {
        time: 20_000_000_000,
        sha1: "65353130",
        sha256: "77737706",
        sha512: "47863826",
    },
];

#[test]
fn rfc6238_appendix_b_totp_sha1() {
    for v in &TOTP_VECTORS {
        let code = generate_totp(
            TOTP_SHA1_SECRET,
            v.time,
            OtpDigits::Eight,
            30,
            OtpAlgorithm::Sha1,
        )
        .expect("TOTP generation should succeed");
        assert_eq!(
            &code, v.sha1,
            "RFC 6238 TOTP SHA1 mismatch at time {}",
            v.time
        );
    }
}

#[test]
fn rfc6238_appendix_b_totp_sha256() {
    for v in &TOTP_VECTORS {
        let code = generate_totp(
            TOTP_SHA256_SECRET,
            v.time,
            OtpDigits::Eight,
            30,
            OtpAlgorithm::Sha256,
        )
        .expect("TOTP generation should succeed");
        assert_eq!(
            &code, v.sha256,
            "RFC 6238 TOTP SHA256 mismatch at time {}",
            v.time
        );
    }
}

#[test]
fn rfc6238_appendix_b_totp_sha512() {
    for v in &TOTP_VECTORS {
        let code = generate_totp(
            TOTP_SHA512_SECRET,
            v.time,
            OtpDigits::Eight,
            30,
            OtpAlgorithm::Sha512,
        )
        .expect("TOTP generation should succeed");
        assert_eq!(
            &code, v.sha512,
            "RFC 6238 TOTP SHA512 mismatch at time {}",
            v.time
        );
    }
}
