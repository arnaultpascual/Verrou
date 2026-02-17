//! Entropy quality tests for CSPRNG outputs (Layer 4).
//!
//! Validates that `SecretBuffer::random()` and `SecretBytes::random()` produce
//! output with Shannon entropy appropriate for their sample size. This serves
//! as a smoke test that the underlying CSPRNG (`OsRng`) is functioning correctly
//! and not producing degenerate output.
//!
//! **Statistical context:** Shannon entropy for truly random bytes approaches
//! 8.0 bits/byte asymptotically as sample size → ∞. For finite samples, the
//! birthday problem reduces measured entropy because not all 256 byte values
//! appear. Expected values for uniform random data:
//!
//! | Sample size | Expected entropy | Min (p=0.01) | Our threshold |
//! |-------------|-----------------|--------------|---------------|
//! | 32 bytes    | ~4.88           | ~4.62        | 4.0           |
//! | 64 bytes    | ~5.75           | ~5.55        | 5.0           |
//! | 1 KB        | ~7.81           | ~7.76        | 7.5           |
//! | 64 KB       | ~7.997          | ~7.996       | 7.99          |
//!
//! The AC threshold of "> 7.99" applies to the 64KB vault padding size, which
//! is the architecturally significant sample. Smaller samples use relaxed
//! thresholds calibrated to detect degenerate CSPRNG output (all-zeros,
//! repeated patterns) while avoiding false positives from natural variance.

use verrou_crypto_core::memory::{SecretBuffer, SecretBytes};

/// Shannon entropy of a byte slice (bits per byte).
///
/// H = -Σ p(x) * log2(p(x)) for each byte value x in [0, 255]
/// Maximum = 8.0 for uniformly distributed bytes.
///
/// Note: Also defined in `vault_format.rs` tests. Intentionally duplicated
/// rather than shared — both are `#[cfg(test)]`-only, and a 15-line helper
/// doesn't warrant a shared test utility module.
#[allow(clippy::cast_precision_loss)]
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] = freq[b as usize].saturating_add(1);
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// 1 KB random buffer — threshold 7.5 bits/byte.
///
/// At 1024 bytes, expected Shannon entropy for truly random data is ~7.81.
/// We use 7.5 as the threshold to avoid false positives while catching
/// obviously broken CSPRNG output.
#[test]
fn secret_buffer_random_1kb_entropy() {
    let buf = SecretBuffer::random(1024).expect("CSPRNG should succeed");
    let entropy = shannon_entropy(buf.expose());
    assert!(
        entropy > 7.5,
        "SecretBuffer::random(1024) entropy too low: {entropy:.4} (expected > 7.5)"
    );
}

/// 64 KB random buffer — AC threshold > 7.99 bits/byte.
///
/// This is the architecturally significant sample size (vault padding).
/// At 65,536 bytes, expected entropy is ~7.997, so > 7.99 is reliable.
#[test]
fn secret_buffer_random_64kb_entropy() {
    let buf = SecretBuffer::random(65536).expect("CSPRNG should succeed");
    let entropy = shannon_entropy(buf.expose());
    assert!(
        entropy > 7.99,
        "SecretBuffer::random(65536) entropy too low: {entropy:.4} (expected > 7.99)"
    );
}

/// 32-byte key — threshold 4.0 bits/byte.
///
/// With only 32 bytes, even truly random data averages ~4.88 bits/byte
/// entropy (birthday problem: most of 256 byte values won't appear).
/// The 4.0 threshold catches degenerate output (all-zeros = 0.0 entropy,
/// repeated byte = 0.0 entropy) while passing legitimate random keys.
#[test]
fn secret_bytes_32_random_entropy() {
    let key = SecretBytes::<32>::random().expect("CSPRNG should succeed");
    let entropy = shannon_entropy(key.expose());
    assert!(
        entropy > 4.0,
        "SecretBytes::<32>::random() entropy too low: {entropy:.4} (expected > 4.0)"
    );
}

/// 64-byte key — threshold 5.0 bits/byte.
///
/// At 64 bytes, expected entropy is ~5.75. Threshold of 5.0 catches
/// degenerate output while accommodating natural variance.
#[test]
fn secret_bytes_64_random_entropy() {
    let key = SecretBytes::<64>::random().expect("CSPRNG should succeed");
    let entropy = shannon_entropy(key.expose());
    assert!(
        entropy > 5.0,
        "SecretBytes::<64>::random() entropy too low: {entropy:.4} (expected > 5.0)"
    );
}

/// Two consecutive random buffers must be distinct.
///
/// The probability of collision for 256 random bytes is 2^(-2048),
/// effectively zero. If this test fails, the CSPRNG is broken.
#[test]
fn csprng_produces_distinct_outputs() {
    let a = SecretBuffer::random(256).expect("CSPRNG should succeed");
    let b = SecretBuffer::random(256).expect("CSPRNG should succeed");
    assert_ne!(
        a.expose(),
        b.expose(),
        "Two consecutive SecretBuffer::random() calls produced identical output — CSPRNG may be broken"
    );
}
