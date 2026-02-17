//! Integration tests for Argon2id hardware calibration.
//!
//! These tests verify that `calibrate()` produces valid, achievable
//! parameters on the current hardware without panicking.

use verrou_crypto_core::kdf::{calibrate, derive};

/// Minimum acceptable memory in KiB (128 MB).
const MIN_MEMORY_KIB: u32 = 131_072;

#[test]
fn calibrate_succeeds_on_current_hardware() {
    let presets = calibrate().expect("calibrate should succeed on any reasonable hardware");

    // All presets should have valid parameters.
    assert!(presets.fast.m_cost > 0, "fast m_cost should be positive");
    assert!(presets.fast.t_cost > 0, "fast t_cost should be positive");
    assert!(presets.fast.p_cost > 0, "fast p_cost should be positive");

    assert!(
        presets.balanced.m_cost > 0,
        "balanced m_cost should be positive"
    );
    assert!(
        presets.balanced.t_cost > 0,
        "balanced t_cost should be positive"
    );

    assert!(
        presets.maximum.m_cost > 0,
        "maximum m_cost should be positive"
    );
    assert!(
        presets.maximum.t_cost > 0,
        "maximum t_cost should be positive"
    );
}

#[test]
fn calibrated_presets_meet_minimum_memory() {
    let presets = calibrate().expect("calibrate should succeed");

    // All presets should use at least the minimum memory.
    assert!(
        presets.fast.m_cost >= MIN_MEMORY_KIB,
        "fast preset memory ({} KiB) below minimum ({MIN_MEMORY_KIB} KiB)",
        presets.fast.m_cost
    );
    assert!(
        presets.balanced.m_cost >= MIN_MEMORY_KIB,
        "balanced preset memory ({} KiB) below minimum ({MIN_MEMORY_KIB} KiB)",
        presets.balanced.m_cost
    );
    assert!(
        presets.maximum.m_cost >= MIN_MEMORY_KIB,
        "maximum preset memory ({} KiB) below minimum ({MIN_MEMORY_KIB} KiB)",
        presets.maximum.m_cost
    );
}

#[test]
fn calibrated_presets_are_derivable() {
    let presets = calibrate().expect("calibrate should succeed");
    let salt = b"integration_test_";

    // Each calibrated preset should actually work for derivation.
    let key_fast = derive(b"test_password", salt, &presets.fast);
    assert!(key_fast.is_ok(), "fast preset should be derivable");

    let key_balanced = derive(b"test_password", salt, &presets.balanced);
    assert!(key_balanced.is_ok(), "balanced preset should be derivable");

    let key_maximum = derive(b"test_password", salt, &presets.maximum);
    assert!(key_maximum.is_ok(), "maximum preset should be derivable");
}

#[test]
fn maximum_iterations_at_least_balanced() {
    let presets = calibrate().expect("calibrate should succeed");

    // Maximum tier should have >= iterations compared to balanced.
    assert!(
        presets.maximum.t_cost >= presets.balanced.t_cost,
        "maximum t_cost ({}) should be >= balanced t_cost ({})",
        presets.maximum.t_cost,
        presets.balanced.t_cost,
    );
}
