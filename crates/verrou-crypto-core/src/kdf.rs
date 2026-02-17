//! Argon2id key derivation with tiered presets.
//!
//! This module provides:
//! - [`derive`] — derive a 256-bit key from a password + salt using Argon2id
//! - [`calibrate`] — benchmark hardware and return achievable presets
//! - [`Argon2idParams`] — serializable parameter set (stored in vault header)
//! - [`KdfPreset`] — Fast / Balanced / Maximum preset selector
//!
//! # Tiered KDF Philosophy
//!
//! - **Session unlock** uses the user's chosen preset (`session_params`)
//! - **Sensitive operations** always use Maximum tier (`sensitive_params`)
//! - Both parameter sets are calibrated at vault creation, stored in the vault header

use crate::error::CryptoError;
use crate::memory::SecretBuffer;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Output length of the KDF in bytes (256 bits).
const OUTPUT_LEN: usize = 32;

/// Minimum salt length in bytes. We enforce 16 (stricter than argon2's 8).
const MIN_SALT_LEN: usize = 16;

/// 512 MB in KiB.
const MEMORY_512MB: u32 = 524_288;

/// 256 MB in KiB.
const MEMORY_256MB: u32 = 262_144;

/// 128 MB in KiB — absolute minimum for VERROU.
const MEMORY_128MB: u32 = 131_072;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Argon2id parameter set — stored in the vault header.
///
/// Fields use the `argon2` crate convention:
/// - `m_cost`: memory in KiB (NOT bytes, NOT MB)
/// - `t_cost`: number of iterations
/// - `p_cost`: degree of parallelism
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2idParams {
    /// Memory cost in kibibytes (1 KiB = 1024 bytes).
    /// 256 MB = `262_144`, 512 MB = `524_288`, 128 MB = `131_072`.
    pub m_cost: u32,
    /// Number of iterations (time cost).
    pub t_cost: u32,
    /// Degree of parallelism (number of lanes).
    pub p_cost: u32,
}

/// KDF preset selector.
///
/// Each preset has default (uncalibrated) parameters from the architecture
/// specification. Use [`calibrate`] to get hardware-adapted versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfPreset {
    /// Quick access, modest hardware (~1s target).
    Fast,
    /// Recommended daily driver (~1.5-2s target).
    Balanced,
    /// Maximum security / sensitive operations (~3-4s target).
    Maximum,
}

impl KdfPreset {
    /// Return the default (uncalibrated) parameters for this preset.
    ///
    /// These are the architecture-specified defaults before hardware
    /// calibration adjusts them.
    #[must_use]
    pub const fn default_params(self) -> Argon2idParams {
        match self {
            Self::Fast => Argon2idParams {
                m_cost: MEMORY_256MB,
                t_cost: 2,
                p_cost: 4,
            },
            Self::Balanced => Argon2idParams {
                m_cost: MEMORY_512MB,
                t_cost: 3,
                p_cost: 4,
            },
            Self::Maximum => Argon2idParams {
                m_cost: MEMORY_512MB,
                t_cost: 4,
                p_cost: 4,
            },
        }
    }
}

/// Result of hardware calibration — achievable parameters for all 3 presets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
pub struct CalibratedPresets {
    /// Fast preset (~1s target).
    pub fast: Argon2idParams,
    /// Balanced preset (~1.5-2s target).
    pub balanced: Argon2idParams,
    /// Maximum preset (~3-4s target).
    pub maximum: Argon2idParams,
}

// ---------------------------------------------------------------------------
// Core KDF
// ---------------------------------------------------------------------------

/// Derive a 256-bit key from a password and salt using Argon2id.
///
/// Returns a [`SecretBuffer`] containing 32 bytes. The intermediate buffer
/// is zeroized after copying into the `SecretBuffer`.
///
/// # Password Validation
///
/// This function accepts any password length, including empty. Password
/// strength validation (minimum length, complexity) must be enforced by the
/// caller (vault layer) before reaching this function.
///
/// # Errors
///
/// Returns `CryptoError::KeyDerivation` if:
/// - The salt is shorter than 16 bytes
/// - The argon2 parameters are invalid
/// - The derivation itself fails (e.g., memory allocation)
pub fn derive(
    password: &[u8],
    salt: &[u8],
    params: &Argon2idParams,
) -> Result<SecretBuffer, CryptoError> {
    if salt.len() < MIN_SALT_LEN {
        return Err(CryptoError::KeyDerivation(format!(
            "salt too short: {} bytes (minimum {MIN_SALT_LEN})",
            salt.len()
        )));
    }

    let argon2_params = argon2::Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(OUTPUT_LEN),
    )
    .map_err(|e| CryptoError::KeyDerivation(format!("invalid argon2 params: {e}")))?;

    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = [0u8; OUTPUT_LEN];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::KeyDerivation(format!("argon2id derivation failed: {e}")))?;

    let result = SecretBuffer::new(&output)
        .map_err(|e| CryptoError::KeyDerivation(format!("secure buffer allocation failed: {e}")))?;
    output.zeroize();
    Ok(result)
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

/// Benchmark the current hardware and return achievable Argon2id presets.
///
/// Attempts the highest memory tier first (512 MB), cascading down to 256 MB
/// and 128 MB if allocation fails. Iterations are compensated when memory is
/// reduced to maintain equivalent brute-force resistance.
///
/// # Errors
///
/// Returns `CryptoError::KeyDerivation` if even 128 MB calibration fails.
pub fn calibrate() -> Result<CalibratedPresets, CryptoError> {
    // Determine the achievable memory ceiling by testing allocation.
    let achievable_memory = find_achievable_memory()?;

    // Build presets scaled to achievable memory.
    // Iteration compensation: scale_iterations() doubles iterations when memory is halved.
    let fast = Argon2idParams {
        m_cost: core::cmp::min(achievable_memory, MEMORY_256MB),
        t_cost: scale_iterations(
            2,
            MEMORY_256MB,
            core::cmp::min(achievable_memory, MEMORY_256MB),
        ),
        p_cost: 4,
    };

    let balanced = Argon2idParams {
        m_cost: achievable_memory,
        t_cost: scale_iterations(3, MEMORY_512MB, achievable_memory),
        p_cost: 4,
    };

    let maximum = Argon2idParams {
        m_cost: achievable_memory,
        t_cost: scale_iterations(4, MEMORY_512MB, achievable_memory),
        p_cost: 4,
    };

    Ok(CalibratedPresets {
        fast,
        balanced,
        maximum,
    })
}

/// Attempt trial allocations to find the highest achievable memory tier.
///
/// Returns the achievable `m_cost` in KiB. Tries 512 MB first, cascading
/// to 256 MB and 128 MB. Iteration compensation is handled by the caller
/// via [`scale_iterations`].
fn find_achievable_memory() -> Result<u32, CryptoError> {
    // Try 512 MB first.
    if try_allocation(MEMORY_512MB) {
        return Ok(MEMORY_512MB);
    }

    // Fall back to 256 MB.
    if try_allocation(MEMORY_256MB) {
        return Ok(MEMORY_256MB);
    }

    // Fall back to 128 MB.
    if try_allocation(MEMORY_128MB) {
        return Ok(MEMORY_128MB);
    }

    Err(CryptoError::KeyDerivation(
        "calibration failed: unable to allocate even 128 MB for Argon2id".into(),
    ))
}

/// Test whether argon2 can allocate the given memory for a trial derivation.
///
/// Uses `catch_unwind` to handle OOM panics gracefully.
fn try_allocation(m_cost_kib: u32) -> bool {
    let result = std::panic::catch_unwind(|| {
        let Ok(params) = argon2::Params::new(m_cost_kib, 1, 4, Some(OUTPUT_LEN)) else {
            return false;
        };
        let argon2 =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; OUTPUT_LEN];
        let dummy_password = b"calibration_probe";
        let dummy_salt = b"calibration_salt_16b";
        let ok = argon2
            .hash_password_into(dummy_password, dummy_salt, &mut out)
            .is_ok();
        out.zeroize();
        ok
    });

    result.unwrap_or(false)
}

/// Scale iterations when memory is reduced.
///
/// When memory is halved, double the iterations to compensate.
const fn scale_iterations(base_t_cost: u32, target_memory: u32, actual_memory: u32) -> u32 {
    if actual_memory >= target_memory || actual_memory == 0 {
        return base_t_cost;
    }
    // ratio = target / actual (e.g., 512/256 = 2, 512/128 = 4)
    // We guard against actual_memory == 0 above, so this division is safe.
    #[allow(clippy::arithmetic_side_effects)]
    let ratio = target_memory / actual_memory;
    base_t_cost.saturating_mul(ratio)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Small params for fast tests — 32 KiB, 1 iteration, 1 lane.
    const TEST_PARAMS: Argon2idParams = Argon2idParams {
        m_cost: 32,
        t_cost: 1,
        p_cost: 1,
    };

    const TEST_SALT: &[u8; 16] = b"0123456789abcdef";

    #[test]
    fn derive_produces_32_byte_output() {
        let key = derive(b"password", TEST_SALT, &TEST_PARAMS).expect("derive should succeed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn derive_is_deterministic() {
        let a = derive(b"password", TEST_SALT, &TEST_PARAMS).expect("derive should succeed");
        let b = derive(b"password", TEST_SALT, &TEST_PARAMS).expect("derive should succeed");
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn derive_different_salts_produce_different_keys() {
        let a = derive(b"password", b"salt_aaaaaaaaaaaaa", &TEST_PARAMS)
            .expect("derive should succeed");
        let b = derive(b"password", b"salt_bbbbbbbbbbbbb", &TEST_PARAMS)
            .expect("derive should succeed");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn derive_different_passwords_produce_different_keys() {
        let a = derive(b"password_a", TEST_SALT, &TEST_PARAMS).expect("derive should succeed");
        let b = derive(b"password_b", TEST_SALT, &TEST_PARAMS).expect("derive should succeed");
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn derive_rejects_short_salt() {
        let err = derive(b"password", b"short", &TEST_PARAMS)
            .expect_err("derive should reject short salt");
        let msg = format!("{err}");
        assert!(msg.contains("salt too short"));
    }

    #[test]
    fn derive_output_is_secret_buffer() {
        let key = derive(b"test", TEST_SALT, &TEST_PARAMS).expect("derive should succeed");
        // Verify it's a SecretBuffer by calling expose() and checking length.
        assert_eq!(key.expose().len(), 32);
        // Debug output should be masked.
        let debug = format!("{key:?}");
        assert_eq!(debug, "SecretBuffer(***)");
    }

    #[test]
    fn kdf_preset_default_params_fast() {
        let p = KdfPreset::Fast.default_params();
        assert_eq!(p.m_cost, 262_144); // 256 MB
        assert_eq!(p.t_cost, 2);
        assert_eq!(p.p_cost, 4);
    }

    #[test]
    fn kdf_preset_default_params_balanced() {
        let p = KdfPreset::Balanced.default_params();
        assert_eq!(p.m_cost, 524_288); // 512 MB
        assert_eq!(p.t_cost, 3);
        assert_eq!(p.p_cost, 4);
    }

    #[test]
    fn kdf_preset_default_params_maximum() {
        let p = KdfPreset::Maximum.default_params();
        assert_eq!(p.m_cost, 524_288); // 512 MB
        assert_eq!(p.t_cost, 4);
        assert_eq!(p.p_cost, 4);
    }

    #[test]
    fn argon2id_params_serde_roundtrip() {
        let params = Argon2idParams {
            m_cost: 262_144,
            t_cost: 3,
            p_cost: 4,
        };
        let json = serde_json::to_string(&params).expect("serialize should succeed");
        let deserialized: Argon2idParams =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(params, deserialized);
    }

    #[test]
    fn scale_iterations_no_reduction() {
        assert_eq!(scale_iterations(3, MEMORY_512MB, MEMORY_512MB), 3);
    }

    #[test]
    fn scale_iterations_half_memory() {
        assert_eq!(scale_iterations(3, MEMORY_512MB, MEMORY_256MB), 6);
    }

    #[test]
    fn scale_iterations_quarter_memory() {
        assert_eq!(scale_iterations(3, MEMORY_512MB, MEMORY_128MB), 12);
    }

    #[test]
    fn kdf_preset_serde_roundtrip() {
        for preset in [KdfPreset::Fast, KdfPreset::Balanced, KdfPreset::Maximum] {
            let json = serde_json::to_string(&preset).expect("serialize should succeed");
            let deserialized: KdfPreset =
                serde_json::from_str(&json).expect("deserialize should succeed");
            assert_eq!(preset, deserialized);
        }
    }

    #[test]
    fn calibrated_presets_serde_roundtrip() {
        let presets = CalibratedPresets {
            fast: Argon2idParams {
                m_cost: 262_144,
                t_cost: 2,
                p_cost: 4,
            },
            balanced: Argon2idParams {
                m_cost: 524_288,
                t_cost: 3,
                p_cost: 4,
            },
            maximum: Argon2idParams {
                m_cost: 524_288,
                t_cost: 4,
                p_cost: 4,
            },
        };
        let json = serde_json::to_string(&presets).expect("serialize should succeed");
        let deserialized: CalibratedPresets =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(presets, deserialized);
    }
}
