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

/// Absolute maximum Argon2id memory cost in KiB (4 GiB).
///
/// Upper bound enforced by [`derive`] so an untrusted or tampered vault header
/// (e.g. a malicious `.verrou` import) cannot request an allocation so large
/// that the process aborts on OOM — a denial of service. Legitimate presets
/// top out at 512 MiB, far below this ceiling.
const MAX_M_COST: u32 = 4_194_304;

/// Maximum Argon2id iterations accepted by [`derive`] / chosen by calibration.
const MAX_T_COST: u32 = 64;

/// Maximum Argon2id parallelism (lanes) accepted by [`derive`].
const MAX_P_COST: u32 = 16;

/// Iteration floor — calibration never drops below the architecture baseline.
const MIN_T_COST: u32 = 2;

/// Per-tier calibration targets in milliseconds — midpoints of the documented
/// ranges (Fast ~1 s, Balanced ~1.5–2 s, Maximum ~3–4 s).
const TARGET_FAST_MS: u128 = 1_000;
const TARGET_BALANCED_MS: u128 = 1_750;
const TARGET_MAXIMUM_MS: u128 = 3_500;

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

    // Reject out-of-range parameters before handing them to argon2. The upper
    // memory bound prevents a tampered header / untrusted import from forcing
    // a multi-terabyte allocation that aborts the process (DoS).
    validate_params(params)?;

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

/// Validate Argon2id parameters against VERROU's accepted ranges.
///
/// Enforces an **upper** bound so a tampered vault header or a malicious
/// `.verrou` import cannot request an allocation large enough to abort the
/// process on OOM. The lower memory bound is a vault-creation *policy* and is
/// deliberately NOT enforced here, so fast unit tests can use small parameters.
///
/// # Errors
///
/// Returns [`CryptoError::KeyDerivation`] if any parameter is out of range.
fn validate_params(p: &Argon2idParams) -> Result<(), CryptoError> {
    if p.m_cost > MAX_M_COST
        || !(1..=MAX_T_COST).contains(&p.t_cost)
        || !(1..=MAX_P_COST).contains(&p.p_cost)
    {
        return Err(CryptoError::KeyDerivation(format!(
            "argon2 params out of allowed range: m_cost={} (max {MAX_M_COST}), \
             t_cost={} (1..={MAX_T_COST}), p_cost={} (1..={MAX_P_COST})",
            p.m_cost, p.t_cost, p.p_cost
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Calibration
// ---------------------------------------------------------------------------

/// Benchmark the current hardware and return achievable Argon2id presets.
///
/// First finds the achievable memory ceiling (512 MB → 256 MB → 128 MB) by
/// trial allocation, then **times a real derivation** at that memory and picks
/// the iteration count (`t_cost`) so each tier approximates its target unlock
/// duration (Fast ~1 s, Balanced ~1.75 s, Maximum ~3.5 s). Argon2id runtime is
/// linear in `t_cost`, so a single-iteration probe extrapolates accurately.
///
/// This is genuine timing calibration: on fast hardware the iteration count
/// rises to keep per-guess brute-force cost near the target; on slow hardware
/// it falls (clamped to a floor) so unlock stays usable.
///
/// # Errors
///
/// Returns `CryptoError::KeyDerivation` if even 128 MB calibration fails.
pub fn calibrate() -> Result<CalibratedPresets, CryptoError> {
    // Determine the achievable memory ceiling by testing allocation.
    let achievable_memory = find_achievable_memory()?;

    // Time a real derivation at each tier's memory and pick t_cost for the
    // target duration. The Fast tier caps memory at 256 MB per the spec.
    let fast_memory = core::cmp::min(achievable_memory, MEMORY_256MB);
    let fast = calibrate_tier(fast_memory, TARGET_FAST_MS)?;
    let balanced = calibrate_tier(achievable_memory, TARGET_BALANCED_MS)?;
    let maximum = calibrate_tier(achievable_memory, TARGET_MAXIMUM_MS)?;

    Ok(CalibratedPresets {
        fast,
        balanced,
        maximum,
    })
}

/// Calibrate one tier by timing a single-iteration derivation and scaling
/// `t_cost` toward `target_ms`.
///
/// Because Argon2id time is ~linear in `t_cost`, `t ≈ target / per_iteration`.
/// The result is clamped to `[MIN_T_COST, MAX_T_COST]`. Uses checked arithmetic
/// to satisfy the workspace `arithmetic_side_effects = deny` lint.
///
/// # Errors
///
/// Returns `CryptoError::KeyDerivation` if the probe derivation fails.
fn calibrate_tier(m_cost: u32, target_ms: u128) -> Result<Argon2idParams, CryptoError> {
    let probe = Argon2idParams {
        m_cost,
        t_cost: 1,
        p_cost: 4,
    };

    let start = std::time::Instant::now();
    let probe_key = derive(
        b"verrou-calibration-probe",
        b"verrou-calibration-salt",
        &probe,
    )?;
    drop(probe_key);
    let per_iteration_ms = start.elapsed().as_millis().max(1);

    // per_iteration_ms is >= 1, so checked_div never returns None; the fallback
    // is bound in a local to keep it out of `unwrap_or` (clippy `or_fun_call`).
    let max_t = u128::from(MAX_T_COST);
    let estimated = target_ms.checked_div(per_iteration_ms).unwrap_or(max_t);
    let t_cost = u32::try_from(estimated)
        .unwrap_or(MAX_T_COST)
        .clamp(MIN_T_COST, MAX_T_COST);

    Ok(Argon2idParams {
        m_cost,
        t_cost,
        p_cost: 4,
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
    fn derive_rejects_oversized_m_cost() {
        // F2: an untrusted header requesting a multi-terabyte allocation must be
        // rejected up front, not handed to argon2 (which would abort on OOM).
        let params = Argon2idParams {
            m_cost: u32::MAX,
            t_cost: 2,
            p_cost: 4,
        };
        let err =
            derive(b"password", TEST_SALT, &params).expect_err("oversized m_cost must be rejected");
        assert!(
            format!("{err}").contains("out of allowed range"),
            "error should mention the range violation"
        );
    }

    #[test]
    fn derive_rejects_zero_t_cost() {
        let params = Argon2idParams {
            m_cost: 32,
            t_cost: 0,
            p_cost: 1,
        };
        assert!(derive(b"password", TEST_SALT, &params).is_err());
    }

    #[test]
    fn validate_params_accepts_all_presets() {
        for preset in [KdfPreset::Fast, KdfPreset::Balanced, KdfPreset::Maximum] {
            assert!(validate_params(&preset.default_params()).is_ok());
        }
    }

    #[test]
    fn calibrate_produces_valid_tiers() {
        // F1: calibration must return in-range params with iterations within the
        // calibrated floor/ceiling, and Fast memory must not exceed Balanced.
        let presets = calibrate().expect("calibration should succeed");
        for p in [&presets.fast, &presets.balanced, &presets.maximum] {
            assert!(
                validate_params(p).is_ok(),
                "calibrated params invalid: {p:?}"
            );
            assert!(p.t_cost >= MIN_T_COST && p.t_cost <= MAX_T_COST);
        }
        assert!(presets.fast.m_cost <= presets.balanced.m_cost);
        assert_eq!(presets.balanced.m_cost, presets.maximum.m_cost);
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
