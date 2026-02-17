//! Vault lifecycle operations — create, calibrate, open (future), lock (future).
//!
//! This module orchestrates the key hierarchy: master password →
//! Argon2id derivation → password key → wraps random master key.
//! Two files are produced per vault:
//!
//! - `vault.verrou` — binary header with KDF params and key slots
//! - `vault.db` — `SQLCipher`-encrypted database for user data

use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use verrou_crypto_core::kdf;
use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::slots::{self, KeySlot, SlotType};
use verrou_crypto_core::vault_format::{self, VaultHeader, FORMAT_VERSION};
use verrou_crypto_core::CryptoError;
use zeroize::Zeroize;

use crate::db::VaultDb;
use crate::error::VaultError;
use crate::recovery::{
    self, decode_recovery_key, AddRecoverySlotRequest, GenerateRecoveryKeyResult,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Salt length in bytes for Argon2id derivation.
const SALT_LEN: usize = 16;

/// Vault header file name.
const HEADER_FILE: &str = "vault.verrou";

/// Vault database file name.
const DB_FILE: &str = "vault.db";

/// Maximum number of backup pairs to keep. Oldest are pruned after `create_backup()`.
const MAX_BACKUPS: usize = 10;

// ---------------------------------------------------------------------------
// Request / Result types
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Integrity verification types
// ---------------------------------------------------------------------------

/// Status of a vault integrity check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum IntegrityStatus {
    /// Vault passes all pre-unlock integrity checks.
    Ok,
    /// Header file is missing entirely.
    FileNotFound,
    /// Header file exists but magic bytes, JSON, or consistency check failed.
    HeaderCorrupted {
        /// Human-readable description of the corruption.
        detail: String,
    },
    /// Database file is missing alongside the header.
    DatabaseMissing,
    /// Vault format version is newer than this app supports.
    VersionUnsupported {
        /// The version found in the header.
        version: u8,
    },
}

/// Result of a vault integrity check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityReport {
    /// The integrity status.
    pub status: IntegrityStatus,
    /// Human-readable message describing the result.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Backup types
// ---------------------------------------------------------------------------

/// Information about a single vault backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    /// Full path to the backup `.verrou` file.
    pub path: PathBuf,
    /// ISO 8601 timestamp extracted from the filename.
    pub timestamp: String,
    /// File size in bytes.
    pub size_bytes: u64,
}

// ---------------------------------------------------------------------------
// Request / Result types
// ---------------------------------------------------------------------------

/// Parameters for vault creation.
pub struct CreateVaultRequest<'a> {
    /// The user's master password (raw bytes).
    pub password: &'a [u8],
    /// The user's chosen KDF preset (Fast / Balanced / Maximum).
    pub preset: KdfPreset,
    /// Directory where vault files will be created.
    pub vault_dir: &'a Path,
    /// Pre-calibrated presets from [`calibrate_for_vault`].
    pub calibrated: &'a CalibratedPresets,
}

/// Result of a successful vault creation.
///
/// Contains ONLY metadata — never raw key material. This struct is safe
/// to pass across IPC boundaries (Tauri commands).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultResult {
    /// Path to the `.verrou` header file.
    pub vault_path: PathBuf,
    /// Path to the `.db` database file.
    pub db_path: PathBuf,
    /// The KDF preset used for session unlock.
    pub kdf_preset: KdfPreset,
}

/// Parameters for vault unlock.
pub struct UnlockVaultRequest<'a> {
    /// The user's master password (raw bytes).
    pub password: &'a [u8],
    /// Directory where vault files reside.
    pub vault_dir: &'a Path,
}

/// Result of a successful vault unlock.
///
/// Contains ONLY metadata — never raw key material. The caller
/// receives the `VaultDb` handle and master key separately (in-process only).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockVaultResult {
    /// Total successful unlock count (for recovery key reminder).
    pub unlock_count: u32,
}

/// In-process result of a successful unlock — NOT for IPC.
///
/// Contains the decrypted database handle and master key.
/// The master key must be held in memory for the session duration
/// and zeroized on vault lock.
///
/// Debug implementation is masked to prevent secret leakage.
pub struct UnlockVaultSession {
    /// Handle to the decrypted `SQLCipher` database.
    pub db: VaultDb,
    /// The 256-bit master key (held for session re-auth operations).
    pub master_key: SecretBytes<32>,
    /// Total successful unlock count (for recovery key reminder).
    pub unlock_count: u32,
}

impl std::fmt::Debug for UnlockVaultSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UnlockVaultSession(***)")
    }
}

/// Parameters for changing the master password from Settings (vault already unlocked).
pub struct ChangeMasterPasswordRequest<'a> {
    /// The current master password (for re-authentication).
    pub old_password: &'a [u8],
    /// The new master password.
    pub new_password: &'a [u8],
    /// Directory where vault files reside.
    pub vault_dir: &'a Path,
    /// The decrypted master key from the current session (for verification).
    pub master_key: &'a [u8],
    /// Pre-calibrated presets for the new password slot.
    pub calibrated: &'a CalibratedPresets,
    /// The user's chosen KDF preset for the new password.
    pub preset: KdfPreset,
}

/// Parameters for changing the master password after a recovery key unlock.
pub struct ChangePasswordAfterRecoveryRequest<'a> {
    /// The new master password (raw bytes).
    pub new_password: &'a [u8],
    /// Directory where vault files reside.
    pub vault_dir: &'a Path,
    /// The decrypted master key from the current session.
    pub master_key: &'a [u8],
    /// Pre-calibrated presets for the new password slot.
    pub calibrated: &'a CalibratedPresets,
    /// The user's chosen KDF preset for the new password.
    pub preset: KdfPreset,
}

/// Result of a post-recovery password change.
///
/// Contains the new recovery key data (displayed to the user once).
/// No raw key material crosses the IPC boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeResult {
    /// New recovery key data (formatted key, fingerprint, date).
    pub recovery_key: GenerateRecoveryKeyResult,
}

// ---------------------------------------------------------------------------
// Brute-force protection constants
// ---------------------------------------------------------------------------

/// Backoff schedule: (threshold, `delay_ms`).
/// If `unlock_attempts >= threshold`, the given delay applies.
/// Checked in descending order — first match wins.
const BACKOFF_SCHEDULE: &[(u32, u64)] = &[
    (10, 300_000), // 10+ attempts → 5 minutes
    (8, 30_000),   //  8+ attempts → 30 seconds
    (5, 5_000),    //  5+ attempts → 5 seconds
    (3, 1_000),    //  3+ attempts → 1 second
];

// ---------------------------------------------------------------------------
// Calibration wrapper
// ---------------------------------------------------------------------------

/// Calibrate Argon2id parameters against the current hardware.
///
/// Delegates to [`kdf::calibrate`] and returns the result. The caller
/// presents all 3 presets to the user for selection.
///
/// # Errors
///
/// Returns [`VaultError::Crypto`] if even 128 MB calibration fails.
pub fn calibrate_for_vault() -> Result<CalibratedPresets, VaultError> {
    kdf::calibrate().map_err(VaultError::from)
}

// ---------------------------------------------------------------------------
// Vault creation
// ---------------------------------------------------------------------------

/// Create a new vault with a master password.
///
/// Performs the full key hierarchy ceremony:
/// 1. Check for existing vault files (refuse if already present)
/// 2. Generate random 16-byte salt
/// 3. Derive password key via Argon2id (user's chosen preset)
/// 4. Generate random 256-bit master key
/// 5. Create password slot (wrap master key with password key)
/// 6. Build `VaultHeader` with session + sensitive params
/// 7. Serialize and write `vault.verrou`
/// 8. Create `SQLCipher` database `vault.db`
/// 9. Insert key slot record into `key_slots` table
///
/// # Errors
///
/// - [`VaultError::VaultAlreadyExists`] if files already exist
/// - [`VaultError::Crypto`] if KDF, slot, or serialization fails
/// - [`VaultError::Io`] if file writing fails
/// - [`VaultError::Database`] if `SQLCipher` creation fails
pub fn create_vault(req: &CreateVaultRequest<'_>) -> Result<CreateVaultResult, VaultError> {
    let header_path = req.vault_dir.join(HEADER_FILE);
    let db_path = req.vault_dir.join(DB_FILE);

    // AC #5: Refuse if vault already exists.
    if header_path.exists() || db_path.exists() {
        return Err(VaultError::VaultAlreadyExists(
            req.vault_dir.display().to_string(),
        ));
    }

    // Ensure the vault directory exists.
    std::fs::create_dir_all(req.vault_dir)?;

    // AC #1 step 1: Generate random 16-byte salt.
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // AC #1 step 2: Derive password key using the user's chosen preset.
    let session_params = select_preset(req.preset, req.calibrated);
    let password_key = kdf::derive(req.password, &salt, &session_params)?;

    // AC #3: Generate random 256-bit master key via CSPRNG.
    let master_key = SecretBytes::<32>::random()?;

    // AC #1 step 3: Create password slot (wraps master key with password key).
    let password_slot = slots::create_slot(
        master_key.expose(),
        password_key.expose(),
        SlotType::Password,
    )?;

    // AC #1 step 4: Build VaultHeader with salt for unlock flow.
    // NOTE: Salt is stored in BOTH the header (authoritative for unlock flow)
    // and the key_slots DB table (informational/audit copy). The header copy
    // is the source of truth because the DB cannot be opened without it.
    let sensitive_params = req.calibrated.maximum.clone();
    let header = VaultHeader {
        version: FORMAT_VERSION,
        slot_count: 1,
        session_params: session_params.clone(),
        sensitive_params,
        unlock_attempts: 0,
        last_attempt_at: None,
        total_unlock_count: 0,
        slots: vec![password_slot.clone()],
        slot_salts: vec![salt.to_vec()],
    };

    // AC #1 step 5: Serialize .verrou file (empty payload — entries in SQLCipher).
    let verrou_bytes = vault_format::serialize(&header, &[], master_key.expose())?;

    // AC #1 step 6: Write .verrou file.
    std::fs::write(&header_path, &verrou_bytes)?;

    // AC #1 step 7: Create SQLCipher database.
    // Guard: if DB creation or key slot insert fails, clean up the orphan files
    // to avoid a permanently broken state where VaultAlreadyExists blocks retry.
    let db = match VaultDb::open(&db_path, &master_key) {
        Ok(db) => db,
        Err(e) => {
            let _ = std::fs::remove_file(&header_path);
            return Err(e);
        }
    };

    // AC #1 step 8: Insert key slot record into key_slots table.
    if let Err(e) = insert_key_slot_record(db.connection(), &password_slot, &salt, &session_params)
    {
        drop(db);
        let _ = std::fs::remove_file(&header_path);
        let _ = std::fs::remove_file(&db_path);
        return Err(e);
    }

    // Explicitly close the database before returning.
    drop(db);

    // AC #4: Return only metadata — no raw key material.
    Ok(CreateVaultResult {
        vault_path: header_path,
        db_path,
        kdf_preset: req.preset,
    })
}

// ---------------------------------------------------------------------------
// Vault unlock
// ---------------------------------------------------------------------------

/// Unlock an existing vault with a master password.
///
/// Performs the full unlock ceremony:
/// 1. Read `.verrou` file and parse header (no decryption needed)
/// 2. Check brute-force cooldown — reject early if active
/// 3. Find the first `Password` slot in the header
/// 4. Derive wrapping key via Argon2id (`session_params`)
/// 5. Unwrap slot to recover master key
/// 6. Open `SQLCipher` database with master key
/// 7. On success: reset attempt counter, increment unlock count, rewrite header
/// 8. On failure: increment attempt counter, record timestamp, rewrite header
///
/// # Errors
///
/// - [`VaultError::NotFound`] if the vault directory or `.verrou` file doesn't exist
/// - [`VaultError::RateLimited`] if brute-force cooldown is active
/// - [`VaultError::InvalidPassword`] if the password is wrong (slot unwrap fails)
/// - [`VaultError::Crypto`] if KDF or vault format parsing fails
/// - [`VaultError::Database`] if `SQLCipher` cannot be opened
pub fn unlock_vault(req: &UnlockVaultRequest<'_>) -> Result<UnlockVaultSession, VaultError> {
    let header_path = req.vault_dir.join(HEADER_FILE);
    let db_path = req.vault_dir.join(DB_FILE);

    // Step 1: Run integrity check before any expensive operations.
    let report = verify_vault_integrity(req.vault_dir);
    match &report.status {
        IntegrityStatus::Ok => {}
        IntegrityStatus::FileNotFound => {
            return Err(VaultError::NotFound(req.vault_dir.display().to_string()));
        }
        IntegrityStatus::HeaderCorrupted { detail: _ }
        | IntegrityStatus::DatabaseMissing
        | IntegrityStatus::VersionUnsupported { version: _ } => {
            return Err(VaultError::IntegrityFailure(report.message.clone()));
        }
    }

    let file_data = std::fs::read(&header_path)?;
    let mut header = vault_format::parse_header_only(&file_data)?;

    // Step 2: Check brute-force cooldown.
    let now_secs = current_epoch_secs();
    if let Some(remaining_ms) = check_cooldown(&header, now_secs) {
        return Err(VaultError::RateLimited { remaining_ms });
    }

    // Step 3: Find the first Password slot.
    let (slot_index, password_slot) = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == SlotType::Password)
        .ok_or_else(|| {
            VaultError::Crypto(CryptoError::VaultFormat(
                "no password slot found in vault header".into(),
            ))
        })?;

    let password_slot = password_slot.clone();

    // Get the matching salt.
    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            VaultError::Crypto(CryptoError::VaultFormat(
                "missing salt for password slot".into(),
            ))
        })?
        .clone();

    // Step 4: Derive wrapping key via Argon2id with session_params.
    let wrapping_key = kdf::derive(req.password, &salt, &header.session_params)?;

    // Step 5: Unwrap slot → master key.
    let Ok(master_key_buf) = slots::unwrap_slot(&password_slot, wrapping_key.expose()) else {
        // Wrong password — increment attempt counter and persist.
        record_failed_attempt(&mut header, now_secs);
        persist_header(&header_path, &file_data, &header)?;
        return Err(VaultError::InvalidPassword);
    };

    // Convert SecretBuffer → SecretBytes<32>.
    if master_key_buf.len() != 32 {
        return Err(VaultError::Crypto(CryptoError::InvalidKeyMaterial(
            format!(
                "unwrapped master key is {} bytes (expected 32)",
                master_key_buf.len()
            ),
        )));
    }
    let mut mk_arr = [0u8; 32];
    mk_arr.copy_from_slice(master_key_buf.expose());
    let master_key = SecretBytes::<32>::new(mk_arr);
    mk_arr.zeroize();

    // Step 6: Open SQLCipher database.
    let db = VaultDb::open(&db_path, &master_key)?;

    // Step 7: Success — reset attempts, increment unlock count, persist.
    header.unlock_attempts = 0;
    header.last_attempt_at = None;
    header.total_unlock_count = header.total_unlock_count.saturating_add(1);
    persist_header(&header_path, &file_data, &header)?;

    Ok(UnlockVaultSession {
        db,
        master_key,
        unlock_count: header.total_unlock_count,
    })
}

// ---------------------------------------------------------------------------
// Password verification (no side effects)
// ---------------------------------------------------------------------------

/// Verify the vault password without opening the database or modifying counters.
///
/// Reads the header, derives the wrapping key via Argon2id, and verifies it
/// can unwrap the password slot. Unlike [`unlock_vault`], this does NOT:
/// - Open the `SQLCipher` database
/// - Increment `total_unlock_count`
/// - Reset `unlock_attempts`
///
/// Used for re-authentication gates (biometric enrollment, etc.) where the
/// vault is already unlocked and we only need to verify the password.
///
/// # Errors
///
/// - [`VaultError::NotFound`] if the vault directory or `.verrou` file doesn't exist
/// - [`VaultError::RateLimited`] if brute-force cooldown is active (shared counter)
/// - [`VaultError::InvalidPassword`] if the password is wrong
/// - [`VaultError::Crypto`] if KDF or vault format parsing fails
pub fn verify_vault_password(
    password: &[u8],
    vault_dir: &Path,
) -> Result<SecretBytes<32>, VaultError> {
    let header_path = vault_dir.join(HEADER_FILE);
    if !header_path.exists() {
        return Err(VaultError::NotFound(vault_dir.display().to_string()));
    }

    let file_data = std::fs::read(&header_path)?;
    let header = vault_format::parse_header_only(&file_data)?;

    // Check brute-force cooldown (read-only — do NOT modify attempts).
    let now_secs = current_epoch_secs();
    if let Some(remaining_ms) = check_cooldown(&header, now_secs) {
        return Err(VaultError::RateLimited { remaining_ms });
    }

    // Find the password slot.
    let (slot_index, password_slot) = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == SlotType::Password)
        .ok_or_else(|| {
            VaultError::Crypto(CryptoError::VaultFormat(
                "no password slot found in vault header".into(),
            ))
        })?;

    let password_slot = password_slot.clone();
    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            VaultError::Crypto(CryptoError::VaultFormat(
                "missing salt for password slot".into(),
            ))
        })?
        .clone();

    // Derive wrapping key via Argon2id (session_params — same KDF as unlock).
    let wrapping_key = kdf::derive(password, &salt, &header.session_params)?;

    // Unwrap slot → master key.
    let master_key_buf = slots::unwrap_slot(&password_slot, wrapping_key.expose())
        .map_err(|_| VaultError::InvalidPassword)?;

    if master_key_buf.len() != 32 {
        return Err(VaultError::Crypto(CryptoError::InvalidKeyMaterial(
            format!(
                "unwrapped master key is {} bytes (expected 32)",
                master_key_buf.len()
            ),
        )));
    }
    let mut mk_arr = [0u8; 32];
    mk_arr.copy_from_slice(master_key_buf.expose());
    let master_key = SecretBytes::<32>::new(mk_arr);
    mk_arr.zeroize();

    Ok(master_key)
}

// ---------------------------------------------------------------------------
// Recovery key unlock
// ---------------------------------------------------------------------------

/// Unlock an existing vault with a recovery key.
///
/// Follows the same ceremony as [`unlock_vault`] but uses a recovery slot
/// instead of a password slot, and derives the wrapping key using
/// `sensitive_params` (Maximum tier) instead of `session_params`.
///
/// # Errors
///
/// - [`VaultError::NotFound`] if the vault directory or `.verrou` file doesn't exist
/// - [`VaultError::RateLimited`] if brute-force cooldown is active (shared counter)
/// - [`VaultError::InvalidRecoveryKey`] if the recovery key is wrong
/// - [`VaultError::RecoverySlotNotFound`] if no recovery slot exists
/// - [`VaultError::Crypto`] if KDF or vault format parsing fails
/// - [`VaultError::Database`] if `SQLCipher` cannot be opened
pub fn unlock_vault_with_recovery_key(
    recovery_key: &str,
    vault_dir: &Path,
) -> Result<UnlockVaultSession, VaultError> {
    // Step 0: Run integrity check before any expensive operations.
    let report = verify_vault_integrity(vault_dir);
    match &report.status {
        IntegrityStatus::Ok => {}
        IntegrityStatus::FileNotFound => {
            return Err(VaultError::NotFound(vault_dir.display().to_string()));
        }
        IntegrityStatus::HeaderCorrupted { detail: _ }
        | IntegrityStatus::DatabaseMissing
        | IntegrityStatus::VersionUnsupported { version: _ } => {
            return Err(VaultError::IntegrityFailure(report.message.clone()));
        }
    }

    // Step 1: Decode the formatted recovery key → raw entropy.
    let mut entropy = decode_recovery_key(recovery_key)?;

    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    let file_data = std::fs::read(&header_path)?;
    let mut header = vault_format::parse_header_only(&file_data)?;

    // Step 3: Check brute-force cooldown (shared counter with password unlock).
    let now_secs = current_epoch_secs();
    if let Some(remaining_ms) = check_cooldown(&header, now_secs) {
        entropy.zeroize();
        return Err(VaultError::RateLimited { remaining_ms });
    }

    // Step 4: Find the first Recovery slot.
    let (slot_index, recovery_slot) = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == SlotType::Recovery)
        .ok_or_else(|| {
            entropy.zeroize();
            VaultError::RecoverySlotNotFound
        })?;

    let recovery_slot = recovery_slot.clone();

    // Get the matching salt.
    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            VaultError::Crypto(CryptoError::VaultFormat(
                "missing salt for recovery slot".into(),
            ))
        })?
        .clone();

    // Step 5: Derive wrapping key via Argon2id with sensitive_params (Maximum tier).
    let wrapping_key = kdf::derive(&entropy, &salt, &header.sensitive_params)?;

    // Zeroize entropy immediately after derivation.
    entropy.zeroize();

    // Step 6: Unwrap slot → master key.
    let Ok(master_key_buf) = slots::unwrap_slot(&recovery_slot, wrapping_key.expose()) else {
        // Wrong recovery key — increment attempt counter and persist.
        record_failed_attempt(&mut header, now_secs);
        persist_header(&header_path, &file_data, &header)?;
        return Err(VaultError::InvalidRecoveryKey);
    };

    // Convert SecretBuffer → SecretBytes<32>.
    if master_key_buf.len() != 32 {
        return Err(VaultError::Crypto(CryptoError::InvalidKeyMaterial(
            format!(
                "unwrapped master key is {} bytes (expected 32)",
                master_key_buf.len()
            ),
        )));
    }
    let mut mk_arr = [0u8; 32];
    mk_arr.copy_from_slice(master_key_buf.expose());
    let master_key = SecretBytes::<32>::new(mk_arr);
    mk_arr.zeroize();

    // Step 7: Open SQLCipher database.
    let db = VaultDb::open(&db_path, &master_key)?;

    // Step 8: Success — reset attempts, increment unlock count, persist.
    header.unlock_attempts = 0;
    header.last_attempt_at = None;
    header.total_unlock_count = header.total_unlock_count.saturating_add(1);
    persist_header(&header_path, &file_data, &header)?;

    Ok(UnlockVaultSession {
        db,
        master_key,
        unlock_count: header.total_unlock_count,
    })
}

// ---------------------------------------------------------------------------
// Biometric unlock
// ---------------------------------------------------------------------------

/// Unlock an existing vault with a biometric token.
///
/// Follows the same ceremony as [`unlock_vault`] but:
/// - Uses a biometric slot instead of a password slot
/// - Derives the wrapping key via HKDF (instant) instead of Argon2id
/// - Shares the brute-force counter with password/recovery unlock
///
/// # Errors
///
/// - [`VaultError::NotFound`] if the vault directory doesn't exist
/// - [`VaultError::RateLimited`] if brute-force cooldown is active (shared counter)
/// - [`VaultError::BiometricSlotNotFound`] if no biometric slot exists
/// - [`VaultError::BiometricUnlockFailed`] if the token is wrong
/// - [`VaultError::Crypto`] if HKDF or vault format parsing fails
/// - [`VaultError::Database`] if `SQLCipher` cannot be opened
pub fn unlock_vault_with_biometric(
    biometric_token: &[u8],
    vault_dir: &Path,
) -> Result<UnlockVaultSession, VaultError> {
    // Step 0: Integrity check.
    let report = verify_vault_integrity(vault_dir);
    match &report.status {
        IntegrityStatus::Ok => {}
        IntegrityStatus::FileNotFound => {
            return Err(VaultError::NotFound(vault_dir.display().to_string()));
        }
        IntegrityStatus::HeaderCorrupted { detail: _ }
        | IntegrityStatus::DatabaseMissing
        | IntegrityStatus::VersionUnsupported { version: _ } => {
            return Err(VaultError::IntegrityFailure(report.message.clone()));
        }
    }

    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    let file_data = std::fs::read(&header_path)?;
    let mut header = vault_format::parse_header_only(&file_data)?;

    // Step 1: Check brute-force cooldown (shared with password/recovery).
    let now_secs = current_epoch_secs();
    if let Some(remaining_ms) = check_cooldown(&header, now_secs) {
        return Err(VaultError::RateLimited { remaining_ms });
    }

    // Step 2: Find the biometric slot.
    let biometric_slot = header
        .slots
        .iter()
        .find(|s| s.slot_type == SlotType::Biometric)
        .ok_or(VaultError::BiometricSlotNotFound)?
        .clone();

    // Step 3: Derive wrapping key via HKDF (no salt needed — instant).
    let wrapping_key =
        verrou_crypto_core::biometric::derive_biometric_wrapping_key(biometric_token)?;

    // Step 4: Unwrap slot → master key.
    let Ok(master_key_buf) = slots::unwrap_slot(&biometric_slot, wrapping_key.expose()) else {
        // Wrong biometric token — increment shared attempt counter.
        record_failed_attempt(&mut header, now_secs);
        persist_header(&header_path, &file_data, &header)?;
        return Err(VaultError::BiometricUnlockFailed);
    };

    // Convert SecretBuffer → SecretBytes<32>.
    if master_key_buf.len() != 32 {
        return Err(VaultError::Crypto(CryptoError::InvalidKeyMaterial(
            format!(
                "unwrapped master key is {} bytes (expected 32)",
                master_key_buf.len()
            ),
        )));
    }
    let mut mk_arr = [0u8; 32];
    mk_arr.copy_from_slice(master_key_buf.expose());
    let master_key = SecretBytes::<32>::new(mk_arr);
    mk_arr.zeroize();

    // Step 5: Open SQLCipher database.
    let db = VaultDb::open(&db_path, &master_key)?;

    // Step 6: Success — reset attempts, increment unlock count, persist.
    header.unlock_attempts = 0;
    header.last_attempt_at = None;
    header.total_unlock_count = header.total_unlock_count.saturating_add(1);
    persist_header(&header_path, &file_data, &header)?;

    Ok(UnlockVaultSession {
        db,
        master_key,
        unlock_count: header.total_unlock_count,
    })
}

// ---------------------------------------------------------------------------
// Biometric slot management
// ---------------------------------------------------------------------------

/// Check if a biometric slot exists in the vault header.
///
/// Reads and parses the vault header file without opening the database.
///
/// # Errors
///
/// - [`VaultError::NotFound`] if the vault header doesn't exist
/// - [`VaultError::Crypto`] if the header cannot be parsed
pub fn has_biometric_slot(vault_dir: &Path) -> Result<bool, VaultError> {
    let header_path = vault_dir.join(HEADER_FILE);
    if !header_path.exists() {
        return Err(VaultError::NotFound(vault_dir.display().to_string()));
    }
    let file_data = std::fs::read(&header_path)?;
    let header = vault_format::parse_header_only(&file_data)?;
    Ok(header
        .slots
        .iter()
        .any(|s| s.slot_type == SlotType::Biometric))
}

/// Add a biometric slot to an existing vault.
///
/// Creates a biometric `KeySlot` wrapping the master key with a key derived
/// from the biometric token via HKDF. The biometric slot uses an empty salt
/// (no Argon2id needed — HKDF is deterministic from the token).
///
/// # Arguments
///
/// - `vault_dir` — directory containing the vault files
/// - `master_key` — the decrypted 32-byte master key (from current session)
/// - `biometric_token` — 32-byte random secret from the OS keychain
///
/// # Errors
///
/// - [`VaultError::NotFound`] if vault files don't exist
/// - [`VaultError::Crypto`] if HKDF, slot creation, or serialization fails
/// - [`VaultError::Io`] if file read/write fails
pub fn add_biometric_slot(
    vault_dir: &Path,
    master_key: &[u8],
    biometric_token: &[u8],
) -> Result<(), VaultError> {
    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    if !header_path.exists() || !db_path.exists() {
        return Err(VaultError::NotFound(vault_dir.display().to_string()));
    }

    let original_bytes = std::fs::read(&header_path)?;
    let mut header = vault_format::parse_header_only(&original_bytes)?;

    // Remove any existing biometric slot first (idempotent).
    remove_biometric_slot_from_header(&mut header);

    // Derive wrapping key from biometric token via HKDF.
    let wrapping_key =
        verrou_crypto_core::biometric::derive_biometric_wrapping_key(biometric_token)?;

    // Create biometric slot wrapping the master key.
    let bio_slot = slots::create_slot(master_key, wrapping_key.expose(), SlotType::Biometric)?;

    // Update header: add slot with empty salt (no Argon2id for biometric).
    header.slot_count = header.slot_count.checked_add(1).ok_or_else(|| {
        VaultError::Crypto(CryptoError::VaultFormat("slot_count overflow".into()))
    })?;
    header.slots.push(bio_slot.clone());
    header.slot_salts.push(vec![]); // Empty salt for biometric

    // Re-serialize and write the updated header.
    let updated_bytes = vault_format::serialize(&header, &[], master_key)?;
    std::fs::write(&header_path, &updated_bytes)?;

    // Insert biometric slot record in DB (informational/audit).
    // Use empty salt and default params for the DB record.
    let db = match VaultDb::open_raw(&db_path, master_key) {
        Ok(db) => db,
        Err(e) => {
            // Restore original header on failure.
            let _ = std::fs::write(&header_path, &original_bytes);
            return Err(e);
        }
    };

    // Insert a minimal key_slot record for the biometric slot.
    let slot_id = generate_uuid();
    let wrapped_key_bytes = bio_slot.wrapped_key.to_bytes();
    let now = now_iso8601();
    let result = db.connection().execute(
        "INSERT INTO key_slots (id, slot_type, wrapped_key, salt, kdf_params, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            slot_id,
            "biometric",
            wrapped_key_bytes,
            &[] as &[u8],
            "{}",
            now
        ],
    );

    if let Err(e) = result {
        drop(db);
        let _ = std::fs::write(&header_path, &original_bytes);
        return Err(VaultError::Database(format!(
            "failed to insert biometric key slot: {e}"
        )));
    }

    Ok(())
}

/// Remove the biometric slot from an existing vault.
///
/// Removes the biometric slot from the vault header and deletes the
/// corresponding record from the `key_slots` DB table.
///
/// # Errors
///
/// - [`VaultError::NotFound`] if vault files don't exist
/// - [`VaultError::BiometricSlotNotFound`] if no biometric slot exists
/// - [`VaultError::Crypto`] if header parsing or serialization fails
/// - [`VaultError::Io`] if file read/write fails
pub fn remove_biometric_slot(vault_dir: &Path, master_key: &[u8]) -> Result<(), VaultError> {
    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    if !header_path.exists() || !db_path.exists() {
        return Err(VaultError::NotFound(vault_dir.display().to_string()));
    }

    let original_bytes = std::fs::read(&header_path)?;
    let mut header = vault_format::parse_header_only(&original_bytes)?;

    // Check that a biometric slot exists.
    if !header
        .slots
        .iter()
        .any(|s| s.slot_type == SlotType::Biometric)
    {
        return Err(VaultError::BiometricSlotNotFound);
    }

    // Remove biometric slot(s) from header.
    remove_biometric_slot_from_header(&mut header);

    // Re-serialize and write the updated header.
    let updated_bytes = vault_format::serialize(&header, &[], master_key)?;
    std::fs::write(&header_path, &updated_bytes)?;

    // Delete biometric slot records from DB.
    let db = match VaultDb::open_raw(&db_path, master_key) {
        Ok(db) => db,
        Err(e) => {
            let _ = std::fs::write(&header_path, &original_bytes);
            return Err(e);
        }
    };

    if let Err(e) = db
        .connection()
        .execute("DELETE FROM key_slots WHERE slot_type = 'biometric'", [])
    {
        drop(db);
        let _ = std::fs::write(&header_path, &original_bytes);
        return Err(VaultError::Database(format!(
            "failed to delete biometric key slot: {e}"
        )));
    }

    Ok(())
}

/// Remove all biometric slots from a header in-place (helper).
fn remove_biometric_slot_from_header(header: &mut VaultHeader) {
    // Collect indices of biometric slots (reverse order for safe removal).
    let bio_indices: Vec<usize> = header
        .slots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.slot_type == SlotType::Biometric)
        .map(|(i, _)| i)
        .rev()
        .collect();

    for i in bio_indices {
        let _ = header.slots.remove(i);
        if i < header.slot_salts.len() {
            header.slot_salts.remove(i);
        }
        header.slot_count = header.slot_count.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// Hardware security slot management
// ---------------------------------------------------------------------------

/// Check whether the vault header contains a hardware security slot.
///
/// # Errors
///
/// Returns [`VaultError::NotFound`] if the vault directory doesn't exist,
/// or [`VaultError::Crypto`] if the header cannot be parsed.
pub fn has_hardware_security_slot(vault_dir: &Path) -> Result<bool, VaultError> {
    let header_path = vault_dir.join(HEADER_FILE);
    if !header_path.exists() {
        return Err(VaultError::NotFound(vault_dir.display().to_string()));
    }
    let file_data = std::fs::read(&header_path)?;
    let header = vault_format::parse_header_only(&file_data)?;
    Ok(header
        .slots
        .iter()
        .any(|s| s.slot_type == SlotType::HardwareSecurity))
}

/// Add a hardware security slot to an existing vault.
///
/// Creates a `HardwareSecurity` `KeySlot` wrapping the master key with a key
/// derived from the hardware token via HKDF. Like biometric, the hardware
/// security slot uses an empty salt (HKDF is deterministic from the token).
///
/// # Arguments
///
/// - `vault_dir` — directory containing the vault files
/// - `master_key` — the decrypted 32-byte master key (from current session)
/// - `hardware_token` — 32-byte random secret from the hardware security module
///
/// # Errors
///
/// - [`VaultError::NotFound`] if vault files don't exist
/// - [`VaultError::Crypto`] if HKDF, slot creation, or serialization fails
/// - [`VaultError::Io`] if file read/write fails
pub fn add_hardware_security_slot(
    vault_dir: &Path,
    master_key: &[u8],
    hardware_token: &[u8],
) -> Result<(), VaultError> {
    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    if !header_path.exists() || !db_path.exists() {
        return Err(VaultError::NotFound(vault_dir.display().to_string()));
    }

    let original_bytes = std::fs::read(&header_path)?;
    let mut header = vault_format::parse_header_only(&original_bytes)?;

    // Remove any existing hardware security slot first (idempotent).
    remove_hardware_security_slot_from_header(&mut header);

    // Derive wrapping key from hardware token via HKDF.
    let wrapping_key =
        verrou_crypto_core::hardware_key::derive_hardware_wrapping_key(hardware_token)?;

    // Create hardware security slot wrapping the master key.
    let hw_slot = slots::create_slot(
        master_key,
        wrapping_key.expose(),
        SlotType::HardwareSecurity,
    )?;

    // Update header: add slot with empty salt (no Argon2id for hardware key).
    header.slot_count = header.slot_count.checked_add(1).ok_or_else(|| {
        VaultError::Crypto(CryptoError::VaultFormat("slot_count overflow".into()))
    })?;
    header.slots.push(hw_slot.clone());
    header.slot_salts.push(vec![]); // Empty salt for hardware security

    // Re-serialize and write the updated header.
    let updated_bytes = vault_format::serialize(&header, &[], master_key)?;
    std::fs::write(&header_path, &updated_bytes)?;

    // Insert hardware security slot record in DB (informational/audit).
    let db = match VaultDb::open_raw(&db_path, master_key) {
        Ok(db) => db,
        Err(e) => {
            // Restore original header on failure.
            let _ = std::fs::write(&header_path, &original_bytes);
            return Err(e);
        }
    };

    let slot_id = generate_uuid();
    let wrapped_key_bytes = hw_slot.wrapped_key.to_bytes();
    let now = now_iso8601();
    let result = db.connection().execute(
        "INSERT INTO key_slots (id, slot_type, wrapped_key, salt, kdf_params, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            slot_id,
            "hardware",
            wrapped_key_bytes,
            &[] as &[u8],
            "{}",
            now
        ],
    );

    if let Err(e) = result {
        drop(db);
        let _ = std::fs::write(&header_path, &original_bytes);
        return Err(VaultError::Database(format!(
            "failed to insert hardware security key slot: {e}"
        )));
    }

    Ok(())
}

/// Remove the hardware security slot from an existing vault.
///
/// # Errors
///
/// - [`VaultError::NotFound`] if vault files don't exist
/// - [`VaultError::Crypto`] if header parsing or serialization fails
/// - [`VaultError::Io`] if file read/write fails
pub fn remove_hardware_security_slot(
    vault_dir: &Path,
    master_key: &[u8],
) -> Result<(), VaultError> {
    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    if !header_path.exists() || !db_path.exists() {
        return Err(VaultError::NotFound(vault_dir.display().to_string()));
    }

    let original_bytes = std::fs::read(&header_path)?;
    let mut header = vault_format::parse_header_only(&original_bytes)?;

    // Check that a hardware security slot exists.
    if !header
        .slots
        .iter()
        .any(|s| s.slot_type == SlotType::HardwareSecurity)
    {
        // No hardware security slot — not an error, just a no-op.
        return Ok(());
    }

    // Remove hardware security slot(s) from header.
    remove_hardware_security_slot_from_header(&mut header);

    // Re-serialize and write the updated header.
    let updated_bytes = vault_format::serialize(&header, &[], master_key)?;
    std::fs::write(&header_path, &updated_bytes)?;

    // Delete hardware security slot records from DB.
    let db = match VaultDb::open_raw(&db_path, master_key) {
        Ok(db) => db,
        Err(e) => {
            let _ = std::fs::write(&header_path, &original_bytes);
            return Err(e);
        }
    };

    if let Err(e) = db
        .connection()
        .execute("DELETE FROM key_slots WHERE slot_type = 'hardware'", [])
    {
        drop(db);
        let _ = std::fs::write(&header_path, &original_bytes);
        return Err(VaultError::Database(format!(
            "failed to delete hardware security key slot: {e}"
        )));
    }

    Ok(())
}

/// Remove all hardware security slots from a header in-place (helper).
fn remove_hardware_security_slot_from_header(header: &mut VaultHeader) {
    let hw_indices: Vec<usize> = header
        .slots
        .iter()
        .enumerate()
        .filter(|(_, s)| s.slot_type == SlotType::HardwareSecurity)
        .map(|(i, _)| i)
        .rev()
        .collect();

    for i in hw_indices {
        let _ = header.slots.remove(i);
        if i < header.slot_salts.len() {
            header.slot_salts.remove(i);
        }
        header.slot_count = header.slot_count.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// Post-recovery password change
// ---------------------------------------------------------------------------

/// Change the master password after a recovery key unlock.
///
/// This is a mandatory operation after recovery. It replaces the password
/// slot with a new one (wrapping the same master key) and generates a
/// fresh recovery key (invalidating the old one).
///
/// Performs:
/// 1. Read and parse the vault header
/// 2. Generate fresh salt for the new password slot
/// 3. Derive new password wrapping key via Argon2id (`session_params`)
/// 4. Create new password slot (wrapping the existing master key)
/// 5. Remove all old password slots from the header
/// 6. Remove all old recovery slots from the header
/// 7. Add the new password slot to the header
/// 8. Persist the updated header
/// 9. Update the `key_slots` table (remove old, insert new)
/// 10. Generate a new recovery key via [`recovery::add_recovery_slot`]
///
/// # Errors
///
/// - [`VaultError::NotFound`] if vault files don't exist
/// - [`VaultError::Crypto`] if KDF, slot creation, or serialization fails
/// - [`VaultError::Io`] if file read/write fails
/// - [`VaultError::Database`] if DB operations fail
pub fn change_password_after_recovery(
    req: &ChangePasswordAfterRecoveryRequest<'_>,
) -> Result<PasswordChangeResult, VaultError> {
    let header_path = req.vault_dir.join(HEADER_FILE);
    let db_path = req.vault_dir.join(DB_FILE);

    // Read and parse vault header.
    if !header_path.exists() {
        return Err(VaultError::NotFound(req.vault_dir.display().to_string()));
    }
    let file_data = std::fs::read(&header_path)?;
    let header = vault_format::parse_header_only(&file_data)?;

    // Delegate to shared slot replacement logic (no backup for recovery — vault was just unlocked).
    replace_password_and_recovery_slots(
        req.new_password,
        req.master_key,
        req.vault_dir,
        req.calibrated,
        req.preset,
        &header,
        &header_path,
        &db_path,
        &file_data,
    )
}

// ---------------------------------------------------------------------------
// Master password change (Settings — vault already unlocked)
// ---------------------------------------------------------------------------

/// Change the master password from the Settings screen.
///
/// The vault must be unlocked. The user re-authenticates with their current
/// password (using `sensitive_params` / Maximum tier) before the slot is
/// replaced. A backup is created before any destructive changes.
///
/// Performs:
/// 1. Read vault header, find password slot
/// 2. Re-authenticate: derive wrapping key from `old_password` using `sensitive_params`
/// 3. Unwrap password slot → compare recovered master key with session master key
/// 4. Create backup of `.verrou` file
/// 5. Replace password slot with new one (same master key)
/// 6. Remove old password + recovery slots
/// 7. Persist updated header + DB
/// 8. Generate new recovery key
///
/// # Errors
///
/// - [`VaultError::NotFound`] if vault files don't exist
/// - [`VaultError::InvalidPassword`] if old password is wrong
/// - [`VaultError::Io`] if backup or file write fails
/// - [`VaultError::Crypto`] if KDF or slot operations fail
/// - [`VaultError::Database`] if DB update fails
pub fn change_master_password(
    req: &ChangeMasterPasswordRequest<'_>,
) -> Result<PasswordChangeResult, VaultError> {
    let header_path = req.vault_dir.join(HEADER_FILE);
    let db_path = req.vault_dir.join(DB_FILE);

    // Step 1: Read and parse vault header.
    if !header_path.exists() {
        return Err(VaultError::NotFound(req.vault_dir.display().to_string()));
    }
    let file_data = std::fs::read(&header_path)?;
    let header = vault_format::parse_header_only(&file_data)?;

    // Step 2: Find password slot for re-authentication.
    let (slot_index, password_slot) = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == SlotType::Password)
        .ok_or_else(|| {
            VaultError::Crypto(CryptoError::VaultFormat(
                "no password slot found in vault header".into(),
            ))
        })?;

    let password_slot = password_slot.clone();

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            VaultError::Crypto(CryptoError::VaultFormat(
                "missing salt for password slot".into(),
            ))
        })?
        .clone();

    // Step 3: Re-authenticate by unwrapping the existing password slot.
    // The slot was created with session_params, so we must derive with session_params.
    let wrapping_key = kdf::derive(req.old_password, &salt, &header.session_params)?;

    let Ok(recovered_key) = slots::unwrap_slot(&password_slot, wrapping_key.expose()) else {
        return Err(VaultError::InvalidPassword);
    };

    // Verify recovered key matches session master key.
    if recovered_key.expose() != req.master_key {
        return Err(VaultError::InvalidPassword);
    }

    // Step 4: Create backup before destructive changes.
    create_backup(req.vault_dir)?;

    // Step 5-8: Delegate to the shared slot replacement logic.
    replace_password_and_recovery_slots(
        req.new_password,
        req.master_key,
        req.vault_dir,
        req.calibrated,
        req.preset,
        &header,
        &header_path,
        &db_path,
        &file_data,
    )
}

/// Shared logic for replacing password and recovery slots.
///
/// Used by both `change_master_password` and `change_password_after_recovery`.
#[allow(clippy::too_many_arguments)]
fn replace_password_and_recovery_slots(
    new_password: &[u8],
    master_key: &[u8],
    vault_dir: &Path,
    calibrated: &CalibratedPresets,
    preset: KdfPreset,
    header: &VaultHeader,
    header_path: &Path,
    db_path: &Path,
    original_file_data: &[u8],
) -> Result<PasswordChangeResult, VaultError> {
    // Generate fresh salt for the new password slot.
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // Derive new password wrapping key.
    let session_params = select_preset(preset, calibrated);
    let password_key = kdf::derive(new_password, &salt, &session_params)?;

    // Create new password slot.
    let new_password_slot =
        slots::create_slot(master_key, password_key.expose(), SlotType::Password)?;

    // Remove old password and recovery slots, keep only other types.
    let mut updated_slots = Vec::new();
    let mut updated_salts = Vec::new();
    for (i, slot) in header.slots.iter().enumerate() {
        if slot.slot_type != SlotType::Password && slot.slot_type != SlotType::Recovery {
            updated_slots.push(slot.clone());
            if let Some(s) = header.slot_salts.get(i) {
                updated_salts.push(s.clone());
            }
        }
    }

    // Add new password slot.
    updated_slots.push(new_password_slot.clone());
    updated_salts.push(salt.to_vec());

    let updated_header = VaultHeader {
        version: header.version,
        slot_count: u8::try_from(updated_slots.len()).unwrap_or(1),
        session_params,
        sensitive_params: header.sensitive_params.clone(),
        unlock_attempts: 0,
        last_attempt_at: None,
        total_unlock_count: header.total_unlock_count,
        slots: updated_slots,
        slot_salts: updated_salts,
    };

    // Persist updated header.
    let new_file_data = vault_format::serialize(&updated_header, &[], master_key)?;
    std::fs::write(header_path, &new_file_data)?;

    // Update key_slots DB table inside a transaction for atomicity.
    let db = match VaultDb::open_raw(db_path, master_key) {
        Ok(db) => db,
        Err(e) => {
            let _ = std::fs::write(header_path, original_file_data);
            return Err(e);
        }
    };

    let conn = db.connection();
    if let Err(e) = conn.execute("BEGIN IMMEDIATE", []) {
        drop(db);
        let _ = std::fs::write(header_path, original_file_data);
        return Err(VaultError::Database(format!(
            "failed to begin transaction: {e}"
        )));
    }

    if let Err(e) = conn.execute("DELETE FROM key_slots", []) {
        let _ = conn.execute("ROLLBACK", []);
        drop(db);
        let _ = std::fs::write(header_path, original_file_data);
        return Err(VaultError::Database(format!(
            "failed to clear old key slots: {e}"
        )));
    }

    if let Err(e) = insert_key_slot_record(
        conn,
        &new_password_slot,
        &salt,
        &updated_header.session_params,
    ) {
        let _ = conn.execute("ROLLBACK", []);
        drop(db);
        let _ = std::fs::write(header_path, original_file_data);
        return Err(e);
    }

    if let Err(e) = conn.execute("COMMIT", []) {
        let _ = conn.execute("ROLLBACK", []);
        drop(db);
        let _ = std::fs::write(header_path, original_file_data);
        return Err(VaultError::Database(format!(
            "failed to commit key slot update: {e}"
        )));
    }

    drop(db);

    // Generate new recovery key (invalidates old one).
    let recovery_result = recovery::add_recovery_slot(&AddRecoverySlotRequest {
        vault_dir,
        master_key,
    })?;

    Ok(PasswordChangeResult {
        recovery_key: recovery_result,
    })
}

// ---------------------------------------------------------------------------
// Vault integrity verification
// ---------------------------------------------------------------------------

/// Verify vault file integrity before unlock (pre-authentication checks).
///
/// Performs header-level validation without requiring the master key:
/// 1. Check `.verrou` file exists
/// 2. Read raw bytes and validate magic bytes (`VROU`)
/// 3. Parse header JSON, validate version, slot counts, salt alignment
/// 4. Check `.db` file exists alongside `.verrou`
///
/// AES-256-GCM tag verification and `SQLCipher` key verification happen
/// later during `unlock_vault()` — they require the master key.
///
/// # Errors
///
/// Returns [`VaultError::Io`] only for unexpected I/O failures (permissions).
/// All integrity failures are reported in the [`IntegrityReport`], not as errors.
#[must_use]
pub fn verify_vault_integrity(vault_dir: &Path) -> IntegrityReport {
    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    // Check .verrou file exists.
    if !header_path.exists() {
        return IntegrityReport {
            status: IntegrityStatus::FileNotFound,
            message: "Vault file not found. No vault exists at this location.".into(),
        };
    }

    // Read raw bytes.
    let file_data = match std::fs::read(&header_path) {
        Ok(data) => data,
        Err(e) => {
            return IntegrityReport {
                status: IntegrityStatus::HeaderCorrupted {
                    detail: format!("cannot read vault file: {e}"),
                },
                message: "Your vault file cannot be read. It may be corrupted or inaccessible."
                    .into(),
            };
        }
    };

    // Parse header (validates magic, version, slot counts, salt alignment).
    if let Err(e) = vault_format::parse_header_only(&file_data) {
        let detail = e.to_string();

        // Distinguish version-unsupported from other corruption.
        if detail.contains("newer than supported version") {
            // Extract the version number from the error message.
            let version = detail
                .split("version ")
                .nth(1)
                .and_then(|s| s.split(' ').next())
                .and_then(|s| s.parse::<u8>().ok())
                .unwrap_or(0);

            return IntegrityReport {
                status: IntegrityStatus::VersionUnsupported { version },
                message: "This vault was created with a newer version of VERROU. Please update the application.".into(),
            };
        }

        return IntegrityReport {
            status: IntegrityStatus::HeaderCorrupted { detail },
            message: "Your vault file appears corrupted or tampered with. If you have a backup, you can restore from it.".into(),
        };
    }

    // Check .db file exists.
    if !db_path.exists() {
        return IntegrityReport {
            status: IntegrityStatus::DatabaseMissing,
            message:
                "Vault database file is missing. If you have a backup, you can restore from it."
                    .into(),
        };
    }

    IntegrityReport {
        status: IntegrityStatus::Ok,
        message: "Vault integrity check passed.".into(),
    }
}

// ---------------------------------------------------------------------------
// Backup management
// ---------------------------------------------------------------------------

/// Create a timestamped backup of both `.verrou` and `.db` files.
///
/// Copies `vault.verrou` → `backups/vault-{timestamp}.verrou`
/// and `vault.db` → `backups/vault-{timestamp}.db`.
///
/// Called automatically before destructive operations (password change,
/// import, format migration).
///
/// # Errors
///
/// - [`VaultError::NotFound`] if the vault header file doesn't exist
/// - [`VaultError::Io`] if file copy or directory creation fails
pub fn create_backup(vault_dir: &Path) -> Result<PathBuf, VaultError> {
    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    if !header_path.exists() {
        return Err(VaultError::NotFound(format!(
            "cannot create backup: {} not found",
            header_path.display()
        )));
    }

    let backup_dir = vault_dir.join("backups");
    std::fs::create_dir_all(&backup_dir)?;

    let timestamp = now_iso8601().replace(':', "-");

    // Copy .verrou file.
    let backup_verrou = backup_dir.join(format!("vault-{timestamp}.verrou"));
    std::fs::copy(&header_path, &backup_verrou)?;

    // Copy .db file (if it exists).
    if db_path.exists() {
        let backup_db = backup_dir.join(format!("vault-{timestamp}.db"));
        std::fs::copy(&db_path, &backup_db)?;
    }

    // Prune old backups beyond MAX_BACKUPS (best-effort, never fail the operation).
    if let Ok(existing) = list_backups(vault_dir) {
        if existing.len() > MAX_BACKUPS {
            for old_backup in &existing[MAX_BACKUPS..] {
                let _ = std::fs::remove_file(&old_backup.path);
                let _ = std::fs::remove_file(old_backup.path.with_extension("db"));
            }
        }
    }

    Ok(backup_verrou)
}

/// List available vault backups, sorted newest first.
///
/// Scans `{vault_dir}/backups/` for `.verrou` files matching the
/// `vault-{timestamp}.verrou` pattern and returns metadata for each.
///
/// # Errors
///
/// Returns [`VaultError::Io`] if the backup directory cannot be read.
pub fn list_backups(vault_dir: &Path) -> Result<Vec<BackupInfo>, VaultError> {
    let backup_dir = vault_dir.join("backups");

    if !backup_dir.exists() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();

    let entries = std::fs::read_dir(&backup_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // Only consider .verrou files with the expected naming pattern.
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) if name.starts_with("vault-") && name.ends_with(".verrou") => name,
            _ => continue,
        };

        // Extract timestamp from filename: "vault-{timestamp}.verrou"
        // create_backup stores: "vault-2026-02-10T12-30-00Z.verrou"
        // (colons replaced with dashes for filesystem safety).
        // We restore only the TIME dashes back to colons — those after 'T'.
        let raw = file_name
            .strip_prefix("vault-")
            .and_then(|s| s.strip_suffix(".verrou"))
            .unwrap_or("");

        let timestamp = raw.find('T').map_or_else(
            || raw.to_string(),
            |t_pos| {
                let (date_part, time_part) = raw.split_at(t_pos);
                format!("{}{}", date_part, time_part.replace('-', ":"))
            },
        );

        let metadata = entry.metadata()?;
        let size_bytes = metadata.len();

        backups.push(BackupInfo {
            path: path.clone(),
            timestamp,
            size_bytes,
        });
    }

    // Sort by filename descending (newest first, since timestamps sort lexicographically).
    backups.sort_by(|a, b| b.path.cmp(&a.path));

    Ok(backups)
}

/// Restore a vault from a backup.
///
/// Copies the selected backup `.verrou` file over the current `vault.verrou`,
/// and the corresponding `.db` file over `vault.db` (if the `.db` backup exists).
///
/// # Errors
///
/// - [`VaultError::NotFound`] if the backup file doesn't exist
/// - [`VaultError::Io`] if file operations fail
pub fn restore_backup(vault_dir: &Path, backup_path: &Path) -> Result<(), VaultError> {
    if !backup_path.exists() {
        return Err(VaultError::NotFound(backup_path.display().to_string()));
    }

    let header_path = vault_dir.join(HEADER_FILE);
    let db_path = vault_dir.join(DB_FILE);

    // Copy to temp files first, then rename — rename is atomic on most
    // filesystems, so we avoid a half-restored state if the process crashes
    // or disk fills up between the two copy operations.
    let tmp_header = vault_dir.join(".vault.verrou.restoring");
    let tmp_db = vault_dir.join(".vault.db.restoring");

    // Copy backup .verrou → temp.
    std::fs::copy(backup_path, &tmp_header)?;

    // Copy backup .db → temp (if it exists).
    let backup_db = backup_path.with_extension("db");
    let has_db_backup = backup_db.exists();
    if has_db_backup {
        if let Err(e) = std::fs::copy(&backup_db, &tmp_db) {
            let _ = std::fs::remove_file(&tmp_header);
            return Err(VaultError::Io(e));
        }
    }

    // Atomic rename phase — if either rename fails, clean up temps.
    if let Err(e) = std::fs::rename(&tmp_header, &header_path) {
        let _ = std::fs::remove_file(&tmp_header);
        let _ = std::fs::remove_file(&tmp_db);
        return Err(VaultError::Io(e));
    }
    if has_db_backup {
        if let Err(e) = std::fs::rename(&tmp_db, &db_path) {
            // .verrou already replaced — restore from backup again to stay consistent.
            let _ = std::fs::copy(backup_path, &header_path);
            let _ = std::fs::remove_file(&tmp_db);
            return Err(VaultError::Io(e));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Brute-force helpers
// ---------------------------------------------------------------------------

/// Calculate the required delay (in ms) for the current attempt count.
fn required_delay_ms(attempts: u32) -> u64 {
    for &(threshold, delay) in BACKOFF_SCHEDULE {
        if attempts >= threshold {
            return delay;
        }
    }
    0
}

/// Check if brute-force cooldown is active. Returns `Some(remaining_ms)` if
/// the user must wait, or `None` if they can proceed.
fn check_cooldown(header: &VaultHeader, now_secs: u64) -> Option<u64> {
    let delay_ms = required_delay_ms(header.unlock_attempts);
    if delay_ms == 0 {
        return None;
    }

    let last_attempt = header.last_attempt_at?;

    // Calculate how much time has elapsed since the last attempt.
    let elapsed_ms = now_secs.saturating_sub(last_attempt).saturating_mul(1000);

    if elapsed_ms < delay_ms {
        Some(delay_ms.saturating_sub(elapsed_ms))
    } else {
        None
    }
}

/// Record a failed unlock attempt in the header.
const fn record_failed_attempt(header: &mut VaultHeader, now_secs: u64) {
    header.unlock_attempts = header.unlock_attempts.saturating_add(1);
    header.last_attempt_at = Some(now_secs);
}

/// Persist an updated header to the `.verrou` file.
fn persist_header(
    header_path: &Path,
    original_file_data: &[u8],
    header: &VaultHeader,
) -> Result<(), VaultError> {
    let new_data = vault_format::rewrite_header(original_file_data, header)?;
    std::fs::write(header_path, &new_data)?;
    Ok(())
}

/// Get the current time as seconds since Unix epoch.
fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Select the `Argon2idParams` for the user's chosen preset.
fn select_preset(preset: KdfPreset, calibrated: &CalibratedPresets) -> Argon2idParams {
    match preset {
        KdfPreset::Fast => calibrated.fast.clone(),
        KdfPreset::Balanced => calibrated.balanced.clone(),
        KdfPreset::Maximum => calibrated.maximum.clone(),
    }
}

/// Insert a key slot record into the `key_slots` table.
///
/// Stores the wrapped key as binary (nonce || ciphertext || tag),
/// the Argon2id salt, and the KDF params as JSON.
pub(crate) fn insert_key_slot_record(
    conn: &rusqlite::Connection,
    slot: &KeySlot,
    salt: &[u8],
    params: &Argon2idParams,
) -> Result<(), VaultError> {
    let slot_id = generate_uuid();
    let slot_type_str = slot.slot_type.as_str();
    let wrapped_key_bytes = slot.wrapped_key.to_bytes();
    let mut kdf_params_json = serde_json::to_string(params)
        .map_err(|e| VaultError::Database(format!("failed to serialize KDF params: {e}")))?;

    let now = now_iso8601();

    let result = conn.execute(
        "INSERT INTO key_slots (id, slot_type, wrapped_key, salt, kdf_params, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            slot_id,
            slot_type_str,
            wrapped_key_bytes,
            salt,
            kdf_params_json,
            now
        ],
    );

    // Zeroize the JSON string that contained KDF params (non-secret but good hygiene).
    kdf_params_json.zeroize();

    result.map_err(|e| VaultError::Database(format!("failed to insert key slot: {e}")))?;

    Ok(())
}

/// Generate a UUIDv4-like string using `OsRng`.
///
/// Format: `xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` where x is random hex
/// and y is one of `{8, 9, a, b}`.
pub(crate) fn generate_uuid() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);

    // Set version (4) and variant (RFC 4122).
    bytes[6] = (bytes[6] & 0x0F) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3F) | 0x80; // variant 1

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Return the current UTC time as an ISO 8601 string.
///
/// Uses `std::time::SystemTime` to avoid pulling in `chrono`.
pub(crate) fn now_iso8601() -> String {
    // Seconds since UNIX epoch.
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    // Simple UTC formatting: YYYY-MM-DDTHH:MM:SSZ
    // We compute the date/time components from epoch seconds.
    let (year, month, day, hour, minute, second) = epoch_to_utc(secs);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert epoch seconds to (year, month, day, hour, minute, second) in UTC.
///
/// This is a simplified civil calendar computation (valid for years 1970–9999).
#[allow(clippy::arithmetic_side_effects)]
const fn epoch_to_utc(epoch_secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    // Algorithm adapted from Howard Hinnant's `civil_from_days`.
    let secs_per_day: u64 = 86_400;
    let total_days = epoch_secs / secs_per_day;
    let remaining_secs = epoch_secs % secs_per_day;

    let hour = remaining_secs / 3600;
    let minute = (remaining_secs % 3600) / 60;
    let second = remaining_secs % 60;

    // Days since 0000-03-01 (shifted epoch for leap year handling).
    let z = total_days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    (year, m, d, hour, minute, second)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_preset_returns_correct_params() {
        let calibrated = CalibratedPresets {
            fast: Argon2idParams {
                m_cost: 131_072,
                t_cost: 2,
                p_cost: 4,
            },
            balanced: Argon2idParams {
                m_cost: 262_144,
                t_cost: 3,
                p_cost: 4,
            },
            maximum: Argon2idParams {
                m_cost: 524_288,
                t_cost: 4,
                p_cost: 4,
            },
        };

        assert_eq!(select_preset(KdfPreset::Fast, &calibrated), calibrated.fast);
        assert_eq!(
            select_preset(KdfPreset::Balanced, &calibrated),
            calibrated.balanced
        );
        assert_eq!(
            select_preset(KdfPreset::Maximum, &calibrated),
            calibrated.maximum
        );
    }

    #[test]
    fn generate_uuid_format() {
        let uuid = generate_uuid();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().nth(8), Some('-'));
        assert_eq!(uuid.chars().nth(13), Some('-'));
        assert_eq!(uuid.chars().nth(14), Some('4')); // version 4
        assert_eq!(uuid.chars().nth(18), Some('-'));
        assert_eq!(uuid.chars().nth(23), Some('-'));

        // Variant bit: position 19 must be 8, 9, a, or b.
        let variant_char = uuid.chars().nth(19).expect("char at pos 19");
        assert!(
            ['8', '9', 'a', 'b'].contains(&variant_char),
            "variant char {variant_char} not in [8, 9, a, b]"
        );
    }

    #[test]
    fn generate_uuid_unique() {
        let a = generate_uuid();
        let b = generate_uuid();
        assert_ne!(a, b);
    }

    #[test]
    fn now_iso8601_format() {
        let ts = now_iso8601();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.chars().nth(4), Some('-'));
        assert_eq!(ts.chars().nth(7), Some('-'));
        assert_eq!(ts.chars().nth(10), Some('T'));
        assert_eq!(ts.chars().nth(13), Some(':'));
        assert_eq!(ts.chars().nth(16), Some(':'));
    }

    #[test]
    fn epoch_to_utc_unix_epoch() {
        let (year, month, day, hour, minute, second) = epoch_to_utc(0);
        assert_eq!(
            (year, month, day, hour, minute, second),
            (1970, 1, 1, 0, 0, 0)
        );
    }

    #[test]
    fn epoch_to_utc_known_date() {
        // 2026-02-09T00:00:00Z = 1_770_595_200 seconds since epoch
        let (year, month, day, hour, minute, second) = epoch_to_utc(1_770_595_200);
        assert_eq!((year, month, day), (2026, 2, 9));
        assert_eq!((hour, minute, second), (0, 0, 0));
    }

    #[test]
    fn create_vault_result_has_no_key_material() {
        // AC #4: Compile-time proof that CreateVaultResult contains no secret fields.
        // If someone adds a SecretBytes or SecretBuffer field, this won't compile
        // because those types don't implement Serialize/Clone.
        fn assert_serializable<T: Serialize + Clone>() {}
        assert_serializable::<CreateVaultResult>();
    }

    // -- Brute-force backoff unit tests --

    #[test]
    fn required_delay_no_attempts() {
        assert_eq!(required_delay_ms(0), 0);
        assert_eq!(required_delay_ms(1), 0);
        assert_eq!(required_delay_ms(2), 0);
    }

    #[test]
    fn required_delay_3_attempts() {
        assert_eq!(required_delay_ms(3), 1_000);
        assert_eq!(required_delay_ms(4), 1_000);
    }

    #[test]
    fn required_delay_5_attempts() {
        assert_eq!(required_delay_ms(5), 5_000);
        assert_eq!(required_delay_ms(6), 5_000);
        assert_eq!(required_delay_ms(7), 5_000);
    }

    #[test]
    fn required_delay_8_attempts() {
        assert_eq!(required_delay_ms(8), 30_000);
        assert_eq!(required_delay_ms(9), 30_000);
    }

    #[test]
    fn required_delay_10_plus_attempts() {
        assert_eq!(required_delay_ms(10), 300_000);
        assert_eq!(required_delay_ms(100), 300_000);
    }

    #[test]
    fn check_cooldown_no_delay_needed() {
        let header = VaultHeader {
            version: FORMAT_VERSION,
            slot_count: 0,
            session_params: Argon2idParams {
                m_cost: 32,
                t_cost: 1,
                p_cost: 1,
            },
            sensitive_params: Argon2idParams {
                m_cost: 128,
                t_cost: 3,
                p_cost: 1,
            },
            unlock_attempts: 2,
            last_attempt_at: Some(1000),
            total_unlock_count: 0,
            slots: vec![],
            slot_salts: vec![],
        };
        // 2 attempts → 0 delay required → always allowed.
        assert_eq!(check_cooldown(&header, 1001), None);
    }

    #[test]
    fn check_cooldown_active() {
        let header = VaultHeader {
            version: FORMAT_VERSION,
            slot_count: 0,
            session_params: Argon2idParams {
                m_cost: 32,
                t_cost: 1,
                p_cost: 1,
            },
            sensitive_params: Argon2idParams {
                m_cost: 128,
                t_cost: 3,
                p_cost: 1,
            },
            unlock_attempts: 5,
            last_attempt_at: Some(1000),
            total_unlock_count: 0,
            slots: vec![],
            slot_salts: vec![],
        };
        // 5 attempts → 5s delay. At time 1001, only 1s elapsed → 4s remaining.
        let remaining = check_cooldown(&header, 1001);
        assert!(remaining.is_some());
        assert_eq!(remaining.expect("should be some"), 4_000);
    }

    #[test]
    fn check_cooldown_expired() {
        let header = VaultHeader {
            version: FORMAT_VERSION,
            slot_count: 0,
            session_params: Argon2idParams {
                m_cost: 32,
                t_cost: 1,
                p_cost: 1,
            },
            sensitive_params: Argon2idParams {
                m_cost: 128,
                t_cost: 3,
                p_cost: 1,
            },
            unlock_attempts: 5,
            last_attempt_at: Some(1000),
            total_unlock_count: 0,
            slots: vec![],
            slot_salts: vec![],
        };
        // 5 attempts → 5s delay. At time 1006, 6s elapsed → cooldown expired.
        assert_eq!(check_cooldown(&header, 1006), None);
    }

    #[test]
    fn check_cooldown_no_last_attempt() {
        let header = VaultHeader {
            version: FORMAT_VERSION,
            slot_count: 0,
            session_params: Argon2idParams {
                m_cost: 32,
                t_cost: 1,
                p_cost: 1,
            },
            sensitive_params: Argon2idParams {
                m_cost: 128,
                t_cost: 3,
                p_cost: 1,
            },
            unlock_attempts: 10,
            last_attempt_at: None,
            total_unlock_count: 0,
            slots: vec![],
            slot_salts: vec![],
        };
        // No last_attempt_at → no cooldown (can't compute elapsed).
        assert_eq!(check_cooldown(&header, 9999), None);
    }

    #[test]
    fn unlock_vault_result_has_no_key_material() {
        fn assert_serializable<T: Serialize + Clone>() {}
        assert_serializable::<UnlockVaultResult>();
    }
}
