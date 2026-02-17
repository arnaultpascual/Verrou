//! Paper backup IPC command.
//!
//! Generates a DTO containing all seed phrases and recovery codes
//! for print-based paper backup. Requires re-authentication (sensitive
//! operation — plaintext secrets are exposed).

#![allow(
    clippy::significant_drop_tightening,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use serde::Serialize;
use tauri::{Manager, State};
use zeroize::Zeroize;

use super::auth_utils::{constant_time_key_eq, err_json};
use crate::state::ManagedVaultState;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// A single seed phrase entry for paper backup.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedBackupEntry {
    /// Display name (e.g., "Bitcoin Wallet").
    pub name: String,
    /// Optional issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Individual BIP39 words.
    pub words: Vec<String>,
    /// Number of words (12, 15, 18, 21, or 24).
    pub word_count: usize,
    /// Whether a BIP39 passphrase (25th word) is associated.
    pub has_passphrase: bool,
}

// Safety: SeedBackupEntry contains secret seed words — never log or print.
impl std::fmt::Debug for SeedBackupEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SeedBackupEntry(***)")
    }
}

/// A single recovery code entry for paper backup.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryBackupEntry {
    /// Display name (e.g., "Google Account").
    pub name: String,
    /// Optional issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Individual recovery code strings.
    pub codes: Vec<String>,
    /// Indices of used codes.
    pub used: Vec<usize>,
    /// Total number of codes.
    pub total_codes: usize,
    /// Number of remaining (unused) codes.
    pub remaining_codes: usize,
}

// Safety: RecoveryBackupEntry contains secret recovery codes — never log or print.
impl std::fmt::Debug for RecoveryBackupEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryBackupEntry(***)")
    }
}

/// Complete paper backup data DTO returned to the frontend.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaperBackupDataDto {
    /// All seed phrase entries.
    pub seeds: Vec<SeedBackupEntry>,
    /// All recovery code entries.
    pub recovery_codes: Vec<RecoveryBackupEntry>,
    /// ISO 8601 generation timestamp.
    pub generated_at: String,
    /// Vault fingerprint (16 hex chars).
    pub vault_fingerprint: String,
    /// BLAKE3 checksum of serialized content.
    pub content_checksum: String,
}

// Safety: PaperBackupDataDto contains secret data — never log or print.
impl std::fmt::Debug for PaperBackupDataDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PaperBackupDataDto(***)")
    }
}

// ---------------------------------------------------------------------------
// IPC command
// ---------------------------------------------------------------------------

/// Generate paper backup data after re-authenticating with the master password.
///
/// Re-authentication verifies the password by deriving a wrapping key
/// and attempting to unwrap the password slot. On success, ALL seed phrase
/// and recovery code entries are decrypted and returned with integrity metadata.
///
/// # Errors
///
/// Returns a string error if:
/// - The vault is locked
/// - The password is incorrect
/// - The vault header cannot be read
#[tauri::command]
pub fn generate_paper_backup_data(
    mut password: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<PaperBackupDataDto, String> {
    // Step 1: Verify the vault is unlocked and copy the master key for comparison.
    let mut master_key_copy = [0u8; 32];
    {
        let state = vault_state.lock().map_err(|_| {
            err_json(
                "INTERNAL_ERROR",
                "Internal error: failed to acquire vault lock",
            )
        })?;
        let session = state
            .as_ref()
            .ok_or_else(|| err_json("VAULT_LOCKED", "Vault is locked. Please unlock first."))?;
        master_key_copy.copy_from_slice(session.master_key.expose());
    }

    // Step 2: Read vault header to get password slot and KDF params.
    let vault_path = app
        .path()
        .app_data_dir()
        .map_err(|_| err_json("INTERNAL_ERROR", "Failed to resolve vault directory."))?;
    let header_path = vault_path.join("vault.verrou");

    if !header_path.exists() {
        password.zeroize();
        master_key_copy.zeroize();
        return Err(err_json("INTERNAL_ERROR", "Vault not found."));
    }

    let file_data = std::fs::read(&header_path).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        err_json("IO_ERROR", "Failed to read vault header.")
    })?;

    let header = verrou_crypto_core::vault_format::parse_header_only(&file_data).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        err_json("INTERNAL_ERROR", "Failed to parse vault header.")
    })?;

    // Step 3: Find password slot and its salt.
    let (slot_index, password_slot) = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == verrou_crypto_core::slots::SlotType::Password)
        .ok_or_else(|| {
            password.zeroize();
            master_key_copy.zeroize();
            err_json("INTERNAL_ERROR", "No password slot found.")
        })?;

    let password_slot = password_slot.clone();

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            password.zeroize();
            master_key_copy.zeroize();
            err_json("INTERNAL_ERROR", "Missing salt for password slot.")
        })?
        .clone();

    // Step 4: Re-authenticate by deriving wrapping key and unwrapping slot.
    let wrapping_key =
        verrou_crypto_core::kdf::derive(password.as_bytes(), &salt, &header.session_params)
            .map_err(|_| {
                password.zeroize();
                master_key_copy.zeroize();
                err_json("INTERNAL_ERROR", "Key derivation failed.")
            })?;

    // Zeroize password immediately after derivation.
    password.zeroize();

    let recovered_key =
        verrou_crypto_core::slots::unwrap_slot(&password_slot, wrapping_key.expose()).map_err(
            |_| {
                master_key_copy.zeroize();
                err_json("INVALID_PASSWORD", "Incorrect password.")
            },
        )?;

    // Verify recovered key matches session master key (constant-time).
    if !constant_time_key_eq(recovered_key.expose(), &master_key_copy) {
        master_key_copy.zeroize();
        return Err(err_json("INVALID_PASSWORD", "Incorrect password."));
    }

    master_key_copy.zeroize();

    // Step 5: Password verified — fetch all seed phrases and recovery codes.
    let (seeds, recovery_codes) = {
        let state = vault_state.lock().map_err(|_| {
            err_json(
                "INTERNAL_ERROR",
                "Internal error: failed to acquire vault lock",
            )
        })?;
        let session = state
            .as_ref()
            .ok_or_else(|| err_json("VAULT_LOCKED", "Vault is locked. Please unlock first."))?;

        let entries = verrou_vault::list_entries(session.db.connection())
            .map_err(|e| err_json("INTERNAL_ERROR", &format!("Failed to list entries: {e}")))?;

        let mut seeds = Vec::new();
        let mut recovery = Vec::new();

        for item in &entries {
            match item.entry_type {
                verrou_vault::EntryType::SeedPhrase => {
                    let entry = verrou_vault::get_entry(
                        session.db.connection(),
                        &session.master_key,
                        &item.id,
                    )
                    .map_err(|e| {
                        err_json(
                            "INTERNAL_ERROR",
                            &format!("Failed to read seed phrase: {e}"),
                        )
                    })?;
                    if let verrou_vault::EntryData::SeedPhrase { words, passphrase } = &entry.data {
                        seeds.push(SeedBackupEntry {
                            name: entry.name.clone(),
                            issuer: entry.issuer.clone(),
                            words: words.clone(),
                            word_count: words.len(),
                            has_passphrase: passphrase.is_some(),
                        });
                    }
                }
                verrou_vault::EntryType::RecoveryCode => {
                    let entry = verrou_vault::get_entry(
                        session.db.connection(),
                        &session.master_key,
                        &item.id,
                    )
                    .map_err(|e| {
                        err_json(
                            "INTERNAL_ERROR",
                            &format!("Failed to read recovery codes: {e}"),
                        )
                    })?;
                    if let verrou_vault::EntryData::RecoveryCode { codes, used, .. } = &entry.data {
                        let used_indices: Vec<usize> = used.clone();
                        let total = codes.len();
                        let remaining = total.saturating_sub(used_indices.len());
                        recovery.push(RecoveryBackupEntry {
                            name: entry.name.clone(),
                            issuer: entry.issuer.clone(),
                            codes: codes.clone(),
                            used: used_indices,
                            total_codes: total,
                            remaining_codes: remaining,
                        });
                    }
                }
                _ => {} // Skip TOTP, HOTP, SecureNote, Credential
            }
        }

        (seeds, recovery)
    };

    // Step 6: Compute vault fingerprint from the .verrou file.
    let vault_fingerprint = verrou_vault::vault_fingerprint(&file_data);

    // Step 7: Compute BLAKE3 checksum of the serialized content.
    let generated_at = now_iso8601();
    let content_for_checksum = serde_json::json!({
        "seeds": seeds,
        "recoveryCodes": recovery_codes,
        "generatedAt": generated_at,
    });
    let content_json = serde_json::to_string(&content_for_checksum).map_err(|e| {
        err_json(
            "INTERNAL_ERROR",
            &format!("Failed to serialize content: {e}"),
        )
    })?;
    let content_checksum = {
        let hash = blake3::hash(content_json.as_bytes());
        hash.to_hex().to_string()
    };

    Ok(PaperBackupDataDto {
        seeds,
        recovery_codes,
        generated_at,
        vault_fingerprint,
        content_checksum,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Current UTC timestamp in ISO 8601 format.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_wrap)]
fn now_iso8601() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from Unix days (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}
