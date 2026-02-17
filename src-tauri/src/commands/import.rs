//! Import IPC commands for VERROU.
//!
//! Two-phase import flow (per source):
//! - Google Auth: `validate_google_auth_import` → `confirm_google_auth_import`
//! - Aegis: `validate_aegis_import` → `confirm_aegis_import`
//! - 2FAS: `validate_twofas_import` → `confirm_twofas_import`

// All IPC commands acquire a MutexGuard that borrows through `session`.
// Clippy's suggestion to merge temporaries is incorrect for this pattern.
#![allow(clippy::significant_drop_tightening)]

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::state::ManagedVaultState;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Request DTO for validating a Google Authenticator import.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateGoogleAuthRequest {
    /// The full `otpauth-migration://offline?data=...` URI
    /// or just the raw base64 payload.
    pub migration_data: String,
}

/// Preview of a single importable entry.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportEntryPreviewDto {
    /// Index in the parsed entries list (used to reference in confirm step).
    pub index: usize,
    /// Display name.
    pub name: String,
    /// Optional issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Entry type string (e.g., "totp", "hotp").
    pub entry_type: String,
    /// Algorithm string (e.g., "SHA1").
    pub algorithm: String,
    /// Digit count.
    pub digits: u32,
}

/// Duplicate entry information for the validation report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateInfoDto {
    /// Index in the parsed entries list.
    pub index: usize,
    /// Name of the parsed entry.
    pub name: String,
    /// Issuer of the parsed entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// ID of the existing vault entry.
    pub existing_id: String,
    /// Name of the existing vault entry.
    pub existing_name: String,
}

/// Unsupported entry information for the validation report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsupportedInfoDto {
    /// Index in the raw parsed data.
    pub index: usize,
    /// Name from the import data.
    pub name: String,
    /// Issuer from the import data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Reason the entry is unsupported.
    pub reason: String,
}

/// Malformed entry information for the validation report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MalformedInfoDto {
    /// Index in the raw parsed data.
    pub index: usize,
    /// Reason the entry is malformed.
    pub reason: String,
}

/// Full validation report returned by the validate phase.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationReportDto {
    /// Total entries found in the migration data.
    pub total_parsed: usize,
    /// Number of valid importable entries.
    pub valid_count: usize,
    /// Number of duplicate entries.
    pub duplicate_count: usize,
    /// Number of unsupported entries.
    pub unsupported_count: usize,
    /// Number of malformed entries.
    pub malformed_count: usize,
    /// Preview of valid entries.
    pub valid_entries: Vec<ImportEntryPreviewDto>,
    /// Details of duplicate entries.
    pub duplicates: Vec<DuplicateInfoDto>,
    /// Details of unsupported entries.
    pub unsupported: Vec<UnsupportedInfoDto>,
    /// Details of malformed entries.
    pub malformed: Vec<MalformedInfoDto>,
}

/// Request DTO for confirming a Google Authenticator import.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmGoogleAuthRequest {
    /// The same migration data from the validate step.
    pub migration_data: String,
    /// Indices of entries to skip (e.g., confirmed duplicates).
    #[serde(default)]
    pub skip_indices: Vec<usize>,
}

/// Result DTO for a completed import.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSummaryDto {
    /// Number of entries successfully imported.
    pub imported: usize,
    /// Number of entries skipped (duplicates + user choice).
    pub skipped: usize,
    /// IDs of the newly created entries.
    pub imported_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse migration data — accepts either a full URI or raw base64.
fn parse_migration(data: &str) -> Result<verrou_vault::import::google_auth::ParseResult, String> {
    if data.starts_with("otpauth-migration://") {
        verrou_vault::import::google_auth::parse_migration_uri(data)
            .map_err(|e| format!("Failed to parse migration data: {e}"))
    } else {
        // Try as raw base64
        let bytes = data_encoding::BASE64
            .decode(data.as_bytes())
            .map_err(|e| format!("Invalid migration data encoding: {e}"))?;
        verrou_vault::import::google_auth::parse_migration_payload(&bytes)
            .map_err(|e| format!("Failed to parse migration data: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Validate a Google Authenticator migration payload without importing.
///
/// Returns a report with valid entries, duplicates, unsupported, and
/// malformed entries so the user can preview before confirming.
///
/// # Errors
///
/// Returns a string error if the vault is locked or parsing fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn validate_google_auth_import(
    request: ValidateGoogleAuthRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<ValidationReportDto, String> {
    let parse_result = parse_migration(&request.migration_data)?;

    // Check duplicates against existing vault entries
    let duplicates = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

        verrou_vault::import::check_duplicates(session.db.connection(), &parse_result.entries)
            .map_err(|e| format!("Failed to check duplicates: {e}"))?
    };

    Ok(build_validation_report(
        &parse_result.entries,
        &duplicates,
        &parse_result.unsupported,
        &parse_result.malformed,
    ))
}

/// Confirm and execute a Google Authenticator import.
///
/// **Stateless re-parse design:** This command re-parses the same migration
/// data that was already parsed during `validate_google_auth_import`. This
/// is safe because protobuf deserialization is deterministic — the same bytes
/// always produce the same entries in the same order, so `skip_indices` from
/// the validate phase remain valid. The alternative (caching parsed entries
/// in server state between the two phases) would add session-management
/// complexity with no practical benefit.
///
/// # Errors
///
/// Returns a string error if the vault is locked, parsing fails,
/// or the transaction fails (fully rolled back on error).
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn confirm_google_auth_import(
    request: ConfirmGoogleAuthRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<ImportSummaryDto, String> {
    let parse_result = parse_migration(&request.migration_data)?;

    let summary = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

        verrou_vault::import::import_entries(
            session.db.connection(),
            &session.master_key,
            &parse_result.entries,
            &request.skip_indices,
        )
        .map_err(|e| format!("Import failed: {e}"))?
    };

    Ok(ImportSummaryDto {
        imported: summary.imported,
        skipped: summary.skipped,
        imported_ids: summary.imported_ids,
    })
}

// ---------------------------------------------------------------------------
// Aegis DTOs
// ---------------------------------------------------------------------------

/// Request DTO for validating an Aegis import.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateAegisRequest {
    /// The Aegis JSON vault export data.
    pub data: String,
    /// Password for encrypted exports (None for plaintext).
    pub password: Option<String>,
}

/// Request DTO for confirming an Aegis import.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmAegisRequest {
    /// The same Aegis JSON data from the validate step.
    pub data: String,
    /// Password for encrypted exports (None for plaintext).
    pub password: Option<String>,
    /// Indices of entries to skip.
    #[serde(default)]
    pub skip_indices: Vec<usize>,
}

// ---------------------------------------------------------------------------
// Aegis helpers
// ---------------------------------------------------------------------------

/// Parse an Aegis export (plaintext or encrypted).
fn parse_aegis(
    data: &str,
    password: Option<&str>,
) -> Result<verrou_vault::import::aegis::ParseResult, String> {
    let encrypted = verrou_vault::import::aegis::is_encrypted(data)
        .map_err(|e| format!("Failed to parse Aegis export: {e}"))?;

    if encrypted {
        let pw = password.ok_or_else(|| {
            "This Aegis export is encrypted. Please provide the vault password.".to_string()
        })?;
        verrou_vault::import::aegis::parse_aegis_encrypted(data, pw.as_bytes())
            .map_err(|e| format!("Failed to decrypt Aegis export: {e}"))
    } else {
        verrou_vault::import::aegis::parse_aegis_json(data)
            .map_err(|e| format!("Failed to parse Aegis export: {e}"))
    }
}

/// Build a `ValidationReportDto` from parsed entries, duplicates, and categorized info.
fn build_validation_report(
    entries: &[verrou_vault::import::ImportedEntry],
    duplicates: &[verrou_vault::import::DuplicateInfo],
    unsupported: &[verrou_vault::import::UnsupportedInfo],
    malformed: &[verrou_vault::import::MalformedInfo],
) -> ValidationReportDto {
    let total_parsed = entries
        .len()
        .saturating_add(unsupported.len())
        .saturating_add(malformed.len());

    let valid_entries: Vec<ImportEntryPreviewDto> = entries
        .iter()
        .enumerate()
        .map(|(idx, entry)| ImportEntryPreviewDto {
            index: idx,
            name: entry.name.clone(),
            issuer: entry.issuer.clone(),
            entry_type: entry.entry_type.as_db_str().to_string(),
            algorithm: entry.algorithm.as_db_str().to_string(),
            digits: entry.digits,
        })
        .collect();

    let duplicate_dtos: Vec<DuplicateInfoDto> = duplicates
        .iter()
        .map(|d| DuplicateInfoDto {
            index: d.index,
            name: d.name.clone(),
            issuer: d.issuer.clone(),
            existing_id: d.existing_id.clone(),
            existing_name: d.existing_name.clone(),
        })
        .collect();

    let unsupported_dtos: Vec<UnsupportedInfoDto> = unsupported
        .iter()
        .map(|u| UnsupportedInfoDto {
            index: u.index,
            name: u.name.clone(),
            issuer: u.issuer.clone(),
            reason: u.reason.clone(),
        })
        .collect();

    let malformed_dtos: Vec<MalformedInfoDto> = malformed
        .iter()
        .map(|m| MalformedInfoDto {
            index: m.index,
            reason: m.reason.clone(),
        })
        .collect();

    ValidationReportDto {
        total_parsed,
        valid_count: valid_entries.len(),
        duplicate_count: duplicate_dtos.len(),
        unsupported_count: unsupported_dtos.len(),
        malformed_count: malformed_dtos.len(),
        valid_entries,
        duplicates: duplicate_dtos,
        unsupported: unsupported_dtos,
        malformed: malformed_dtos,
    }
}

// ---------------------------------------------------------------------------
// Aegis Commands
// ---------------------------------------------------------------------------

/// Validate an Aegis vault export without importing.
///
/// Detects encrypted vs plaintext automatically. Returns a preview report.
///
/// # Errors
///
/// Returns a string error if the vault is locked, parsing/decryption fails,
/// or an encrypted export is missing a password.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn validate_aegis_import(
    request: ValidateAegisRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<ValidationReportDto, String> {
    let parse_result = parse_aegis(&request.data, request.password.as_deref())?;

    let duplicates = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

        verrou_vault::import::check_duplicates(session.db.connection(), &parse_result.entries)
            .map_err(|e| format!("Failed to check duplicates: {e}"))?
    };

    Ok(build_validation_report(
        &parse_result.entries,
        &duplicates,
        &parse_result.unsupported,
        &parse_result.malformed,
    ))
}

/// Confirm and execute an Aegis import.
///
/// **Stateless re-parse design:** Re-parses the same data from the validate
/// step. This is safe because JSON deserialization is deterministic — the
/// same input always produces the same entries in the same order.
///
/// # Errors
///
/// Returns a string error if the vault is locked, parsing/decryption fails,
/// or the transaction fails (fully rolled back on error).
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn confirm_aegis_import(
    request: ConfirmAegisRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<ImportSummaryDto, String> {
    let parse_result = parse_aegis(&request.data, request.password.as_deref())?;

    let summary = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

        verrou_vault::import::import_entries(
            session.db.connection(),
            &session.master_key,
            &parse_result.entries,
            &request.skip_indices,
        )
        .map_err(|e| format!("Import failed: {e}"))?
    };

    Ok(ImportSummaryDto {
        imported: summary.imported,
        skipped: summary.skipped,
        imported_ids: summary.imported_ids,
    })
}

// ---------------------------------------------------------------------------
// 2FAS DTOs
// ---------------------------------------------------------------------------

/// Request DTO for validating a 2FAS import.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateTwofasRequest {
    /// The 2FAS JSON backup export data.
    pub data: String,
    /// Password for encrypted exports (None for plaintext).
    pub password: Option<String>,
}

/// Request DTO for confirming a 2FAS import.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmTwofasRequest {
    /// The same 2FAS JSON data from the validate step.
    pub data: String,
    /// Password for encrypted exports (None for plaintext).
    pub password: Option<String>,
    /// Indices of entries to skip.
    #[serde(default)]
    pub skip_indices: Vec<usize>,
}

// ---------------------------------------------------------------------------
// 2FAS helpers
// ---------------------------------------------------------------------------

/// Parse a 2FAS export (plaintext or encrypted).
fn parse_twofas(
    data: &str,
    password: Option<&str>,
) -> Result<verrou_vault::import::twofas::ParseResult, String> {
    let encrypted = verrou_vault::import::twofas::is_encrypted(data)
        .map_err(|e| format!("Failed to parse 2FAS export: {e}"))?;

    if encrypted {
        let pw = password.ok_or_else(|| {
            "This 2FAS export is encrypted. Please provide the backup password.".to_string()
        })?;
        verrou_vault::import::twofas::parse_twofas_encrypted(data, pw.as_bytes())
            .map_err(|e| format!("Failed to decrypt 2FAS export: {e}"))
    } else {
        verrou_vault::import::twofas::parse_twofas_json(data)
            .map_err(|e| format!("Failed to parse 2FAS export: {e}"))
    }
}

// ---------------------------------------------------------------------------
// 2FAS Commands
// ---------------------------------------------------------------------------

/// Validate a 2FAS backup export without importing.
///
/// Detects encrypted vs plaintext automatically. Returns a preview report.
///
/// # Errors
///
/// Returns a string error if the vault is locked, parsing/decryption fails,
/// or an encrypted export is missing a password.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn validate_twofas_import(
    request: ValidateTwofasRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<ValidationReportDto, String> {
    let parse_result = parse_twofas(&request.data, request.password.as_deref())?;

    let duplicates = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

        verrou_vault::import::check_duplicates(session.db.connection(), &parse_result.entries)
            .map_err(|e| format!("Failed to check duplicates: {e}"))?
    };

    Ok(build_validation_report(
        &parse_result.entries,
        &duplicates,
        &parse_result.unsupported,
        &parse_result.malformed,
    ))
}

/// Confirm and execute a 2FAS import.
///
/// **Stateless re-parse design:** Re-parses the same data from the validate
/// step. This is safe because JSON deserialization is deterministic — the
/// same input always produces the same entries in the same order.
///
/// # Errors
///
/// Returns a string error if the vault is locked, parsing/decryption fails,
/// or the transaction fails (fully rolled back on error).
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn confirm_twofas_import(
    request: ConfirmTwofasRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<ImportSummaryDto, String> {
    let parse_result = parse_twofas(&request.data, request.password.as_deref())?;

    let summary = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

        verrou_vault::import::import_entries(
            session.db.connection(),
            &session.master_key,
            &parse_result.entries,
            &request.skip_indices,
        )
        .map_err(|e| format!("Import failed: {e}"))?
    };

    Ok(ImportSummaryDto {
        imported: summary.imported,
        skipped: summary.skipped,
        imported_ids: summary.imported_ids,
    })
}

// ---------------------------------------------------------------------------
// Verrou (.verrou file) DTOs
// ---------------------------------------------------------------------------

/// Request DTO for validating a .verrou vault import.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateVerrouImportRequest {
    /// Path to the .verrou file.
    pub file_path: String,
    /// Password used to encrypt the export file.
    pub password: String,
}

/// Preview of a .verrou import for the validation report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerrouImportPreviewDto {
    /// Total entries in the import file.
    pub total_entries: usize,
    /// Total folders in the import file.
    pub total_folders: usize,
    /// Total attachments in the import file.
    pub total_attachments: usize,
    /// Number of duplicate entries found.
    pub duplicate_count: usize,
    /// Preview of each entry.
    pub entries: Vec<VerrouEntryPreviewDto>,
    /// Details of duplicate entries.
    pub duplicates: Vec<VerrouDuplicateInfoDto>,
}

/// Preview of a single entry from the import file.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerrouEntryPreviewDto {
    /// Index in the import file's entry list.
    pub index: usize,
    /// Entry display name.
    pub name: String,
    /// Optional issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Entry type string.
    pub entry_type: String,
}

/// Duplicate entry information for the .verrou validation report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerrouDuplicateInfoDto {
    /// Index in the import file's entry list.
    pub index: usize,
    /// Name of the imported entry.
    pub name: String,
    /// Issuer of the imported entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Entry type string.
    pub entry_type: String,
    /// ID of the existing vault entry.
    pub existing_id: String,
    /// Name of the existing vault entry.
    pub existing_name: String,
}

/// Request DTO for confirming a .verrou vault import.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmVerrouImportRequest {
    /// Path to the .verrou file.
    pub file_path: String,
    /// Password used to encrypt the export file.
    pub password: String,
    /// How to handle duplicates: "skip" or "replace".
    pub duplicate_mode: String,
    /// Vault directory (for backup creation).
    pub vault_dir: String,
}

/// Result DTO for a completed .verrou import.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerrouImportResultDto {
    /// Number of entries imported.
    pub imported_entries: usize,
    /// Number of folders imported.
    pub imported_folders: usize,
    /// Number of attachments imported.
    pub imported_attachments: usize,
    /// Number of entries skipped as duplicates.
    pub skipped_duplicates: usize,
    /// Number of existing entries replaced.
    pub replaced_entries: usize,
}

// ---------------------------------------------------------------------------
// Verrou import helpers
// ---------------------------------------------------------------------------

/// Parse duplicate mode string to enum.
fn parse_duplicate_mode(mode: &str) -> Result<verrou_vault::DuplicateMode, String> {
    match mode {
        "skip" => Ok(verrou_vault::DuplicateMode::Skip),
        "replace" => Ok(verrou_vault::DuplicateMode::Replace),
        other => Err(format!(
            "Unknown duplicate mode: {other}. Expected 'skip' or 'replace'."
        )),
    }
}

/// Format a `VaultError` into a structured JSON error string for the frontend.
fn format_import_error(e: verrou_vault::VaultError) -> String {
    use super::vault::UnlockErrorResponse;

    match e {
        verrou_vault::VaultError::InvalidPassword => serde_json::to_string(&UnlockErrorResponse {
            code: "INVALID_PASSWORD".into(),
            message: "Incorrect password for this vault file. Please try again.".into(),
            remaining_ms: None,
        })
        .unwrap_or_else(|_| "Incorrect password.".into()),
        verrou_vault::VaultError::Import(ref msg) if msg.contains("newer version") => {
            serde_json::to_string(&UnlockErrorResponse {
                code: "IMPORT_VERSION_ERROR".into(),
                message: msg.clone(),
                remaining_ms: None,
            })
            .unwrap_or_else(|_| msg.clone())
        }
        verrou_vault::VaultError::Import(msg) => serde_json::to_string(&UnlockErrorResponse {
            code: "IMPORT_ERROR".into(),
            message: format!("Import failed: {msg}"),
            remaining_ms: None,
        })
        .unwrap_or_else(|_| format!("Import failed: {msg}")),
        other => serde_json::to_string(&UnlockErrorResponse {
            code: "IMPORT_ERROR".into(),
            message: format!("Import failed: {other}"),
            remaining_ms: None,
        })
        .unwrap_or_else(|_| format!("Import failed: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Verrou import commands
// ---------------------------------------------------------------------------

/// Validate a `.verrou` vault file for import.
///
/// Decrypts the file with the provided password, checks version compatibility,
/// and detects duplicates. Returns a preview report.
///
/// # Errors
///
/// Returns a structured JSON error string for invalid password, version
/// mismatch, or file format errors.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn validate_verrou_import(
    request: ValidateVerrouImportRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<VerrouImportPreviewDto, String> {
    let file_data = std::fs::read(&request.file_path)
        .map_err(|e| format!("Failed to read import file: {e}"))?;

    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let preview = verrou_vault::validate_verrou_import(
        session.db.connection(),
        &file_data,
        request.password.as_bytes(),
    )
    .map_err(format_import_error)?;

    Ok(VerrouImportPreviewDto {
        total_entries: preview.total_entries,
        total_folders: preview.total_folders,
        total_attachments: preview.total_attachments,
        duplicate_count: preview.duplicate_count,
        entries: preview
            .entries
            .iter()
            .map(|e| VerrouEntryPreviewDto {
                index: e.index,
                name: e.name.clone(),
                issuer: e.issuer.clone(),
                entry_type: e.entry_type.clone(),
            })
            .collect(),
        duplicates: preview
            .duplicates
            .iter()
            .map(|d| VerrouDuplicateInfoDto {
                index: d.index,
                name: d.name.clone(),
                issuer: d.issuer.clone(),
                entry_type: d.entry_type.clone(),
                existing_id: d.existing_id.clone(),
                existing_name: d.existing_name.clone(),
            })
            .collect(),
    })
}

/// Confirm and execute a `.verrou` vault import.
///
/// Re-decrypts the file, creates a backup, and imports entries/folders/attachments
/// in a single transaction. Returns a summary of the import.
///
/// # Errors
///
/// Returns a structured JSON error string for invalid password, version
/// mismatch, transaction failures, or file I/O errors.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub async fn confirm_verrou_import(
    request: ConfirmVerrouImportRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<VerrouImportResultDto, String> {
    let duplicate_mode = parse_duplicate_mode(&request.duplicate_mode)?;

    let file_data = std::fs::read(&request.file_path)
        .map_err(|e| format!("Failed to read import file: {e}"))?;

    let mut master_key_copy = [0u8; 32];
    {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;
        master_key_copy.copy_from_slice(session.master_key.expose());
    }

    let mut password = request.password;
    let vault_dir = request.vault_dir;

    tauri::async_runtime::spawn_blocking(move || {
        use zeroize::Zeroize;

        let vault_path = std::path::PathBuf::from(&vault_dir);

        let result = {
            let mut mk_array = [0u8; 32];
            mk_array.copy_from_slice(&master_key_copy);
            let master_key = verrou_crypto_core::memory::SecretBytes::<32>::new(mk_array);
            mk_array.zeroize();

            let db_path = vault_path.join("vault.db");
            let db = verrou_vault::VaultDb::open_raw(&db_path, &master_key_copy)
                .map_err(|e| format!("Failed to open vault database: {e}"))?;

            verrou_vault::import_verrou_file(
                db.connection(),
                &master_key,
                &file_data,
                password.as_bytes(),
                &vault_path,
                duplicate_mode,
            )
            .map_err(format_import_error)
        };

        master_key_copy.zeroize();
        password.zeroize();

        let result = result?;

        Ok(VerrouImportResultDto {
            imported_entries: result.imported_entries,
            imported_folders: result.imported_folders,
            imported_attachments: result.imported_attachments,
            skipped_duplicates: result.skipped_duplicates,
            replaced_entries: result.replaced_entries,
        })
    })
    .await
    .map_err(|e| format!("Import task failed: {e}"))?
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_report_dto_snapshot() {
        let dto = ValidationReportDto {
            total_parsed: 5,
            valid_count: 3,
            duplicate_count: 1,
            unsupported_count: 1,
            malformed_count: 0,
            valid_entries: vec![ImportEntryPreviewDto {
                index: 0,
                name: "user@example.com".into(),
                issuer: Some("GitHub".into()),
                entry_type: "totp".into(),
                algorithm: "SHA1".into(),
                digits: 6,
            }],
            duplicates: vec![DuplicateInfoDto {
                index: 1,
                name: "existing@test.com".into(),
                issuer: Some("Slack".into()),
                existing_id: "abc-123".into(),
                existing_name: "existing@test.com".into(),
            }],
            unsupported: vec![UnsupportedInfoDto {
                index: 2,
                name: "md5-user".into(),
                issuer: None,
                reason: "MD5 algorithm not supported".into(),
            }],
            malformed: vec![],
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn import_summary_dto_snapshot() {
        let dto = ImportSummaryDto {
            imported: 3,
            skipped: 2,
            imported_ids: vec!["id-1".into(), "id-2".into(), "id-3".into()],
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn validation_report_dto_camel_case() {
        let dto = ValidationReportDto {
            total_parsed: 1,
            valid_count: 1,
            duplicate_count: 0,
            unsupported_count: 0,
            malformed_count: 0,
            valid_entries: vec![ImportEntryPreviewDto {
                index: 0,
                name: "test".into(),
                issuer: None,
                entry_type: "totp".into(),
                algorithm: "SHA1".into(),
                digits: 6,
            }],
            duplicates: vec![],
            unsupported: vec![],
            malformed: vec![],
        };

        let json = serde_json::to_value(&dto).expect("serialize");
        let obj = json.as_object().expect("should be object");

        assert!(obj.contains_key("totalParsed"), "should have totalParsed");
        assert!(obj.contains_key("validCount"), "should have validCount");
        assert!(
            obj.contains_key("duplicateCount"),
            "should have duplicateCount"
        );
        assert!(obj.contains_key("validEntries"), "should have validEntries");

        assert!(
            !obj.contains_key("total_parsed"),
            "should NOT have snake_case"
        );
        assert!(
            !obj.contains_key("valid_count"),
            "should NOT have snake_case"
        );
    }

    #[test]
    fn import_entry_preview_dto_camel_case() {
        let dto = ImportEntryPreviewDto {
            index: 0,
            name: "test".into(),
            issuer: Some("TestIssuer".into()),
            entry_type: "totp".into(),
            algorithm: "SHA256".into(),
            digits: 8,
        };

        let json = serde_json::to_value(&dto).expect("serialize");
        let obj = json.as_object().expect("should be object");

        assert!(obj.contains_key("entryType"), "should have entryType");
        assert!(
            !obj.contains_key("entry_type"),
            "should NOT have snake_case"
        );
    }

    #[test]
    fn aegis_validate_request_dto_camel_case() {
        let json_str = r#"{"data":"{}","password":"secret"}"#;
        let dto: ValidateAegisRequest = serde_json::from_str(json_str).expect("deserialize");
        assert_eq!(dto.data, "{}");
        assert_eq!(dto.password.as_deref(), Some("secret"));
    }

    #[test]
    fn aegis_validate_request_dto_no_password() {
        let json_str = r#"{"data":"{}"}"#;
        let dto: ValidateAegisRequest = serde_json::from_str(json_str).expect("deserialize");
        assert!(dto.password.is_none());
    }

    #[test]
    fn aegis_confirm_request_dto_camel_case() {
        let json_str = r#"{"data":"{}","password":"pw","skipIndices":[0,2]}"#;
        let dto: ConfirmAegisRequest = serde_json::from_str(json_str).expect("deserialize");
        assert_eq!(dto.skip_indices, vec![0, 2]);
    }

    #[test]
    fn aegis_confirm_request_dto_defaults() {
        let json_str = r#"{"data":"{}"}"#;
        let dto: ConfirmAegisRequest = serde_json::from_str(json_str).expect("deserialize");
        assert!(dto.password.is_none());
        assert!(dto.skip_indices.is_empty());
    }

    #[test]
    fn twofas_validate_request_dto_camel_case() {
        let json_str = r#"{"data":"{}","password":"secret"}"#;
        let dto: ValidateTwofasRequest = serde_json::from_str(json_str).expect("deserialize");
        assert_eq!(dto.data, "{}");
        assert_eq!(dto.password.as_deref(), Some("secret"));
    }

    #[test]
    fn twofas_validate_request_dto_no_password() {
        let json_str = r#"{"data":"{}"}"#;
        let dto: ValidateTwofasRequest = serde_json::from_str(json_str).expect("deserialize");
        assert!(dto.password.is_none());
    }

    #[test]
    fn twofas_confirm_request_dto_camel_case() {
        let json_str = r#"{"data":"{}","password":"pw","skipIndices":[1,3]}"#;
        let dto: ConfirmTwofasRequest = serde_json::from_str(json_str).expect("deserialize");
        assert_eq!(dto.skip_indices, vec![1, 3]);
    }

    #[test]
    fn twofas_confirm_request_dto_defaults() {
        let json_str = r#"{"data":"{}"}"#;
        let dto: ConfirmTwofasRequest = serde_json::from_str(json_str).expect("deserialize");
        assert!(dto.password.is_none());
        assert!(dto.skip_indices.is_empty());
    }
}
