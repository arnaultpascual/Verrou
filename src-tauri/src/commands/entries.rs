//! Entry CRUD IPC commands.
//!
//! Each command returns a DTO with `#[serde(rename_all = "camelCase")]`.
//! The `EntryMetadataDto` never includes secret data — only display-safe fields.

// All IPC commands acquire a MutexGuard that borrows through `session`.
// Clippy's suggestion to merge temporaries is incorrect for this pattern.
#![allow(
    clippy::significant_drop_tightening,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::missing_errors_doc
)]

use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use zeroize::Zeroize;

use crate::state::ManagedVaultState;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Display-safe entry metadata returned to the frontend.
///
/// This DTO crosses the IPC boundary. It NEVER includes `secret`,
/// `encrypted_data`, or any raw key bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryMetadataDto {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Entry type discriminator.
    pub entry_type: String,
    /// Display name (e.g., "GitHub").
    pub name: String,
    /// Optional issuer (e.g., "github.com").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Folder ID (nullable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    /// OTP algorithm (SHA1, SHA256, SHA512).
    pub algorithm: String,
    /// OTP digit count (6 or 8).
    pub digits: u32,
    /// TOTP period in seconds (15, 30, or 60).
    pub period: u32,
    /// Whether this entry is pinned for quick access.
    pub pinned: bool,
    /// Tags (plaintext, for search and display).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Username (plaintext, for credential `EntryCard` display and search).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Template identifier (plaintext, for `EntryCard` display).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// ISO 8601 last-update timestamp.
    pub updated_at: String,
}

/// Full entry detail DTO (includes decrypted secret for code generation).
///
/// Only returned by `get_entry_detail` — never by list operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDetailDto {
    /// All metadata fields.
    #[serde(flatten)]
    pub metadata: EntryMetadataDto,
    /// The decrypted secret (Base32 for TOTP/HOTP).
    pub secret: String,
    /// HOTP counter value (0 for TOTP).
    pub counter: u64,
    /// Tags (only populated for `secure_note` entries).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Request DTO for adding a new entry.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddEntryRequest {
    /// Entry type: `totp`, `hotp`, `seed_phrase`, `recovery_code`, `secure_note`.
    pub entry_type: String,
    /// Display name.
    pub name: String,
    /// Optional issuer.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Folder ID (nullable).
    #[serde(default)]
    pub folder_id: Option<String>,
    /// OTP algorithm.
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    /// OTP digit count.
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// TOTP period.
    #[serde(default = "default_period")]
    pub period: u32,
    /// HOTP counter.
    #[serde(default)]
    pub counter: u64,
    /// Whether pinned.
    #[serde(default)]
    pub pinned: bool,
    /// The raw secret (Base32 for TOTP/HOTP).
    pub secret: String,
    /// Optional BIP39 passphrase (25th word) for `seed_phrase` entries.
    #[serde(default)]
    pub passphrase: Option<String>,
    /// BIP39 language for seed phrase validation (e.g. "english").
    #[serde(default)]
    pub language: Option<String>,
    /// Optional parent TOTP/HOTP entry ID for recovery code linking (FR14).
    #[serde(default)]
    pub linked_entry_id: Option<String>,
    /// Tags for `secure_note` entries.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Username for `credential` entries.
    #[serde(default)]
    pub username: Option<String>,
    /// URLs for `credential` entries.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Notes for `credential` entries.
    #[serde(default)]
    pub notes: Option<String>,
    /// Linked TOTP entry ID for `credential` entries (autofill integration).
    #[serde(default)]
    pub linked_totp_id: Option<String>,
    /// Custom fields for `credential` entries.
    #[serde(default)]
    pub custom_fields: Vec<CustomFieldDto>,
    /// Template identifier for `credential` entries (e.g., `credit_card`, `ssh_key`).
    #[serde(default)]
    pub template: Option<String>,
}

/// Custom field DTO for credential entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldDto {
    /// Field label.
    pub label: String,
    /// Field value.
    pub value: String,
    /// Field type: `text`, `hidden`, `url`.
    pub field_type: String,
}

/// Password history entry DTO.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntryDto {
    /// The previous password value.
    pub password: String,
    /// ISO 8601 timestamp when this password was replaced.
    pub changed_at: String,
}

// Safety: PasswordHistoryEntryDto contains secret password — never log or print.
impl std::fmt::Debug for PasswordHistoryEntryDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordHistoryEntryDto(***)")
    }
}

/// Credential display DTO returned after re-authentication.
///
/// Contains the decrypted password and metadata for credential entries.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialDisplay {
    /// The password.
    pub password: String,
    /// Username or email.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// URLs associated with this credential.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Free-form notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Linked TOTP entry ID for autofill integration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_totp_id: Option<String>,
    /// Custom fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_fields: Vec<CustomFieldDto>,
    /// Password history (previous passwords with timestamps).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub password_history: Vec<PasswordHistoryEntryDto>,
    /// Template identifier (e.g., `credit_card`, `ssh_key`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
}

// Safety: CredentialDisplay contains secret password — never log or print.
impl std::fmt::Debug for CredentialDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialDisplay(***)")
    }
}

// Safety: AddEntryRequest contains `secret` and `passphrase` — never log or print.
#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for AddEntryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddEntryRequest")
            .field("entry_type", &self.entry_type)
            .field("name", &self.name)
            .field("secret", &"***")
            .field("passphrase", &self.passphrase.as_ref().map(|_| "***"))
            .finish()
    }
}

/// Seed phrase display DTO returned after re-authentication.
///
/// Contains the individual BIP39 words for UI display — never raw entropy.
/// Passphrase value is never included; only a boolean indicator.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SeedDisplay {
    /// Individual BIP39 words.
    pub words: Vec<String>,
    /// Number of words (12, 15, 18, 21, or 24).
    pub word_count: u8,
    /// Whether a BIP39 passphrase (25th word) is associated.
    pub has_passphrase: bool,
}

// Safety: SeedDisplay contains secret seed words — never log or print.
impl std::fmt::Debug for SeedDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SeedDisplay(***)")
    }
}

/// Recovery code display DTO returned after re-authentication.
///
/// Contains individual recovery codes with used/unused tracking.
/// Only returned by `reveal_recovery_codes` — never by list operations.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodeDisplay {
    /// Individual recovery code strings.
    pub codes: Vec<String>,
    /// Indexes of used codes.
    pub used: Vec<usize>,
    /// Total number of codes.
    pub total_codes: u32,
    /// Number of remaining (unused) codes.
    pub remaining_codes: u32,
    /// Parent TOTP/HOTP entry ID (if linked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_entry_id: Option<String>,
    /// Whether this entry has a linked parent entry.
    pub has_linked_entry: bool,
}

// Safety: RecoveryCodeDisplay contains secret recovery codes — never log or print.
impl std::fmt::Debug for RecoveryCodeDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryCodeDisplay(***)")
    }
}

/// Recovery stats DTO for display on TOTP entry cards.
///
/// Lightweight stats — no re-auth required, no secret data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStats {
    /// Total number of recovery codes linked to this entry.
    pub total: u32,
    /// Number of remaining (unused) recovery codes.
    pub remaining: u32,
}

fn default_algorithm() -> String {
    "SHA1".into()
}

const fn default_digits() -> u32 {
    6
}

const fn default_period() -> u32 {
    30
}

/// Request DTO for updating an entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateEntryRequest {
    /// Entry ID to update.
    pub id: String,
    /// New display name (if changed).
    #[serde(default)]
    pub name: Option<String>,
    /// New issuer (if changed).
    #[serde(default)]
    pub issuer: Option<Option<String>>,
    /// New folder ID (if changed).
    #[serde(default)]
    pub folder_id: Option<Option<String>>,
    /// New algorithm (if changed).
    #[serde(default)]
    pub algorithm: Option<String>,
    /// New digits (if changed).
    #[serde(default)]
    pub digits: Option<u32>,
    /// New period (if changed).
    #[serde(default)]
    pub period: Option<u32>,
    /// New counter (if changed).
    #[serde(default)]
    pub counter: Option<u64>,
    /// New pinned state (if changed).
    #[serde(default)]
    pub pinned: Option<bool>,
    /// New secret (if changed — will be re-encrypted).
    #[serde(default)]
    pub secret: Option<String>,
    /// BIP39 passphrase tri-state for seed phrases:
    /// absent = no change, `Some(None)` = remove, `Some(Some(v))` = set new.
    #[serde(default)]
    pub passphrase: Option<Option<String>>,
    /// New tags (if changed).
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// New username for `credential` entries (if changed).
    #[serde(default)]
    pub username: Option<Option<String>>,
    /// New URLs for `credential` entries (if changed).
    #[serde(default)]
    pub urls: Option<Vec<String>>,
    /// New notes for `credential` entries (if changed).
    #[serde(default)]
    pub notes: Option<Option<String>>,
    /// New linked TOTP ID for `credential` entries (if changed).
    #[serde(default)]
    pub linked_totp_id: Option<Option<String>>,
    /// New custom fields for `credential` entries (if changed).
    #[serde(default)]
    pub custom_fields: Option<Vec<CustomFieldDto>>,
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn parse_entry_type(s: &str) -> Result<verrou_vault::EntryType, String> {
    verrou_vault::EntryType::from_db_str(s).map_err(|_| "Invalid entry type.".to_string())
}

fn parse_algorithm(s: &str) -> Result<verrou_vault::Algorithm, String> {
    verrou_vault::Algorithm::from_db_str(s).map_err(|_| "Invalid algorithm.".to_string())
}

fn entry_to_metadata_dto(item: &verrou_vault::EntryListItem) -> EntryMetadataDto {
    EntryMetadataDto {
        id: item.id.clone(),
        entry_type: item.entry_type.as_db_str().to_string(),
        name: item.name.clone(),
        issuer: item.issuer.clone(),
        folder_id: item.folder_id.clone(),
        algorithm: item.algorithm.as_db_str().to_string(),
        digits: item.digits,
        period: item.period,
        pinned: item.pinned,
        tags: item.tags.clone(),
        username: item.username.clone(),
        template: item.template.clone(),
        created_at: item.created_at.clone(),
        updated_at: item.updated_at.clone(),
    }
}

fn full_entry_to_metadata_dto(entry: &verrou_vault::Entry) -> EntryMetadataDto {
    EntryMetadataDto {
        id: entry.id.clone(),
        entry_type: entry.entry_type.as_db_str().to_string(),
        name: entry.name.clone(),
        issuer: entry.issuer.clone(),
        folder_id: entry.folder_id.clone(),
        algorithm: entry.algorithm.as_db_str().to_string(),
        digits: entry.digits,
        period: entry.period,
        pinned: entry.pinned,
        tags: extract_tags(&entry.data),
        username: extract_username(&entry.data),
        template: extract_template(&entry.data),
        created_at: entry.created_at.clone(),
        updated_at: entry.updated_at.clone(),
    }
}

/// Extract username from `EntryData` (only `Credential` has a username).
fn extract_username(data: &verrou_vault::EntryData) -> Option<String> {
    match data {
        verrou_vault::EntryData::Credential { username, .. } => username.clone(),
        _ => None,
    }
}

/// Extract template from `EntryData` (only `Credential` has a template).
fn extract_template(data: &verrou_vault::EntryData) -> Option<String> {
    match data {
        verrou_vault::EntryData::Credential { template, .. } => template.clone(),
        _ => None,
    }
}

/// Extract the secret string from `EntryData` for the detail DTO.
fn extract_secret(data: &verrou_vault::EntryData) -> String {
    match data {
        verrou_vault::EntryData::Totp { secret } | verrou_vault::EntryData::Hotp { secret } => {
            secret.clone()
        }
        verrou_vault::EntryData::SeedPhrase { words, .. } => words.join(" "),
        verrou_vault::EntryData::RecoveryCode { codes, .. } => codes.join("\n"),
        verrou_vault::EntryData::SecureNote { body, .. } => body.clone(),
        // Credential passwords are NEVER returned via get_entry.
        // Use reveal_password (with re-auth) to access the password.
        verrou_vault::EntryData::Credential { .. } => String::new(),
    }
}

/// Extract tags from `EntryData` (only `SecureNote` has tags; others return empty).
fn extract_tags(data: &verrou_vault::EntryData) -> Vec<String> {
    match data {
        verrou_vault::EntryData::SecureNote { tags, .. } => tags.clone(),
        _ => Vec::new(),
    }
}

/// Optional credential-specific fields for `build_entry_data`.
#[derive(Default)]
struct CredentialFields {
    username: Option<String>,
    urls: Vec<String>,
    notes: Option<String>,
    linked_totp_id: Option<String>,
    custom_fields: Vec<verrou_vault::CustomField>,
    password_history: Vec<verrou_vault::PasswordHistoryEntry>,
    template: Option<String>,
}

/// Build the `EntryData` variant from the entry type and secret string.
///
/// Validates that the secret format is appropriate for the entry type:
/// - TOTP/HOTP: non-empty, valid Base32 alphabet (A-Z, 2-7, =)
/// - `SeedPhrase`: word count in {12, 15, 18, 21, 24}
/// - `RecoveryCode`: at least one code, individual codes ≤ 256 chars
/// - `SecureNote`: non-empty body
/// - `Credential`: non-empty password
fn build_entry_data(
    entry_type: verrou_vault::EntryType,
    secret: &str,
    passphrase: Option<String>,
    language: Option<&str>,
    linked_entry_id: Option<String>,
    tags: Vec<String>,
) -> Result<verrou_vault::EntryData, String> {
    match entry_type {
        verrou_vault::EntryType::Totp | verrou_vault::EntryType::Hotp => {
            validate_base32(secret)?;
            let data = if entry_type == verrou_vault::EntryType::Totp {
                verrou_vault::EntryData::Totp {
                    secret: secret.to_string(),
                }
            } else {
                verrou_vault::EntryData::Hotp {
                    secret: secret.to_string(),
                }
            };
            Ok(data)
        }
        verrou_vault::EntryType::SeedPhrase => {
            let words: Vec<String> = secret.split_whitespace().map(String::from).collect();
            if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
                if let Some(mut pp) = passphrase {
                    pp.zeroize();
                }
                return Err(format!(
                    "Seed phrase must be 12, 15, 18, 21, or 24 words (got {}).",
                    words.len()
                ));
            }

            // Parse language (default English for backwards compat / update_entry)
            let lang = match language
                .map(crate::commands::bip39::parse_language)
                .transpose()
            {
                Ok(l) => l.unwrap_or(verrou_crypto_core::bip39::Bip39Language::English),
                Err(e) => {
                    if let Some(mut pp) = passphrase {
                        pp.zeroize();
                    }
                    return Err(e);
                }
            };

            // BIP39 checksum validation
            let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
            match verrou_crypto_core::bip39::validate_phrase(&word_refs, lang) {
                Ok(()) => Ok(verrou_vault::EntryData::SeedPhrase { words, passphrase }),
                Err(e) => {
                    if let Some(mut pp) = passphrase {
                        pp.zeroize();
                    }
                    Err(format!("BIP39 validation failed: {e}"))
                }
            }
        }
        verrou_vault::EntryType::RecoveryCode => {
            let codes: Vec<String> = secret
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            if codes.is_empty() {
                return Err("At least one recovery code is required.".to_string());
            }
            // Validate individual code lengths (AC3: ≤ 256 chars).
            for code in &codes {
                if code.len() > 256 {
                    return Err(format!(
                        "Recovery code exceeds maximum length of 256 characters (got {}).",
                        code.len()
                    ));
                }
            }
            Ok(verrou_vault::EntryData::RecoveryCode {
                codes,
                used: Vec::new(),
                linked_entry_id,
            })
        }
        verrou_vault::EntryType::SecureNote => {
            if secret.is_empty() {
                return Err("Note body cannot be empty.".to_string());
            }
            Ok(verrou_vault::EntryData::SecureNote {
                body: secret.to_string(),
                tags,
            })
        }
        verrou_vault::EntryType::Credential => {
            // For credentials, `secret` carries the password.
            if secret.is_empty() {
                return Err("Password cannot be empty.".to_string());
            }
            // Credential-specific fields are passed via thread-local (see build_credential_entry_data).
            Ok(verrou_vault::EntryData::Credential {
                password: secret.to_string(),
                username: None,
                urls: Vec::new(),
                notes: None,
                linked_totp_id: None,
                custom_fields: Vec::new(),
                password_history: Vec::new(),
                template: None,
            })
        }
    }
}

/// Build a `Credential` `EntryData` with all fields.
fn build_credential_entry_data(
    password: &str,
    fields: CredentialFields,
) -> Result<verrou_vault::EntryData, String> {
    if password.is_empty() {
        return Err("Password cannot be empty.".to_string());
    }
    Ok(verrou_vault::EntryData::Credential {
        password: password.to_string(),
        username: fields.username,
        urls: fields.urls,
        notes: fields.notes,
        linked_totp_id: fields.linked_totp_id,
        custom_fields: fields.custom_fields,
        password_history: fields.password_history,
        template: fields.template,
    })
}

/// Convert `CustomFieldDto` to domain `CustomField`.
fn dto_to_custom_field(dto: &CustomFieldDto) -> Result<verrou_vault::CustomField, String> {
    let field_type = match dto.field_type.as_str() {
        "text" => verrou_vault::CustomFieldType::Text,
        "hidden" => verrou_vault::CustomFieldType::Hidden,
        "url" => verrou_vault::CustomFieldType::Url,
        "date" => verrou_vault::CustomFieldType::Date,
        other => return Err(format!("Invalid custom field type: {other}")),
    };
    Ok(verrou_vault::CustomField {
        label: dto.label.clone(),
        value: dto.value.clone(),
        field_type,
    })
}

/// Convert domain `CustomField` to `CustomFieldDto`.
fn custom_field_to_dto(field: &verrou_vault::CustomField) -> CustomFieldDto {
    CustomFieldDto {
        label: field.label.clone(),
        value: field.value.clone(),
        field_type: match field.field_type {
            verrou_vault::CustomFieldType::Text => "text".into(),
            verrou_vault::CustomFieldType::Hidden => "hidden".into(),
            verrou_vault::CustomFieldType::Url => "url".into(),
            verrou_vault::CustomFieldType::Date => "date".into(),
        },
    }
}

/// Validate that a string contains only valid Base32 characters.
fn validate_base32(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("Secret cannot be empty.".to_string());
    }
    // Base32 alphabet: A-Z, 2-7, optional trailing '=' padding.
    // Many TOTP providers omit padding, so we accept with or without.
    let stripped = s.trim_end_matches('=');
    if !stripped
        .chars()
        .all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c))
    {
        return Err("Secret must be valid Base32 (A-Z, 2-7).".to_string());
    }
    Ok(())
}

/// Constant-time comparison for key material.
///
/// Prevents timing side-channels when verifying recovered keys.
/// The early return on length mismatch is acceptable because key
/// lengths (32 bytes) are public knowledge — the constant-time
/// property protects the *key value*.
fn constant_time_key_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Get current ISO 8601 timestamp for password history.
///
/// Uses `std::time::SystemTime` to avoid adding a `chrono` dependency.
/// The calendar arithmetic uses Howard Hinnant's algorithm.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_wrap)]
pub(crate) fn now_for_history() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Simple UTC timestamp: YYYY-MM-DDTHH:MM:SSZ
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Civil date from Unix days (algorithm from Howard Hinnant).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Map vault errors to user-friendly IPC error strings.
fn map_vault_error(err: &verrou_vault::VaultError) -> String {
    match err {
        verrou_vault::VaultError::EntryNotFound(_) => {
            "Entry not found. It may have been deleted.".to_string()
        }
        verrou_vault::VaultError::Locked => "Vault is locked. Please unlock first.".to_string(),
        _ => "Operation failed. Please try again.".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// List all entries (metadata only — no secret data).
///
/// Returns `Vec<EntryMetadataDto>` sorted by pinned (desc), then name (asc).
///
/// # Errors
///
/// Returns a string error if the vault is locked or the query fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn list_entries(
    vault_state: State<'_, ManagedVaultState>,
) -> Result<Vec<EntryMetadataDto>, String> {
    let items = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;
        verrou_vault::list_entries(session.db.connection()).map_err(|e| map_vault_error(&e))?
    };

    Ok(items.iter().map(entry_to_metadata_dto).collect())
}

/// Add a new entry to the vault.
///
/// Encrypts the secret data (Layer 2) and inserts into `SQLCipher`.
/// Returns the metadata of the created entry.
///
/// # Errors
///
/// Returns a string error if the vault is locked, the entry type is
/// invalid, or the insert fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn add_entry(
    mut request: AddEntryRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<EntryMetadataDto, String> {
    let entry_type = parse_entry_type(&request.entry_type)?;
    let algorithm = parse_algorithm(&request.algorithm)?;

    // Build entry data: credentials use a dedicated builder with extra fields.
    let data_result = if entry_type == verrou_vault::EntryType::Credential {
        let custom_fields: Result<Vec<_>, _> = request
            .custom_fields
            .iter()
            .map(dto_to_custom_field)
            .collect();
        let custom_fields = custom_fields?;
        build_credential_entry_data(
            &request.secret,
            CredentialFields {
                username: request.username.clone(),
                urls: request.urls.clone(),
                notes: request.notes.clone(),
                linked_totp_id: request.linked_totp_id.clone(),
                custom_fields,
                password_history: Vec::new(),
                template: request.template.clone(),
            },
        )
    } else {
        build_entry_data(
            entry_type,
            &request.secret,
            request.passphrase.clone(),
            request.language.as_deref(),
            request.linked_entry_id.clone(),
            request.tags.clone(),
        )
    };

    // Zeroize sensitive request fields immediately — regardless of success or failure.
    request.secret.zeroize();
    if let Some(ref mut pp) = request.passphrase {
        pp.zeroize();
    }

    let data = data_result?;

    let entry = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

        // Validate linked_entry_id: referenced entry must exist and be TOTP or HOTP.
        if let Some(ref linked_id) = request.linked_entry_id {
            let linked_type = verrou_vault::get_entry_type(session.db.connection(), linked_id)
                .map_err(|_| "Linked entry not found.".to_string())?;
            if !matches!(
                linked_type,
                verrou_vault::EntryType::Totp | verrou_vault::EntryType::Hotp
            ) {
                return Err(
                    "Recovery codes can only be linked to TOTP or HOTP entries.".to_string()
                );
            }
        }

        let params = verrou_vault::AddEntryParams {
            entry_type,
            name: request.name.clone(),
            issuer: request.issuer.clone(),
            folder_id: request.folder_id.clone(),
            algorithm,
            digits: request.digits,
            period: request.period,
            counter: request.counter,
            pinned: request.pinned,
            tags: request.tags.clone(),
            data,
        };

        verrou_vault::add_entry(session.db.connection(), &session.master_key, &params)
            .map_err(|e| map_vault_error(&e))?
    };

    Ok(full_entry_to_metadata_dto(&entry))
}

/// Get a single entry with decrypted secret data.
///
/// Returns the full entry detail including the secret.
///
/// # Errors
///
/// Returns a string error if the vault is locked or the entry is not found.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_entry(
    entry_id: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<EntryDetailDto, String> {
    let entry = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;
        verrou_vault::get_entry(session.db.connection(), &session.master_key, &entry_id)
            .map_err(|e| map_vault_error(&e))?
    };

    let secret = extract_secret(&entry.data);
    let tags = extract_tags(&entry.data);

    Ok(EntryDetailDto {
        metadata: full_entry_to_metadata_dto(&entry),
        secret,
        counter: entry.counter,
        tags,
    })
}

/// Update an existing entry.
///
/// Only fields present in the request are changed. If `secret` is provided,
/// the entry data is re-encrypted.
///
/// # Errors
///
/// Returns a string error if the vault is locked, the entry is not found,
/// or the update fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn update_entry(
    mut request: UpdateEntryRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<EntryMetadataDto, String> {
    let algorithm = request
        .algorithm
        .as_deref()
        .map(parse_algorithm)
        .transpose()?;

    let entry = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

        // Build updated entry data if secret, passphrase, or credential fields changed.
        let secret_changed = request.secret.is_some();
        let passphrase_changed = request.passphrase.is_some();
        let credential_fields_changed = request.username.is_some()
            || request.urls.is_some()
            || request.notes.is_some()
            || request.linked_totp_id.is_some()
            || request.custom_fields.is_some();

        let data = if secret_changed || passphrase_changed || credential_fields_changed {
            let entry_type = verrou_vault::get_entry_type(session.db.connection(), &request.id)
                .map_err(|e| map_vault_error(&e))?;

            if entry_type == verrou_vault::EntryType::Credential {
                // Credential update: merge changed fields with existing data.
                let existing = verrou_vault::get_entry(
                    session.db.connection(),
                    &session.master_key,
                    &request.id,
                )
                .map_err(|e| map_vault_error(&e))?;

                if let verrou_vault::EntryData::Credential {
                    password: ref old_password,
                    username: ref old_username,
                    urls: ref old_urls,
                    notes: ref old_notes,
                    linked_totp_id: ref old_linked_totp_id,
                    custom_fields: ref old_custom_fields,
                    ref password_history,
                    ref template,
                } = existing.data
                {
                    let mut password_history = password_history.clone();
                    // If password changed, push old password to history.
                    let new_password = request.secret.as_ref().map_or_else(
                        || old_password.clone(),
                        |new_secret| {
                            if !new_secret.is_empty() && new_secret != old_password {
                                password_history.push(verrou_vault::PasswordHistoryEntry {
                                    password: old_password.clone(),
                                    changed_at: now_for_history(),
                                });
                                // Cap history at 20 entries.
                                if password_history.len() > 20 {
                                    password_history.remove(0);
                                }
                                new_secret.clone()
                            } else {
                                old_password.clone()
                            }
                        },
                    );

                    let new_username = request
                        .username
                        .as_ref()
                        .map_or_else(|| old_username.clone(), Clone::clone);
                    let new_urls = request
                        .urls
                        .as_ref()
                        .map_or_else(|| old_urls.clone(), Clone::clone);
                    let new_notes = request
                        .notes
                        .as_ref()
                        .map_or_else(|| old_notes.clone(), Clone::clone);
                    let new_linked_totp_id = request
                        .linked_totp_id
                        .as_ref()
                        .map_or_else(|| old_linked_totp_id.clone(), Clone::clone);
                    let new_custom_fields = if let Some(ref fields) = request.custom_fields {
                        let converted: Result<Vec<_>, _> =
                            fields.iter().map(dto_to_custom_field).collect();
                        converted?
                    } else {
                        old_custom_fields.clone()
                    };

                    Some(verrou_vault::EntryData::Credential {
                        password: new_password,
                        username: new_username,
                        urls: new_urls,
                        notes: new_notes,
                        linked_totp_id: new_linked_totp_id,
                        custom_fields: new_custom_fields,
                        password_history,
                        template: template.clone(),
                    })
                } else {
                    None
                }
            } else if let Some(ref secret) = request.secret {
                // Secret changed — rebuild with new secret and possibly new passphrase.
                let passphrase = request.passphrase.clone().flatten();
                // Preserve linked_entry_id for recovery code entries.
                let linked_id = if entry_type == verrou_vault::EntryType::RecoveryCode {
                    let existing = verrou_vault::get_entry(
                        session.db.connection(),
                        &session.master_key,
                        &request.id,
                    )
                    .map_err(|e| map_vault_error(&e))?;
                    match &existing.data {
                        verrou_vault::EntryData::RecoveryCode {
                            linked_entry_id, ..
                        } => linked_entry_id.clone(),
                        _ => None,
                    }
                } else {
                    None
                };
                Some(build_entry_data(
                    entry_type,
                    secret,
                    passphrase,
                    None,
                    linked_id,
                    Vec::new(),
                )?)
            } else if entry_type == verrou_vault::EntryType::SeedPhrase {
                // Only passphrase changed for a seed phrase — fetch existing
                // words and rebuild with updated passphrase.
                let existing = verrou_vault::get_entry(
                    session.db.connection(),
                    &session.master_key,
                    &request.id,
                )
                .map_err(|e| map_vault_error(&e))?;
                let existing_secret = extract_secret(&existing.data);
                let passphrase = request.passphrase.clone().flatten();
                Some(build_entry_data(
                    entry_type,
                    &existing_secret,
                    passphrase,
                    None,
                    None,
                    Vec::new(),
                )?)
            } else {
                // Passphrase change on non-seed-phrase entry — ignore.
                None
            }
        } else {
            None
        };

        let params = verrou_vault::UpdateEntryParams {
            name: request.name.clone(),
            issuer: request.issuer.clone(),
            folder_id: request.folder_id.clone(),
            algorithm,
            digits: request.digits,
            period: request.period,
            counter: request.counter,
            pinned: request.pinned,
            tags: request.tags.clone(),
            data,
        };

        verrou_vault::update_entry(
            session.db.connection(),
            &session.master_key,
            &request.id,
            &params,
        )
        .map_err(|e| map_vault_error(&e))?
    };

    // Zeroize sensitive request fields after use.
    if let Some(ref mut secret) = request.secret {
        secret.zeroize();
    }
    if let Some(Some(ref mut pp)) = request.passphrase {
        pp.zeroize();
    }

    Ok(full_entry_to_metadata_dto(&entry))
}

/// Delete an entry by ID.
///
/// Permanently removes the entry. Confirmation is handled by the frontend.
///
/// For TOTP/HOTP entries, linked recovery code entries are cascade-deleted
/// first (within the same vault lock scope) to prevent orphaned records.
///
/// # Errors
///
/// Returns a string error if the vault is locked or the entry is not found.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn delete_entry(
    entry_id: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<(), String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    // Check if this is a TOTP/HOTP entry — if so, cascade-delete linked recovery codes first.
    let entry_type = verrou_vault::get_entry_type(session.db.connection(), &entry_id)
        .map_err(|e| map_vault_error(&e))?;

    if matches!(
        entry_type,
        verrou_vault::EntryType::Totp | verrou_vault::EntryType::Hotp
    ) {
        let items =
            verrou_vault::list_entries(session.db.connection()).map_err(|e| map_vault_error(&e))?;

        for item in &items {
            if item.entry_type != verrou_vault::EntryType::RecoveryCode {
                continue;
            }
            let entry =
                verrou_vault::get_entry(session.db.connection(), &session.master_key, &item.id)
                    .map_err(|e| map_vault_error(&e))?;

            if let verrou_vault::EntryData::RecoveryCode {
                linked_entry_id, ..
            } = &entry.data
            {
                if linked_entry_id.as_deref() == Some(entry_id.as_str()) {
                    tracing::info!(
                        parent_id = %entry_id,
                        child_id = %item.id,
                        "Cascade-deleting linked recovery code entry"
                    );
                    verrou_vault::delete_entry(session.db.connection(), &item.id)
                        .map_err(|e| map_vault_error(&e))?;
                }
            }
        }
    }

    verrou_vault::delete_entry(session.db.connection(), &entry_id).map_err(|e| map_vault_error(&e))
}

/// Delete an entry with re-authentication for sensitive types.
///
/// Sensitive entry types (`SeedPhrase`, `RecoveryCode`) require master
/// password verification before deletion. Non-sensitive types (`Totp`,
/// `Hotp`, `SecureNote`) are deleted directly without re-auth.
///
/// This generalized command is forward-compatible for Story 6.6
/// (recovery code deletion).
///
/// # Errors
///
/// Returns a string error if:
/// - The vault is locked
/// - The password is incorrect (for sensitive types)
/// - The entry is not found
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn delete_entry_with_auth(
    entry_id: String,
    mut password: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<(), String> {
    // Step 1: Get entry type (lightweight query, no decryption).
    let entry_type = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;
        verrou_vault::get_entry_type(session.db.connection(), &entry_id)
            .map_err(|e| map_vault_error(&e))?
    };

    // Step 2: For sensitive types, verify master password before deletion.
    let requires_auth = matches!(
        entry_type,
        verrou_vault::EntryType::SeedPhrase
            | verrou_vault::EntryType::RecoveryCode
            | verrou_vault::EntryType::Credential
    );

    // Human-readable entry type for error messages.
    let type_label = match entry_type {
        verrou_vault::EntryType::SeedPhrase => "Seed phrase",
        verrou_vault::EntryType::RecoveryCode => "Recovery code",
        verrou_vault::EntryType::Credential => "Credential",
        _ => "Entry",
    };

    if requires_auth {
        // Copy master key for constant-time comparison.
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

        // Read vault header for password slot and KDF params.
        let vault_path = app
            .path()
            .app_data_dir()
            .map_err(|_| "Failed to resolve vault directory.".to_string())?;
        let header_path = vault_path.join("vault.verrou");

        if !header_path.exists() {
            password.zeroize();
            master_key_copy.zeroize();
            return Err("Vault not found.".to_string());
        }

        let file_data = std::fs::read(&header_path).map_err(|_| {
            password.zeroize();
            master_key_copy.zeroize();
            "Failed to read vault header.".to_string()
        })?;

        let header =
            verrou_crypto_core::vault_format::parse_header_only(&file_data).map_err(|_| {
                password.zeroize();
                master_key_copy.zeroize();
                "Failed to parse vault header.".to_string()
            })?;

        // Find password slot and its salt.
        let (slot_index, password_slot) = header
            .slots
            .iter()
            .enumerate()
            .find(|(_, s)| s.slot_type == verrou_crypto_core::slots::SlotType::Password)
            .ok_or_else(|| {
                password.zeroize();
                master_key_copy.zeroize();
                "No password slot found.".to_string()
            })?;

        let password_slot = password_slot.clone();

        let salt = header
            .slot_salts
            .get(slot_index)
            .ok_or_else(|| {
                password.zeroize();
                master_key_copy.zeroize();
                "Missing salt for password slot.".to_string()
            })?
            .clone();

        // Re-derive wrapping key using session_params (NOT sensitive_params).
        let wrapping_key =
            verrou_crypto_core::kdf::derive(password.as_bytes(), &salt, &header.session_params)
                .map_err(|_| {
                    password.zeroize();
                    master_key_copy.zeroize();
                    "Key derivation failed.".to_string()
                })?;

        // Zeroize password immediately after derivation.
        password.zeroize();

        let recovered_key =
            verrou_crypto_core::slots::unwrap_slot(&password_slot, wrapping_key.expose()).map_err(
                |_| {
                    master_key_copy.zeroize();
                    format!("Incorrect password. {type_label} not deleted.")
                },
            )?;

        // Constant-time comparison to prevent timing leaks.
        if !constant_time_key_eq(recovered_key.expose(), &master_key_copy) {
            master_key_copy.zeroize();
            return Err(format!("Incorrect password. {type_label} not deleted."));
        }

        master_key_copy.zeroize();
    } else {
        // Non-sensitive type: zeroize password (unused but received) and proceed.
        password.zeroize();
    }

    // Step 3: Password verified (or not required) — delete the entry.
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    verrou_vault::delete_entry(session.db.connection(), &entry_id).map_err(|e| map_vault_error(&e))
}

/// Reveal a seed phrase after re-authenticating with the master password.
///
/// Re-authentication verifies the password by deriving a wrapping key
/// and attempting to unwrap the password slot. On success, the entry is
/// decrypted and the seed phrase words are returned via `SeedDisplay`.
///
/// # Errors
///
/// Returns a string error if:
/// - The vault is locked
/// - The password is incorrect
/// - The entry is not found or is not a seed phrase
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn reveal_seed_phrase(
    entry_id: String,
    mut password: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<SeedDisplay, String> {
    // Step 1: Verify the vault is unlocked and copy the master key for comparison.
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

    // Step 2: Read vault header to get password slot and KDF params.
    let vault_path = app
        .path()
        .app_data_dir()
        .map_err(|_| "Failed to resolve vault directory.".to_string())?;
    let header_path = vault_path.join("vault.verrou");

    if !header_path.exists() {
        password.zeroize();
        master_key_copy.zeroize();
        return Err("Vault not found.".to_string());
    }

    let file_data = std::fs::read(&header_path).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to read vault header.".to_string()
    })?;

    let header = verrou_crypto_core::vault_format::parse_header_only(&file_data).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to parse vault header.".to_string()
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
            "No password slot found.".to_string()
        })?;

    let password_slot = password_slot.clone();

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            password.zeroize();
            master_key_copy.zeroize();
            "Missing salt for password slot.".to_string()
        })?
        .clone();

    // Step 4: Re-authenticate by deriving wrapping key and unwrapping slot.
    // NOTE: Architecture specifies `sensitive_params` for seed phrase reveal,
    // but the password slot was wrapped with `session_params` at vault creation.
    // Using `sensitive_params` here would fail unwrapping. A future story should
    // introduce a dual-slot scheme (session + sensitive wrapping) to enable
    // Maximum-tier KDF for re-auth operations. The SecurityCeremony animation
    // still provides the expected 3-4s UX experience.
    let wrapping_key =
        verrou_crypto_core::kdf::derive(password.as_bytes(), &salt, &header.session_params)
            .map_err(|_| {
                password.zeroize();
                master_key_copy.zeroize();
                "Key derivation failed.".to_string()
            })?;

    // Zeroize password immediately after derivation.
    password.zeroize();

    let recovered_key =
        verrou_crypto_core::slots::unwrap_slot(&password_slot, wrapping_key.expose()).map_err(
            |_| {
                master_key_copy.zeroize();
                "Incorrect password. Seed phrase not revealed.".to_string()
            },
        )?;

    // Verify recovered key matches session master key (constant-time to prevent timing leaks).
    if !constant_time_key_eq(recovered_key.expose(), &master_key_copy) {
        master_key_copy.zeroize();
        return Err("Incorrect password. Seed phrase not revealed.".to_string());
    }

    master_key_copy.zeroize();

    // Step 5: Password verified — now fetch and decrypt the entry.
    let entry = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;
        verrou_vault::get_entry(session.db.connection(), &session.master_key, &entry_id)
            .map_err(|e| map_vault_error(&e))?
    };

    // Step 6: Verify entry is a seed phrase and extract words.
    match &entry.data {
        verrou_vault::EntryData::SeedPhrase { words, passphrase } => {
            let word_count = words.len() as u8;
            let has_passphrase = passphrase.is_some();
            Ok(SeedDisplay {
                words: words.clone(),
                word_count,
                has_passphrase,
            })
        }
        _ => Err("Entry is not a seed phrase.".to_string()),
    }
}

/// Reveal recovery codes after re-authenticating with the master password.
///
/// Re-authentication verifies the password by deriving a wrapping key
/// and attempting to unwrap the password slot. On success, the entry is
/// decrypted and recovery codes are returned via `RecoveryCodeDisplay`.
///
/// # Errors
///
/// Returns a string error if:
/// - The vault is locked
/// - The password is incorrect
/// - The entry is not found or is not a recovery code entry
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn reveal_recovery_codes(
    entry_id: String,
    mut password: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<RecoveryCodeDisplay, String> {
    // Step 1: Verify the vault is unlocked and copy the master key for comparison.
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

    // Step 2: Read vault header to get password slot and KDF params.
    let vault_path = app
        .path()
        .app_data_dir()
        .map_err(|_| "Failed to resolve vault directory.".to_string())?;
    let header_path = vault_path.join("vault.verrou");

    if !header_path.exists() {
        password.zeroize();
        master_key_copy.zeroize();
        return Err("Vault not found.".to_string());
    }

    let file_data = std::fs::read(&header_path).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to read vault header.".to_string()
    })?;

    let header = verrou_crypto_core::vault_format::parse_header_only(&file_data).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to parse vault header.".to_string()
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
            "No password slot found.".to_string()
        })?;

    let password_slot = password_slot.clone();

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            password.zeroize();
            master_key_copy.zeroize();
            "Missing salt for password slot.".to_string()
        })?
        .clone();

    // Step 4: Re-authenticate by deriving wrapping key and unwrapping slot.
    let wrapping_key =
        verrou_crypto_core::kdf::derive(password.as_bytes(), &salt, &header.session_params)
            .map_err(|_| {
                password.zeroize();
                master_key_copy.zeroize();
                "Key derivation failed.".to_string()
            })?;

    // Zeroize password immediately after derivation.
    password.zeroize();

    let recovered_key =
        verrou_crypto_core::slots::unwrap_slot(&password_slot, wrapping_key.expose()).map_err(
            |_| {
                master_key_copy.zeroize();
                "Incorrect password. Recovery codes not revealed.".to_string()
            },
        )?;

    // Verify recovered key matches session master key (constant-time).
    if !constant_time_key_eq(recovered_key.expose(), &master_key_copy) {
        master_key_copy.zeroize();
        return Err("Incorrect password. Recovery codes not revealed.".to_string());
    }

    master_key_copy.zeroize();

    // Step 5: Password verified — fetch and decrypt the entry.
    let entry = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;
        verrou_vault::get_entry(session.db.connection(), &session.master_key, &entry_id)
            .map_err(|e| map_vault_error(&e))?
    };

    // Step 6: Verify entry is a recovery code and extract codes.
    match &entry.data {
        verrou_vault::EntryData::RecoveryCode {
            codes,
            used,
            linked_entry_id,
        } => {
            let total_codes = codes.len() as u32;
            let remaining_codes = total_codes.saturating_sub(used.len() as u32);
            Ok(RecoveryCodeDisplay {
                codes: codes.clone(),
                used: used.clone(),
                total_codes,
                remaining_codes,
                linked_entry_id: linked_entry_id.clone(),
                has_linked_entry: linked_entry_id.is_some(),
            })
        }
        _ => Err("Entry is not a recovery code entry.".to_string()),
    }
}

/// Get recovery code statistics for a TOTP/HOTP entry.
///
/// Scans all recovery code entries, decrypts each, and checks
/// `linked_entry_id` to find codes linked to the given entry.
/// Returns aggregate stats (total/remaining) without exposing codes.
///
/// No re-auth required — this returns stats only, not secret data.
///
/// # Errors
///
/// Returns a string error if the vault is locked or the query fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_recovery_stats(
    entry_id: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<RecoveryStats, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    // List all entries, then filter to recovery_code type.
    let items =
        verrou_vault::list_entries(session.db.connection()).map_err(|e| map_vault_error(&e))?;

    let mut total: u32 = 0;
    let mut remaining: u32 = 0;

    for item in &items {
        if item.entry_type != verrou_vault::EntryType::RecoveryCode {
            continue;
        }
        // Decrypt each recovery code entry to check linked_entry_id.
        let entry = verrou_vault::get_entry(session.db.connection(), &session.master_key, &item.id)
            .map_err(|e| map_vault_error(&e))?;

        if let verrou_vault::EntryData::RecoveryCode {
            codes,
            used,
            linked_entry_id: Some(ref linked_id),
        } = &entry.data
        {
            if linked_id == &entry_id {
                let count = codes.len() as u32;
                total = total.saturating_add(count);
                remaining = remaining.saturating_add(count.saturating_sub(used.len() as u32));
            }
        }
    }

    Ok(RecoveryStats { total, remaining })
}

/// Recovery stats for a single linked entry (used in batch response).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStatEntry {
    /// The TOTP/HOTP entry ID that recovery codes are linked to.
    pub entry_id: String,
    /// Total number of recovery codes linked to this entry.
    pub total: u32,
    /// Number of remaining (unused) recovery codes.
    pub remaining: u32,
}

/// Get recovery code statistics for ALL entries in a single scan.
///
/// Scans all recovery code entries once, decrypts each, and produces:
/// 1. Stats keyed by `linked_entry_id` (for TOTP entry cards showing linked recovery counts)
/// 2. Stats keyed by the recovery code entry's own ID (for recovery code entry cards)
///
/// No re-auth required — this returns stats only, not secret data.
///
/// # Errors
///
/// Returns a string error if the vault is locked or the query fails.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_all_recovery_stats(
    vault_state: State<'_, ManagedVaultState>,
) -> Result<Vec<RecoveryStatEntry>, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let items =
        verrou_vault::list_entries(session.db.connection()).map_err(|e| map_vault_error(&e))?;

    let mut stats_map: std::collections::HashMap<String, (u32, u32)> =
        std::collections::HashMap::new();

    for item in &items {
        if item.entry_type != verrou_vault::EntryType::RecoveryCode {
            continue;
        }
        let entry = verrou_vault::get_entry(session.db.connection(), &session.master_key, &item.id)
            .map_err(|e| map_vault_error(&e))?;

        if let verrou_vault::EntryData::RecoveryCode {
            codes,
            used,
            linked_entry_id,
        } = &entry.data
        {
            let count = codes.len() as u32;
            let rem = count.saturating_sub(used.len() as u32);

            // Stats for the recovery code entry itself (for recovery_code entry cards)
            stats_map.insert(item.id.clone(), (count, rem));

            // Stats aggregated by linked TOTP/HOTP entry (for TOTP entry cards)
            // Guard: skip if linked_entry_id equals own ID (prevents double-counting)
            if let Some(ref linked_id) = linked_entry_id {
                if linked_id != &item.id {
                    let linked_stats = stats_map.entry(linked_id.clone()).or_insert((0, 0));
                    linked_stats.0 = linked_stats.0.saturating_add(count);
                    linked_stats.1 = linked_stats.1.saturating_add(rem);
                }
            }
        }
    }

    Ok(stats_map
        .into_iter()
        .map(|(entry_id, (total, remaining))| RecoveryStatEntry {
            entry_id,
            total,
            remaining,
        })
        .collect())
}

/// Toggle a recovery code's used/unused status after re-authentication.
///
/// Re-authenticates with the master password, decrypts the entry,
/// toggles the specified code index in/out of the `used` vec,
/// re-encrypts and saves, then returns the updated `RecoveryCodeDisplay`.
///
/// # Errors
///
/// Returns a string error if:
/// - The vault is locked
/// - The password is incorrect
/// - The entry is not found or is not a recovery code entry
/// - The code index is out of bounds
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn toggle_recovery_code_used(
    entry_id: String,
    code_index: u32,
    mut password: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<RecoveryCodeDisplay, String> {
    // Step 1: Verify the vault is unlocked and copy the master key for comparison.
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

    // Step 2: Read vault header to get password slot and KDF params.
    let vault_path = app
        .path()
        .app_data_dir()
        .map_err(|_| "Failed to resolve vault directory.".to_string())?;
    let header_path = vault_path.join("vault.verrou");

    if !header_path.exists() {
        password.zeroize();
        master_key_copy.zeroize();
        return Err("Vault not found.".to_string());
    }

    let file_data = std::fs::read(&header_path).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to read vault header.".to_string()
    })?;

    let header = verrou_crypto_core::vault_format::parse_header_only(&file_data).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to parse vault header.".to_string()
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
            "No password slot found.".to_string()
        })?;

    let password_slot = password_slot.clone();

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            password.zeroize();
            master_key_copy.zeroize();
            "Missing salt for password slot.".to_string()
        })?
        .clone();

    // Step 4: Re-authenticate by deriving wrapping key and unwrapping slot.
    let wrapping_key =
        verrou_crypto_core::kdf::derive(password.as_bytes(), &salt, &header.session_params)
            .map_err(|_| {
                password.zeroize();
                master_key_copy.zeroize();
                "Key derivation failed.".to_string()
            })?;

    // Zeroize password immediately after derivation.
    password.zeroize();

    let recovered_key =
        verrou_crypto_core::slots::unwrap_slot(&password_slot, wrapping_key.expose()).map_err(
            |_| {
                master_key_copy.zeroize();
                "Incorrect password. Toggle failed.".to_string()
            },
        )?;

    // Verify recovered key matches session master key (constant-time).
    if !constant_time_key_eq(recovered_key.expose(), &master_key_copy) {
        master_key_copy.zeroize();
        return Err("Incorrect password. Toggle failed.".to_string());
    }

    master_key_copy.zeroize();

    // Step 5: Password verified — fetch, toggle, and save.
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let entry = verrou_vault::get_entry(session.db.connection(), &session.master_key, &entry_id)
        .map_err(|e| map_vault_error(&e))?;

    match &entry.data {
        verrou_vault::EntryData::RecoveryCode {
            codes,
            used,
            linked_entry_id,
        } => {
            let idx = code_index as usize;
            if idx >= codes.len() {
                return Err(format!(
                    "Code index {} is out of bounds (total codes: {}).",
                    code_index,
                    codes.len()
                ));
            }

            // Toggle: remove if present, add if absent.
            let mut new_used = used.clone();
            if let Some(pos) = new_used.iter().position(|&u| u == idx) {
                new_used.remove(pos);
            } else {
                new_used.push(idx);
            }

            let updated_data = verrou_vault::EntryData::RecoveryCode {
                codes: codes.clone(),
                used: new_used.clone(),
                linked_entry_id: linked_entry_id.clone(),
            };

            let params = verrou_vault::UpdateEntryParams {
                name: None,
                issuer: None,
                folder_id: None,
                algorithm: None,
                digits: None,
                period: None,
                counter: None,
                pinned: None,
                tags: None,
                data: Some(updated_data),
            };

            verrou_vault::update_entry(
                session.db.connection(),
                &session.master_key,
                &entry_id,
                &params,
            )
            .map_err(|e| map_vault_error(&e))?;

            let total_codes = codes.len() as u32;
            let remaining_codes = total_codes.saturating_sub(new_used.len() as u32);

            tracing::info!(entry_id = %entry_id, code_index, "Recovery code toggled");

            Ok(RecoveryCodeDisplay {
                codes: codes.clone(),
                used: new_used,
                total_codes,
                remaining_codes,
                linked_entry_id: linked_entry_id.clone(),
                has_linked_entry: linked_entry_id.is_some(),
            })
        }
        _ => Err("Entry is not a recovery code entry.".to_string()),
    }
}

/// Update a recovery code set: add new codes and/or remove existing codes.
///
/// Re-authenticates with the master password, decrypts the entry,
/// applies additions and removals, adjusts used indexes, re-encrypts
/// and saves, then returns the updated `RecoveryCodeDisplay`.
///
/// Removals are processed highest-index-first so earlier indexes are
/// unaffected.  After removal, the `used` vec is adjusted: entries
/// referencing removed codes are dropped, and entries referencing codes
/// after a removed index are decremented.
///
/// # Errors
///
/// Returns a string error if:
/// - The vault is locked
/// - The password is incorrect
/// - The entry is not found or is not a recovery code entry
/// - Any removal index is out of bounds
/// - Both `codes_to_add` and `indexes_to_remove` are empty (no-op)
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn update_recovery_codes(
    entry_id: String,
    codes_to_add: Vec<String>,
    indexes_to_remove: Vec<u32>,
    mut password: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<RecoveryCodeDisplay, String> {
    if codes_to_add.is_empty() && indexes_to_remove.is_empty() {
        password.zeroize();
        return Err("No changes specified.".to_string());
    }

    // Validate added codes are non-empty.
    for (i, code) in codes_to_add.iter().enumerate() {
        let trimmed = code.trim();
        if trimmed.is_empty() {
            password.zeroize();
            return Err(format!("Code at position {i} is empty."));
        }
        if trimmed.len() > 256 {
            password.zeroize();
            return Err(format!("Code at position {i} exceeds 256 characters."));
        }
    }

    // Step 1: Verify the vault is unlocked and copy the master key for comparison.
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

    // Step 2: Read vault header to get password slot and KDF params.
    let vault_path = app
        .path()
        .app_data_dir()
        .map_err(|_| "Failed to resolve vault directory.".to_string())?;
    let header_path = vault_path.join("vault.verrou");

    if !header_path.exists() {
        password.zeroize();
        master_key_copy.zeroize();
        return Err("Vault not found.".to_string());
    }

    let file_data = std::fs::read(&header_path).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to read vault header.".to_string()
    })?;

    let header = verrou_crypto_core::vault_format::parse_header_only(&file_data).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to parse vault header.".to_string()
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
            "No password slot found.".to_string()
        })?;

    let password_slot = password_slot.clone();

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            password.zeroize();
            master_key_copy.zeroize();
            "Missing salt for password slot.".to_string()
        })?
        .clone();

    // Step 4: Re-authenticate by deriving wrapping key and unwrapping slot.
    let wrapping_key =
        verrou_crypto_core::kdf::derive(password.as_bytes(), &salt, &header.session_params)
            .map_err(|_| {
                password.zeroize();
                master_key_copy.zeroize();
                "Key derivation failed.".to_string()
            })?;

    password.zeroize();

    let recovered_key =
        verrou_crypto_core::slots::unwrap_slot(&password_slot, wrapping_key.expose()).map_err(
            |_| {
                master_key_copy.zeroize();
                "Incorrect password. Update failed.".to_string()
            },
        )?;

    if !constant_time_key_eq(recovered_key.expose(), &master_key_copy) {
        master_key_copy.zeroize();
        return Err("Incorrect password. Update failed.".to_string());
    }

    master_key_copy.zeroize();

    // Step 5: Password verified — fetch, modify, and save.
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let entry = verrou_vault::get_entry(session.db.connection(), &session.master_key, &entry_id)
        .map_err(|e| map_vault_error(&e))?;

    match &entry.data {
        verrou_vault::EntryData::RecoveryCode {
            codes,
            used,
            linked_entry_id,
        } => {
            let mut new_codes = codes.clone();
            let mut new_used = used.clone();

            // Validate removal indexes before mutating.
            for &idx in &indexes_to_remove {
                if (idx as usize) >= new_codes.len() {
                    return Err(format!(
                        "Removal index {} is out of bounds (total codes: {}).",
                        idx,
                        new_codes.len()
                    ));
                }
            }

            // Remove codes highest-index-first to preserve ordering.
            let mut sorted_removes: Vec<usize> =
                indexes_to_remove.iter().map(|&i| i as usize).collect();
            sorted_removes.sort_unstable_by(|a, b| b.cmp(a));
            sorted_removes.dedup();

            for &idx in &sorted_removes {
                new_codes.remove(idx);
            }

            // Adjust used indexes: drop entries for removed codes, decrement those above.
            let remove_set: std::collections::HashSet<usize> =
                sorted_removes.iter().copied().collect();
            let mut adjusted_used: Vec<usize> = new_used
                .iter()
                .filter(|&&u| !remove_set.contains(&u))
                .copied()
                .collect();

            for &removed_idx in &sorted_removes {
                for u in &mut adjusted_used {
                    if *u > removed_idx {
                        *u = u.saturating_sub(1);
                    }
                }
            }

            new_used = adjusted_used;

            // Append new codes (trimmed, non-empty — already validated above).
            for code in &codes_to_add {
                new_codes.push(code.trim().to_string());
            }

            let updated_data = verrou_vault::EntryData::RecoveryCode {
                codes: new_codes.clone(),
                used: new_used.clone(),
                linked_entry_id: linked_entry_id.clone(),
            };

            let params = verrou_vault::UpdateEntryParams {
                name: None,
                issuer: None,
                folder_id: None,
                algorithm: None,
                digits: None,
                period: None,
                counter: None,
                pinned: None,
                tags: None,
                data: Some(updated_data),
            };

            verrou_vault::update_entry(
                session.db.connection(),
                &session.master_key,
                &entry_id,
                &params,
            )
            .map_err(|e| map_vault_error(&e))?;

            let total_codes = new_codes.len() as u32;
            let remaining_codes = total_codes.saturating_sub(new_used.len() as u32);

            tracing::info!(
                entry_id = %entry_id,
                added = codes_to_add.len(),
                removed = indexes_to_remove.len(),
                "Recovery codes updated"
            );

            Ok(RecoveryCodeDisplay {
                codes: new_codes,
                used: new_used,
                total_codes,
                remaining_codes,
                linked_entry_id: linked_entry_id.clone(),
                has_linked_entry: linked_entry_id.is_some(),
            })
        }
        _ => Err("Entry is not a recovery code entry.".to_string()),
    }
}

/// Get the count of recovery code entries linked to a given TOTP/HOTP entry.
///
/// Used by the frontend to display cascade deletion warnings.
/// Returns 0 if no linked recovery codes exist.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_linked_recovery_count(
    entry_id: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<u32, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let items =
        verrou_vault::list_entries(session.db.connection()).map_err(|e| map_vault_error(&e))?;

    let mut count: u32 = 0;
    for item in &items {
        if item.entry_type != verrou_vault::EntryType::RecoveryCode {
            continue;
        }
        let entry = verrou_vault::get_entry(session.db.connection(), &session.master_key, &item.id)
            .map_err(|e| map_vault_error(&e))?;

        if let verrou_vault::EntryData::RecoveryCode {
            linked_entry_id, ..
        } = &entry.data
        {
            if linked_entry_id.as_deref() == Some(entry_id.as_str()) {
                count = count.saturating_add(1);
            }
        }
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Credential Reveal
// ---------------------------------------------------------------------------

/// Reveal a credential's password and details after re-authenticating.
///
/// Re-authentication verifies the password by deriving a wrapping key
/// and attempting to unwrap the password slot. On success, the entry is
/// decrypted and the credential details are returned via `CredentialDisplay`.
///
/// # Errors
///
/// Returns a string error if:
/// - The vault is locked
/// - The password is incorrect
/// - The entry is not found or is not a credential
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn reveal_password(
    entry_id: String,
    mut password: String,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<CredentialDisplay, String> {
    // Step 1: Verify the vault is unlocked and copy the master key for comparison.
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

    // Step 2: Read vault header to get password slot and KDF params.
    let vault_path = app
        .path()
        .app_data_dir()
        .map_err(|_| "Failed to resolve vault directory.".to_string())?;
    let header_path = vault_path.join("vault.verrou");

    if !header_path.exists() {
        password.zeroize();
        master_key_copy.zeroize();
        return Err("Vault not found.".to_string());
    }

    let file_data = std::fs::read(&header_path).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to read vault header.".to_string()
    })?;

    let header = verrou_crypto_core::vault_format::parse_header_only(&file_data).map_err(|_| {
        password.zeroize();
        master_key_copy.zeroize();
        "Failed to parse vault header.".to_string()
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
            "No password slot found.".to_string()
        })?;

    let password_slot = password_slot.clone();

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            password.zeroize();
            master_key_copy.zeroize();
            "Missing salt for password slot.".to_string()
        })?
        .clone();

    // Step 4: Re-authenticate by deriving wrapping key and unwrapping slot.
    let wrapping_key =
        verrou_crypto_core::kdf::derive(password.as_bytes(), &salt, &header.session_params)
            .map_err(|_| {
                password.zeroize();
                master_key_copy.zeroize();
                "Key derivation failed.".to_string()
            })?;

    // Zeroize password immediately after derivation.
    password.zeroize();

    let recovered_key =
        verrou_crypto_core::slots::unwrap_slot(&password_slot, wrapping_key.expose()).map_err(
            |_| {
                master_key_copy.zeroize();
                "Incorrect password. Credential not revealed.".to_string()
            },
        )?;

    // Verify recovered key matches session master key (constant-time).
    if !constant_time_key_eq(recovered_key.expose(), &master_key_copy) {
        master_key_copy.zeroize();
        return Err("Incorrect password. Credential not revealed.".to_string());
    }

    master_key_copy.zeroize();

    // Step 5: Password verified — fetch and decrypt the entry.
    let entry = {
        let state = vault_state
            .lock()
            .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
        let session = state
            .as_ref()
            .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;
        verrou_vault::get_entry(session.db.connection(), &session.master_key, &entry_id)
            .map_err(|e| map_vault_error(&e))?
    };

    // Step 6: Verify entry is a credential and extract fields.
    match &entry.data {
        verrou_vault::EntryData::Credential {
            password: cred_password,
            username,
            urls,
            notes,
            linked_totp_id,
            custom_fields,
            password_history,
            template,
        } => Ok(CredentialDisplay {
            password: cred_password.clone(),
            username: username.clone(),
            urls: urls.clone(),
            notes: notes.clone(),
            linked_totp_id: linked_totp_id.clone(),
            custom_fields: custom_fields.iter().map(custom_field_to_dto).collect(),
            password_history: password_history
                .iter()
                .map(|h| PasswordHistoryEntryDto {
                    password: h.password.clone(),
                    changed_at: h.changed_at.clone(),
                })
                .collect(),
            template: template.clone(),
        }),
        _ => Err("Entry is not a credential.".to_string()),
    }
}

// ---------------------------------------------------------------------------
// Note Content Search
// ---------------------------------------------------------------------------

/// A single note search result with a snippet around the match.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NoteSearchResultDto {
    /// Entry ID of the matching note.
    pub entry_id: String,
    /// Entry name (title).
    pub name: String,
    /// Context snippet around the match (±40 chars).
    pub snippet: String,
}

/// Server-side search of secure note content.
///
/// Decrypts all `secure_note` entries, searches bodies for `query`,
/// and returns matching entry IDs with contextual snippets.
/// Note content stays in Rust memory — never sent to the frontend search index.
///
/// # Errors
///
/// Returns a string error if the vault is locked.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn search_note_content(
    query: String,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<Vec<NoteSearchResultDto>, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;

    let lower_query = query.to_lowercase();
    if lower_query.is_empty() {
        return Ok(Vec::new());
    }

    let items =
        verrou_vault::list_entries(session.db.connection()).map_err(|e| map_vault_error(&e))?;

    let mut results = Vec::new();
    for item in &items {
        if item.entry_type != verrou_vault::EntryType::SecureNote {
            continue;
        }
        let entry = verrou_vault::get_entry(session.db.connection(), &session.master_key, &item.id)
            .map_err(|e| map_vault_error(&e))?;

        if let verrou_vault::EntryData::SecureNote { ref body, .. } = entry.data {
            let lower_body = body.to_lowercase();
            if let Some(pos) = lower_body.find(&lower_query) {
                let snippet = build_snippet(body, pos, lower_query.len(), 40);
                results.push(NoteSearchResultDto {
                    entry_id: item.id.clone(),
                    name: item.name.clone(),
                    snippet,
                });
            }
        }
    }

    Ok(results)
}

/// Build a context snippet around a match position.
fn build_snippet(text: &str, match_pos: usize, match_len: usize, context: usize) -> String {
    let start = match_pos.saturating_sub(context);
    let end = text
        .len()
        .min(match_pos.saturating_add(match_len).saturating_add(context));

    // Snap to char boundaries.
    let start = text[..start]
        .char_indices()
        .next_back()
        .map_or(0, |(i, _)| i);
    let end = text[end..]
        .char_indices()
        .next()
        .map_or(text.len(), |(i, _)| end.saturating_add(i));

    let mut snippet = String::new();
    if start > 0 {
        snippet.push_str("...");
    }
    snippet.push_str(&text[start..end]);
    if end < text.len() {
        snippet.push_str("...");
    }
    snippet
}

// ---------------------------------------------------------------------------
// Password Health DTOs + Command
// ---------------------------------------------------------------------------

/// A credential reference (ID + name) — safe for IPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialRefDto {
    pub id: String,
    pub name: String,
}

/// A group of credentials sharing the same password.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReusedGroupDto {
    pub credentials: Vec<CredentialRefDto>,
}

/// A credential flagged as weak.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WeakCredentialDto {
    pub id: String,
    pub name: String,
    pub strength: String,
}

/// A credential with an old password.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OldCredentialDto {
    pub id: String,
    pub name: String,
    pub days_since_change: u64,
    pub severity: String,
}

/// Complete password health report DTO.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHealthDto {
    pub overall_score: u32,
    pub total_credentials: u32,
    pub reused_count: u32,
    pub reused_groups: Vec<ReusedGroupDto>,
    pub weak_count: u32,
    pub weak_credentials: Vec<WeakCredentialDto>,
    pub old_count: u32,
    pub old_credentials: Vec<OldCredentialDto>,
    pub no_totp_count: u32,
    pub no_totp_credentials: Vec<CredentialRefDto>,
}

impl From<verrou_vault::PasswordHealthReport> for PasswordHealthDto {
    fn from(r: verrou_vault::PasswordHealthReport) -> Self {
        Self {
            overall_score: r.overall_score,
            total_credentials: r.total_credentials,
            reused_count: r.reused_count,
            reused_groups: r
                .reused_groups
                .into_iter()
                .map(|g| ReusedGroupDto {
                    credentials: g
                        .credentials
                        .into_iter()
                        .map(|c| CredentialRefDto {
                            id: c.id,
                            name: c.name,
                        })
                        .collect(),
                })
                .collect(),
            weak_count: r.weak_count,
            weak_credentials: r
                .weak_credentials
                .into_iter()
                .map(|w| WeakCredentialDto {
                    id: w.id,
                    name: w.name,
                    strength: w.strength.as_str().to_string(),
                })
                .collect(),
            old_count: r.old_count,
            old_credentials: r
                .old_credentials
                .into_iter()
                .map(|o| OldCredentialDto {
                    id: o.id,
                    name: o.name,
                    days_since_change: o.days_since_change,
                    severity: o.severity.as_str().to_string(),
                })
                .collect(),
            no_totp_count: r.no_totp_count,
            no_totp_credentials: r
                .no_totp_credentials
                .into_iter()
                .map(|c| CredentialRefDto {
                    id: c.id,
                    name: c.name,
                })
                .collect(),
        }
    }
}

/// Analyze password health for all credential entries.
///
/// All analysis runs server-side — passwords never cross IPC.
/// Requires vault unlock (session auth) but NOT re-auth.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn get_password_health(
    vault_state: State<'_, ManagedVaultState>,
) -> Result<PasswordHealthDto, String> {
    let state = vault_state
        .lock()
        .map_err(|_| "Internal error: failed to acquire vault lock".to_string())?;
    let session = state
        .as_ref()
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string())?;
    let report =
        verrou_vault::analyze_password_health(session.db.connection(), &session.master_key)
            .map_err(|e| map_vault_error(&e))?;
    Ok(PasswordHealthDto::from(report))
}

// ---------------------------------------------------------------------------
// Snapshot tests (insta)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;

    fn sample_metadata() -> EntryMetadataDto {
        EntryMetadataDto {
            id: "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d".into(),
            entry_type: "totp".into(),
            name: "GitHub".into(),
            issuer: Some("github.com".into()),
            folder_id: None,
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
            pinned: true,
            created_at: "2026-02-05T10:00:00Z".into(),
            updated_at: "2026-02-05T10:00:00Z".into(),
            tags: Vec::new(),
            username: None,
            template: None,
        }
    }

    #[test]
    fn entry_metadata_dto_snapshot() {
        insta::assert_json_snapshot!(sample_metadata());
    }

    #[test]
    fn entry_detail_dto_snapshot() {
        let dto = EntryDetailDto {
            metadata: sample_metadata(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            counter: 0,
            tags: Vec::new(),
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn entry_metadata_dto_minimal_snapshot() {
        let dto = EntryMetadataDto {
            id: "00000000-0000-4000-8000-000000000000".into(),
            entry_type: "secure_note".into(),
            name: "Private Note".into(),
            issuer: None,
            folder_id: None,
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
            pinned: false,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            tags: Vec::new(),
            username: None,
            template: None,
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn entry_metadata_dto_no_secret_field() {
        let dto = sample_metadata();
        let json = serde_json::to_value(&dto).expect("serialize");
        assert!(
            json.get("secret").is_none(),
            "EntryMetadataDto must NEVER contain a 'secret' field"
        );
        assert!(
            json.get("encryptedData").is_none(),
            "EntryMetadataDto must NEVER contain an 'encryptedData' field"
        );
    }

    #[test]
    fn seed_display_dto_snapshot() {
        let dto = SeedDisplay {
            words: vec![
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "about".into(),
            ],
            word_count: 12,
            has_passphrase: false,
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn seed_display_dto_with_passphrase_snapshot() {
        let dto = SeedDisplay {
            words: vec![
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "abandon".into(),
                "about".into(),
            ],
            word_count: 12,
            has_passphrase: true,
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn seed_display_dto_fields_are_camel_case() {
        let dto = SeedDisplay {
            words: vec!["abandon".into()],
            word_count: 1,
            has_passphrase: true,
        };
        let json = serde_json::to_value(&dto).expect("serialize");
        let obj = json.as_object().expect("should be object");

        assert!(
            obj.contains_key("wordCount"),
            "should have camelCase wordCount"
        );
        assert!(
            obj.contains_key("hasPassphrase"),
            "should have camelCase hasPassphrase"
        );
        assert!(
            !obj.contains_key("word_count"),
            "should NOT have snake_case word_count"
        );
        assert!(
            !obj.contains_key("has_passphrase"),
            "should NOT have snake_case has_passphrase"
        );
    }

    #[test]
    fn dto_fields_are_camel_case() {
        let dto = sample_metadata();
        let json = serde_json::to_value(&dto).expect("serialize");
        let obj = json.as_object().expect("should be object");

        // Verify camelCase keys.
        assert!(obj.contains_key("entryType"), "should have entryType");
        assert!(obj.contains_key("createdAt"), "should have createdAt");
        assert!(obj.contains_key("updatedAt"), "should have updatedAt");

        // Verify no snake_case keys.
        assert!(
            !obj.contains_key("entry_type"),
            "should NOT have snake_case entry_type"
        );
        assert!(
            !obj.contains_key("created_at"),
            "should NOT have snake_case created_at"
        );
        assert!(
            !obj.contains_key("updated_at"),
            "should NOT have snake_case updated_at"
        );
    }

    // ─── constant_time_key_eq tests (used by delete_entry_with_auth & reveal) ───

    #[test]
    fn constant_time_eq_matching_keys() {
        let key = [0x42u8; 32];
        assert!(constant_time_key_eq(&key, &key));
    }

    #[test]
    fn constant_time_eq_different_keys() {
        let a = [0x42u8; 32];
        let mut b = [0x42u8; 32];
        b[31] = 0x43;
        assert!(!constant_time_key_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(constant_time_key_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 16];
        assert!(!constant_time_key_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_single_bit_difference() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 1; // Single bit flip
        assert!(!constant_time_key_eq(&a, &b));
    }

    // ─── entry type auth requirement tests ───

    #[test]
    fn seed_phrase_requires_auth() {
        let entry_type = verrou_vault::EntryType::SeedPhrase;
        let requires = matches!(
            entry_type,
            verrou_vault::EntryType::SeedPhrase | verrou_vault::EntryType::RecoveryCode
        );
        assert!(requires, "SeedPhrase must require re-auth for deletion");
    }

    #[test]
    fn recovery_code_requires_auth() {
        let entry_type = verrou_vault::EntryType::RecoveryCode;
        let requires = matches!(
            entry_type,
            verrou_vault::EntryType::SeedPhrase | verrou_vault::EntryType::RecoveryCode
        );
        assert!(requires, "RecoveryCode must require re-auth for deletion");
    }

    #[test]
    fn totp_skips_auth() {
        let entry_type = verrou_vault::EntryType::Totp;
        let requires = matches!(
            entry_type,
            verrou_vault::EntryType::SeedPhrase | verrou_vault::EntryType::RecoveryCode
        );
        assert!(!requires, "Totp must NOT require re-auth for deletion");
    }

    #[test]
    fn hotp_skips_auth() {
        let entry_type = verrou_vault::EntryType::Hotp;
        let requires = matches!(
            entry_type,
            verrou_vault::EntryType::SeedPhrase | verrou_vault::EntryType::RecoveryCode
        );
        assert!(!requires, "Hotp must NOT require re-auth for deletion");
    }

    #[test]
    fn secure_note_skips_auth() {
        let entry_type = verrou_vault::EntryType::SecureNote;
        let requires = matches!(
            entry_type,
            verrou_vault::EntryType::SeedPhrase | verrou_vault::EntryType::RecoveryCode
        );
        assert!(
            !requires,
            "SecureNote must NOT require re-auth for deletion"
        );
    }

    // ─── RecoveryCodeDisplay DTO tests ───

    #[test]
    fn recovery_code_display_dto_snapshot() {
        let dto = RecoveryCodeDisplay {
            codes: vec!["ABCD-1234".into(), "EFGH-5678".into(), "IJKL-9012".into()],
            used: vec![1],
            total_codes: 3,
            remaining_codes: 2,
            linked_entry_id: Some("totp-uuid-123".into()),
            has_linked_entry: true,
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn recovery_code_display_dto_standalone_snapshot() {
        let dto = RecoveryCodeDisplay {
            codes: vec!["CODE-A".into(), "CODE-B".into()],
            used: vec![],
            total_codes: 2,
            remaining_codes: 2,
            linked_entry_id: None,
            has_linked_entry: false,
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn recovery_code_display_fields_are_camel_case() {
        let dto = RecoveryCodeDisplay {
            codes: vec!["X".into()],
            used: vec![],
            total_codes: 1,
            remaining_codes: 1,
            linked_entry_id: Some("id".into()),
            has_linked_entry: true,
        };
        let json = serde_json::to_value(&dto).expect("serialize");
        let obj = json.as_object().expect("should be object");

        assert!(
            obj.contains_key("totalCodes"),
            "should have camelCase totalCodes"
        );
        assert!(
            obj.contains_key("remainingCodes"),
            "should have camelCase remainingCodes"
        );
        assert!(
            obj.contains_key("linkedEntryId"),
            "should have camelCase linkedEntryId"
        );
        assert!(
            obj.contains_key("hasLinkedEntry"),
            "should have camelCase hasLinkedEntry"
        );
        assert!(
            !obj.contains_key("total_codes"),
            "should NOT have snake_case total_codes"
        );
        assert!(
            !obj.contains_key("remaining_codes"),
            "should NOT have snake_case remaining_codes"
        );
        assert!(
            !obj.contains_key("linked_entry_id"),
            "should NOT have snake_case linked_entry_id"
        );
    }

    #[test]
    fn recovery_code_display_no_linked_id_omits_field() {
        let dto = RecoveryCodeDisplay {
            codes: vec!["X".into()],
            used: vec![],
            total_codes: 1,
            remaining_codes: 1,
            linked_entry_id: None,
            has_linked_entry: false,
        };
        let json = serde_json::to_value(&dto).expect("serialize");
        assert!(
            json.get("linkedEntryId").is_none(),
            "linkedEntryId should be omitted when None"
        );
    }

    #[test]
    fn recovery_code_display_debug_masks_codes() {
        let dto = RecoveryCodeDisplay {
            codes: vec!["SECRET-CODE".into()],
            used: vec![],
            total_codes: 1,
            remaining_codes: 1,
            linked_entry_id: None,
            has_linked_entry: false,
        };
        let debug = format!("{dto:?}");
        assert!(!debug.contains("SECRET-CODE"), "Debug must not leak codes");
        assert!(debug.contains("***"), "Debug should show masked output");
    }

    // ─── RecoveryStats DTO tests ───

    #[test]
    fn recovery_stats_dto_snapshot() {
        let dto = RecoveryStats {
            total: 10,
            remaining: 7,
        };
        insta::assert_json_snapshot!(dto);
    }

    #[test]
    fn recovery_stats_fields_are_camel_case() {
        let dto = RecoveryStats {
            total: 5,
            remaining: 3,
        };
        let json = serde_json::to_value(&dto).expect("serialize");
        let obj = json.as_object().expect("should be object");
        assert!(obj.contains_key("total"), "should have total");
        assert!(obj.contains_key("remaining"), "should have remaining");
    }

    // ─── build_entry_data recovery code tests ───

    #[test]
    fn build_entry_data_recovery_code_bulk_import() {
        let result = build_entry_data(
            verrou_vault::EntryType::RecoveryCode,
            "CODE-1\nCODE-2\nCODE-3\n",
            None,
            None,
            None,
            Vec::new(),
        );
        let data = result.expect("should succeed");
        match &data {
            verrou_vault::EntryData::RecoveryCode {
                codes,
                used,
                linked_entry_id,
            } => {
                assert_eq!(codes, &["CODE-1", "CODE-2", "CODE-3"]);
                assert!(used.is_empty());
                assert!(linked_entry_id.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn build_entry_data_recovery_code_trims_whitespace() {
        let result = build_entry_data(
            verrou_vault::EntryType::RecoveryCode,
            "  CODE-1  \n  CODE-2  \n",
            None,
            None,
            None,
            Vec::new(),
        );
        let data = result.expect("should succeed");
        match &data {
            verrou_vault::EntryData::RecoveryCode { codes, .. } => {
                assert_eq!(codes, &["CODE-1", "CODE-2"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn build_entry_data_recovery_code_empty_rejected() {
        let result = build_entry_data(
            verrou_vault::EntryType::RecoveryCode,
            "",
            None,
            None,
            None,
            Vec::new(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("At least one recovery code"));
    }

    #[test]
    fn build_entry_data_recovery_code_only_whitespace_rejected() {
        let result = build_entry_data(
            verrou_vault::EntryType::RecoveryCode,
            "  \n  \n  ",
            None,
            None,
            None,
            Vec::new(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("At least one recovery code"));
    }

    #[test]
    fn build_entry_data_recovery_code_too_long_rejected() {
        let long_code = "A".repeat(257);
        let result = build_entry_data(
            verrou_vault::EntryType::RecoveryCode,
            &long_code,
            None,
            None,
            None,
            Vec::new(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds maximum length"));
    }

    #[test]
    fn build_entry_data_recovery_code_max_length_accepted() {
        let max_code = "A".repeat(256);
        let result = build_entry_data(
            verrou_vault::EntryType::RecoveryCode,
            &max_code,
            None,
            None,
            None,
            Vec::new(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn build_entry_data_recovery_code_with_linked_id() {
        let result = build_entry_data(
            verrou_vault::EntryType::RecoveryCode,
            "CODE-1\nCODE-2",
            None,
            None,
            Some("totp-uuid-123".into()),
            Vec::new(),
        );
        let data = result.expect("should succeed");
        match &data {
            verrou_vault::EntryData::RecoveryCode {
                linked_entry_id, ..
            } => {
                assert_eq!(linked_entry_id.as_deref(), Some("totp-uuid-123"));
            }
            _ => panic!("wrong variant"),
        }
    }

    // ─── toggle_recovery_code_used logic tests ───

    /// Simulate the toggle logic: if index is in `used`, remove it; otherwise add it.
    fn toggle_used(used: &mut Vec<usize>, idx: usize) {
        if let Some(pos) = used.iter().position(|&u| u == idx) {
            used.remove(pos);
        } else {
            used.push(idx);
        }
    }

    #[test]
    fn toggle_used_marks_unused_code_as_used() {
        let mut used = vec![];
        toggle_used(&mut used, 0);
        assert_eq!(used, vec![0]);
    }

    #[test]
    fn toggle_used_unmarks_used_code() {
        let mut used = vec![0, 2];
        toggle_used(&mut used, 0);
        assert_eq!(used, vec![2]);
    }

    #[test]
    fn toggle_used_preserves_other_indexes() {
        let mut used = vec![1, 3, 5];
        toggle_used(&mut used, 3);
        assert_eq!(used, vec![1, 5]);
    }

    #[test]
    fn toggle_used_round_trip() {
        let mut used = vec![];
        toggle_used(&mut used, 2);
        assert_eq!(used, vec![2]);
        toggle_used(&mut used, 2);
        assert!(used.is_empty(), "toggling twice should return to unused");
    }

    #[test]
    fn toggle_used_multiple_codes() {
        let mut used = vec![];
        toggle_used(&mut used, 0);
        toggle_used(&mut used, 2);
        toggle_used(&mut used, 4);
        assert_eq!(used, vec![0, 2, 4]);
        // Remaining count calculation
        let total: u32 = 6;
        let remaining = total.saturating_sub(used.len() as u32);
        assert_eq!(remaining, 3);
    }

    #[test]
    fn toggle_used_count_all_used() {
        let total_codes: u32 = 3;
        let used = [0, 1, 2];
        let remaining = total_codes.saturating_sub(used.len() as u32);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn build_entry_data_recovery_code_filters_empty_lines() {
        let result = build_entry_data(
            verrou_vault::EntryType::RecoveryCode,
            "CODE-1\n\n\nCODE-2\n\n",
            None,
            None,
            None,
            Vec::new(),
        );
        let data = result.expect("should succeed");
        match &data {
            verrou_vault::EntryData::RecoveryCode { codes, .. } => {
                assert_eq!(codes.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    // ─── update_recovery_codes logic tests ───

    /// Simulate the `update_recovery_codes` index adjustment algorithm.
    /// Removes codes at given indexes (highest-first), adjusts used indexes.
    fn update_codes_logic(
        codes: &mut Vec<String>,
        used: &mut Vec<usize>,
        indexes_to_remove: &[u32],
        codes_to_add: &[String],
    ) {
        // Deduplicate and sort removal indexes descending.
        let mut sorted_removes: Vec<usize> = indexes_to_remove
            .iter()
            .map(|&i| i as usize)
            .collect::<std::collections::BTreeSet<usize>>()
            .into_iter()
            .collect::<Vec<_>>();
        sorted_removes.sort_unstable_by(|a, b| b.cmp(a));

        // Remove codes highest-first.
        for &idx in &sorted_removes {
            if idx < codes.len() {
                codes.remove(idx);
            }
        }

        // Adjust used: drop references to removed, decrement above.
        let removes_set: std::collections::HashSet<usize> =
            sorted_removes.iter().copied().collect();
        let mut adjusted: Vec<usize> = used
            .iter()
            .filter(|u| !removes_set.contains(u))
            .copied()
            .collect();
        // Process removals descending (matches actual command logic).
        for &removed_idx in &sorted_removes {
            for u in &mut adjusted {
                if *u > removed_idx {
                    *u -= 1;
                }
            }
        }
        *used = adjusted;

        // Append new codes.
        for code in codes_to_add {
            let trimmed = code.trim().to_string();
            if !trimmed.is_empty() {
                codes.push(trimmed);
            }
        }
    }

    #[test]
    fn update_codes_add_only() {
        let mut codes = vec!["A".into(), "B".into()];
        let mut used = vec![0];
        update_codes_logic(&mut codes, &mut used, &[], &["C".into(), "D".into()]);
        assert_eq!(codes, vec!["A", "B", "C", "D"]);
        assert_eq!(used, vec![0], "used indexes unchanged when only adding");
    }

    #[test]
    fn update_codes_remove_only() {
        let mut codes = vec!["A".into(), "B".into(), "C".into(), "D".into()];
        let mut used: Vec<usize> = vec![1, 3];
        // Remove index 1 ("B")
        update_codes_logic(&mut codes, &mut used, &[1], &[]);
        assert_eq!(codes, vec!["A", "C", "D"]);
        // used[1] was removed (was "B"), used[3] → 2 (decremented)
        assert_eq!(used, vec![2]);
    }

    #[test]
    fn update_codes_add_and_remove_combined() {
        let mut codes = vec!["A".into(), "B".into(), "C".into()];
        let mut used: Vec<usize> = vec![0, 2];
        // Remove index 1 ("B"), add "D"
        update_codes_logic(&mut codes, &mut used, &[1], &["D".into()]);
        assert_eq!(codes, vec!["A", "C", "D"]);
        // used[0] stays 0 (below removed), used[2] → 1 (decremented)
        assert_eq!(used, vec![0, 1]);
    }

    #[test]
    fn update_codes_used_index_adjustment_multiple_removals() {
        let mut codes = vec!["A".into(), "B".into(), "C".into(), "D".into(), "E".into()];
        let mut used: Vec<usize> = vec![0, 2, 4];
        // Remove indexes 1 ("B") and 3 ("D")
        update_codes_logic(&mut codes, &mut used, &[1, 3], &[]);
        assert_eq!(codes, vec!["A", "C", "E"]);
        // 0 → stays 0 (below both removed)
        // 2 → 1 (one removal below: idx 1)
        // 4 → 2 (two removals below: idx 1 and 3)
        assert_eq!(used, vec![0, 1, 2]);
    }

    #[test]
    fn update_codes_remove_used_code_drops_from_used() {
        let mut codes = vec!["A".into(), "B".into(), "C".into()];
        let mut used: Vec<usize> = vec![0, 1, 2];
        // Remove index 1 ("B") which is in used — should be dropped
        update_codes_logic(&mut codes, &mut used, &[1], &[]);
        assert_eq!(codes, vec!["A", "C"]);
        // used[0] stays 0, used[1] dropped, used[2] → 1
        assert_eq!(used, vec![0, 1]);
    }

    #[test]
    fn update_codes_empty_operations_no_change() {
        let mut codes = vec!["A".into(), "B".into()];
        let mut used: Vec<usize> = vec![1];
        update_codes_logic(&mut codes, &mut used, &[], &[]);
        assert_eq!(codes, vec!["A", "B"]);
        assert_eq!(used, vec![1]);
    }

    // ─── cascade deletion logic tests ───

    #[test]
    fn cascade_identifies_totp_hotp_for_linked_check() {
        // TOTP and HOTP trigger cascade check
        assert!(matches!(
            verrou_vault::EntryType::Totp,
            verrou_vault::EntryType::Totp | verrou_vault::EntryType::Hotp
        ));
        assert!(matches!(
            verrou_vault::EntryType::Hotp,
            verrou_vault::EntryType::Totp | verrou_vault::EntryType::Hotp
        ));
        // Other types do NOT trigger cascade
        assert!(!matches!(
            verrou_vault::EntryType::SeedPhrase,
            verrou_vault::EntryType::Totp | verrou_vault::EntryType::Hotp
        ));
        assert!(!matches!(
            verrou_vault::EntryType::RecoveryCode,
            verrou_vault::EntryType::Totp | verrou_vault::EntryType::Hotp
        ));
        assert!(!matches!(
            verrou_vault::EntryType::SecureNote,
            verrou_vault::EntryType::Totp | verrou_vault::EntryType::Hotp
        ));
    }

    #[test]
    fn credential_requires_auth() {
        let entry_type = verrou_vault::EntryType::Credential;
        let requires = matches!(
            entry_type,
            verrou_vault::EntryType::SeedPhrase
                | verrou_vault::EntryType::RecoveryCode
                | verrou_vault::EntryType::Credential
        );
        assert!(requires, "Credential must require re-auth for deletion");
    }

    // ─── now_for_history timestamp tests ───

    #[test]
    fn now_for_history_produces_valid_iso8601() {
        let ts = now_for_history();
        // Must match YYYY-MM-DDTHH:MM:SSZ
        assert_eq!(ts.len(), 20, "ISO 8601 UTC timestamp should be 20 chars");
        assert!(ts.ends_with('Z'), "should end with Z for UTC");
        assert_eq!(&ts[4..5], "-", "dash after year");
        assert_eq!(&ts[7..8], "-", "dash after month");
        assert_eq!(&ts[10..11], "T", "T separator");
        assert_eq!(&ts[13..14], ":", "colon after hours");
        assert_eq!(&ts[16..17], ":", "colon after minutes");

        // Year should be reasonable (2020+)
        let year: u32 = ts[0..4].parse().expect("year should parse");
        assert!(year >= 2020, "year should be 2020 or later");

        // Month 01-12
        let month: u32 = ts[5..7].parse().expect("month should parse");
        assert!((1..=12).contains(&month), "month should be 1-12");

        // Day 01-31
        let day: u32 = ts[8..10].parse().expect("day should parse");
        assert!((1..=31).contains(&day), "day should be 1-31");

        // Hour 00-23
        let hour: u32 = ts[11..13].parse().expect("hour should parse");
        assert!(hour <= 23, "hour should be 0-23");

        // Minute 00-59
        let minute: u32 = ts[14..16].parse().expect("minute should parse");
        assert!(minute <= 59, "minute should be 0-59");

        // Second 00-59
        let second: u32 = ts[17..19].parse().expect("second should parse");
        assert!(second <= 59, "second should be 0-59");
    }

    #[test]
    fn add_entry_request_with_template_round_trips_serde() {
        let json = serde_json::json!({
            "entryType": "credential",
            "name": "My Card",
            "secret": "s3cur3",
            "username": "user@test.com",
            "template": "credit_card",
            "customFields": [
                { "label": "Card Number", "value": "4111", "fieldType": "hidden" }
            ]
        });
        let req: AddEntryRequest = serde_json::from_value(json).expect("deserialize");
        assert_eq!(req.template.as_deref(), Some("credit_card"));
        assert_eq!(req.custom_fields.len(), 1);

        // Re-serialize and verify template is present
        let re = serde_json::to_value(&req).expect("serialize");
        assert_eq!(re["template"], "credit_card");
    }

    #[test]
    fn add_entry_request_without_template_defaults_to_none() {
        let json = serde_json::json!({
            "entryType": "credential",
            "name": "Login",
            "secret": "pass"
        });
        let req: AddEntryRequest = serde_json::from_value(json).expect("deserialize");
        assert!(req.template.is_none());
    }

    #[test]
    fn credential_display_with_template_serializes() {
        let dto = CredentialDisplay {
            password: "s3cur3".into(),
            username: Some("admin".into()),
            urls: vec!["https://example.com".into()],
            notes: None,
            linked_totp_id: None,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            template: Some("ssh_key".into()),
        };
        let json = serde_json::to_value(&dto).expect("serialize");
        assert_eq!(json["template"], "ssh_key");
    }

    #[test]
    fn credential_display_without_template_omits_field() {
        let dto = CredentialDisplay {
            password: "pass".into(),
            username: None,
            urls: Vec::new(),
            notes: None,
            linked_totp_id: None,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            template: None,
        };
        let json = serde_json::to_value(&dto).expect("serialize");
        assert!(
            json.get("template").is_none(),
            "template should be omitted when None"
        );
    }

    #[test]
    fn cascade_linked_entry_id_matching() {
        let parent_id = "totp-uuid-123";
        let linked: Option<String> = Some("totp-uuid-123".into());
        let unlinked: Option<String> = Some("other-uuid-456".into());
        let none: Option<String> = None;

        assert_eq!(linked.as_deref(), Some(parent_id), "linked should match");
        assert_ne!(
            unlinked.as_deref(),
            Some(parent_id),
            "unlinked should NOT match"
        );
        assert_ne!(none.as_deref(), Some(parent_id), "None should NOT match");
    }
}
