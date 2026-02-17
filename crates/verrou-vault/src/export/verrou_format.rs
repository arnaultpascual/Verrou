//! Encrypted `.verrou` vault export.
//!
//! Serializes all vault data (entries, folders, attachments) into an
//! encrypted `.verrou` binary file that can be imported on any VERROU
//! instance with the correct password.
//!
//! # Security Model
//!
//! - Re-authentication verifies the password before export
//! - A **fresh** master key is generated per export (independent of session key)
//! - The export file contains its own password slot for decryption
//! - Compromise of an export file does not expose the source vault's master key

use std::path::Path;

use rand::rngs::OsRng;
use rand::RngCore;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use verrou_crypto_core::kdf;
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::slots::{self, SlotType};
use verrou_crypto_core::vault_format::{self, VaultHeader, FORMAT_VERSION};

use crate::attachments;
use crate::entries::{self, Algorithm, EntryData, EntryType};
use crate::error::VaultError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SALT_LEN: usize = 16;
const HEADER_FILE: &str = "vault.verrou";

// ---------------------------------------------------------------------------
// Export payload types
// ---------------------------------------------------------------------------

/// Complete vault export payload (serialized to JSON, then encrypted).
#[derive(Serialize, Deserialize)]
pub struct ExportPayload {
    /// Export format version.
    pub version: u8,
    /// ISO 8601 timestamp of export.
    pub exported_at: String,
    /// All vault entries with decrypted data.
    pub entries: Vec<ExportedEntry>,
    /// All vault folders.
    pub folders: Vec<ExportedFolder>,
    /// All vault attachments with decrypted data.
    pub attachments: Vec<ExportedAttachment>,
}

/// A single entry with all metadata and decrypted payload.
#[derive(Serialize, Deserialize)]
pub struct ExportedEntry {
    pub id: String,
    pub entry_type: EntryType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u32,
    pub counter: u64,
    pub pinned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    pub data: EntryData,
    pub created_at: String,
    pub updated_at: String,
}

/// A folder in the export payload.
#[derive(Serialize, Deserialize)]
pub struct ExportedFolder {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub sort_order: i32,
}

/// An attachment with decrypted file data.
#[derive(Serialize, Deserialize)]
pub struct ExportedAttachment {
    pub id: String,
    pub entry_id: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: i64,
    /// Raw decrypted file bytes.
    pub data: Vec<u8>,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Request / result types
// ---------------------------------------------------------------------------

/// Parameters for vault export.
pub struct ExportVaultRequest<'a> {
    /// Master password (for re-auth verification and export key slot creation).
    pub password: &'a [u8],
    /// Session master key (for decrypting entries/attachments).
    pub master_key: &'a [u8],
    /// Vault directory containing `vault.verrou` and `vault.db`.
    pub vault_dir: &'a Path,
}

/// Result of a successful vault export.
#[derive(Debug)]
pub struct ExportResult {
    /// The encrypted `.verrou` binary data (ready to write to file).
    pub export_data: Vec<u8>,
    /// Number of entries exported.
    pub entry_count: usize,
    /// Number of folders exported.
    pub folder_count: usize,
    /// Number of attachments exported.
    pub attachment_count: usize,
}

// ---------------------------------------------------------------------------
// Core export function
// ---------------------------------------------------------------------------

/// Export the entire vault as an encrypted `.verrou` file.
///
/// # Flow
///
/// 1. Re-authenticate by verifying the password against the vault header
/// 2. Read and decrypt all entries, folders, and attachments
/// 3. Serialize the data as a JSON payload
/// 4. Generate a fresh export master key and password slot
/// 5. Encrypt and pad the payload using `vault_format::serialize`
///
/// # Errors
///
/// - [`VaultError::InvalidPassword`] if the password is incorrect
/// - [`VaultError::Export`] if the vault header is malformed
/// - [`VaultError::Crypto`] if encryption fails
/// - [`VaultError::Io`] if the vault files cannot be read
pub fn export_vault(
    conn: &Connection,
    req: &ExportVaultRequest<'_>,
) -> Result<ExportResult, VaultError> {
    // Step 1: Re-authenticate by verifying password against vault header.
    let header_path = req.vault_dir.join(HEADER_FILE);
    let file_data = std::fs::read(&header_path)?;
    let header = vault_format::parse_header_only(&file_data)?;

    verify_password(req.password, req.master_key, &header)?;

    // Step 2: Read all vault data.
    let mut mk_array = [0u8; 32];
    mk_array.copy_from_slice(req.master_key);
    let master_key = SecretBytes::<32>::new(mk_array);
    mk_array.zeroize(); // Clear stack copy; SecretBytes owns the key now.
    let exported_entries = read_all_entries(conn, &master_key)?;
    let exported_folders = read_all_folders(conn)?;
    let exported_attachments = read_all_attachments(conn, &master_key, &exported_entries)?;

    let entry_count = exported_entries.len();
    let folder_count = exported_folders.len();
    let attachment_count = exported_attachments.len();

    // Step 3: Build and serialize payload.
    let payload = ExportPayload {
        version: 1,
        exported_at: crate::lifecycle::now_iso8601(),
        entries: exported_entries,
        folders: exported_folders,
        attachments: exported_attachments,
    };

    let mut payload_json = serde_json::to_vec(&payload)
        .map_err(|e| VaultError::Export(format!("failed to serialize export payload: {e}")))?;

    // Step 4: Generate fresh export encryption key.
    let export_master_key = SecretBytes::<32>::random()?;

    // Step 5: Create a password slot for the export file.
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let wrapping_key = kdf::derive(req.password, &salt, &header.session_params)?;
    let export_slot = slots::create_slot(
        export_master_key.expose(),
        wrapping_key.expose(),
        SlotType::Password,
    )?;

    // Step 6: Build export header.
    let export_header = VaultHeader {
        version: FORMAT_VERSION,
        slot_count: 1,
        session_params: header.session_params.clone(),
        sensitive_params: header.sensitive_params,
        unlock_attempts: 0,
        last_attempt_at: None,
        total_unlock_count: 0,
        slots: vec![export_slot],
        slot_salts: vec![salt.to_vec()],
    };

    // Step 7: Serialize to encrypted .verrou binary.
    let export_data =
        vault_format::serialize(&export_header, &payload_json, export_master_key.expose())?;

    // Step 8: Zeroize intermediates.
    payload_json.zeroize();

    Ok(ExportResult {
        export_data,
        entry_count,
        folder_count,
        attachment_count,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Verify the password by unwrapping the vault's password slot and comparing
/// the recovered key to the session master key.
fn verify_password(
    password: &[u8],
    master_key: &[u8],
    header: &VaultHeader,
) -> Result<(), VaultError> {
    let (slot_index, password_slot) = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == SlotType::Password)
        .ok_or_else(|| VaultError::Export("no password slot found in vault header".into()))?;

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| VaultError::Export("missing salt for password slot".into()))?;

    let wrapping_key = kdf::derive(password, salt, &header.session_params)?;
    let recovered_key = slots::unwrap_slot(password_slot, wrapping_key.expose())
        .map_err(|_| VaultError::InvalidPassword)?;

    if recovered_key.expose() != master_key {
        return Err(VaultError::InvalidPassword);
    }

    Ok(())
}

/// Read all entries from the database with decrypted payload data.
fn read_all_entries(
    conn: &Connection,
    master_key: &SecretBytes<32>,
) -> Result<Vec<ExportedEntry>, VaultError> {
    let mut stmt = conn
        .prepare(
            "SELECT id, entry_type, name, issuer, folder_id, algorithm, digits, period, \
             counter, pinned, tags, username, template, encrypted_data, created_at, updated_at \
             FROM entries ORDER BY created_at ASC",
        )
        .map_err(|e| VaultError::Database(format!("failed to prepare entry query: {e}")))?;

    let rows = stmt
        .query_map([], |row| {
            let id: String = row.get(0)?;
            let entry_type_str: String = row.get(1)?;
            let name: String = row.get(2)?;
            let issuer: Option<String> = row.get(3)?;
            let folder_id: Option<String> = row.get(4)?;
            let algo_str: String = row.get(5)?;
            let digits: u32 = row.get(6)?;
            let period: u32 = row.get(7)?;
            let counter: i64 = row.get(8)?;
            let pinned: bool = row.get(9)?;
            let tags: Option<String> = row.get(10)?;
            let username: Option<String> = row.get(11)?;
            let template: Option<String> = row.get(12)?;
            let encrypted_data: Vec<u8> = row.get(13)?;
            let created_at: String = row.get(14)?;
            let updated_at: String = row.get(15)?;

            Ok((
                id,
                entry_type_str,
                name,
                issuer,
                folder_id,
                algo_str,
                digits,
                period,
                counter,
                pinned,
                tags,
                username,
                template,
                encrypted_data,
                created_at,
                updated_at,
            ))
        })
        .map_err(|e| VaultError::Database(format!("failed to query entries: {e}")))?;

    let mut result = Vec::new();

    for row in rows {
        let (
            id,
            entry_type_str,
            name,
            issuer,
            folder_id,
            algo_str,
            digits,
            period,
            counter,
            pinned,
            tags,
            username,
            template,
            encrypted_data,
            created_at,
            updated_at,
        ) = row.map_err(|e| VaultError::Database(format!("failed to read entry row: {e}")))?;

        let entry_type = EntryType::from_db_str(&entry_type_str)?;
        let algorithm = Algorithm::from_db_str(&algo_str)?;

        #[allow(clippy::cast_sign_loss)]
        let counter_u64 = counter as u64;

        let data = entries::decrypt_entry_data(&encrypted_data, master_key)?;

        result.push(ExportedEntry {
            id,
            entry_type,
            name,
            issuer,
            folder_id,
            algorithm,
            digits,
            period,
            counter: counter_u64,
            pinned,
            tags,
            username,
            template,
            data,
            created_at,
            updated_at,
        });
    }

    Ok(result)
}

/// Read all folders from the database.
fn read_all_folders(conn: &Connection) -> Result<Vec<ExportedFolder>, VaultError> {
    let mut stmt = conn
        .prepare("SELECT id, name, parent_id, sort_order FROM folders ORDER BY sort_order ASC")
        .map_err(|e| VaultError::Database(format!("failed to prepare folder query: {e}")))?;

    let rows = stmt
        .query_map([], |row| {
            Ok(ExportedFolder {
                id: row.get(0)?,
                name: row.get(1)?,
                parent_id: row.get(2)?,
                sort_order: row.get(3)?,
            })
        })
        .map_err(|e| VaultError::Database(format!("failed to query folders: {e}")))?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| VaultError::Database(format!("failed to read folder row: {e}")))
}

/// Read and decrypt all attachments for the exported entries.
fn read_all_attachments(
    conn: &Connection,
    master_key: &SecretBytes<32>,
    entries: &[ExportedEntry],
) -> Result<Vec<ExportedAttachment>, VaultError> {
    let mut result = Vec::new();

    for entry in entries {
        let metas = attachments::list_attachments(conn, &entry.id)?;
        for meta in metas {
            let (_, mut decrypted_data) = attachments::get_attachment(conn, master_key, &meta.id)?;

            result.push(ExportedAttachment {
                id: meta.id,
                entry_id: meta.entry_id,
                filename: meta.filename,
                mime_type: meta.mime_type,
                size_bytes: meta.size_bytes,
                data: decrypted_data.clone(),
                created_at: meta.created_at,
            });

            decrypted_data.zeroize();
        }
    }

    Ok(result)
}
