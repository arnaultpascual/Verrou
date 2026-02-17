//! Entry CRUD operations for the vault.
//!
//! Entries are the primary user data: TOTP secrets, HOTP counters,
//! seed phrases, recovery codes, and secure notes. Each entry has
//! plaintext metadata (name, issuer, type) protected by `SQLCipher`
//! (Layer 1) and an encrypted payload (`encrypted_data`) protected
//! by AES-256-GCM (Layer 2) using the master key.

use rusqlite::params;
use serde::{Deserialize, Serialize};
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::symmetric::{self, SealedData};
use zeroize::Zeroize;

use crate::error::VaultError;
use crate::lifecycle::{generate_uuid, now_iso8601};

// ---------------------------------------------------------------------------
// Entry type enums
// ---------------------------------------------------------------------------

/// Supported entry types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    /// Time-based one-time password (RFC 6238).
    Totp,
    /// HMAC-based one-time password (RFC 4226).
    Hotp,
    /// BIP39 seed phrase (12/24 words + optional passphrase).
    SeedPhrase,
    /// Service recovery codes (e.g., backup codes for 2FA).
    RecoveryCode,
    /// Free-form encrypted note.
    SecureNote,
    /// Credential (username + password + URLs + custom fields).
    Credential,
}

impl EntryType {
    /// Convert to the `snake_case` string stored in `SQLCipher`.
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Hotp => "hotp",
            Self::SeedPhrase => "seed_phrase",
            Self::RecoveryCode => "recovery_code",
            Self::SecureNote => "secure_note",
            Self::Credential => "credential",
        }
    }

    /// Parse from the database `TEXT` value.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Database`] for unknown type strings.
    pub fn from_db_str(s: &str) -> Result<Self, VaultError> {
        match s {
            "totp" => Ok(Self::Totp),
            "hotp" => Ok(Self::Hotp),
            "seed_phrase" => Ok(Self::SeedPhrase),
            "recovery_code" => Ok(Self::RecoveryCode),
            "secure_note" => Ok(Self::SecureNote),
            "credential" => Ok(Self::Credential),
            other => Err(VaultError::Database(format!("unknown entry_type: {other}"))),
        }
    }
}

/// OTP algorithm (SHA family).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// SHA-1 (default for most TOTP providers).
    SHA1,
    /// SHA-256.
    SHA256,
    /// SHA-512.
    SHA512,
}

impl Algorithm {
    /// Convert to the string stored in `SQLCipher`.
    #[must_use]
    pub const fn as_db_str(self) -> &'static str {
        match self {
            Self::SHA1 => "SHA1",
            Self::SHA256 => "SHA256",
            Self::SHA512 => "SHA512",
        }
    }

    /// Parse from the database `TEXT` value.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Database`] for unknown algorithm strings.
    pub fn from_db_str(s: &str) -> Result<Self, VaultError> {
        match s {
            "SHA1" => Ok(Self::SHA1),
            "SHA256" => Ok(Self::SHA256),
            "SHA512" => Ok(Self::SHA512),
            other => Err(VaultError::Database(format!("unknown algorithm: {other}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Encrypted payload (Layer 2)
// ---------------------------------------------------------------------------

/// The type-specific encrypted payload stored in `encrypted_data`.
///
/// Serialized to JSON, then encrypted with AES-256-GCM using the master key.
/// Each variant stores only the data specific to that entry type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntryData {
    /// TOTP/HOTP secret and parameters.
    Totp {
        /// Base32-encoded secret key.
        secret: String,
    },
    /// HOTP secret (same structure, different tag for deserialization).
    Hotp {
        /// Base32-encoded secret key.
        secret: String,
    },
    /// BIP39 seed phrase (future: Epic 6).
    SeedPhrase {
        /// Individual words.
        words: Vec<String>,
        /// Optional BIP39 passphrase (25th word).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<String>,
    },
    /// Recovery codes (Epic 6).
    RecoveryCode {
        /// Recovery code strings.
        codes: Vec<String>,
        /// Indexes of used codes.
        #[serde(default)]
        used: Vec<usize>,
        /// Optional parent TOTP/HOTP entry ID for account linking (FR14).
        /// Stored inside encrypted JSON payload to keep relationship metadata encrypted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        linked_entry_id: Option<String>,
    },
    /// Secure note (future: Epic 7).
    SecureNote {
        /// Note body (plain text or markdown).
        body: String,
        /// Optional tags for search.
        #[serde(default)]
        tags: Vec<String>,
    },
    /// Credential (username + password + URLs + custom fields).
    Credential {
        /// The password.
        password: String,
        /// Username or email.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        /// URLs associated with this credential.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        urls: Vec<String>,
        /// Free-form notes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
        /// Linked TOTP entry ID for autofill integration.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        linked_totp_id: Option<String>,
        /// Custom fields (typed key-value pairs).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        custom_fields: Vec<CustomField>,
        /// Password history (previous passwords with timestamps).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        password_history: Vec<PasswordHistoryEntry>,
        /// Template name used to create this credential (Story 7.5.8 forward-compat).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        template: Option<String>,
    },
}

/// Typed custom field for credential entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CustomField {
    /// Field label.
    pub label: String,
    /// Field value.
    pub value: String,
    /// Field type (determines display and copy behavior).
    pub field_type: CustomFieldType,
}

/// Custom field type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomFieldType {
    /// Plain text (visible).
    Text,
    /// Hidden value (masked, requires reveal).
    Hidden,
    /// URL (rendered as clickable link).
    Url,
    /// Date value (ISO 8601, rendered as formatted date).
    Date,
}

/// A previous password with the timestamp it was replaced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PasswordHistoryEntry {
    /// The previous password value.
    pub password: String,
    /// ISO 8601 timestamp when this password was replaced.
    pub changed_at: String,
}

/// Zeroize secret data on drop to prevent memory residue.
///
/// Note: `serde` (de)serialization inherently creates intermediate `String`
/// values that cannot be zeroized. This `Drop` impl covers the primary
/// in-memory lifetime of the `EntryData` struct itself, which is the most
/// important surface (the struct may live across function calls).
impl Drop for EntryData {
    fn drop(&mut self) {
        match self {
            Self::Totp { secret } | Self::Hotp { secret } => {
                secret.zeroize();
            }
            Self::SeedPhrase { words, passphrase } => {
                for word in words.iter_mut() {
                    word.zeroize();
                }
                if let Some(ref mut p) = passphrase {
                    p.zeroize();
                }
            }
            Self::RecoveryCode { codes, .. } => {
                for code in codes.iter_mut() {
                    code.zeroize();
                }
            }
            Self::SecureNote { body, .. } => {
                body.zeroize();
            }
            Self::Credential {
                password,
                username,
                urls,
                notes,
                custom_fields,
                password_history,
                template: _, // not secret
                ..
            } => {
                password.zeroize();
                if let Some(ref mut u) = username {
                    u.zeroize();
                }
                for url in urls.iter_mut() {
                    url.zeroize();
                }
                if let Some(ref mut n) = notes {
                    n.zeroize();
                }
                for field in custom_fields.iter_mut() {
                    field.value.zeroize();
                }
                for entry in password_history.iter_mut() {
                    entry.password.zeroize();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Domain model
// ---------------------------------------------------------------------------

/// Full entry domain model (in-process only — never crosses IPC).
#[derive(Debug)]
pub struct Entry {
    /// Unique identifier (UUID v4).
    pub id: String,
    /// Entry type discriminator.
    pub entry_type: EntryType,
    /// Display name (e.g., "GitHub").
    pub name: String,
    /// Optional issuer (e.g., "github.com").
    pub issuer: Option<String>,
    /// Folder ID (nullable).
    pub folder_id: Option<String>,
    /// OTP algorithm.
    pub algorithm: Algorithm,
    /// OTP digit count (6 or 8).
    pub digits: u32,
    /// TOTP period in seconds (15, 30, or 60).
    pub period: u32,
    /// HOTP counter (0 for TOTP).
    pub counter: u64,
    /// Whether this entry is pinned for quick access.
    pub pinned: bool,
    /// Decrypted entry-specific data.
    pub data: EntryData,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// ISO 8601 last-update timestamp.
    pub updated_at: String,
}

/// Metadata-only view for list operations (no decryption required).
pub struct EntryListItem {
    /// Unique identifier.
    pub id: String,
    /// Entry type.
    pub entry_type: EntryType,
    /// Display name.
    pub name: String,
    /// Optional issuer.
    pub issuer: Option<String>,
    /// Folder ID.
    pub folder_id: Option<String>,
    /// OTP algorithm.
    pub algorithm: Algorithm,
    /// OTP digits.
    pub digits: u32,
    /// TOTP period.
    pub period: u32,
    /// Whether pinned.
    pub pinned: bool,
    /// Tags (plaintext, for search; authoritative copy is in encrypted blob).
    pub tags: Vec<String>,
    /// Username (plaintext, for `EntryCard` display and search).
    /// Only populated for credential entries; `None` for other types.
    pub username: Option<String>,
    /// Template identifier (plaintext, for `EntryCard` display).
    /// Only populated for credential entries; `None` for other types.
    pub template: Option<String>,
    /// Creation timestamp.
    pub created_at: String,
    /// Last-update timestamp.
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Parameters for CRUD operations
// ---------------------------------------------------------------------------

/// Parameters for creating a new entry.
pub struct AddEntryParams {
    /// Entry type.
    pub entry_type: EntryType,
    /// Display name.
    pub name: String,
    /// Optional issuer.
    pub issuer: Option<String>,
    /// Folder ID.
    pub folder_id: Option<String>,
    /// OTP algorithm.
    pub algorithm: Algorithm,
    /// OTP digits.
    pub digits: u32,
    /// TOTP period.
    pub period: u32,
    /// HOTP counter.
    pub counter: u64,
    /// Whether pinned.
    pub pinned: bool,
    /// Tags (stored in plaintext column for search).
    pub tags: Vec<String>,
    /// Entry-specific data (will be encrypted).
    pub data: EntryData,
}

/// Parameters for updating an existing entry.
pub struct UpdateEntryParams {
    /// New display name (if changed).
    pub name: Option<String>,
    /// New issuer (if changed).
    pub issuer: Option<Option<String>>,
    /// New folder ID (if changed).
    pub folder_id: Option<Option<String>>,
    /// New algorithm (if changed).
    pub algorithm: Option<Algorithm>,
    /// New digits (if changed).
    pub digits: Option<u32>,
    /// New period (if changed).
    pub period: Option<u32>,
    /// New counter (if changed).
    pub counter: Option<u64>,
    /// New pinned state (if changed).
    pub pinned: Option<bool>,
    /// New tags (if changed).
    pub tags: Option<Vec<String>>,
    /// New entry data (if changed — will be re-encrypted).
    pub data: Option<EntryData>,
}

// ---------------------------------------------------------------------------
// Layer 2 encryption helpers
// ---------------------------------------------------------------------------

/// Convert a HOTP counter (`u64`) to the `i64` that the database stores.
///
/// Practical HOTP counters never approach `i64::MAX`, so the cast
/// is safe in practice.
#[allow(clippy::cast_possible_wrap)]
const fn counter_to_db(counter: u64) -> i64 {
    counter as i64
}

/// Convert the `i64` counter value from the database back to `u64`.
///
/// The database constraint ensures counters are non-negative.
#[allow(clippy::cast_sign_loss)]
const fn counter_from_db(value: i64) -> u64 {
    value as u64
}

/// Domain separation tag for entry data encryption.
/// Used as AAD (Additional Authenticated Data) to bind ciphertext to context.
pub(crate) const ENTRY_AAD: &[u8] = b"verrou-entry-data-v1";

/// Encrypt an [`EntryData`] struct using Layer 2 (AES-256-GCM).
///
/// # Errors
///
/// Returns [`VaultError::Crypto`] if serialization or encryption fails.
fn encrypt_entry_data(
    data: &EntryData,
    master_key: &SecretBytes<32>,
) -> Result<Vec<u8>, VaultError> {
    let json = serde_json::to_vec(data)
        .map_err(|e| VaultError::Database(format!("failed to serialize entry data: {e}")))?;

    let sealed = symmetric::encrypt(&json, master_key.expose(), ENTRY_AAD)?;
    Ok(sealed.to_bytes())
}

/// Decrypt a `BLOB` back to an [`EntryData`] struct.
///
/// # Errors
///
/// Returns [`VaultError::Crypto`] if decryption fails or data is corrupt.
pub(crate) fn decrypt_entry_data(
    blob: &[u8],
    master_key: &SecretBytes<32>,
) -> Result<EntryData, VaultError> {
    let sealed = SealedData::from_bytes(blob)?;
    let plaintext = symmetric::decrypt(&sealed, master_key.expose(), ENTRY_AAD)?;

    let data: EntryData = serde_json::from_slice(plaintext.expose())
        .map_err(|e| VaultError::Database(format!("failed to deserialize entry data: {e}")))?;

    Ok(data)
}

// ---------------------------------------------------------------------------
// CRUD operations
// ---------------------------------------------------------------------------

/// Add a new entry to the vault.
///
/// Generates a UUID, encrypts the entry data (Layer 2), and inserts
/// into the `entries` table. Returns the full `Entry` with generated fields.
///
/// # Errors
///
/// - [`VaultError::Crypto`] if encryption fails
/// - [`VaultError::Database`] if the SQL INSERT fails
pub fn add_entry(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    params: &AddEntryParams,
) -> Result<Entry, VaultError> {
    let id = generate_uuid();
    let now = now_iso8601();
    let encrypted_blob = encrypt_entry_data(&params.data, master_key)?;

    let tags_json = serde_json::to_string(&params.tags).unwrap_or_else(|_| "[]".to_string());

    // Extract username and template from credential entries for plaintext columns.
    let (username, template): (Option<&str>, Option<&str>) = match &params.data {
        EntryData::Credential {
            username, template, ..
        } => (username.as_deref(), template.as_deref()),
        _ => (None, None),
    };

    conn.execute(
        "INSERT INTO entries (id, entry_type, name, issuer, folder_id, encrypted_data, \
         algorithm, digits, period, counter, pinned, tags, username, template, \
         created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            id,
            params.entry_type.as_db_str(),
            params.name,
            params.issuer,
            params.folder_id,
            encrypted_blob,
            params.algorithm.as_db_str(),
            params.digits,
            params.period,
            counter_to_db(params.counter),
            i32::from(params.pinned),
            tags_json,
            username,
            template,
            now,
            now,
        ],
    )
    .map_err(|e| VaultError::Database(format!("failed to insert entry: {e}")))?;

    Ok(Entry {
        id,
        entry_type: params.entry_type,
        name: params.name.clone(),
        issuer: params.issuer.clone(),
        folder_id: params.folder_id.clone(),
        algorithm: params.algorithm,
        digits: params.digits,
        period: params.period,
        counter: params.counter,
        pinned: params.pinned,
        data: params.data.clone(),
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Get a single entry by ID, decrypting its data.
///
/// # Errors
///
/// - [`VaultError::EntryNotFound`] if no entry matches the ID
/// - [`VaultError::Crypto`] if decryption fails
/// - [`VaultError::Database`] if the query fails
pub fn get_entry(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    entry_id: &str,
) -> Result<Entry, VaultError> {
    let row = conn
        .query_row(
            "SELECT id, entry_type, name, issuer, folder_id, encrypted_data, \
             algorithm, digits, period, counter, pinned, created_at, updated_at \
             FROM entries WHERE id = ?1",
            params![entry_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, u32>(7)?,
                    row.get::<_, u32>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i32>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                ))
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => VaultError::EntryNotFound(entry_id.to_string()),
            other => VaultError::Database(format!("failed to query entry: {other}")),
        })?;

    let entry_type = EntryType::from_db_str(&row.1)?;
    let algorithm = Algorithm::from_db_str(&row.6)?;
    let data = decrypt_entry_data(&row.5, master_key)?;

    Ok(Entry {
        id: row.0,
        entry_type,
        name: row.2,
        issuer: row.3,
        folder_id: row.4,
        algorithm,
        digits: row.7,
        period: row.8,
        counter: counter_from_db(row.9),
        pinned: row.10 != 0,
        data,
        created_at: row.11,
        updated_at: row.12,
    })
}

/// List all entries (metadata only — no decryption).
///
/// Returns [`EntryListItem`] structs with only plaintext columns.
/// This is efficient for 500+ entries (NFR3: <100ms) because it
/// never reads or decrypts the `encrypted_data` BLOB.
///
/// # Errors
///
/// Returns [`VaultError::Database`] if the query fails.
pub fn list_entries(conn: &rusqlite::Connection) -> Result<Vec<EntryListItem>, VaultError> {
    let mut stmt = conn
        .prepare(
            "SELECT id, entry_type, name, issuer, folder_id, \
             algorithm, digits, period, pinned, tags, created_at, updated_at, \
             username, template \
             FROM entries ORDER BY pinned DESC, name ASC",
        )
        .map_err(|e| VaultError::Database(format!("failed to prepare list query: {e}")))?;

    let items = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, u32>(6)?,
                row.get::<_, u32>(7)?,
                row.get::<_, i32>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, String>(11)?,
                row.get::<_, Option<String>>(12)?,
                row.get::<_, Option<String>>(13)?,
            ))
        })
        .map_err(|e| VaultError::Database(format!("failed to execute list query: {e}")))?;

    let mut result = Vec::new();
    for item in items {
        let row = item.map_err(|e| VaultError::Database(format!("row read error: {e}")))?;
        let entry_type = EntryType::from_db_str(&row.1)?;
        let algorithm = Algorithm::from_db_str(&row.5)?;
        let tags: Vec<String> = serde_json::from_str(&row.9).unwrap_or_default();

        result.push(EntryListItem {
            id: row.0,
            entry_type,
            name: row.2,
            issuer: row.3,
            folder_id: row.4,
            algorithm,
            digits: row.6,
            period: row.7,
            pinned: row.8 != 0,
            tags,
            username: row.12,
            template: row.13,
            created_at: row.10,
            updated_at: row.11,
        });
    }

    Ok(result)
}

/// Update an existing entry.
///
/// Only fields present in `updates` are changed. If `updates.data` is
/// `Some`, the entry data is re-encrypted. The `updated_at` timestamp
/// is always refreshed.
///
/// # Errors
///
/// - [`VaultError::EntryNotFound`] if no entry matches the ID
/// - [`VaultError::Crypto`] if re-encryption fails
/// - [`VaultError::Database`] if the UPDATE fails
pub fn update_entry(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
    entry_id: &str,
    updates: &UpdateEntryParams,
) -> Result<Entry, VaultError> {
    // Verify the entry exists first.
    let existing = get_entry(conn, master_key, entry_id)?;

    let now = now_iso8601();
    let name = updates.name.as_deref().unwrap_or(&existing.name);
    let issuer = updates.issuer.as_ref().map_or(&existing.issuer, |v| v);
    let folder_id = updates
        .folder_id
        .as_ref()
        .map_or(&existing.folder_id, |v| v);
    let algorithm = updates.algorithm.unwrap_or(existing.algorithm);
    let digits = updates.digits.unwrap_or(existing.digits);
    let period = updates.period.unwrap_or(existing.period);
    let counter = updates.counter.unwrap_or(existing.counter);
    let pinned = updates.pinned.unwrap_or(existing.pinned);
    let data = updates.data.as_ref().unwrap_or(&existing.data);

    // Resolve tags: if explicitly provided use new value, otherwise keep existing
    // (read from the plaintext column via a quick SELECT).
    let tags_json = updates.tags.as_ref().map_or_else(
        || {
            // Read current tags from DB to preserve them.
            conn.query_row(
                "SELECT tags FROM entries WHERE id = ?1",
                params![entry_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap_or_else(|_| "[]".to_string())
        },
        |new_tags| serde_json::to_string(new_tags).unwrap_or_else(|_| "[]".to_string()),
    );

    // Only re-encrypt when the entry data actually changed.
    // Metadata-only updates skip the crypto operation entirely.
    // NOTE: entry_type is intentionally omitted from UPDATE — it is immutable after creation.
    if updates.data.is_some() {
        let encrypted_blob = encrypt_entry_data(data, master_key)?;
        // Extract username and template from credential data for plaintext column sync.
        let (username, template): (Option<&str>, Option<&str>) = match data {
            EntryData::Credential {
                username, template, ..
            } => (username.as_deref(), template.as_deref()),
            _ => (None, None),
        };
        conn.execute(
            "UPDATE entries SET name = ?1, issuer = ?2, folder_id = ?3, \
             algorithm = ?4, digits = ?5, period = ?6, counter = ?7, \
             pinned = ?8, encrypted_data = ?9, tags = ?10, username = ?11, \
             template = ?12, updated_at = ?13 WHERE id = ?14",
            params![
                name,
                issuer,
                folder_id,
                algorithm.as_db_str(),
                digits,
                period,
                counter_to_db(counter),
                i32::from(pinned),
                encrypted_blob,
                tags_json,
                username,
                template,
                now,
                entry_id,
            ],
        )
        .map_err(|e| VaultError::Database(format!("failed to update entry: {e}")))?;
    } else {
        conn.execute(
            "UPDATE entries SET name = ?1, issuer = ?2, folder_id = ?3, \
             algorithm = ?4, digits = ?5, period = ?6, counter = ?7, \
             pinned = ?8, tags = ?9, updated_at = ?10 \
             WHERE id = ?11",
            params![
                name,
                issuer,
                folder_id,
                algorithm.as_db_str(),
                digits,
                period,
                counter_to_db(counter),
                i32::from(pinned),
                tags_json,
                now,
                entry_id,
            ],
        )
        .map_err(|e| VaultError::Database(format!("failed to update entry: {e}")))?;
    }

    Ok(Entry {
        id: existing.id,
        entry_type: existing.entry_type,
        name: name.to_string(),
        issuer: issuer.clone(),
        folder_id: folder_id.clone(),
        algorithm,
        digits,
        period,
        counter,
        pinned,
        data: data.clone(),
        created_at: existing.created_at,
        updated_at: now,
    })
}

/// Get the entry type for an entry without decrypting its data.
///
/// Lightweight query for when only the type discriminator is needed
/// (e.g., to construct the right `EntryData` variant during update).
///
/// # Errors
///
/// - [`VaultError::EntryNotFound`] if no entry matches the ID
/// - [`VaultError::Database`] if the query fails
pub fn get_entry_type(
    conn: &rusqlite::Connection,
    entry_id: &str,
) -> Result<EntryType, VaultError> {
    let type_str: String = conn
        .query_row(
            "SELECT entry_type FROM entries WHERE id = ?1",
            params![entry_id],
            |row| row.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => VaultError::EntryNotFound(entry_id.to_string()),
            other => VaultError::Database(format!("failed to query entry type: {other}")),
        })?;

    EntryType::from_db_str(&type_str)
}

/// Delete an entry by ID.
///
/// Permanently removes the entry from the database. Confirmation
/// is handled at the IPC caller level (frontend), not here.
///
/// # Errors
///
/// - [`VaultError::EntryNotFound`] if no entry matches the ID
/// - [`VaultError::Database`] if the DELETE fails
pub fn delete_entry(conn: &rusqlite::Connection, entry_id: &str) -> Result<(), VaultError> {
    let rows_affected = conn
        .execute("DELETE FROM entries WHERE id = ?1", params![entry_id])
        .map_err(|e| VaultError::Database(format!("failed to delete entry: {e}")))?;

    if rows_affected == 0 {
        return Err(VaultError::EntryNotFound(entry_id.to_string()));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_type_roundtrip() {
        let types = [
            EntryType::Totp,
            EntryType::Hotp,
            EntryType::SeedPhrase,
            EntryType::RecoveryCode,
            EntryType::SecureNote,
            EntryType::Credential,
        ];
        for ty in &types {
            let db_str = ty.as_db_str();
            let parsed = EntryType::from_db_str(db_str)
                .unwrap_or_else(|_| panic!("failed to parse {db_str}"));
            assert_eq!(*ty, parsed);
        }
    }

    #[test]
    fn entry_type_unknown_returns_error() {
        assert!(EntryType::from_db_str("unknown").is_err());
    }

    #[test]
    fn algorithm_roundtrip() {
        let algos = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
        for algo in &algos {
            let db_str = algo.as_db_str();
            let parsed = Algorithm::from_db_str(db_str)
                .unwrap_or_else(|_| panic!("failed to parse {db_str}"));
            assert_eq!(*algo, parsed);
        }
    }

    #[test]
    fn algorithm_unknown_returns_error() {
        assert!(Algorithm::from_db_str("MD5").is_err());
    }

    #[test]
    fn entry_data_totp_serde_roundtrip() {
        let data = EntryData::Totp {
            secret: "JBSWY3DPEHPK3PXP".into(),
        };
        let json = serde_json::to_string(&data).expect("serialize");
        let parsed: EntryData = serde_json::from_str(&json).expect("deserialize");
        match &parsed {
            EntryData::Totp { secret } => assert_eq!(secret, "JBSWY3DPEHPK3PXP"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn entry_data_hotp_serde_roundtrip() {
        let data = EntryData::Hotp {
            secret: "JBSWY3DPEHPK3PXP".into(),
        };
        let json = serde_json::to_string(&data).expect("serialize");
        let parsed: EntryData = serde_json::from_str(&json).expect("deserialize");
        match &parsed {
            EntryData::Hotp { secret } => assert_eq!(secret, "JBSWY3DPEHPK3PXP"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn entry_data_seed_phrase_serde_roundtrip() {
        let data = EntryData::SeedPhrase {
            words: vec!["abandon".into(), "ability".into()],
            passphrase: Some("test".into()),
        };
        let json = serde_json::to_string(&data).expect("serialize");
        let parsed: EntryData = serde_json::from_str(&json).expect("deserialize");
        match &parsed {
            EntryData::SeedPhrase { words, passphrase } => {
                assert_eq!(words.len(), 2);
                assert_eq!(passphrase.as_deref(), Some("test"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn entry_data_recovery_code_serde_roundtrip() {
        let data = EntryData::RecoveryCode {
            codes: vec!["ABCD-1234".into(), "EFGH-5678".into()],
            used: vec![0],
            linked_entry_id: Some("totp-entry-uuid".into()),
        };
        let json = serde_json::to_string(&data).expect("serialize");
        let parsed: EntryData = serde_json::from_str(&json).expect("deserialize");
        match &parsed {
            EntryData::RecoveryCode {
                codes,
                used,
                linked_entry_id,
            } => {
                assert_eq!(codes, &["ABCD-1234", "EFGH-5678"]);
                assert_eq!(used, &[0]);
                assert_eq!(linked_entry_id.as_deref(), Some("totp-entry-uuid"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn entry_data_recovery_code_without_linked_id() {
        let data = EntryData::RecoveryCode {
            codes: vec!["CODE-1".into()],
            used: Vec::new(),
            linked_entry_id: None,
        };
        let json = serde_json::to_string(&data).expect("serialize");
        // linked_entry_id should be omitted from JSON when None
        assert!(!json.contains("linked_entry_id"));
        let parsed: EntryData = serde_json::from_str(&json).expect("deserialize");
        match &parsed {
            EntryData::RecoveryCode {
                codes,
                used,
                linked_entry_id,
            } => {
                assert_eq!(codes, &["CODE-1"]);
                assert!(used.is_empty());
                assert!(linked_entry_id.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn entry_data_recovery_code_backward_compat() {
        // Simulate existing JSON without linked_entry_id field
        let legacy_json = r#"{"type":"recovery_code","codes":["OLD-CODE"],"used":[]}"#;
        let parsed: EntryData =
            serde_json::from_str(legacy_json).expect("backward-compat deserialize");
        match &parsed {
            EntryData::RecoveryCode {
                codes,
                used,
                linked_entry_id,
            } => {
                assert_eq!(codes, &["OLD-CODE"]);
                assert!(used.is_empty());
                assert!(
                    linked_entry_id.is_none(),
                    "missing field should default to None"
                );
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn entry_data_secure_note_serde_roundtrip() {
        let data = EntryData::SecureNote {
            body: "My secure note".into(),
            tags: vec!["important".into()],
        };
        let json = serde_json::to_string(&data).expect("serialize");
        let parsed: EntryData = serde_json::from_str(&json).expect("deserialize");
        match &parsed {
            EntryData::SecureNote { body, tags } => {
                assert_eq!(body, "My secure note");
                assert_eq!(tags, &["important"]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn entry_data_credential_serde_roundtrip() {
        let data = EntryData::Credential {
            password: "s3cur3P@ss!".into(),
            username: Some("admin@example.com".into()),
            urls: vec![
                "https://example.com".into(),
                "https://app.example.com".into(),
            ],
            notes: Some("Production server".into()),
            linked_totp_id: Some("totp-uuid-123".into()),
            custom_fields: vec![
                CustomField {
                    label: "API Key".into(),
                    value: "sk-1234".into(),
                    field_type: CustomFieldType::Hidden,
                },
                CustomField {
                    label: "Docs".into(),
                    value: "https://docs.example.com".into(),
                    field_type: CustomFieldType::Url,
                },
            ],
            password_history: vec![PasswordHistoryEntry {
                password: "oldP@ss".into(),
                changed_at: "2026-01-01T00:00:00Z".into(),
            }],
            template: Some("web-login".into()),
        };
        let json = serde_json::to_string(&data).expect("serialize");
        let parsed: EntryData = serde_json::from_str(&json).expect("deserialize");
        match &parsed {
            EntryData::Credential {
                password,
                username,
                urls,
                notes,
                linked_totp_id,
                custom_fields,
                password_history,
                template,
            } => {
                assert_eq!(password, "s3cur3P@ss!");
                assert_eq!(username.as_deref(), Some("admin@example.com"));
                assert_eq!(urls.len(), 2);
                assert_eq!(notes.as_deref(), Some("Production server"));
                assert_eq!(linked_totp_id.as_deref(), Some("totp-uuid-123"));
                assert_eq!(custom_fields.len(), 2);
                assert_eq!(custom_fields[0].label, "API Key");
                assert_eq!(custom_fields[0].field_type, CustomFieldType::Hidden);
                assert_eq!(password_history.len(), 1);
                assert_eq!(password_history[0].password, "oldP@ss");
                assert_eq!(template.as_deref(), Some("web-login"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn entry_data_credential_minimal_serde_roundtrip() {
        let data = EntryData::Credential {
            password: "test123".into(),
            username: None,
            urls: Vec::new(),
            notes: None,
            linked_totp_id: None,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            template: None,
        };
        let json = serde_json::to_string(&data).expect("serialize");
        // Optional fields should be omitted
        assert!(!json.contains("username"));
        assert!(!json.contains("urls"));
        assert!(!json.contains("notes"));
        assert!(!json.contains("linked_totp_id"));
        assert!(!json.contains("template"));
        let parsed: EntryData = serde_json::from_str(&json).expect("deserialize");
        match &parsed {
            EntryData::Credential {
                password,
                username,
                urls,
                notes,
                linked_totp_id,
                custom_fields,
                password_history,
                template,
            } => {
                assert_eq!(password, "test123");
                assert!(username.is_none());
                assert!(urls.is_empty());
                assert!(notes.is_none());
                assert!(linked_totp_id.is_none());
                assert!(custom_fields.is_empty());
                assert!(password_history.is_empty());
                assert!(template.is_none());
            }
            _ => panic!("wrong variant"),
        }
    }
}
