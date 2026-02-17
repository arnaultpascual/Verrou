//! Vault error types for `verrou-vault`.

use thiserror::Error;
use verrou_crypto_core::CryptoError;

/// Errors produced by vault operations.
#[derive(Debug, Error)]
pub enum VaultError {
    /// Cryptographic operation failed (delegated from crypto-core).
    #[error(transparent)]
    Crypto(#[from] CryptoError),

    /// Incorrect master password or recovery key — the `SQLCipher` database
    /// could not be decrypted.
    #[error("invalid password")]
    InvalidPassword,

    /// `SQLCipher` database error.
    #[error("database error: {0}")]
    Database(String),

    /// Vault file not found or inaccessible.
    #[error("vault not found: {0}")]
    NotFound(String),

    /// Vault is locked — operation requires an unlocked vault.
    #[error("vault is locked")]
    Locked,

    /// Entry not found by ID.
    #[error("entry not found: {0}")]
    EntryNotFound(String),

    /// Import format parsing failure.
    #[error("import error: {0}")]
    Import(String),

    /// Export or backup failure.
    #[error("export error: {0}")]
    Export(String),

    /// Vault integrity check failed (corruption detected).
    #[error("integrity check failed: {0}")]
    IntegrityFailure(String),

    /// Too many failed unlock attempts — brute-force cooldown active.
    #[error("rate limited: {remaining_ms}ms remaining")]
    RateLimited {
        /// Milliseconds remaining in the cooldown period.
        remaining_ms: u64,
    },

    /// No recovery slot found in the vault header.
    #[error("no recovery slot configured for this vault")]
    RecoverySlotNotFound,

    /// Invalid recovery key (wrong format, bad checksum, or wrong key).
    #[error("invalid recovery key")]
    InvalidRecoveryKey,

    /// A vault already exists at the target path.
    #[error("vault already exists: {0}")]
    VaultAlreadyExists(String),

    /// Migration error during schema upgrade.
    #[error("migration error: {0}")]
    Migration(String),

    /// I/O error from the filesystem.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Biometric unlock failed (wrong token or corrupted slot).
    #[error("biometric unlock failed")]
    BiometricUnlockFailed,

    /// No biometric slot found in the vault header.
    #[error("no biometric slot configured for this vault")]
    BiometricSlotNotFound,

    /// Attachment not found by ID.
    #[error("attachment not found: {0}")]
    AttachmentNotFound(String),

    /// File exceeds the maximum allowed size for attachments.
    #[error("file size {actual_bytes} bytes exceeds maximum {max_bytes} bytes")]
    FileSizeLimitExceeded {
        /// Maximum allowed size in bytes.
        max_bytes: usize,
        /// Actual file size in bytes.
        actual_bytes: usize,
    },

    /// Entry already has the maximum number of attachments.
    #[error("entry {entry_id} already has {max} attachments")]
    AttachmentCountExceeded {
        /// Maximum attachments per entry.
        max: usize,
        /// The entry that exceeded the limit.
        entry_id: String,
    },
}

impl From<rusqlite::Error> for VaultError {
    fn from(err: rusqlite::Error) -> Self {
        // SQLITE_NOTADB (code 26) signals an incorrect encryption key.
        if let rusqlite::Error::SqliteFailure(ref ffi_err, _) = err {
            if ffi_err.code == rusqlite::ffi::ErrorCode::NotADatabase {
                return Self::InvalidPassword;
            }
        }
        Self::Database(err.to_string())
    }
}
