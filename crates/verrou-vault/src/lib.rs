//! `verrou-vault` — Vault business logic for VERROU.
//!
//! Manages encrypted storage via `SQLCipher`, entry CRUD operations,
//! and vault lifecycle (create, open, lock, backup).

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::arithmetic_side_effects))]

pub mod db;
pub mod error;
pub mod lifecycle;
pub mod recovery;

pub mod entries;

pub mod import;

pub mod export;

pub mod folders;

// TODO: Search across all entry types
// pub mod search;

pub mod health;

pub mod attachments;

pub mod preferences;

pub mod transfer;

pub use attachments::{
    add_attachment, count_attachments, delete_attachment, get_attachment, list_attachments,
    mime_from_filename, AttachmentMetadata,
};
pub use db::VaultDb;
pub use entries::{
    add_entry, delete_entry, get_entry, get_entry_type, list_entries, update_entry, AddEntryParams,
    Algorithm, CustomField, CustomFieldType, Entry, EntryData, EntryListItem, EntryType,
    PasswordHistoryEntry, UpdateEntryParams,
};
pub use error::VaultError;
pub use export::verrou_format::{export_vault, ExportResult, ExportVaultRequest};
pub use folders::{
    create_folder, delete_folder, list_folders_with_counts, rename_folder, Folder, FolderListItem,
};
pub use health::{
    analyze_password_health, evaluate_password_strength, AgeSeverity, CredentialRef, OldCredential,
    PasswordHealthReport, PasswordStrength, ReusedGroup, WeakCredential,
};
pub use import::verrou_format::{
    import_verrou_file, validate_verrou_import, DuplicateMode, VerrouDuplicateInfo,
    VerrouEntryPreview, VerrouImportPreview, VerrouImportResult,
};
pub use lifecycle::{
    add_biometric_slot, add_hardware_security_slot, calibrate_for_vault, change_master_password,
    change_password_after_recovery, create_backup, create_vault, has_biometric_slot,
    has_hardware_security_slot, list_backups, remove_biometric_slot, remove_hardware_security_slot,
    restore_backup, unlock_vault, unlock_vault_with_biometric, unlock_vault_with_recovery_key,
    verify_vault_integrity, verify_vault_password, BackupInfo, ChangeMasterPasswordRequest,
    ChangePasswordAfterRecoveryRequest, CreateVaultRequest, CreateVaultResult, IntegrityReport,
    IntegrityStatus, PasswordChangeResult, UnlockVaultRequest, UnlockVaultResult,
    UnlockVaultSession,
};
pub use recovery::{
    add_recovery_slot, decode_recovery_key, encode_recovery_key, vault_fingerprint,
    AddRecoverySlotRequest, GenerateRecoveryKeyResult,
};
pub use transfer::{
    import_transfer_entries, serialize_entries_for_transfer, TransferEntry, TransferPayload,
};
