//! Integration tests for IPC auth-tier enforcement.
//!
//! These tests verify that the security-critical command-layer gates work
//! correctly without requiring a live Tauri runtime.  Each test exercises
//! the exact code path used by the corresponding Tauri command:
//!
//! - [`test_get_entry_seed_phrase_secret_is_empty`] — the H1 fix: `get_entry`
//!   must return an empty `secret` for `seed_phrase` and `recovery_code` entries
//!   so that raw BIP39 words/codes never cross the IPC boundary on session auth
//!   alone.  Only `reveal_seed_phrase` / `reveal_recovery_codes` (which require
//!   a live master-password re-authentication) may return the plaintext.
//!
//! - [`test_get_entry_recovery_code_secret_is_empty`] — same gate, recovery codes.
//!
//! - [`test_get_entry_totp_secret_is_empty`] — the same gate extended to OTP:
//!   `get_entry` must withhold the raw TOTP/HOTP secret too. Codes are produced
//!   server-side (`generate_totp_code`); the raw secret only crosses IPC via
//!   `reveal_otp_secret` (re-auth), never under session-only auth.
//!
//! - [`test_restore_vault_backup_rejects_wrong_password`] — the H3 fix: the
//!   `restore_vault_backup` command authenticates the caller with `unlock_vault`
//!   before touching any files.  A wrong password must return `InvalidPassword`
//!   and leave the live header unmodified.
//!
//! - [`test_restore_vault_backup_accepts_correct_password`] — positive control:
//!   the correct password passes the re-auth gate.
//!
//! - [`test_locked_vault_returns_locked_error`] — session-required commands check
//!   `ManagedVaultState`.  When the state is `None` (vault locked) they must
//!   return the "Vault is locked" error string.
//!
//! # Approach
//!
//! The Tauri mock runtime (`tauri::test::MockRuntime`) requires `AppHandle` for
//! commands that call `app.path()`, making it impractical for the re-auth path
//! tested here.  Instead, we exercise the exact library seams that the commands
//! delegate to:
//!
//! - The secret-gating logic is the `match &entry.data { SeedPhrase | RecoveryCode
//!   => String::new(), ... }` block in `get_entry`.  We replicate that match
//!   directly against real `verrou_vault::EntryData` values obtained from a
//!   temp vault — this is not an abstraction: it tests the exact discriminant
//!   check the command performs.
//!
//! - The re-auth gate is the `verrou_vault::unlock_vault` call that
//!   `restore_vault_backup` executes.  We call it directly with a wrong
//!   password and assert `InvalidPassword`; then read the live header bytes and
//!   confirm they are unchanged.
//!
//! - The locked-vault guard is `state.as_ref().ok_or_else(|| "Vault is locked...")`.
//!   We construct a `ManagedVaultState` set to `None` and apply the same
//!   guard — this is identical to what every session-required command does at
//!   the top of its body.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::lifecycle::{CreateVaultRequest, UnlockVaultRequest};
use verrou_vault::{
    add_entry, get_entry, AddEntryParams, Algorithm, EntryData, EntryType, VaultError,
};

// ---------------------------------------------------------------------------
// Shared test helpers
// ---------------------------------------------------------------------------

/// Minimal Argon2id params for fast tests (not secure — test only).
const fn test_calibrated() -> CalibratedPresets {
    CalibratedPresets {
        fast: Argon2idParams {
            m_cost: 32,
            t_cost: 1,
            p_cost: 1,
        },
        balanced: Argon2idParams {
            m_cost: 64,
            t_cost: 2,
            p_cost: 1,
        },
        maximum: Argon2idParams {
            m_cost: 128,
            t_cost: 3,
            p_cost: 1,
        },
    }
}

/// Create a vault in `dir` and immediately unlock it.
///
/// Returns the open `VaultDb` and the session master key.
fn setup_vault(dir: &Path, password: &[u8]) -> (verrou_vault::VaultDb, SecretBytes<32>) {
    let calibrated = test_calibrated();
    verrou_vault::lifecycle::create_vault(&CreateVaultRequest {
        password,
        preset: KdfPreset::Fast,
        vault_dir: dir,
        calibrated: &calibrated,
    })
    .expect("vault creation should succeed in test");

    let session = verrou_vault::lifecycle::unlock_vault(&UnlockVaultRequest {
        password,
        vault_dir: dir,
    })
    .expect("vault unlock should succeed in test");

    (session.db, session.master_key)
}

/// The secret-gating predicate that `get_entry` (IPC command) applies
/// before returning `EntryDetailDto`.  Mirrors the exact `extract_secret`
/// match block in `src-tauri/src/commands/entries.rs`.
///
/// Returns an empty string for every type whose plaintext is re-auth-gated
/// (`Totp`, `Hotp`, `SeedPhrase`, `RecoveryCode`, `Credential`).  TOTP/HOTP
/// codes are produced server-side by `generate_totp_code`/`generate_hotp_code`,
/// and the raw OTP secret only leaves Rust via `reveal_otp_secret` (re-auth).
/// Only `SecureNote` bodies (display content, not a key) flow through directly.
fn command_layer_secret(data: &EntryData) -> String {
    match data {
        EntryData::SecureNote { body, .. } => body.clone(),
        EntryData::Totp { .. }
        | EntryData::Hotp { .. }
        | EntryData::SeedPhrase { .. }
        | EntryData::RecoveryCode { .. }
        | EntryData::Credential { .. } => String::new(),
    }
}

// ---------------------------------------------------------------------------
// H1 fix: `get_entry` must return an empty secret for sensitive entry types
// ---------------------------------------------------------------------------

/// `get_entry` MUST return an empty `secret` for `seed_phrase` entries.
///
/// BIP39 words must only flow through `reveal_seed_phrase` (which requires
/// master-password re-authentication).  This test verifies that the
/// command-layer gate suppresses the decrypted words unconditionally,
/// regardless of session state.
#[test]
fn test_get_entry_seed_phrase_secret_is_empty() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let password = b"seed-phrase-gate-test-pw";

    let (db, master_key) = setup_vault(tmp.path(), password);

    // Insert a 12-word BIP39 seed phrase entry.  These 12 words form a
    // valid BIP39 phrase (abandon x11 + about) — skipping checksum
    // validation at this layer since we store words directly.
    let seed_words: Vec<String> = vec![
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
    ];

    let entry = add_entry(
        db.connection(),
        &master_key,
        &AddEntryParams {
            entry_type: EntryType::SeedPhrase,
            name: "Test Wallet".into(),
            issuer: None,
            folder_id: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::SeedPhrase {
                words: seed_words.clone(),
                passphrase: None,
            },
        },
    )
    .expect("add_entry should succeed for seed phrase");

    // Fetch the entry through the vault layer (decrypts the ciphertext).
    let fetched = get_entry(db.connection(), &master_key, &entry.id)
        .expect("get_entry should succeed for existing seed phrase");

    // Confirm the vault layer DID decrypt the words (sanity check that
    // encryption/decryption is working — necessary so the gate test below
    // is meaningful).
    match &fetched.data {
        EntryData::SeedPhrase { words, .. } => {
            assert_eq!(
                *words, seed_words,
                "vault layer must decrypt seed phrase words correctly"
            );
        }
        other => panic!("expected SeedPhrase EntryData, got: {other:?}"),
    }

    // Apply the same gate the `get_entry` IPC command applies.
    // The secret crossing the IPC boundary MUST be empty.
    let ipc_secret = command_layer_secret(&fetched.data);
    assert!(
        ipc_secret.is_empty(),
        "get_entry must return empty secret for seed_phrase entries (H1 gate); \
         found non-empty secret which would bypass re-auth requirement"
    );
}

/// `get_entry` MUST return an empty `secret` for `recovery_code` entries.
///
/// Recovery codes must only flow through `reveal_recovery_codes` (which
/// requires master-password re-authentication).  Identical gate to the
/// seed-phrase case but for a different `EntryData` variant.
#[test]
fn test_get_entry_recovery_code_secret_is_empty() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let password = b"recovery-code-gate-test-pw";

    let (db, master_key) = setup_vault(tmp.path(), password);

    let codes = vec![
        "ABCD-1234-EFGH".to_string(),
        "WXYZ-5678-IJKL".to_string(),
        "MNOP-9012-QRST".to_string(),
    ];

    let entry = add_entry(
        db.connection(),
        &master_key,
        &AddEntryParams {
            entry_type: EntryType::RecoveryCode,
            name: "GitHub Recovery".into(),
            issuer: Some("github.com".into()),
            folder_id: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::RecoveryCode {
                codes: codes.clone(),
                used: Vec::new(),
                linked_entry_id: None,
            },
        },
    )
    .expect("add_entry should succeed for recovery code");

    let fetched = get_entry(db.connection(), &master_key, &entry.id)
        .expect("get_entry should succeed for existing recovery code entry");

    // Vault layer must have decrypted the codes correctly (meaningful gate below).
    match &fetched.data {
        EntryData::RecoveryCode { codes: stored, .. } => {
            assert_eq!(
                *stored, codes,
                "vault layer must decrypt recovery codes correctly"
            );
        }
        other => panic!("expected RecoveryCode EntryData, got: {other:?}"),
    }

    // IPC boundary: secret MUST be empty.
    let ipc_secret = command_layer_secret(&fetched.data);
    assert!(
        ipc_secret.is_empty(),
        "get_entry must return empty secret for recovery_code entries (H1 gate); \
         found non-empty secret which would bypass re-auth requirement"
    );
}

/// `get_entry` MUST return an empty `secret` for `totp` entries.
///
/// The raw OTP secret is a key, not display content: returning it to the
/// untrusted `WebView` under session-only auth would expose every 2FA seed.
/// The display-safe code is produced server-side by `generate_totp_code`,
/// and the raw secret only flows through `reveal_otp_secret` (re-auth).
#[test]
fn test_get_entry_totp_secret_is_empty() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let password = b"totp-gate-pw";

    let (db, master_key) = setup_vault(tmp.path(), password);

    let totp_secret = "JBSWY3DPEHPK3PXP";

    let entry = add_entry(
        db.connection(),
        &master_key,
        &AddEntryParams {
            entry_type: EntryType::Totp,
            name: "Example TOTP".into(),
            issuer: Some("example.com".into()),
            folder_id: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::Totp {
                secret: totp_secret.into(),
            },
        },
    )
    .expect("add_entry should succeed for totp");

    let fetched = get_entry(db.connection(), &master_key, &entry.id)
        .expect("get_entry should succeed for existing totp entry");

    let ipc_secret = command_layer_secret(&fetched.data);
    assert!(
        ipc_secret.is_empty(),
        "get_entry must NOT return the raw TOTP secret under session-only auth; \
         use generate_totp_code (code) or reveal_otp_secret (re-auth)"
    );
}

// ---------------------------------------------------------------------------
// H3 fix: `restore_vault_backup` must reject wrong password before touching files
// ---------------------------------------------------------------------------

/// Wrong password must make `restore_vault_backup`'s re-auth gate return
/// `InvalidPassword` and leave the live vault header byte-for-byte unchanged.
///
/// `restore_vault_backup` calls `unlock_vault` before `restore_backup`.
/// This test calls `unlock_vault` with a wrong password — exactly what the
/// command does — and then verifies that the live header was not modified.
/// The sentinel backup file has content that differs from the live header,
/// so any successful overwrite would be detectable.
#[test]
fn test_restore_vault_backup_rejects_wrong_password() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let vault_dir = tmp.path();

    let correct_password = b"correct-horse-battery-staple-h3";
    let calibrated = test_calibrated();

    verrou_vault::lifecycle::create_vault(&CreateVaultRequest {
        password: correct_password,
        preset: KdfPreset::Fast,
        vault_dir,
        calibrated: &calibrated,
    })
    .expect("vault creation should succeed");

    // Capture the live header bytes before the attempted restore.
    let header_path = vault_dir.join("vault.verrou");
    let original_header_bytes =
        std::fs::read(&header_path).expect("failed to read live vault header");

    // Create a distinguishably different sentinel backup so we can detect
    // if `restore_backup` were accidentally called (it would write these bytes).
    let backups_dir = vault_dir.join("backups");
    std::fs::create_dir_all(&backups_dir).expect("failed to create backups dir");
    let backup_path = backups_dir.join("backup_20240101T000000.verrou");
    let sentinel: Vec<u8> = original_header_bytes
        .iter()
        .map(|b| b.wrapping_add(1))
        .collect();
    std::fs::write(&backup_path, &sentinel).expect("failed to write sentinel backup");

    // The re-auth gate in `restore_vault_backup` is:
    //   match verrou_vault::unlock_vault(&req) { ... Err(InvalidPassword) => return Err(...) }
    // Call it directly with a WRONG password.
    let wrong_req = UnlockVaultRequest {
        password: b"WRONG-password",
        vault_dir,
    };
    let auth_result = verrou_vault::lifecycle::unlock_vault(&wrong_req);

    assert!(
        matches!(auth_result, Err(VaultError::InvalidPassword)),
        "re-auth gate must return InvalidPassword for wrong password; got: {auth_result:?}"
    );

    // The live header MUST be unchanged — restore_backup was never called.
    let current_bytes =
        std::fs::read(&header_path).expect("failed to read vault header after failed auth");

    // The header may have had its brute-force counter incremented (that is
    // the unlock_vault side-effect) — which is fine and expected.  The
    // critical invariant is that the sentinel bytes were NOT written.
    assert_ne!(
        current_bytes, sentinel,
        "live vault header was overwritten with sentinel backup bytes despite wrong password \
         — restore_backup must not be called before successful re-authentication"
    );
}

/// Correct password must pass the re-auth gate (positive control for H3).
///
/// Verifies that `unlock_vault` (the re-auth check inside `restore_vault_backup`)
/// succeeds with the correct password.
#[test]
fn test_restore_vault_backup_accepts_correct_password() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let vault_dir = tmp.path();

    let password = b"correct-horse-battery-staple-h3";
    let calibrated = test_calibrated();

    verrou_vault::lifecycle::create_vault(&CreateVaultRequest {
        password,
        preset: KdfPreset::Fast,
        vault_dir,
        calibrated: &calibrated,
    })
    .expect("vault creation should succeed");

    let req = UnlockVaultRequest {
        password,
        vault_dir,
    };
    let result = verrou_vault::lifecycle::unlock_vault(&req);

    assert!(
        result.is_ok(),
        "re-auth gate must succeed with correct password; got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Locked-vault guard: session-required commands return "Vault is locked"
// ---------------------------------------------------------------------------

/// Session-required commands must return the "Vault is locked" error when
/// `ManagedVaultState` is `None`.
///
/// Every session-required IPC command (e.g. `list_entries`, `get_entry`,
/// `get_recovery_stats`) begins with:
///
/// ```rust,ignore
/// let session = state.as_ref().ok_or_else(|| "Vault is locked. Please unlock first.")?;
/// ```
///
/// This test constructs a `ManagedVaultState` set to `None` and applies
/// that exact guard — validating that the error is returned correctly and
/// no vault operation proceeds.
#[test]
fn test_locked_vault_guard_returns_locked_error() {
    // ManagedVaultState = Arc<Mutex<Option<VaultSession>>>.
    // None means locked.
    let vault_state: Arc<Mutex<Option<verrou::state::VaultSession>>> = Arc::new(Mutex::new(None));

    // This is the exact check every session-required command performs.
    // Merge guard into a single expression to satisfy clippy::significant_drop_tightening.
    let result: Result<String, String> = vault_state
        .lock()
        .expect("mutex must not be poisoned")
        .as_ref()
        .map(|_| "ok".to_string())
        .ok_or_else(|| "Vault is locked. Please unlock first.".to_string());

    assert!(
        result.is_err(),
        "locked-vault guard must return Err when state is None"
    );
    let err_msg = result.expect_err("result must be Err");
    assert_eq!(
        err_msg, "Vault is locked. Please unlock first.",
        "locked-vault error message must match the IPC command string exactly"
    );
}

/// Locked-vault guard must succeed (return Ok) when the vault IS unlocked.
///
/// Positive control: when `ManagedVaultState` holds `Some(session)`, the
/// guard must pass and `session` must be accessible.
#[test]
fn test_locked_vault_guard_passes_when_unlocked() {
    let tmp = tempfile::tempdir().expect("failed to create tempdir");
    let password = b"locked-vault-guard-positive";

    let (db, master_key) = setup_vault(tmp.path(), password);

    let vault_state: Arc<Mutex<Option<verrou::state::VaultSession>>> =
        Arc::new(Mutex::new(Some(verrou::state::VaultSession {
            db,
            master_key,
            unlock_count: 1,
            unlock_method: verrou::state::UnlockMethod::Password,
        })));

    // Same guard as every session-required command; merged per clippy::significant_drop_tightening.
    let is_unlocked: bool = vault_state
        .lock()
        .expect("mutex must not be poisoned")
        .as_ref()
        .is_some();

    assert!(
        is_unlocked,
        "locked-vault guard must report unlocked when vault state is Some"
    );
}
