#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for the password health analysis module.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::lifecycle::{self, CreateVaultRequest};
use verrou_vault::{
    add_entry, analyze_password_health, evaluate_password_strength, AddEntryParams, Algorithm,
    EntryData, EntryType, PasswordHistoryEntry, PasswordStrength,
};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

fn setup_vault(dir: &Path) -> (verrou_vault::VaultDb, SecretBytes<32>) {
    let password = b"test-password-for-health";
    let calibrated = test_calibrated();
    let req = CreateVaultRequest {
        password,
        preset: KdfPreset::Fast,
        vault_dir: dir,
        calibrated: &calibrated,
    };
    lifecycle::create_vault(&req).expect("vault creation should succeed");

    let unlock_req = lifecycle::UnlockVaultRequest {
        password,
        vault_dir: dir,
    };
    let result = lifecycle::unlock_vault(&unlock_req).expect("vault unlock should succeed");
    (result.db, result.master_key)
}

fn credential_params(name: &str, password: &str) -> AddEntryParams {
    AddEntryParams {
        entry_type: EntryType::Credential,
        name: name.to_string(),
        issuer: Some("example.com".to_string()),
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::Credential {
            password: password.to_string(),
            username: Some("user@example.com".to_string()),
            urls: vec!["https://example.com".to_string()],
            notes: None,
            linked_totp_id: None,
            custom_fields: Vec::new(),
            password_history: Vec::new(),
            template: None,
        },
    }
}

fn credential_with_totp(name: &str, password: &str, totp_id: &str) -> AddEntryParams {
    let mut params = credential_params(name, password);
    if let EntryData::Credential {
        ref mut linked_totp_id,
        ..
    } = params.data
    {
        *linked_totp_id = Some(totp_id.to_string());
    }
    params
}

fn credential_with_history(
    name: &str,
    password: &str,
    history: Vec<PasswordHistoryEntry>,
) -> AddEntryParams {
    let mut params = credential_params(name, password);
    if let EntryData::Credential {
        ref mut password_history,
        ..
    } = params.data
    {
        *password_history = history;
    }
    params
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn empty_vault_returns_perfect_score() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    let report = analyze_password_health(db.connection(), &master_key).unwrap();

    assert_eq!(report.overall_score, 100);
    assert_eq!(report.total_credentials, 0);
    assert_eq!(report.reused_count, 0);
    assert_eq!(report.weak_count, 0);
    assert_eq!(report.old_count, 0);
    assert_eq!(report.no_totp_count, 0);
}

#[test]
fn single_strong_credential_with_totp_is_healthy() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // Add a TOTP entry first (for linking).
    add_entry(
        db.connection(),
        &master_key,
        &AddEntryParams {
            entry_type: EntryType::Totp,
            name: "GitHub TOTP".to_string(),
            issuer: None,
            folder_id: None,
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
            pinned: false,
            tags: Vec::new(),
            data: EntryData::Totp {
                secret: "JBSWY3DPEHPK3PXP".to_string(),
            },
        },
    )
    .unwrap();

    // Get the TOTP entry ID.
    let entries = verrou_vault::list_entries(db.connection()).unwrap();
    let totp_id = &entries[0].id;

    // Add a strong credential linked to TOTP.
    add_entry(
        db.connection(),
        &master_key,
        &credential_with_totp("GitHub", "C0mpl3x!P@ssw0rd#2024", totp_id),
    )
    .unwrap();

    let report = analyze_password_health(db.connection(), &master_key).unwrap();

    assert_eq!(report.total_credentials, 1);
    // Strong password, has TOTP, not old (just created) → no issues.
    // Only no_totp_count might be 0 (has linked TOTP).
    assert_eq!(report.reused_count, 0);
    assert_eq!(report.no_totp_count, 0);
    // The password "C0mpl3x!P@ssw0rd#2024" should be Excellent (len=22, mixed, digits, symbols).
    assert_eq!(report.weak_count, 0);
}

#[test]
fn detects_reused_passwords() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // Two credentials sharing the same password.
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("GitHub", "SharedPassword123!"),
    )
    .unwrap();
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("GitLab", "SharedPassword123!"),
    )
    .unwrap();
    // One with a different password.
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("BitBucket", "UniquePass!456$XY"),
    )
    .unwrap();

    let report = analyze_password_health(db.connection(), &master_key).unwrap();

    assert_eq!(report.total_credentials, 3);
    assert_eq!(report.reused_count, 2, "two credentials share a password");
    assert_eq!(report.reused_groups.len(), 1, "one reused group");
    assert_eq!(report.reused_groups[0].credentials.len(), 2);
}

#[test]
fn detects_weak_passwords() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // Weak: short, all lowercase.
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("Weak Site", "pass"),
    )
    .unwrap();
    // Fair: 8 chars, mixed case only.
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("Fair Site", "AbCdEfGhIjKl"),
    )
    .unwrap();
    // Excellent: long, mixed, digits, symbols.
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("Strong Site", "V3ry$tr0ng!P@ssw0rd"),
    )
    .unwrap();

    let report = analyze_password_health(db.connection(), &master_key).unwrap();

    assert_eq!(report.total_credentials, 3);
    assert_eq!(
        report.weak_count, 2,
        "weak and fair passwords should both be flagged"
    );
    let names: Vec<&str> = report
        .weak_credentials
        .iter()
        .map(|w| w.name.as_str())
        .collect();
    assert!(names.contains(&"Weak Site"));
    assert!(names.contains(&"Fair Site"));
}

#[test]
fn detects_missing_totp() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // No TOTP linked.
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("No TOTP Site", "SomeP@ssword!123"),
    )
    .unwrap();

    let report = analyze_password_health(db.connection(), &master_key).unwrap();

    assert_eq!(report.no_totp_count, 1);
    assert_eq!(report.no_totp_credentials[0].name, "No TOTP Site");
}

#[test]
fn detects_old_passwords_via_history() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // Credential with password history showing old last change (2024-01-01 = ~400+ days ago).
    let history = vec![PasswordHistoryEntry {
        password: "OldPass!123".to_string(),
        changed_at: "2024-01-01T00:00:00Z".to_string(),
    }];
    add_entry(
        db.connection(),
        &master_key,
        &credential_with_history("Old Service", "CurrentP@ss!99", history),
    )
    .unwrap();

    let report = analyze_password_health(db.connection(), &master_key).unwrap();

    assert_eq!(report.old_count, 1);
    assert_eq!(report.old_credentials[0].name, "Old Service");
    assert!(report.old_credentials[0].days_since_change >= 365);
    assert_eq!(
        report.old_credentials[0].severity,
        verrou_vault::AgeSeverity::Danger
    );
}

#[test]
fn overall_score_decreases_with_issues() {
    let tmp = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(tmp.path());

    // 2 credentials, both weak, both no TOTP.
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("Site A", "weak"),
    )
    .unwrap();
    add_entry(
        db.connection(),
        &master_key,
        &credential_params("Site B", "weak"),
    )
    .unwrap();

    let report = analyze_password_health(db.connection(), &master_key).unwrap();

    assert_eq!(report.total_credentials, 2);
    // Issues: 2 reused + 2 weak + 0 old + 2 no_totp = 6 issues
    // Total checks: 2 * 4 = 8
    // Score: 100 - (6 * 100 / 8) = 100 - 75 = 25
    assert!(
        report.overall_score < 50,
        "score should be low with many issues"
    );
    assert!(report.overall_score > 0, "score should not be negative");
}

// ---------------------------------------------------------------------------
// Strength parity tests (mirrors frontend evaluateStrength)
// ---------------------------------------------------------------------------

#[test]
fn strength_parity_weak_short() {
    assert_eq!(evaluate_password_strength("abc"), PasswordStrength::Weak);
}

#[test]
fn strength_parity_weak_eight_lower() {
    assert_eq!(
        evaluate_password_strength("abcdefgh"),
        PasswordStrength::Weak
    );
}

#[test]
fn strength_parity_fair_twelve_mixed() {
    assert_eq!(
        evaluate_password_strength("AbcDefGhIjKl"),
        PasswordStrength::Fair
    );
}

#[test]
fn strength_parity_good_sixteen_mixed_digit() {
    assert_eq!(
        evaluate_password_strength("AbcDefGhIj1lmnop"),
        PasswordStrength::Good
    );
}

#[test]
fn strength_parity_excellent_long_complex() {
    assert_eq!(
        evaluate_password_strength("AbcDef!1GhIjklmn"),
        PasswordStrength::Excellent
    );
}
