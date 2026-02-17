#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for Google Authenticator import.
//!
//! Tests the full import pipeline: protobuf parsing → validation →
//! duplicate detection → transactional bulk import → rollback.

use std::path::Path;

use prost::Message;
use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::import::google_auth::{MigrationPayload, OtpParameters};
use verrou_vault::import::{self, ImportedEntry};
use verrou_vault::lifecycle::{self, CreateVaultRequest};
use verrou_vault::{
    add_entry, get_entry, list_entries, AddEntryParams, Algorithm, EntryData, EntryType,
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
    let password = b"test-password-for-import";
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

/// Build a protobuf payload from OTP parameters.
fn build_payload(entries: Vec<OtpParameters>) -> Vec<u8> {
    let payload = MigrationPayload {
        otp_parameters: entries,
        version: 1,
        batch_size: 1,
        batch_index: 0,
        batch_id: 12345,
    };
    payload.encode_to_vec()
}

/// Build a full migration URI from OTP parameters.
fn build_migration_uri(entries: Vec<OtpParameters>) -> String {
    let bytes = build_payload(entries);
    let b64 = data_encoding::BASE64.encode(&bytes);
    let url_encoded = b64
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace('=', "%3D");
    format!("otpauth-migration://offline?data={url_encoded}")
}

fn test_otp(name: &str, issuer: &str, secret: &[u8]) -> OtpParameters {
    OtpParameters {
        secret: secret.to_vec(),
        name: name.to_string(),
        issuer: issuer.to_string(),
        algorithm: 1, // SHA1
        digits: 1,    // SIX
        otp_type: 2,  // TOTP
        counter: 0,
    }
}

// ---------------------------------------------------------------------------
// Parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_migration_uri_extracts_entries() {
    let uri = build_migration_uri(vec![
        test_otp("user@github.com", "GitHub", b"secret-github"),
        test_otp("admin@aws.com", "AWS", b"secret-aws"),
    ]);

    let result =
        import::google_auth::parse_migration_uri(&uri).expect("should parse migration URI");

    assert_eq!(result.entries.len(), 2);
    assert!(result.unsupported.is_empty());
    assert!(result.malformed.is_empty());
}

#[test]
fn parse_payload_with_all_algorithms() {
    let payload_bytes = build_payload(vec![
        OtpParameters {
            secret: b"sha1".to_vec(),
            name: "SHA1 Account".into(),
            issuer: String::new(),
            algorithm: 1, // SHA1
            digits: 1,
            otp_type: 2,
            counter: 0,
        },
        OtpParameters {
            secret: b"sha256".to_vec(),
            name: "SHA256 Account".into(),
            issuer: String::new(),
            algorithm: 2, // SHA256
            digits: 1,
            otp_type: 2,
            counter: 0,
        },
        OtpParameters {
            secret: b"sha512".to_vec(),
            name: "SHA512 Account".into(),
            issuer: String::new(),
            algorithm: 3, // SHA512
            digits: 1,
            otp_type: 2,
            counter: 0,
        },
    ]);

    let result =
        import::google_auth::parse_migration_payload(&payload_bytes).expect("should parse");

    assert_eq!(result.entries.len(), 3);
    assert_eq!(result.entries[0].algorithm, Algorithm::SHA1);
    assert_eq!(result.entries[1].algorithm, Algorithm::SHA256);
    assert_eq!(result.entries[2].algorithm, Algorithm::SHA512);
}

#[test]
fn parse_payload_md5_flagged_unsupported() {
    let payload_bytes = build_payload(vec![OtpParameters {
        secret: b"md5-secret".to_vec(),
        name: "MD5 Account".into(),
        issuer: "Test".into(),
        algorithm: 4, // MD5
        digits: 1,
        otp_type: 2,
        counter: 0,
    }]);

    let result =
        import::google_auth::parse_migration_payload(&payload_bytes).expect("should parse");

    assert!(result.entries.is_empty());
    assert_eq!(result.unsupported.len(), 1);
    assert!(result.unsupported[0].reason.contains("MD5"));
}

#[test]
fn parse_payload_empty_secret_flagged_malformed() {
    let payload_bytes = build_payload(vec![OtpParameters {
        secret: vec![],
        name: "Bad Account".into(),
        issuer: String::new(),
        algorithm: 1,
        digits: 1,
        otp_type: 2,
        counter: 0,
    }]);

    let result =
        import::google_auth::parse_migration_payload(&payload_bytes).expect("should parse");

    assert!(result.entries.is_empty());
    assert_eq!(result.malformed.len(), 1);
    assert!(result.malformed[0].reason.contains("empty secret"));
}

#[test]
fn parse_payload_hotp_preserves_counter() {
    let payload_bytes = build_payload(vec![OtpParameters {
        secret: b"hotp-key".to_vec(),
        name: "HOTP Account".into(),
        issuer: "Service".into(),
        algorithm: 1,
        digits: 2,   // EIGHT
        otp_type: 1, // HOTP
        counter: 42,
    }]);

    let result =
        import::google_auth::parse_migration_payload(&payload_bytes).expect("should parse");

    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].entry_type, EntryType::Hotp);
    assert_eq!(result.entries[0].counter, 42);
    assert_eq!(result.entries[0].digits, 8);
}

#[test]
fn parse_payload_mixed_valid_unsupported_malformed() {
    let payload_bytes = build_payload(vec![
        // Valid
        test_otp("good", "Good", b"good-secret"),
        // Unsupported (MD5)
        OtpParameters {
            secret: b"md5".to_vec(),
            name: "md5-user".into(),
            issuer: String::new(),
            algorithm: 4,
            digits: 1,
            otp_type: 2,
            counter: 0,
        },
        // Malformed (empty secret)
        OtpParameters {
            secret: vec![],
            name: "bad".into(),
            issuer: String::new(),
            algorithm: 1,
            digits: 1,
            otp_type: 2,
            counter: 0,
        },
    ]);

    let result =
        import::google_auth::parse_migration_payload(&payload_bytes).expect("should parse");

    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.unsupported.len(), 1);
    assert_eq!(result.malformed.len(), 1);
}

#[test]
fn parse_payload_secret_encoded_as_base32() {
    let raw_secret = b"Hello!";
    let payload_bytes = build_payload(vec![test_otp("test", "Test", raw_secret)]);

    let result =
        import::google_auth::parse_migration_payload(&payload_bytes).expect("should parse");

    let expected_b32 = data_encoding::BASE32.encode(raw_secret);
    assert_eq!(result.entries[0].secret, expected_b32);
}

#[test]
fn parse_corrupted_bytes_returns_error() {
    let result = import::google_auth::parse_migration_payload(&[0xFF, 0xFF, 0xFF, 0xFF]);
    assert!(result.is_err());
}

#[test]
fn parse_empty_bytes_returns_empty_payload() {
    // Empty bytes decode as a valid protobuf with all defaults (no entries)
    let result = import::google_auth::parse_migration_payload(&[]);
    assert!(result.is_ok());
    assert!(result.expect("empty bytes should parse").entries.is_empty());
}

// ---------------------------------------------------------------------------
// Name/issuer splitting tests
// ---------------------------------------------------------------------------

#[test]
fn issuer_prefix_stripped_from_name() {
    let payload_bytes = build_payload(vec![OtpParameters {
        secret: b"sec".to_vec(),
        name: "GitHub:user@example.com".into(),
        issuer: "GitHub".into(),
        algorithm: 1,
        digits: 1,
        otp_type: 2,
        counter: 0,
    }]);

    let result =
        import::google_auth::parse_migration_payload(&payload_bytes).expect("should parse");

    assert_eq!(result.entries[0].name, "user@example.com");
    assert_eq!(result.entries[0].issuer.as_deref(), Some("GitHub"));
}

#[test]
fn no_issuer_inferred_from_colon_name() {
    let payload_bytes = build_payload(vec![OtpParameters {
        secret: b"sec".to_vec(),
        name: "Slack:alice@corp.com".into(),
        issuer: String::new(),
        algorithm: 1,
        digits: 1,
        otp_type: 2,
        counter: 0,
    }]);

    let result =
        import::google_auth::parse_migration_payload(&payload_bytes).expect("should parse");

    assert_eq!(result.entries[0].name, "alice@corp.com");
    assert_eq!(result.entries[0].issuer.as_deref(), Some("Slack"));
}

// ---------------------------------------------------------------------------
// Duplicate detection tests
// ---------------------------------------------------------------------------

#[test]
fn check_duplicates_finds_exact_match() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    // Add an existing entry
    let params = AddEntryParams {
        entry_type: EntryType::Totp,
        name: "user@example.com".to_string(),
        issuer: Some("GitHub".to_string()),
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
    };
    add_entry(db.connection(), &master_key, &params).expect("add should succeed");

    // Check for duplicates with a matching imported entry
    let imported = vec![ImportedEntry {
        entry_type: EntryType::Totp,
        name: "user@example.com".to_string(),
        issuer: Some("GitHub".to_string()),
        secret: "DIFFERENTBASE32SECRET".to_string(),
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
    }];

    let dupes = import::check_duplicates(db.connection(), &imported)
        .expect("duplicate check should succeed");

    assert_eq!(dupes.len(), 1);
    assert_eq!(dupes[0].name, "user@example.com");
}

#[test]
fn check_duplicates_case_insensitive() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let params = AddEntryParams {
        entry_type: EntryType::Totp,
        name: "User@Example.COM".to_string(),
        issuer: Some("GITHUB".to_string()),
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
    };
    add_entry(db.connection(), &master_key, &params).expect("add should succeed");

    let imported = vec![ImportedEntry {
        entry_type: EntryType::Totp,
        name: "user@example.com".to_string(),
        issuer: Some("github".to_string()),
        secret: "AAAABBBB".to_string(),
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
    }];

    let dupes = import::check_duplicates(db.connection(), &imported)
        .expect("duplicate check should succeed");

    assert_eq!(dupes.len(), 1, "case-insensitive match expected");
}

#[test]
fn check_duplicates_no_match() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let params = AddEntryParams {
        entry_type: EntryType::Totp,
        name: "existing@test.com".to_string(),
        issuer: Some("Existing".to_string()),
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
    };
    add_entry(db.connection(), &master_key, &params).expect("add should succeed");

    let imported = vec![ImportedEntry {
        entry_type: EntryType::Totp,
        name: "completely-different".to_string(),
        issuer: Some("Other".to_string()),
        secret: "AAAABBBB".to_string(),
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
    }];

    let dupes = import::check_duplicates(db.connection(), &imported)
        .expect("duplicate check should succeed");

    assert!(dupes.is_empty(), "no duplicates expected");
}

#[test]
fn check_duplicates_null_issuer_match() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    // Entry with no issuer
    let params = AddEntryParams {
        entry_type: EntryType::Totp,
        name: "my-account".to_string(),
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
    };
    add_entry(db.connection(), &master_key, &params).expect("add should succeed");

    let imported = vec![ImportedEntry {
        entry_type: EntryType::Totp,
        name: "my-account".to_string(),
        issuer: None,
        secret: "AAAABBBB".to_string(),
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
    }];

    let dupes = import::check_duplicates(db.connection(), &imported)
        .expect("duplicate check should succeed");

    assert_eq!(dupes.len(), 1, "should match null issuer");
}

// ---------------------------------------------------------------------------
// Transactional import tests
// ---------------------------------------------------------------------------

#[test]
fn import_entries_success() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let entries = vec![
        ImportedEntry {
            entry_type: EntryType::Totp,
            name: "GitHub".to_string(),
            issuer: Some("github.com".to_string()),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
        },
        ImportedEntry {
            entry_type: EntryType::Totp,
            name: "AWS".to_string(),
            issuer: Some("amazon.com".to_string()),
            secret: "GEZDGNBVGY3TQOJQ".to_string(),
            algorithm: Algorithm::SHA256,
            digits: 8,
            period: 30,
            counter: 0,
        },
    ];

    let summary = import::import_entries(db.connection(), &master_key, &entries, &[])
        .expect("import should succeed");

    assert_eq!(summary.imported, 2);
    assert_eq!(summary.imported_ids.len(), 2);
    assert_eq!(summary.skipped, 0);

    // Verify entries are actually in the database
    let all_entries = list_entries(db.connection()).expect("list should succeed");
    assert_eq!(all_entries.len(), 2);

    // Verify entry data is correctly encrypted/decrypted
    let entry = get_entry(db.connection(), &master_key, &summary.imported_ids[0])
        .expect("get should succeed");
    assert_eq!(entry.name, "GitHub");
    assert_eq!(entry.issuer.as_deref(), Some("github.com"));
    match &entry.data {
        EntryData::Totp { secret } => assert_eq!(secret, "JBSWY3DPEHPK3PXP"),
        _ => panic!("expected TOTP data"),
    }
}

#[test]
fn import_entries_with_skip_indices() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let entries = vec![
        ImportedEntry {
            entry_type: EntryType::Totp,
            name: "Keep".to_string(),
            issuer: None,
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
        },
        ImportedEntry {
            entry_type: EntryType::Totp,
            name: "Skip".to_string(),
            issuer: None,
            secret: "GEZDGNBVGY3TQOJQ".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
        },
        ImportedEntry {
            entry_type: EntryType::Totp,
            name: "Also Keep".to_string(),
            issuer: None,
            secret: "MFRGGZDFMY3TQLLB".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
        },
    ];

    // Skip index 1 ("Skip")
    let summary = import::import_entries(db.connection(), &master_key, &entries, &[1])
        .expect("import should succeed");

    assert_eq!(summary.imported, 2);
    assert_eq!(summary.skipped, 1);

    let all_entries = list_entries(db.connection()).expect("list should succeed");
    assert_eq!(all_entries.len(), 2);

    let names: Vec<&str> = all_entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"Keep"));
    assert!(names.contains(&"Also Keep"));
    assert!(!names.contains(&"Skip"));
}

#[test]
fn import_entries_hotp_preserves_counter() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let entries = vec![ImportedEntry {
        entry_type: EntryType::Hotp,
        name: "HOTP Account".to_string(),
        issuer: Some("Service".to_string()),
        secret: "JBSWY3DPEHPK3PXP".to_string(),
        algorithm: Algorithm::SHA1,
        digits: 8,
        period: 30,
        counter: 100,
    }];

    let summary = import::import_entries(db.connection(), &master_key, &entries, &[])
        .expect("import should succeed");

    let entry = get_entry(db.connection(), &master_key, &summary.imported_ids[0])
        .expect("get should succeed");

    assert_eq!(entry.entry_type, EntryType::Hotp);
    assert_eq!(entry.counter, 100);
    assert_eq!(entry.digits, 8);
}

#[test]
fn import_preserves_different_algorithms() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let entries = vec![
        ImportedEntry {
            entry_type: EntryType::Totp,
            name: "SHA1".to_string(),
            issuer: None,
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::SHA1,
            digits: 6,
            period: 30,
            counter: 0,
        },
        ImportedEntry {
            entry_type: EntryType::Totp,
            name: "SHA256".to_string(),
            issuer: None,
            secret: "GEZDGNBVGY3TQOJQ".to_string(),
            algorithm: Algorithm::SHA256,
            digits: 6,
            period: 30,
            counter: 0,
        },
        ImportedEntry {
            entry_type: EntryType::Totp,
            name: "SHA512".to_string(),
            issuer: None,
            secret: "MFRGGZDFMY3TQLLB".to_string(),
            algorithm: Algorithm::SHA512,
            digits: 6,
            period: 30,
            counter: 0,
        },
    ];

    let summary = import::import_entries(db.connection(), &master_key, &entries, &[])
        .expect("import should succeed");

    for (idx, expected_algo) in [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512]
        .iter()
        .enumerate()
    {
        let entry = get_entry(db.connection(), &master_key, &summary.imported_ids[idx])
            .expect("get should succeed");
        assert_eq!(entry.algorithm, *expected_algo);
    }
}

// ---------------------------------------------------------------------------
// End-to-end: parse → import pipeline
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_parse_and_import() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    // Build a realistic migration URI
    let uri = build_migration_uri(vec![
        OtpParameters {
            secret: b"github-totp-secret-key".to_vec(),
            name: "GitHub:dev@company.com".into(),
            issuer: "GitHub".into(),
            algorithm: 1, // SHA1
            digits: 1,    // SIX
            otp_type: 2,  // TOTP
            counter: 0,
        },
        OtpParameters {
            secret: b"aws-totp-secret".to_vec(),
            name: "AWS:admin@prod.com".into(),
            issuer: "AWS".into(),
            algorithm: 2, // SHA256
            digits: 2,    // EIGHT
            otp_type: 2,  // TOTP
            counter: 0,
        },
        OtpParameters {
            secret: b"hotp-counter-key".to_vec(),
            name: "Legacy HOTP".into(),
            issuer: "OldService".into(),
            algorithm: 1,
            digits: 1,
            otp_type: 1, // HOTP
            counter: 7,
        },
    ]);

    // Phase 1: Parse
    let parse_result = import::google_auth::parse_migration_uri(&uri).expect("should parse");

    assert_eq!(parse_result.entries.len(), 3);

    // Phase 2: Check duplicates (none expected)
    let dupes = import::check_duplicates(db.connection(), &parse_result.entries)
        .expect("dupe check should succeed");
    assert!(dupes.is_empty());

    // Phase 3: Import
    let summary = import::import_entries(db.connection(), &master_key, &parse_result.entries, &[])
        .expect("import should succeed");

    assert_eq!(summary.imported, 3);

    // Verify all entries exist and data is correct
    let all = list_entries(db.connection()).expect("list should succeed");
    assert_eq!(all.len(), 3);

    // Verify the HOTP entry has correct counter
    let hotp_id = &summary.imported_ids[2];
    let hotp_entry =
        get_entry(db.connection(), &master_key, hotp_id).expect("get HOTP should succeed");
    assert_eq!(hotp_entry.entry_type, EntryType::Hotp);
    assert_eq!(hotp_entry.counter, 7);
}

#[test]
fn end_to_end_with_duplicates_skipped() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    // Pre-populate with an existing entry
    let params = AddEntryParams {
        entry_type: EntryType::Totp,
        name: "dev@company.com".to_string(),
        issuer: Some("GitHub".to_string()),
        folder_id: None,
        algorithm: Algorithm::SHA1,
        digits: 6,
        period: 30,
        counter: 0,
        pinned: false,
        tags: Vec::new(),
        data: EntryData::Totp {
            secret: "EXISTING".to_string(),
        },
    };
    add_entry(db.connection(), &master_key, &params).expect("add should succeed");

    // Import includes a duplicate
    let uri = build_migration_uri(vec![
        OtpParameters {
            secret: b"new-secret".to_vec(),
            name: "GitHub:dev@company.com".into(), // duplicate
            issuer: "GitHub".into(),
            algorithm: 1,
            digits: 1,
            otp_type: 2,
            counter: 0,
        },
        OtpParameters {
            secret: b"unique-secret".to_vec(),
            name: "New Account".into(),
            issuer: "NewService".into(),
            algorithm: 1,
            digits: 1,
            otp_type: 2,
            counter: 0,
        },
    ]);

    let parse_result = import::google_auth::parse_migration_uri(&uri).expect("should parse");

    // Check duplicates
    let dupes = import::check_duplicates(db.connection(), &parse_result.entries)
        .expect("dupe check should succeed");
    assert_eq!(dupes.len(), 1);
    assert_eq!(dupes[0].index, 0); // First entry is duplicate

    // Import, skipping the duplicate
    let skip: Vec<usize> = dupes.iter().map(|d| d.index).collect();
    let summary =
        import::import_entries(db.connection(), &master_key, &parse_result.entries, &skip)
            .expect("import should succeed");

    assert_eq!(summary.imported, 1);
    assert_eq!(summary.skipped, 1);

    // Verify only 2 total entries (1 pre-existing + 1 new)
    let all = list_entries(db.connection()).expect("list should succeed");
    assert_eq!(all.len(), 2);
}

// ---------------------------------------------------------------------------
// Validation helper tests
// ---------------------------------------------------------------------------

#[test]
fn validate_secret_valid_base32() {
    assert!(import::validate_secret("JBSWY3DPEHPK3PXP").is_ok());
    // With proper padding (5 bytes = "GEZDG" → 8 chars, needs no padding; 6 bytes = needs "==")
    assert!(import::validate_secret("JBSWY3DPEHPK3PXP").is_ok());
    // A secret that requires padding: 3 bytes → 8 chars with one '=' pad
    assert!(import::validate_secret("MFRGG===").is_ok());
}

#[test]
fn validate_secret_empty() {
    let result = import::validate_secret("");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("empty"));
}

#[test]
fn validate_secret_invalid_chars() {
    // Lowercase not valid Base32
    let result = import::validate_secret("jbswy3dpehpk3pxp");
    assert!(result.is_err());
}

#[test]
fn validate_otp_params_valid() {
    assert!(import::validate_otp_params(6, 30).is_ok());
    assert!(import::validate_otp_params(8, 60).is_ok());
    assert!(import::validate_otp_params(6, 15).is_ok());
}

#[test]
fn validate_otp_params_invalid_digits() {
    assert!(import::validate_otp_params(4, 30).is_err());
    assert!(import::validate_otp_params(10, 30).is_err());
}

#[test]
fn validate_otp_params_invalid_period() {
    assert!(import::validate_otp_params(6, 10).is_err());
    assert!(import::validate_otp_params(6, 45).is_err());
}

// ---------------------------------------------------------------------------
// Error categorization tests
// ---------------------------------------------------------------------------

#[test]
fn import_error_invalid_format() {
    let result = import::google_auth::parse_migration_uri("not-a-valid-uri");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, import::ImportError::InvalidFormat(_)));
}

#[test]
fn import_error_encoding() {
    let result =
        import::google_auth::parse_migration_uri("otpauth-migration://offline?data=!!!invalid!!!");
    assert!(result.is_err());
}

#[test]
fn import_error_corrupted() {
    // Valid base64 but invalid protobuf
    let bad_proto = data_encoding::BASE64.encode(b"\xff\xff\xff\xff");
    let uri = format!("otpauth-migration://offline?data={bad_proto}");
    let result = import::google_auth::parse_migration_uri(&uri);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptest_tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn parse_never_panics_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
            // Should return Ok or Err, never panic
            let _ = import::google_auth::parse_migration_payload(&data);
        }

        #[test]
        fn parse_never_panics_on_arbitrary_uri(data in ".*") {
            let _ = import::google_auth::parse_migration_uri(&data);
        }

        #[test]
        fn valid_secrets_always_base32(secret_bytes in proptest::collection::vec(1u8..=255u8, 1..64)) {
            // Build a valid OTP entry and verify the secret is valid Base32
            let payload_bytes = build_payload(vec![OtpParameters {
                secret: secret_bytes,
                name: "test".into(),
                issuer: String::new(),
                algorithm: 1,
                digits: 1,
                otp_type: 2,
                counter: 0,
            }]);

            let result = import::google_auth::parse_migration_payload(&payload_bytes)
                .expect("valid payload should parse");

            for entry in &result.entries {
                // Verify the Base32 string decodes back
                let decoded = data_encoding::BASE32.decode(entry.secret.as_bytes())
                    .expect("secret should be valid Base32");
                assert!(!decoded.is_empty());
            }
        }
    }
}
