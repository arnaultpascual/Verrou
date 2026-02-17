#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for 2FAS import.
//!
//! Tests the full import pipeline: JSON parsing → validation →
//! duplicate detection → transactional bulk import.
//! Includes encrypted export roundtrip tests with PBKDF2 + AES-256-GCM.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::import;
use verrou_vault::import::twofas;
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

/// A valid Base32 secret for tests.
const TEST_SECRET: &str = "JBSWY3DPEE======";

/// Build a minimal valid plaintext 2FAS backup JSON.
fn make_backup_json(services: &[serde_json::Value]) -> String {
    serde_json::json!({
        "services": services,
        "groups": [],
        "schemaVersion": 4,
        "servicesEncrypted": null,
        "reference": null
    })
    .to_string()
}

/// Build a single TOTP service JSON value.
fn make_totp_service(name: &str, account: &str, issuer: &str, secret: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "secret": secret,
        "otp": {
            "account": account,
            "issuer": issuer,
            "tokenType": "TOTP",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "counter": 0
        }
    })
}

/// PBKDF2 iteration count matching 2FAS.
const PBKDF2_ITERATIONS: u32 = 10_000;

/// Build an encrypted 2FAS backup with known content for testing.
fn build_encrypted_backup(services: &[serde_json::Value], password: &[u8]) -> String {
    use verrou_crypto_core::symmetric::encrypt as aes_encrypt;

    let services_json = serde_json::to_string(&serde_json::Value::Array(services.to_vec()))
        .expect("serialize services");
    let salt = [0xAA; 256]; // 2FAS uses 256-byte salt

    // Derive key via PBKDF2
    let mut derived_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut derived_key);

    // Encrypt services
    let sealed =
        aes_encrypt(services_json.as_bytes(), &derived_key, &[]).expect("encrypt services");

    // Build 2FAS colon-separated encrypted format
    let mut ciphertext_with_tag = sealed.ciphertext.clone();
    ciphertext_with_tag.extend_from_slice(&sealed.tag);

    let encrypted_str = format!(
        "{}:{}:{}",
        data_encoding::BASE64.encode(&ciphertext_with_tag),
        data_encoding::BASE64.encode(&salt),
        data_encoding::BASE64.encode(&sealed.nonce),
    );

    serde_json::json!({
        "services": [],
        "servicesEncrypted": encrypted_str,
        "reference": null,
        "schemaVersion": 4
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_plaintext_backup_extracts_entries() {
    let json = make_backup_json(&[
        make_totp_service("GitHub", "user@github.com", "GitHub", TEST_SECRET),
        make_totp_service("AWS", "admin@aws.com", "AWS", TEST_SECRET),
    ]);

    let result = twofas::parse_twofas_json(&json).expect("should parse");

    assert_eq!(result.entries.len(), 2);
    assert!(result.unsupported.is_empty());
    assert!(result.malformed.is_empty());
    assert_eq!(result.schema_version, 4);
}

#[test]
fn parse_hotp_entry_with_counter() {
    let service = serde_json::json!({
        "name": "Service",
        "secret": TEST_SECRET,
        "otp": {
            "account": "HOTP Account",
            "issuer": "Service",
            "tokenType": "HOTP",
            "algorithm": "SHA256",
            "digits": 8,
            "period": 30,
            "counter": 42
        }
    });
    let json = make_backup_json(&[service]);
    let result = twofas::parse_twofas_json(&json).expect("should parse");

    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].entry_type, EntryType::Hotp);
    assert_eq!(result.entries[0].algorithm, Algorithm::SHA256);
    assert_eq!(result.entries[0].digits, 8);
    assert_eq!(result.entries[0].counter, 42);
}

#[test]
fn parse_all_supported_algorithms() {
    for (algo, expected) in [
        ("SHA1", Algorithm::SHA1),
        ("SHA256", Algorithm::SHA256),
        ("SHA512", Algorithm::SHA512),
    ] {
        let service = serde_json::json!({
            "name": "test",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "TOTP",
                "algorithm": algo,
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = twofas::parse_twofas_json(&json).expect("should parse");
        assert_eq!(result.entries[0].algorithm, expected, "algo={algo}");
    }
}

#[test]
fn unsupported_types_flagged_correctly() {
    let service = serde_json::json!({
        "name": "Steam",
        "secret": TEST_SECRET,
        "otp": {
            "account": "steam-user",
            "issuer": "Steam",
            "tokenType": "STEAM",
            "algorithm": "SHA1",
            "digits": 5,
            "period": 30
        }
    });
    let json = make_backup_json(&[service]);
    let result = twofas::parse_twofas_json(&json).expect("should parse");

    assert!(result.entries.is_empty());
    assert_eq!(result.unsupported.len(), 1);
    assert!(result.unsupported[0].reason.contains("STEAM"));
}

#[test]
fn unsupported_algorithms_flagged_correctly() {
    for algo in ["SHA224", "SHA384", "MD5"] {
        let service = serde_json::json!({
            "name": "test",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "TOTP",
                "algorithm": algo,
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = twofas::parse_twofas_json(&json).expect("should parse");

        assert!(result.entries.is_empty(), "algo={algo}");
        assert_eq!(result.unsupported.len(), 1, "algo={algo}");
        assert!(result.unsupported[0].reason.contains(algo));
    }
}

#[test]
fn mixed_entries_categorized_correctly() {
    let services = vec![
        // Valid TOTP
        make_totp_service("GitHub", "good1@test.com", "GitHub", TEST_SECRET),
        // Unsupported (Steam)
        serde_json::json!({
            "name": "Steam",
            "secret": TEST_SECRET,
            "otp": {
                "account": "steam-user",
                "issuer": "Steam",
                "tokenType": "STEAM",
                "algorithm": "SHA1",
                "digits": 5,
                "period": 30
            }
        }),
        // Valid TOTP
        make_totp_service("Slack", "good2@test.com", "Slack", TEST_SECRET),
        // Malformed (empty secret)
        serde_json::json!({
            "name": "Bad",
            "secret": "",
            "otp": {
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        }),
        // Unsupported (SHA224)
        serde_json::json!({
            "name": "sha224",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "TOTP",
                "algorithm": "SHA224",
                "digits": 6,
                "period": 30
            }
        }),
    ];

    let json = make_backup_json(&services);
    let result = twofas::parse_twofas_json(&json).expect("should parse");

    assert_eq!(result.entries.len(), 2, "valid");
    assert_eq!(result.unsupported.len(), 2, "unsupported (steam + sha224)");
    assert_eq!(result.malformed.len(), 1, "malformed (empty secret)");

    // Verify indices
    assert_eq!(result.unsupported[0].index, 1); // steam
    assert_eq!(result.malformed[0].index, 3); // empty secret
    assert_eq!(result.unsupported[1].index, 4); // sha224
}

#[test]
fn secret_whitespace_stripping() {
    let service = serde_json::json!({
        "name": "Spaced",
        "secret": "JBSW Y3DP EE== ====",
        "otp": {
            "tokenType": "TOTP",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30
        }
    });
    let json = make_backup_json(&[service]);
    let result = twofas::parse_twofas_json(&json).expect("should parse");

    assert_eq!(result.entries.len(), 1);
    assert_eq!(result.entries[0].secret, TEST_SECRET);
}

#[test]
fn secret_is_passed_through_not_reencoded() {
    let original_secret = "NBSWY3DPEHPK3PXP";
    let json = make_backup_json(&[make_totp_service(
        "test",
        "test",
        "Service",
        original_secret,
    )]);
    let result = twofas::parse_twofas_json(&json).expect("should parse");

    // 2FAS secrets are already Base32 — verify passthrough, not double-encoding
    assert_eq!(result.entries[0].secret, original_secret);
}

#[test]
fn name_issuer_extraction_priority() {
    // otp.account preferred over name
    let s1 = serde_json::json!({
        "name": "GitHub",
        "secret": TEST_SECRET,
        "otp": {
            "account": "user@example.com",
            "issuer": "GitHub",
            "tokenType": "TOTP",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30
        }
    });
    let json = make_backup_json(&[s1]);
    let result = twofas::parse_twofas_json(&json).expect("should parse");
    assert_eq!(result.entries[0].name, "user@example.com");
    assert_eq!(result.entries[0].issuer.as_deref(), Some("GitHub"));
}

// ---------------------------------------------------------------------------
// Version validation tests
// ---------------------------------------------------------------------------

#[test]
fn rejects_unsupported_schema_versions() {
    for bad_version in [0, 5, 100] {
        let json = serde_json::json!({
            "services": [],
            "schemaVersion": bad_version
        })
        .to_string();

        let err = twofas::parse_twofas_json(&json).unwrap_err();
        assert!(
            matches!(err, import::ImportError::Unsupported(_)),
            "schema version {bad_version} should be rejected"
        );
    }
}

#[test]
fn accepts_valid_schema_versions() {
    for version in 1..=4 {
        let json = serde_json::json!({
            "services": [],
            "schemaVersion": version
        })
        .to_string();

        assert!(
            twofas::parse_twofas_json(&json).is_ok(),
            "schema version {version} should be accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Encrypted export tests
// ---------------------------------------------------------------------------

#[test]
fn encrypted_export_detected_correctly() {
    let backup_str = build_encrypted_backup(&[], b"password");
    assert!(twofas::is_encrypted(&backup_str).unwrap());

    let plaintext = make_backup_json(&[]);
    assert!(!twofas::is_encrypted(&plaintext).unwrap());
}

#[test]
fn encrypted_roundtrip_with_entries() {
    let password = b"test-password-2fas";
    let services = vec![
        make_totp_service("GitHub", "encrypted@test.com", "GitHub", TEST_SECRET),
        serde_json::json!({
            "name": "AWS",
            "secret": "GEZDGNBVGY3TQOJQ",
            "otp": {
                "account": "hotp-encrypted",
                "issuer": "AWS",
                "tokenType": "HOTP",
                "algorithm": "SHA512",
                "digits": 8,
                "period": 30,
                "counter": 99
            }
        }),
    ];

    let backup_str = build_encrypted_backup(&services, password);
    let result =
        twofas::parse_twofas_encrypted(&backup_str, password).expect("should decrypt and parse");

    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].name, "encrypted@test.com");
    assert_eq!(result.entries[0].issuer.as_deref(), Some("GitHub"));
    assert_eq!(result.entries[0].entry_type, EntryType::Totp);

    assert_eq!(result.entries[1].name, "hotp-encrypted");
    assert_eq!(result.entries[1].entry_type, EntryType::Hotp);
    assert_eq!(result.entries[1].algorithm, Algorithm::SHA512);
    assert_eq!(result.entries[1].counter, 99);
}

#[test]
fn encrypted_wrong_password_fails() {
    let backup_str = build_encrypted_backup(
        &[make_totp_service("test", "test", "Service", TEST_SECRET)],
        b"correct-password",
    );

    let err = twofas::parse_twofas_encrypted(&backup_str, b"wrong-password").unwrap_err();
    assert!(matches!(err, import::ImportError::Corrupted(_)));
}

#[test]
fn plaintext_parser_rejects_encrypted_export() {
    let backup_str = build_encrypted_backup(&[], b"password");
    let err = twofas::parse_twofas_json(&backup_str).unwrap_err();
    assert!(matches!(err, import::ImportError::InvalidFormat(_)));
}

// ---------------------------------------------------------------------------
// Duplicate detection tests
// ---------------------------------------------------------------------------

#[test]
fn check_duplicates_finds_twofas_import_match() {
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

    // Parse 2FAS export with matching entry
    let json = make_backup_json(&[
        make_totp_service("GitHub", "user@example.com", "GitHub", TEST_SECRET),
        make_totp_service("Other", "unique@other.com", "Other", TEST_SECRET),
    ]);
    let parse_result = twofas::parse_twofas_json(&json).expect("should parse");

    let dupes = import::check_duplicates(db.connection(), &parse_result.entries)
        .expect("duplicate check should succeed");

    assert_eq!(dupes.len(), 1);
    assert_eq!(dupes[0].index, 0);
    assert_eq!(dupes[0].name, "user@example.com");
}

// ---------------------------------------------------------------------------
// Transactional import tests
// ---------------------------------------------------------------------------

#[test]
fn import_twofas_entries_success() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let json = make_backup_json(&[
        make_totp_service("GitHub", "dev@github.com", "GitHub", TEST_SECRET),
        serde_json::json!({
            "name": "AWS",
            "secret": "GEZDGNBVGY3TQOJQ",
            "otp": {
                "account": "admin@aws.com",
                "issuer": "AWS",
                "tokenType": "TOTP",
                "algorithm": "SHA256",
                "digits": 8,
                "period": 30
            }
        }),
    ]);

    let parse_result = twofas::parse_twofas_json(&json).expect("should parse");
    let summary = import::import_entries(db.connection(), &master_key, &parse_result.entries, &[])
        .expect("import should succeed");

    assert_eq!(summary.imported, 2);
    assert_eq!(summary.imported_ids.len(), 2);
    assert_eq!(summary.skipped, 0);

    // Verify entries in database
    let all_entries = list_entries(db.connection()).expect("list should succeed");
    assert_eq!(all_entries.len(), 2);

    // Verify entry data roundtrip
    let entry = get_entry(db.connection(), &master_key, &summary.imported_ids[0])
        .expect("get should succeed");
    assert_eq!(entry.name, "dev@github.com");
    assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
    match &entry.data {
        EntryData::Totp { secret } => assert_eq!(secret, TEST_SECRET),
        _ => panic!("expected TOTP data"),
    }
}

#[test]
fn import_with_skip_indices() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let json = make_backup_json(&[
        make_totp_service("Keep", "keep@test.com", "Keep", TEST_SECRET),
        make_totp_service("Skip", "skip@test.com", "Skip", "GEZDGNBVGY3TQOJQ"),
        make_totp_service(
            "Also Keep",
            "alsokeep@test.com",
            "AlsoKeep",
            "MFRGGZDFMY3TQLLB",
        ),
    ]);

    let parse_result = twofas::parse_twofas_json(&json).expect("should parse");
    let summary = import::import_entries(db.connection(), &master_key, &parse_result.entries, &[1])
        .expect("import should succeed");

    assert_eq!(summary.imported, 2);
    assert_eq!(summary.skipped, 1);

    let all_entries = list_entries(db.connection()).expect("list should succeed");
    let names: Vec<&str> = all_entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"keep@test.com"));
    assert!(names.contains(&"alsokeep@test.com"));
    assert!(!names.contains(&"skip@test.com"));
}

// ---------------------------------------------------------------------------
// End-to-end: parse → import pipeline
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_twofas_parse_and_import() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let json = make_backup_json(&[
        make_totp_service("GitHub", "dev@company.com", "GitHub", TEST_SECRET),
        serde_json::json!({
            "name": "Legacy",
            "secret": "GEZDGNBVGY3TQOJQ",
            "otp": {
                "account": "Legacy HOTP",
                "issuer": "OldService",
                "tokenType": "HOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
                "counter": 7
            }
        }),
        serde_json::json!({
            "name": "Steam",
            "secret": TEST_SECRET,
            "otp": {
                "account": "steam-game",
                "issuer": "Steam",
                "tokenType": "STEAM",
                "algorithm": "SHA1",
                "digits": 5,
                "period": 30
            }
        }),
    ]);

    // Phase 1: Parse
    let parse_result = twofas::parse_twofas_json(&json).expect("should parse");
    assert_eq!(parse_result.entries.len(), 2);
    assert_eq!(parse_result.unsupported.len(), 1);

    // Phase 2: Check duplicates (none expected)
    let dupes = import::check_duplicates(db.connection(), &parse_result.entries)
        .expect("dupe check should succeed");
    assert!(dupes.is_empty());

    // Phase 3: Import
    let summary = import::import_entries(db.connection(), &master_key, &parse_result.entries, &[])
        .expect("import should succeed");

    assert_eq!(summary.imported, 2);

    // Verify HOTP counter preserved
    let hotp_entry = get_entry(db.connection(), &master_key, &summary.imported_ids[1])
        .expect("get should succeed");
    assert_eq!(hotp_entry.entry_type, EntryType::Hotp);
    assert_eq!(hotp_entry.counter, 7);
}

#[test]
fn end_to_end_encrypted_twofas_import() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let password = b"vault-export-password";
    let backup_str = build_encrypted_backup(
        &[
            make_totp_service("GitHub", "encrypted-github", "GitHub", TEST_SECRET),
            make_totp_service("AWS", "encrypted-aws", "AWS", "GEZDGNBVGY3TQOJQ"),
        ],
        password,
    );

    // Phase 1: Detect encrypted
    assert!(twofas::is_encrypted(&backup_str).unwrap());

    // Phase 2: Decrypt and parse
    let parse_result =
        twofas::parse_twofas_encrypted(&backup_str, password).expect("should decrypt and parse");
    assert_eq!(parse_result.entries.len(), 2);

    // Phase 3: Import
    let summary = import::import_entries(db.connection(), &master_key, &parse_result.entries, &[])
        .expect("import should succeed");

    assert_eq!(summary.imported, 2);

    // Verify data integrity after decrypt → import → decrypt roundtrip
    let entry = get_entry(db.connection(), &master_key, &summary.imported_ids[0])
        .expect("get should succeed");
    assert_eq!(entry.name, "encrypted-github");
    match &entry.data {
        EntryData::Totp { secret } => assert_eq!(secret, TEST_SECRET),
        _ => panic!("expected TOTP data"),
    }
}

// ---------------------------------------------------------------------------
// Error categorization tests
// ---------------------------------------------------------------------------

#[test]
fn error_invalid_json() {
    let err = twofas::parse_twofas_json("not json").unwrap_err();
    assert!(matches!(err, import::ImportError::InvalidFormat(_)));
}

#[test]
fn error_unsupported_schema_version() {
    let json = serde_json::json!({
        "services": [],
        "schemaVersion": 99
    })
    .to_string();
    let err = twofas::parse_twofas_json(&json).unwrap_err();
    assert!(matches!(err, import::ImportError::Unsupported(_)));
}

#[test]
fn error_encrypted_payload_bad_format() {
    // Missing colon-separated parts
    let json = serde_json::json!({
        "services": [],
        "servicesEncrypted": "not-colon-separated",
        "schemaVersion": 4
    })
    .to_string();
    let err = twofas::parse_twofas_encrypted(&json, b"password").unwrap_err();
    assert!(matches!(err, import::ImportError::InvalidFormat(_)));
}

// ---------------------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptest_tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn parse_never_panics_on_arbitrary_json(data in ".*") {
            // Should return Ok or Err, never panic
            let _ = verrou_vault::import::twofas::parse_twofas_json(&data);
        }

        #[test]
        fn is_encrypted_never_panics(data in ".*") {
            let _ = verrou_vault::import::twofas::is_encrypted(&data);
        }

        #[test]
        fn parse_encrypted_never_panics_on_arbitrary_input(
            data in ".*",
            password in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let _ = verrou_vault::import::twofas::parse_twofas_encrypted(&data, &password);
        }
    }
}
