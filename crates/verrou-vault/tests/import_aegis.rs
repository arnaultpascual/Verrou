#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for Aegis import.
//!
//! Tests the full import pipeline: JSON parsing → validation →
//! duplicate detection → transactional bulk import.
//! Includes encrypted export roundtrip tests.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::import;
use verrou_vault::import::aegis;
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

/// Build a minimal valid plaintext Aegis vault JSON.
fn make_vault_json(entries: &[serde_json::Value]) -> String {
    serde_json::json!({
        "version": 1,
        "header": null,
        "db": {
            "version": 3,
            "entries": entries,
            "groups": []
        }
    })
    .to_string()
}

/// Build a TOTP entry JSON value.
fn make_totp_entry(name: &str, issuer: &str, secret: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "totp",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "name": name,
        "issuer": issuer,
        "note": "",
        "favorite": false,
        "icon": null,
        "info": {
            "secret": secret,
            "algo": "SHA1",
            "digits": 6,
            "period": 30
        },
        "groups": []
    })
}

// ---------------------------------------------------------------------------
// Parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_plaintext_vault_extracts_entries() {
    let json = make_vault_json(&[
        make_totp_entry("user@github.com", "GitHub", TEST_SECRET),
        make_totp_entry("admin@aws.com", "AWS", TEST_SECRET),
    ]);

    let result = aegis::parse_aegis_json(&json).expect("should parse");

    assert_eq!(result.entries.len(), 2);
    assert!(result.unsupported.is_empty());
    assert!(result.malformed.is_empty());
    assert_eq!(result.vault_version, 1);
    assert_eq!(result.db_version, 3);
}

#[test]
fn parse_hotp_entry_with_counter() {
    let entry = serde_json::json!({
        "type": "hotp",
        "name": "HOTP Account",
        "issuer": "Service",
        "info": {
            "secret": TEST_SECRET,
            "algo": "SHA256",
            "digits": 8,
            "period": 30,
            "counter": 42
        }
    });
    let json = make_vault_json(&[entry]);
    let result = aegis::parse_aegis_json(&json).expect("should parse");

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
        let entry = serde_json::json!({
            "type": "totp",
            "name": "test",
            "issuer": "",
            "info": {
                "secret": TEST_SECRET,
                "algo": algo,
                "digits": 6,
                "period": 30
            }
        });
        let json = make_vault_json(&[entry]);
        let result = aegis::parse_aegis_json(&json).expect("should parse");
        assert_eq!(result.entries[0].algorithm, expected, "algo={algo}");
    }
}

#[test]
fn unsupported_types_flagged_correctly() {
    for unsupported in ["steam", "motp", "yandex"] {
        let entry = serde_json::json!({
            "type": unsupported,
            "name": "account",
            "issuer": "Service",
            "info": {
                "secret": TEST_SECRET,
                "algo": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_vault_json(&[entry]);
        let result = aegis::parse_aegis_json(&json).expect("should parse");

        assert!(result.entries.is_empty(), "type={unsupported}");
        assert_eq!(result.unsupported.len(), 1, "type={unsupported}");
        assert!(result.unsupported[0].reason.contains(unsupported));
    }
}

#[test]
fn mixed_entries_categorized_correctly() {
    let entries = vec![
        // Valid TOTP
        make_totp_entry("good1", "Service1", TEST_SECRET),
        // Unsupported (Steam)
        serde_json::json!({
            "type": "steam",
            "name": "steam-account",
            "issuer": "Steam",
            "info": { "secret": TEST_SECRET, "algo": "SHA1", "digits": 5, "period": 30 }
        }),
        // Valid TOTP
        make_totp_entry("good2", "Service2", TEST_SECRET),
        // Malformed (empty secret)
        serde_json::json!({
            "type": "totp",
            "name": "bad",
            "issuer": "",
            "info": { "secret": "", "algo": "SHA1", "digits": 6, "period": 30 }
        }),
        // Unsupported (MD5)
        serde_json::json!({
            "type": "totp",
            "name": "md5-account",
            "issuer": "",
            "info": { "secret": TEST_SECRET, "algo": "MD5", "digits": 6, "period": 30 }
        }),
    ];

    let json = make_vault_json(&entries);
    let result = aegis::parse_aegis_json(&json).expect("should parse");

    assert_eq!(result.entries.len(), 2, "valid");
    assert_eq!(result.unsupported.len(), 2, "unsupported (steam + md5)");
    assert_eq!(result.malformed.len(), 1, "malformed (empty secret)");

    // Verify indices
    assert_eq!(result.unsupported[0].index, 1); // steam
    assert_eq!(result.malformed[0].index, 3); // empty secret
    assert_eq!(result.unsupported[1].index, 4); // md5
}

#[test]
fn secret_is_passed_through_not_reencoded() {
    let original_secret = "NBSWY3DPEHPK3PXP";
    let json = make_vault_json(&[make_totp_entry("test", "Service", original_secret)]);
    let result = aegis::parse_aegis_json(&json).expect("should parse");

    // Aegis secrets are already Base32 — verify passthrough, not double-encoding
    assert_eq!(result.entries[0].secret, original_secret);
}

// ---------------------------------------------------------------------------
// Version validation tests
// ---------------------------------------------------------------------------

#[test]
fn rejects_unsupported_vault_version() {
    let json = serde_json::json!({
        "version": 2,
        "header": null,
        "db": { "version": 3, "entries": [], "groups": [] }
    })
    .to_string();

    let err = aegis::parse_aegis_json(&json).unwrap_err();
    assert!(matches!(err, import::ImportError::Unsupported(_)));
}

#[test]
fn rejects_unsupported_db_versions() {
    for bad_version in [0, 4, 100] {
        let json = serde_json::json!({
            "version": 1,
            "header": null,
            "db": { "version": bad_version, "entries": [], "groups": [] }
        })
        .to_string();

        let err = aegis::parse_aegis_json(&json).unwrap_err();
        assert!(
            matches!(err, import::ImportError::Unsupported(_)),
            "db version {bad_version} should be rejected"
        );
    }
}

#[test]
fn accepts_valid_db_versions() {
    for version in 1..=3 {
        let json = serde_json::json!({
            "version": 1,
            "header": null,
            "db": { "version": version, "entries": [], "groups": [] }
        })
        .to_string();

        assert!(
            aegis::parse_aegis_json(&json).is_ok(),
            "db version {version} should be accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Encrypted export tests
// ---------------------------------------------------------------------------

/// Build an encrypted Aegis vault with known content for testing.
fn build_encrypted_vault(entries: &[serde_json::Value], password: &[u8]) -> String {
    use verrou_crypto_core::symmetric::encrypt as aes_encrypt;

    let db_json = serde_json::json!({
        "version": 2,
        "entries": entries,
        "groups": []
    });
    let db_plaintext = serde_json::to_string(&db_json).unwrap();

    // Generate a random master key
    let master_key = [0x42u8; 32];

    // Encrypt the db payload
    let db_sealed = aes_encrypt(db_plaintext.as_bytes(), &master_key, &[]).expect("encrypt db");

    // Derive slot key with scrypt (N=1024 for test speed)
    let salt = [0xAA; 32];
    let scrypt_params = scrypt::Params::new(10, 8, 1, 32).unwrap(); // log2(1024)=10
    let mut slot_key = vec![0u8; 32];
    scrypt::scrypt(password, &salt, &scrypt_params, &mut slot_key).unwrap();

    // Encrypt master key with slot key
    let master_key_sealed = aes_encrypt(&master_key, &slot_key, &[]).expect("encrypt master key");

    serde_json::json!({
        "version": 1,
        "header": {
            "slots": [{
                "type": 1,
                "uuid": "test-slot",
                "key": data_encoding::HEXLOWER.encode(&master_key_sealed.ciphertext),
                "key_params": {
                    "nonce": data_encoding::HEXLOWER.encode(&master_key_sealed.nonce),
                    "tag": data_encoding::HEXLOWER.encode(&master_key_sealed.tag)
                },
                "n": 1024,
                "r": 8,
                "p": 1,
                "salt": data_encoding::HEXLOWER.encode(&salt)
            }],
            "params": {
                "nonce": data_encoding::HEXLOWER.encode(&db_sealed.nonce),
                "tag": data_encoding::HEXLOWER.encode(&db_sealed.tag)
            }
        },
        "db": data_encoding::BASE64.encode(&db_sealed.ciphertext)
    })
    .to_string()
}

#[test]
fn encrypted_export_detected_correctly() {
    let vault_str = build_encrypted_vault(&[], b"password");
    assert!(aegis::is_encrypted(&vault_str).unwrap());

    let plaintext = make_vault_json(&[]);
    assert!(!aegis::is_encrypted(&plaintext).unwrap());
}

#[test]
fn encrypted_roundtrip_with_entries() {
    let password = b"test-password-aegis";
    let entries = vec![
        make_totp_entry("encrypted-test", "SecureService", TEST_SECRET),
        serde_json::json!({
            "type": "hotp",
            "name": "hotp-encrypted",
            "issuer": "OtherService",
            "info": {
                "secret": TEST_SECRET,
                "algo": "SHA512",
                "digits": 8,
                "period": 30,
                "counter": 99
            }
        }),
    ];

    let vault_str = build_encrypted_vault(&entries, password);
    let result =
        aegis::parse_aegis_encrypted(&vault_str, password).expect("should decrypt and parse");

    assert_eq!(result.entries.len(), 2);
    assert_eq!(result.entries[0].name, "encrypted-test");
    assert_eq!(result.entries[0].issuer.as_deref(), Some("SecureService"));
    assert_eq!(result.entries[0].entry_type, EntryType::Totp);

    assert_eq!(result.entries[1].name, "hotp-encrypted");
    assert_eq!(result.entries[1].entry_type, EntryType::Hotp);
    assert_eq!(result.entries[1].algorithm, Algorithm::SHA512);
    assert_eq!(result.entries[1].counter, 99);
}

#[test]
fn encrypted_wrong_password_fails() {
    let vault_str = build_encrypted_vault(
        &[make_totp_entry("test", "Service", TEST_SECRET)],
        b"correct-password",
    );

    let err = aegis::parse_aegis_encrypted(&vault_str, b"wrong-password").unwrap_err();
    assert!(matches!(err, import::ImportError::Corrupted(_)));
}

#[test]
fn plaintext_parser_rejects_encrypted_export() {
    let vault_str = build_encrypted_vault(&[], b"password");
    let err = aegis::parse_aegis_json(&vault_str).unwrap_err();
    assert!(matches!(err, import::ImportError::InvalidFormat(_)));
}

// ---------------------------------------------------------------------------
// Duplicate detection tests (reuse shared infra)
// ---------------------------------------------------------------------------

#[test]
fn check_duplicates_finds_aegis_import_match() {
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

    // Parse Aegis export with matching entry
    let json = make_vault_json(&[
        make_totp_entry("user@example.com", "GitHub", TEST_SECRET),
        make_totp_entry("unique@other.com", "Other", TEST_SECRET),
    ]);
    let parse_result = aegis::parse_aegis_json(&json).expect("should parse");

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
fn import_aegis_entries_success() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let json = make_vault_json(&[
        make_totp_entry("GitHub", "github.com", TEST_SECRET),
        serde_json::json!({
            "type": "totp",
            "name": "AWS",
            "issuer": "amazon.com",
            "info": {
                "secret": "GEZDGNBVGY3TQOJQ",
                "algo": "SHA256",
                "digits": 8,
                "period": 30
            }
        }),
    ]);

    let parse_result = aegis::parse_aegis_json(&json).expect("should parse");
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
    assert_eq!(entry.name, "GitHub");
    assert_eq!(entry.issuer.as_deref(), Some("github.com"));
    match &entry.data {
        EntryData::Totp { secret } => assert_eq!(secret, TEST_SECRET),
        _ => panic!("expected TOTP data"),
    }
}

#[test]
fn import_with_skip_indices() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let json = make_vault_json(&[
        make_totp_entry("Keep", "", TEST_SECRET),
        make_totp_entry("Skip", "", "GEZDGNBVGY3TQOJQ"),
        make_totp_entry("Also Keep", "", "MFRGGZDFMY3TQLLB"),
    ]);

    let parse_result = aegis::parse_aegis_json(&json).expect("should parse");
    let summary = import::import_entries(db.connection(), &master_key, &parse_result.entries, &[1])
        .expect("import should succeed");

    assert_eq!(summary.imported, 2);
    assert_eq!(summary.skipped, 1);

    let all_entries = list_entries(db.connection()).expect("list should succeed");
    let names: Vec<&str> = all_entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"Keep"));
    assert!(names.contains(&"Also Keep"));
    assert!(!names.contains(&"Skip"));
}

// ---------------------------------------------------------------------------
// End-to-end: parse → import pipeline
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_aegis_parse_and_import() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let json = make_vault_json(&[
        make_totp_entry("GitHub:dev@company.com", "GitHub", TEST_SECRET),
        serde_json::json!({
            "type": "hotp",
            "name": "Legacy HOTP",
            "issuer": "OldService",
            "info": {
                "secret": "GEZDGNBVGY3TQOJQ",
                "algo": "SHA1",
                "digits": 6,
                "period": 30,
                "counter": 7
            }
        }),
        serde_json::json!({
            "type": "steam",
            "name": "steam-game",
            "issuer": "Steam",
            "info": { "secret": TEST_SECRET, "algo": "SHA1", "digits": 5, "period": 30 }
        }),
    ]);

    // Phase 1: Parse
    let parse_result = aegis::parse_aegis_json(&json).expect("should parse");
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
fn end_to_end_encrypted_aegis_import() {
    let dir = tempfile::tempdir().unwrap();
    let (db, master_key) = setup_vault(dir.path());

    let password = b"vault-export-password";
    let vault_str = build_encrypted_vault(
        &[
            make_totp_entry("encrypted-github", "GitHub", TEST_SECRET),
            make_totp_entry("encrypted-aws", "AWS", "GEZDGNBVGY3TQOJQ"),
        ],
        password,
    );

    // Phase 1: Detect encrypted
    assert!(aegis::is_encrypted(&vault_str).unwrap());

    // Phase 2: Decrypt and parse
    let parse_result =
        aegis::parse_aegis_encrypted(&vault_str, password).expect("should decrypt and parse");
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
    let err = aegis::parse_aegis_json("not json").unwrap_err();
    assert!(matches!(err, import::ImportError::InvalidFormat(_)));
}

#[test]
fn error_missing_db() {
    let err = aegis::parse_aegis_json(r#"{"version": 1}"#).unwrap_err();
    assert!(matches!(err, import::ImportError::InvalidFormat(_)));
}

#[test]
fn error_unsupported_vault_version() {
    let json = serde_json::json!({
        "version": 99,
        "header": null,
        "db": { "version": 1, "entries": [], "groups": [] }
    })
    .to_string();
    let err = aegis::parse_aegis_json(&json).unwrap_err();
    assert!(matches!(err, import::ImportError::Unsupported(_)));
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
            let _ = verrou_vault::import::aegis::parse_aegis_json(&data);
        }

        #[test]
        fn is_encrypted_never_panics(data in ".*") {
            let _ = verrou_vault::import::aegis::is_encrypted(&data);
        }

        #[test]
        fn parse_encrypted_never_panics_on_arbitrary_input(
            data in ".*",
            password in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let _ = verrou_vault::import::aegis::parse_aegis_encrypted(&data, &password);
        }
    }
}
