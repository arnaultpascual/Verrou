#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Integration tests for vault lifecycle — creation, calibration, key hierarchy.

use std::path::Path;

use verrou_crypto_core::kdf::{Argon2idParams, CalibratedPresets, KdfPreset};
use verrou_crypto_core::memory::SecretBytes;
use verrou_crypto_core::slots::{self, SlotType};
use verrou_crypto_core::vault_format::{self, VaultHeader, FORMAT_VERSION};
use verrou_vault::error::VaultError;
use verrou_vault::lifecycle::{
    self, ChangePasswordAfterRecoveryRequest, CreateVaultRequest, CreateVaultResult,
    IntegrityStatus, UnlockVaultRequest,
};
use verrou_vault::recovery::{
    add_recovery_slot, decode_recovery_key, encode_recovery_key, vault_fingerprint,
    AddRecoverySlotRequest, GenerateRecoveryKeyResult,
};
use verrou_vault::VaultDb;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a test-friendly `CalibratedPresets` with minimal memory.
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

/// Create a vault in a temp directory with the given password and preset.
fn create_test_vault(
    dir: &Path,
    password: &[u8],
    preset: KdfPreset,
) -> Result<CreateVaultResult, VaultError> {
    let calibrated = test_calibrated();
    let req = CreateVaultRequest {
        password,
        preset,
        vault_dir: dir,
        calibrated: &calibrated,
    };
    lifecycle::create_vault(&req)
}

/// Parse the unencrypted `VaultHeader` from a `.verrou` file's raw bytes.
#[allow(clippy::arithmetic_side_effects)]
fn parse_header(verrou_bytes: &[u8]) -> VaultHeader {
    let header_len = u32::from_le_bytes(
        verrou_bytes[4..8]
            .try_into()
            .expect("4 bytes for header len"),
    ) as usize;
    serde_json::from_slice(&verrou_bytes[8..8 + header_len]).expect("header JSON should parse")
}

/// Recover the master key from a vault using the password and header data.
///
/// Uses the salt stored in `slot_salts[0]` and `session_params` from the
/// header to re-derive the password key, then unwraps the password slot.
fn recover_master_key_from_password(verrou_bytes: &[u8], password: &[u8]) -> SecretBytes<32> {
    let header = parse_header(verrou_bytes);

    // Salt is stored in the header's slot_salts (index-aligned with slots).
    assert!(
        !header.slot_salts.is_empty(),
        "header must have at least one salt"
    );
    let salt = &header.slot_salts[0];

    // Re-derive the password key using session_params.
    let password_key = verrou_crypto_core::kdf::derive(password, salt, &header.session_params)
        .expect("derive should succeed");

    // Unwrap the password slot to get the master key.
    let master_key_buf = slots::unwrap_slot(&header.slots[0], password_key.expose())
        .expect("unwrap_slot should succeed");

    assert_eq!(master_key_buf.len(), 32, "master key must be 32 bytes");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(master_key_buf.expose());
    SecretBytes::new(arr)
}

// ---------------------------------------------------------------------------
// AC #1: Vault creation succeeds, files exist
// ---------------------------------------------------------------------------

#[test]
fn create_vault_balanced_succeeds_files_exist() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let result = create_test_vault(tmp.path(), b"test-password-123", KdfPreset::Balanced)
        .expect("create_vault should succeed");

    assert!(result.vault_path.exists(), ".verrou file must exist");
    assert!(result.db_path.exists(), ".db file must exist");
    assert_eq!(result.kdf_preset, KdfPreset::Balanced);
}

// ---------------------------------------------------------------------------
// AC #1: VaultHeader contains correct session_params and sensitive_params
// ---------------------------------------------------------------------------

#[test]
fn vault_header_contains_correct_kdf_params() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let calibrated = test_calibrated();
    let req = CreateVaultRequest {
        password: b"my-password",
        preset: KdfPreset::Fast,
        vault_dir: tmp.path(),
        calibrated: &calibrated,
    };
    let result = lifecycle::create_vault(&req).expect("create_vault should succeed");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read .verrou should succeed");
    assert_eq!(&verrou_bytes[..4], b"VROU", "magic must be VROU");

    let header = parse_header(&verrou_bytes);

    // session_params should match the user's chosen preset (Fast).
    assert_eq!(header.session_params, calibrated.fast);
    // sensitive_params should always be Maximum.
    assert_eq!(header.sensitive_params, calibrated.maximum);
    assert_eq!(header.version, FORMAT_VERSION);
    assert_eq!(header.slot_count, 1);
    assert_eq!(header.unlock_attempts, 0);
    assert_eq!(header.slots.len(), 1);
    assert_eq!(header.slots[0].slot_type, SlotType::Password);
    // Salt should be stored in the header.
    assert_eq!(header.slot_salts.len(), 1);
    assert_eq!(header.slot_salts[0].len(), 16, "salt must be 16 bytes");
}

// ---------------------------------------------------------------------------
// AC #1: Password slot can be unwrapped → master key roundtrip
// ---------------------------------------------------------------------------

#[test]
fn password_slot_unwrap_recovers_master_key() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"roundtrip-password";
    let calibrated = test_calibrated();
    let req = CreateVaultRequest {
        password,
        preset: KdfPreset::Balanced,
        vault_dir: tmp.path(),
        calibrated: &calibrated,
    };
    let result = lifecycle::create_vault(&req).expect("create_vault should succeed");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read .verrou should succeed");
    let master_key = recover_master_key_from_password(&verrou_bytes, password);

    // Verify the master key can decrypt the .verrou payload.
    let (recovered_header, payload) = vault_format::deserialize(&verrou_bytes, master_key.expose())
        .expect("deserialize should succeed");
    assert!(payload.expose().is_empty(), "payload should be empty");
    assert_eq!(recovered_header.version, FORMAT_VERSION);
}

// ---------------------------------------------------------------------------
// AC #1: Vault roundtrip — create + unlock via password
// ---------------------------------------------------------------------------

#[test]
fn vault_roundtrip_create_then_open_with_correct_password() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"full-roundtrip-test";
    let result = create_test_vault(tmp.path(), password, KdfPreset::Balanced)
        .expect("create_vault should succeed");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read should succeed");
    let master_key = recover_master_key_from_password(&verrou_bytes, password);

    // Open the SQLCipher DB with the recovered master key.
    let db = VaultDb::open(&result.db_path, &master_key).expect("VaultDb::open should succeed");

    // Verify schema version matches the number of applied migrations.
    assert_eq!(db.schema_version().expect("schema_version"), 7);

    // Verify cipher_version is non-empty (SQLCipher is linked).
    let cv = db.cipher_version();
    assert!(!cv.is_empty(), "cipher_version must be non-empty");
}

// ---------------------------------------------------------------------------
// AC #2: Wrong password fails
// ---------------------------------------------------------------------------

#[test]
fn vault_cannot_be_opened_with_wrong_password() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let result = create_test_vault(tmp.path(), b"correct-password", KdfPreset::Balanced)
        .expect("create_vault should succeed");

    let wrong_key = SecretBytes::<32>::random().expect("random should succeed");
    let open_result = VaultDb::open(&result.db_path, &wrong_key);

    assert!(open_result.is_err(), "opening with wrong key should fail");
    assert!(
        matches!(open_result, Err(VaultError::InvalidPassword)),
        "wrong key should yield VaultError::InvalidPassword"
    );
}

#[test]
fn wrong_password_fails_slot_unwrap() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let result = create_test_vault(tmp.path(), b"correct-password", KdfPreset::Balanced)
        .expect("create_vault should succeed");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read should succeed");
    let header = parse_header(&verrou_bytes);

    // Derive with wrong password.
    let wrong_key = verrou_crypto_core::kdf::derive(
        b"wrong-password",
        &header.slot_salts[0],
        &header.session_params,
    )
    .expect("derive should succeed");

    // Unwrap should fail with wrong wrapping key.
    let unwrap_result = slots::unwrap_slot(&header.slots[0], wrong_key.expose());
    assert!(
        unwrap_result.is_err(),
        "wrong password should fail slot unwrap"
    );
}

// ---------------------------------------------------------------------------
// AC #5: VaultAlreadyExists
// ---------------------------------------------------------------------------

#[test]
fn create_vault_on_existing_vault_returns_already_exists() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");

    create_test_vault(tmp.path(), b"first-password", KdfPreset::Balanced)
        .expect("first create should succeed");

    let result = create_test_vault(tmp.path(), b"second-password", KdfPreset::Fast);
    assert!(result.is_err());
    assert!(
        matches!(result, Err(VaultError::VaultAlreadyExists(_))),
        "duplicate create should yield VaultAlreadyExists"
    );
}

#[test]
fn create_vault_refuses_if_only_db_exists() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    std::fs::write(tmp.path().join("vault.db"), b"dummy").expect("write should succeed");

    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Balanced);
    assert!(
        matches!(result, Err(VaultError::VaultAlreadyExists(_))),
        "existing .db file should trigger VaultAlreadyExists"
    );
}

#[test]
fn create_vault_refuses_if_only_verrou_exists() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    std::fs::write(tmp.path().join("vault.verrou"), b"dummy").expect("write should succeed");

    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Balanced);
    assert!(
        matches!(result, Err(VaultError::VaultAlreadyExists(_))),
        "existing .verrou file should trigger VaultAlreadyExists"
    );
}

// ---------------------------------------------------------------------------
// AC #1: All 3 KDF presets produce valid vaults
// ---------------------------------------------------------------------------

#[test]
fn all_three_presets_produce_valid_vaults() {
    for preset in [KdfPreset::Fast, KdfPreset::Balanced, KdfPreset::Maximum] {
        let tmp = tempfile::tempdir().expect("tempdir should succeed");
        let result = create_test_vault(tmp.path(), b"preset-test-password", preset)
            .expect("create_vault should succeed for all presets");

        assert!(result.vault_path.exists(), "{preset:?}: .verrou must exist");
        assert!(result.db_path.exists(), "{preset:?}: .db must exist");
        assert_eq!(result.kdf_preset, preset);

        let bytes = std::fs::read(&result.vault_path).expect("read .verrou should succeed");
        assert_eq!(&bytes[..4], b"VROU");
    }
}

// ---------------------------------------------------------------------------
// AC #1: SQLCipher database has correct schema
// ---------------------------------------------------------------------------

#[test]
fn sqlcipher_database_has_correct_schema_after_creation() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"schema-test";
    let result = create_test_vault(tmp.path(), password, KdfPreset::Balanced)
        .expect("create_vault should succeed");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read should succeed");
    let master_key = recover_master_key_from_password(&verrou_bytes, password);

    let db = VaultDb::open(&result.db_path, &master_key).expect("open DB should succeed");
    assert_eq!(db.schema_version().expect("schema_version"), 7);

    // Verify tables exist.
    let conn = db.connection();
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .expect("prepare should succeed");
        let rows = stmt
            .query_map([], |row| row.get(0))
            .expect("query should succeed");
        rows.map(|r| r.expect("row")).collect()
    };

    assert!(
        tables.contains(&"entries".to_string()),
        "entries table must exist"
    );
    assert!(
        tables.contains(&"folders".to_string()),
        "folders table must exist"
    );
    assert!(
        tables.contains(&"key_slots".to_string()),
        "key_slots table must exist"
    );
}

// ---------------------------------------------------------------------------
// AC #1: key_slots table has password slot record with salt and kdf_params
// ---------------------------------------------------------------------------

#[test]
fn key_slots_table_has_password_slot_with_salt_and_kdf_params() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"key-slot-test";
    let calibrated = test_calibrated();
    let req = CreateVaultRequest {
        password,
        preset: KdfPreset::Balanced,
        vault_dir: tmp.path(),
        calibrated: &calibrated,
    };
    lifecycle::create_vault(&req).expect("create_vault should succeed");

    let verrou_bytes = std::fs::read(tmp.path().join("vault.verrou")).expect("read should succeed");
    let master_key = recover_master_key_from_password(&verrou_bytes, password);

    let db =
        VaultDb::open(&tmp.path().join("vault.db"), &master_key).expect("open DB should succeed");
    let conn = db.connection();

    // Query the key_slots table.
    let (slot_type, wrapped_key, salt, kdf_params_json, created_at): (
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
    ) = conn
        .query_row(
            "SELECT slot_type, wrapped_key, salt, kdf_params, created_at FROM key_slots LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0).expect("slot_type"),
                    row.get(1).expect("wrapped_key"),
                    row.get(2).expect("salt"),
                    row.get(3).expect("kdf_params"),
                    row.get(4).expect("created_at"),
                ))
            },
        )
        .expect("query key_slots should succeed");

    assert_eq!(slot_type, "password");
    assert!(!wrapped_key.is_empty(), "wrapped_key must not be empty");
    assert_eq!(salt.len(), 16, "salt must be 16 bytes");
    assert!(!kdf_params_json.is_empty(), "kdf_params must not be empty");
    assert!(created_at.ends_with('Z'), "created_at must be UTC ISO 8601");

    // Verify kdf_params deserializes correctly.
    let kdf_params: Argon2idParams =
        serde_json::from_str(&kdf_params_json).expect("parse kdf_params should succeed");
    assert_eq!(kdf_params, calibrated.balanced);

    // Verify the salt in the DB matches the salt in the header.
    let header = parse_header(&verrou_bytes);
    assert_eq!(salt, header.slot_salts[0], "DB salt must match header salt");
}

// ---------------------------------------------------------------------------
// AC #4: CreateVaultResult contains no raw key material
// ---------------------------------------------------------------------------

#[test]
fn create_vault_result_is_safe_for_ipc() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let result = create_test_vault(tmp.path(), b"ipc-test", KdfPreset::Balanced)
        .expect("create_vault should succeed");

    let json = serde_json::to_string(&result).expect("serialize should succeed");

    let lower = json.to_lowercase();
    assert!(
        !lower.contains("master_key"),
        "result must not contain master_key"
    );
    assert!(
        !lower.contains("password_key"),
        "result must not contain password_key"
    );
    assert!(
        !lower.contains("wrapped_key"),
        "result must not contain wrapped_key"
    );
    assert!(!lower.contains("secret"), "result must not contain secret");

    assert!(json.contains("vaultPath"));
    assert!(json.contains("dbPath"));
    assert!(json.contains("kdfPreset"));
}

// ---------------------------------------------------------------------------
// AC #3: Master key is SecretBytes<32>
// ---------------------------------------------------------------------------

#[test]
fn master_key_type_is_secret_bytes_32() {
    let key: SecretBytes<32> = SecretBytes::<32>::random().expect("random should succeed");
    assert_eq!(key.expose().len(), 32);
    assert_eq!(format!("{key:?}"), "SecretBytes<32>(***)");
}

// ---------------------------------------------------------------------------
// .verrou file is 64KB-aligned
// ---------------------------------------------------------------------------

#[test]
fn verrou_file_is_64kb_aligned() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    create_test_vault(tmp.path(), b"alignment-test", KdfPreset::Balanced)
        .expect("create_vault should succeed");

    let bytes = std::fs::read(tmp.path().join("vault.verrou")).expect("read should succeed");
    assert_eq!(
        bytes.len() % 65_536,
        0,
        ".verrou file must be 64KB-aligned, got {} bytes",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Calibration wrapper
// ---------------------------------------------------------------------------

#[test]
fn calibrate_for_vault_returns_three_presets() {
    let presets = lifecycle::calibrate_for_vault().expect("calibration should succeed");

    assert!(presets.fast.m_cost > 0);
    assert!(presets.balanced.m_cost > 0);
    assert!(presets.maximum.m_cost > 0);

    assert!(presets.maximum.m_cost >= presets.balanced.m_cost);
    assert!(presets.balanced.m_cost >= presets.fast.m_cost);
}

// ---------------------------------------------------------------------------
// slot_salts roundtrip through VaultHeader serialization
// ---------------------------------------------------------------------------

#[test]
fn slot_salts_survive_header_serialization_roundtrip() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"salt-roundtrip";
    create_test_vault(tmp.path(), password, KdfPreset::Fast).expect("create_vault should succeed");

    let verrou_bytes = std::fs::read(tmp.path().join("vault.verrou")).expect("read should succeed");
    let header = parse_header(&verrou_bytes);

    // Re-serialize and re-parse the header to verify slot_salts survive.
    let json = serde_json::to_string(&header).expect("serialize should succeed");
    let roundtripped: VaultHeader =
        serde_json::from_str(&json).expect("deserialize should succeed");

    assert_eq!(roundtripped.slot_salts.len(), 1);
    assert_eq!(roundtripped.slot_salts[0].len(), 16);
    assert_eq!(roundtripped.slot_salts, header.slot_salts);
}

// ===========================================================================
// Story 2.8: Vault Unlock with Master Password
// ===========================================================================

// ---------------------------------------------------------------------------
// AC #2: Successful unlock flow
// ---------------------------------------------------------------------------

#[test]
fn unlock_vault_with_correct_password_succeeds() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"correct-unlock-password";

    create_test_vault(tmp.path(), password, KdfPreset::Balanced)
        .expect("create_vault should succeed");

    let req = UnlockVaultRequest {
        password,
        vault_dir: tmp.path(),
    };
    let session = lifecycle::unlock_vault(&req).expect("unlock should succeed");

    assert_eq!(session.unlock_count, 1, "first unlock should have count 1");
    assert_eq!(
        session.master_key.expose().len(),
        32,
        "master key must be 32 bytes"
    );

    // Verify DB is usable — query schema version.
    assert_eq!(
        session.db.schema_version().expect("schema_version"),
        7,
        "schema version must match migration count"
    );
}

#[test]
fn unlock_vault_increments_total_unlock_count() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"count-test-password";

    create_test_vault(tmp.path(), password, KdfPreset::Fast).expect("create_vault should succeed");

    // Unlock 3 times.
    for expected_count in 1..=3 {
        let req = UnlockVaultRequest {
            password,
            vault_dir: tmp.path(),
        };
        let session = lifecycle::unlock_vault(&req).expect("unlock should succeed");
        assert_eq!(
            session.unlock_count, expected_count,
            "unlock count should be {expected_count}"
        );
    }
}

// ---------------------------------------------------------------------------
// AC #3: Incorrect password feedback
// ---------------------------------------------------------------------------

#[test]
fn unlock_vault_with_wrong_password_returns_invalid_password() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");

    create_test_vault(tmp.path(), b"correct", KdfPreset::Fast)
        .expect("create_vault should succeed");

    let req = UnlockVaultRequest {
        password: b"wrong-password",
        vault_dir: tmp.path(),
    };
    let result = lifecycle::unlock_vault(&req);

    assert!(
        matches!(result, Err(VaultError::InvalidPassword)),
        "wrong password should yield InvalidPassword, got: {result:?}"
    );
}

#[test]
fn unlock_vault_increments_attempt_counter_on_failure() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");

    create_test_vault(tmp.path(), b"correct", KdfPreset::Fast)
        .expect("create_vault should succeed");

    // Fail twice.
    for _ in 0..2 {
        let req = UnlockVaultRequest {
            password: b"wrong",
            vault_dir: tmp.path(),
        };
        let _ = lifecycle::unlock_vault(&req);
    }

    // Read header to check attempt counter.
    let verrou_bytes = std::fs::read(tmp.path().join("vault.verrou")).expect("read should succeed");
    let header = parse_header(&verrou_bytes);
    assert_eq!(
        header.unlock_attempts, 2,
        "attempt counter should be 2 after 2 failures"
    );
    assert!(
        header.last_attempt_at.is_some(),
        "last_attempt_at should be set after failure"
    );
}

#[test]
fn unlock_vault_resets_attempt_counter_on_success() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");

    create_test_vault(tmp.path(), b"correct", KdfPreset::Fast)
        .expect("create_vault should succeed");

    // Fail twice.
    for _ in 0..2 {
        let req = UnlockVaultRequest {
            password: b"wrong",
            vault_dir: tmp.path(),
        };
        let _ = lifecycle::unlock_vault(&req);
    }

    // Succeed once.
    let req = UnlockVaultRequest {
        password: b"correct",
        vault_dir: tmp.path(),
    };
    let _ = lifecycle::unlock_vault(&req).expect("unlock should succeed");

    // Read header to verify counter was reset.
    let verrou_bytes = std::fs::read(tmp.path().join("vault.verrou")).expect("read should succeed");
    let header = parse_header(&verrou_bytes);
    assert_eq!(
        header.unlock_attempts, 0,
        "attempt counter should be 0 after success"
    );
    assert!(
        header.last_attempt_at.is_none(),
        "last_attempt_at should be None after success"
    );
}

// ---------------------------------------------------------------------------
// AC #3/#4: Brute-force backoff enforcement
// ---------------------------------------------------------------------------

#[test]
fn unlock_vault_rate_limited_after_3_failures() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");

    create_test_vault(tmp.path(), b"correct", KdfPreset::Fast)
        .expect("create_vault should succeed");

    // Fail 3 times.
    for _ in 0..3 {
        let req = UnlockVaultRequest {
            password: b"wrong",
            vault_dir: tmp.path(),
        };
        let _ = lifecycle::unlock_vault(&req);
    }

    // 4th attempt should be rate limited (3+ failures → 1s cooldown).
    let req = UnlockVaultRequest {
        password: b"wrong",
        vault_dir: tmp.path(),
    };
    let result = lifecycle::unlock_vault(&req);

    assert!(
        matches!(result, Err(VaultError::RateLimited { .. })),
        "should be rate limited after 3 failures, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Vault not found
// ---------------------------------------------------------------------------

#[test]
fn unlock_vault_not_found_returns_error() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");

    let req = UnlockVaultRequest {
        password: b"password",
        vault_dir: tmp.path(),
    };
    let result = lifecycle::unlock_vault(&req);

    assert!(
        matches!(result, Err(VaultError::NotFound(_))),
        "unlock on missing vault should yield NotFound, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// New header fields backward compatibility
// ---------------------------------------------------------------------------

#[test]
fn new_header_fields_have_serde_defaults() {
    // Simulate an old vault header without the new fields.
    let old_header_json = r#"{
        "version": 1,
        "slot_count": 0,
        "session_params": {"m_cost": 32, "t_cost": 1, "p_cost": 1},
        "sensitive_params": {"m_cost": 128, "t_cost": 3, "p_cost": 1},
        "unlock_attempts": 0,
        "slots": [],
        "slot_salts": []
    }"#;

    let header: VaultHeader =
        serde_json::from_str(old_header_json).expect("old header should deserialize");

    assert_eq!(
        header.last_attempt_at, None,
        "last_attempt_at should default to None"
    );
    assert_eq!(
        header.total_unlock_count, 0,
        "total_unlock_count should default to 0"
    );
}

// ---------------------------------------------------------------------------
// UnlockVaultResult is safe for IPC
// ---------------------------------------------------------------------------

#[test]
fn unlock_vault_result_is_safe_for_ipc() {
    let result = verrou_vault::UnlockVaultResult { unlock_count: 42 };
    let json = serde_json::to_string(&result).expect("serialize should succeed");

    // Must use camelCase.
    assert!(json.contains("unlockCount"));
    assert!(!json.contains("unlock_count"));

    // Must not contain any key material.
    let lower = json.to_lowercase();
    assert!(!lower.contains("master_key"));
    assert!(!lower.contains("password"));
    assert!(!lower.contains("secret"));
}

// ---------------------------------------------------------------------------
// Proptest: random passwords + random presets produce valid vaults
// ---------------------------------------------------------------------------

// ===========================================================================
// Story 2.3: Recovery Key Generation, Display, and Print
// ===========================================================================

/// Helper: create a vault and add a recovery slot, returning the result
/// along with the master key for further verification.
fn create_vault_with_recovery(
    dir: &Path,
    password: &[u8],
) -> (
    CreateVaultResult,
    GenerateRecoveryKeyResult,
    SecretBytes<32>,
) {
    let vault_result =
        create_test_vault(dir, password, KdfPreset::Balanced).expect("create_vault should succeed");

    let verrou_bytes =
        std::fs::read(&vault_result.vault_path).expect("read .verrou should succeed");
    let master_key = recover_master_key_from_password(&verrou_bytes, password);

    let recovery_req = AddRecoverySlotRequest {
        vault_dir: dir,
        master_key: master_key.expose(),
    };
    let recovery_result =
        add_recovery_slot(&recovery_req).expect("add_recovery_slot should succeed");

    (vault_result, recovery_result, master_key)
}

// ---------------------------------------------------------------------------
// Task 5.5: add_recovery_slot succeeds — vault has 2 slots
// ---------------------------------------------------------------------------

#[test]
fn add_recovery_slot_succeeds_vault_has_two_slots() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let (vault_result, _recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), b"recovery-test");

    let updated_bytes =
        std::fs::read(&vault_result.vault_path).expect("read updated .verrou should succeed");
    let header = parse_header(&updated_bytes);

    assert_eq!(
        header.slot_count, 2,
        "vault must have 2 slots after recovery"
    );
    assert_eq!(header.slots.len(), 2, "slots array must have 2 entries");
    assert_eq!(
        header.slots[0].slot_type,
        SlotType::Password,
        "first slot must be password"
    );
    assert_eq!(
        header.slots[1].slot_type,
        SlotType::Recovery,
        "second slot must be recovery"
    );
}

// ---------------------------------------------------------------------------
// Task 5.6: recovery slot unwrap recovers master key
// ---------------------------------------------------------------------------

#[test]
fn recovery_slot_unwrap_recovers_master_key() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let (vault_result, recovery_result, master_key) =
        create_vault_with_recovery(tmp.path(), b"recovery-unwrap-test");

    // Decode the recovery key to get entropy.
    let entropy = decode_recovery_key(&recovery_result.formatted_key)
        .expect("decode_recovery_key should succeed");

    // Read the updated header to get the recovery salt and sensitive_params.
    let updated_bytes =
        std::fs::read(&vault_result.vault_path).expect("read updated .verrou should succeed");
    let header = parse_header(&updated_bytes);

    // Re-derive the recovery wrapping key.
    let recovery_salt = &header.slot_salts[1];
    let recovery_wrapping_key =
        verrou_crypto_core::kdf::derive(&entropy, recovery_salt, &header.sensitive_params)
            .expect("derive should succeed");

    // Unwrap the recovery slot.
    let recovered_master_key = slots::unwrap_slot(&header.slots[1], recovery_wrapping_key.expose())
        .expect("unwrap_slot should succeed");

    assert_eq!(
        recovered_master_key.expose(),
        master_key.expose().as_slice(),
        "recovery slot must unwrap to the same master key"
    );
}

// ---------------------------------------------------------------------------
// Task 5.7: password and recovery slots unwrap to same master key
// ---------------------------------------------------------------------------

#[test]
fn password_and_recovery_slots_unwrap_to_same_master_key() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"dual-slot-test";
    let (vault_result, recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let updated_bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
    let header = parse_header(&updated_bytes);

    // Unwrap password slot.
    let password_key =
        verrou_crypto_core::kdf::derive(password, &header.slot_salts[0], &header.session_params)
            .expect("derive password key");
    let mk_from_password =
        slots::unwrap_slot(&header.slots[0], password_key.expose()).expect("unwrap password slot");

    // Unwrap recovery slot.
    let entropy = decode_recovery_key(&recovery_result.formatted_key)
        .expect("decode_recovery_key should succeed");
    let recovery_key =
        verrou_crypto_core::kdf::derive(&entropy, &header.slot_salts[1], &header.sensitive_params)
            .expect("derive recovery key");
    let mk_from_recovery =
        slots::unwrap_slot(&header.slots[1], recovery_key.expose()).expect("unwrap recovery slot");

    assert_eq!(
        mk_from_password.expose(),
        mk_from_recovery.expose(),
        "both slots must unwrap to the same master key"
    );
}

// ---------------------------------------------------------------------------
// Task 5.8: recovery slot stored in database
// ---------------------------------------------------------------------------

#[test]
fn recovery_slot_stored_in_database() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"db-slot-test";
    let (vault_result, _recovery_result, master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let db = VaultDb::open(&vault_result.db_path, &master_key).expect("open DB should succeed");
    let conn = db.connection();

    // Query all key_slots — should have 2 (password + recovery).
    let count: i64 = conn
        .query_row("SELECT count(*) FROM key_slots", [], |row| row.get(0))
        .expect("count query should succeed");
    assert_eq!(count, 2, "key_slots table must have 2 records");

    // Verify the recovery slot record.
    let (slot_type, wrapped_key, salt, kdf_params_json, created_at): (
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
    ) = conn
        .query_row(
            "SELECT slot_type, wrapped_key, salt, kdf_params, created_at \
             FROM key_slots WHERE slot_type = 'recovery' LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get(0).expect("slot_type"),
                    row.get(1).expect("wrapped_key"),
                    row.get(2).expect("salt"),
                    row.get(3).expect("kdf_params"),
                    row.get(4).expect("created_at"),
                ))
            },
        )
        .expect("query recovery slot should succeed");

    assert_eq!(slot_type, "recovery");
    assert!(!wrapped_key.is_empty(), "wrapped_key must not be empty");
    assert_eq!(salt.len(), 16, "salt must be 16 bytes");
    assert!(!kdf_params_json.is_empty(), "kdf_params must not be empty");
    assert!(created_at.ends_with('Z'), "created_at must be UTC ISO 8601");

    // Verify the salt in the DB matches the salt in the header.
    let updated_bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
    let header = parse_header(&updated_bytes);
    assert_eq!(salt, header.slot_salts[1], "DB salt must match header salt");
}

// ---------------------------------------------------------------------------
// Task 5.9: vault header updated after recovery slot
// ---------------------------------------------------------------------------

#[test]
fn vault_header_updated_after_recovery_slot() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let (vault_result, _recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), b"header-update-test");

    let updated_bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
    let header = parse_header(&updated_bytes);

    assert_eq!(header.slot_count, 2, "slot_count must be 2");
    assert_eq!(header.slot_salts.len(), 2, "slot_salts.len() must be 2");
    assert_eq!(header.slots.len(), 2, "slots.len() must be 2");

    // Verify both salts are 16 bytes.
    assert_eq!(
        header.slot_salts[0].len(),
        16,
        "password salt must be 16 bytes"
    );
    assert_eq!(
        header.slot_salts[1].len(),
        16,
        "recovery salt must be 16 bytes"
    );

    // Verify salts are different (different random values).
    assert_ne!(
        header.slot_salts[0], header.slot_salts[1],
        "password and recovery salts must differ"
    );
}

// ---------------------------------------------------------------------------
// Task 5.10: vault file still 64KB-aligned after recovery slot
// ---------------------------------------------------------------------------

#[test]
fn vault_file_still_64kb_aligned_after_recovery_slot() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let (vault_result, _recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), b"alignment-test-recovery");

    let updated_bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
    assert_eq!(
        updated_bytes.len() % 65_536,
        0,
        ".verrou file must be 64KB-aligned after recovery slot, got {} bytes",
        updated_bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Task 5.11: GenerateRecoveryKeyResult has no raw entropy
// ---------------------------------------------------------------------------

#[test]
fn generate_recovery_key_result_has_no_raw_entropy() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let (_vault_result, recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), b"no-entropy-test");

    let json = serde_json::to_string(&recovery_result).expect("serialize should succeed");
    let lower = json.to_lowercase();

    // Must not contain binary/hex patterns.
    assert!(
        !lower.contains("entropy"),
        "result must not contain 'entropy'"
    );
    assert!(
        !lower.contains("master_key"),
        "result must not contain 'master_key'"
    );
    assert!(
        !lower.contains("wrapping_key"),
        "result must not contain 'wrapping_key'"
    );
    assert!(
        !lower.contains("secret"),
        "result must not contain 'secret'"
    );

    // Must use camelCase field names.
    assert!(json.contains("formattedKey"));
    assert!(json.contains("vaultFingerprint"));
    assert!(json.contains("generationDate"));

    // Formatted key must be present and properly formatted.
    assert_eq!(
        recovery_result
            .formatted_key
            .chars()
            .filter(|c| *c == '-')
            .count(),
        6,
        "formatted key must have 6 dashes"
    );

    // Vault fingerprint must be 16 hex chars.
    assert_eq!(recovery_result.vault_fingerprint.len(), 16);
    assert!(recovery_result
        .vault_fingerprint
        .chars()
        .all(|c| c.is_ascii_hexdigit()));

    // Generation date must be ISO 8601.
    assert!(recovery_result.generation_date.ends_with('Z'));
}

// ---------------------------------------------------------------------------
// Task 5.12: vault fingerprint is deterministic
// ---------------------------------------------------------------------------

#[test]
fn vault_fingerprint_is_deterministic() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let (vault_result, _recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), b"fingerprint-test");

    let bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
    let fp1 = vault_fingerprint(&bytes);
    let fp2 = vault_fingerprint(&bytes);
    assert_eq!(fp1, fp2, "fingerprint must be deterministic");
}

// ---------------------------------------------------------------------------
// Recovery slot on non-existent vault fails
// ---------------------------------------------------------------------------

#[test]
fn add_recovery_slot_fails_on_missing_vault() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let req = AddRecoverySlotRequest {
        vault_dir: tmp.path(),
        master_key: &[0xAA; 32],
    };
    let result = add_recovery_slot(&req);
    assert!(
        matches!(result, Err(VaultError::NotFound(_))),
        "recovery slot on missing vault should yield NotFound"
    );
}

// ===========================================================================
// Story 2.10: Recovery Key Vault Access
// ===========================================================================

// ---------------------------------------------------------------------------
// Task 8.1: recovery key unlock succeeds with valid key
// ---------------------------------------------------------------------------

#[test]
fn recovery_key_unlock_succeeds_with_valid_key() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"original-password";
    let (_vault_result, recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let session =
        lifecycle::unlock_vault_with_recovery_key(&recovery_result.formatted_key, tmp.path())
            .expect("recovery key unlock should succeed");

    assert!(session.unlock_count > 0, "unlock_count must be positive");
    assert_eq!(
        session.master_key.expose().len(),
        32,
        "master key must be 32 bytes"
    );

    let version = session
        .db
        .schema_version()
        .expect("schema_version should work");
    assert_eq!(version, 7);
}

// ---------------------------------------------------------------------------
// Task 8.2: recovery key unlock fails with invalid key
// ---------------------------------------------------------------------------

#[test]
fn recovery_key_unlock_fails_with_invalid_key() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"test-password";
    let (_vault_result, _recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let fake_entropy = [0xAA; 16];
    let fake_key = encode_recovery_key(&fake_entropy);

    let result = lifecycle::unlock_vault_with_recovery_key(&fake_key, tmp.path());
    assert!(
        matches!(result, Err(VaultError::InvalidRecoveryKey)),
        "wrong recovery key should return InvalidRecoveryKey, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Task 8.2b: recovery key unlock increments brute-force counter
// ---------------------------------------------------------------------------

#[test]
fn recovery_key_unlock_increments_brute_force_counter() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"counter-test";
    let (vault_result, _recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let fake_entropy = [0xBB; 16];
    let fake_key = encode_recovery_key(&fake_entropy);

    let _ = lifecycle::unlock_vault_with_recovery_key(&fake_key, tmp.path());

    let bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
    let header = parse_header(&bytes);
    assert_eq!(
        header.unlock_attempts, 1,
        "unlock_attempts must be 1 after one failed recovery"
    );
}

// ---------------------------------------------------------------------------
// Task 8.3: shared brute-force counter (password fail + recovery fail)
// ---------------------------------------------------------------------------

#[test]
fn shared_brute_force_counter_password_and_recovery() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"shared-counter-test";
    let (vault_result, _recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let wrong_pw_req = UnlockVaultRequest {
        password: b"wrong-password",
        vault_dir: tmp.path(),
    };
    let _ = lifecycle::unlock_vault(&wrong_pw_req);

    let fake_entropy = [0xCC; 16];
    let fake_key = encode_recovery_key(&fake_entropy);
    let _ = lifecycle::unlock_vault_with_recovery_key(&fake_key, tmp.path());

    let bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
    let header = parse_header(&bytes);
    assert_eq!(
        header.unlock_attempts, 2,
        "unlock_attempts must be 2 (1 pw + 1 recovery)"
    );
}

// ---------------------------------------------------------------------------
// Task 8.3b: successful recovery resets brute-force counter
// ---------------------------------------------------------------------------

#[test]
fn successful_recovery_resets_brute_force_counter() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"reset-counter-test";
    let (vault_result, recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let wrong_pw_req = UnlockVaultRequest {
        password: b"wrong",
        vault_dir: tmp.path(),
    };
    let _ = lifecycle::unlock_vault(&wrong_pw_req);
    let _ = lifecycle::unlock_vault(&wrong_pw_req);

    let bytes_before = std::fs::read(&vault_result.vault_path).expect("read");
    let header_before = parse_header(&bytes_before);
    assert_eq!(header_before.unlock_attempts, 2);

    let session =
        lifecycle::unlock_vault_with_recovery_key(&recovery_result.formatted_key, tmp.path())
            .expect("recovery should succeed");
    drop(session);

    let bytes_after = std::fs::read(&vault_result.vault_path).expect("read");
    let header_after = parse_header(&bytes_after);
    assert_eq!(
        header_after.unlock_attempts, 0,
        "unlock_attempts must be 0 after successful recovery"
    );
}

// ---------------------------------------------------------------------------
// Task 8.4: post-recovery password change creates new slots + new recovery key
// ---------------------------------------------------------------------------

#[test]
fn post_recovery_password_change_creates_new_slots() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"old-password";
    let (_vault_result, recovery_result, _master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let session =
        lifecycle::unlock_vault_with_recovery_key(&recovery_result.formatted_key, tmp.path())
            .expect("recovery should succeed");

    let master_key_copy: Vec<u8> = session.master_key.expose().to_vec();
    drop(session);

    let calibrated = test_calibrated();
    let change_req = ChangePasswordAfterRecoveryRequest {
        new_password: b"new-strong-password",
        vault_dir: tmp.path(),
        master_key: &master_key_copy,
        calibrated: &calibrated,
        preset: KdfPreset::Balanced,
    };

    let result = lifecycle::change_password_after_recovery(&change_req)
        .expect("password change should succeed");

    assert_eq!(
        result
            .recovery_key
            .formatted_key
            .chars()
            .filter(|c| *c == '-')
            .count(),
        6,
        "new recovery key must have 6 dashes"
    );

    // Verify new password works.
    let new_pw_req = UnlockVaultRequest {
        password: b"new-strong-password",
        vault_dir: tmp.path(),
    };
    let new_session =
        lifecycle::unlock_vault(&new_pw_req).expect("unlock with new password should succeed");
    drop(new_session);

    // Verify old password no longer works.
    let old_pw_req = UnlockVaultRequest {
        password,
        vault_dir: tmp.path(),
    };
    let old_result = lifecycle::unlock_vault(&old_pw_req);
    assert!(
        matches!(old_result, Err(VaultError::InvalidPassword)),
        "old password must not work after change"
    );

    // Verify old recovery key no longer works.
    let old_recovery_result =
        lifecycle::unlock_vault_with_recovery_key(&recovery_result.formatted_key, tmp.path());
    assert!(
        matches!(old_recovery_result, Err(VaultError::InvalidRecoveryKey)),
        "old recovery key must not work after change"
    );

    // Verify new recovery key works.
    let new_recovery_session =
        lifecycle::unlock_vault_with_recovery_key(&result.recovery_key.formatted_key, tmp.path())
            .expect("new recovery key should work");
    drop(new_recovery_session);
}

// ---------------------------------------------------------------------------
// Task 8.4b: recovery on vault without recovery slot returns error
// ---------------------------------------------------------------------------

#[test]
fn recovery_on_vault_without_recovery_slot_returns_error() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    create_test_vault(tmp.path(), b"no-recovery-slot", KdfPreset::Balanced)
        .expect("create_vault should succeed");

    let fake_entropy = [0xDD; 16];
    let fake_key = encode_recovery_key(&fake_entropy);

    let result = lifecycle::unlock_vault_with_recovery_key(&fake_key, tmp.path());
    assert!(
        matches!(result, Err(VaultError::RecoverySlotNotFound)),
        "vault without recovery slot should return RecoverySlotNotFound, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Task 8.5: recovery key on nonexistent vault returns NotFound
// ---------------------------------------------------------------------------

#[test]
fn recovery_key_on_nonexistent_vault_returns_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let fake_key = encode_recovery_key(&[0xEE; 16]);

    let result = lifecycle::unlock_vault_with_recovery_key(&fake_key, tmp.path());
    assert!(
        matches!(result, Err(VaultError::NotFound(_))),
        "recovery on missing vault should return NotFound"
    );
}

// ===========================================================================
// Story 2.11: Master Password Change with Vault Re-wrapping
// ===========================================================================

// ---------------------------------------------------------------------------
// Task 5.1: valid password change — new password unlocks, old password fails
// ---------------------------------------------------------------------------

#[test]
fn change_master_password_new_password_unlocks_old_fails() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let old_password = b"old-password-2-11";
    let new_password = b"new-strong-password-2-11";

    let (_vault_result, _recovery_result, master_key) =
        create_vault_with_recovery(tmp.path(), old_password);

    let calibrated = test_calibrated();
    let change_req = lifecycle::ChangeMasterPasswordRequest {
        old_password,
        new_password,
        vault_dir: tmp.path(),
        master_key: master_key.expose(),
        calibrated: &calibrated,
        preset: KdfPreset::Balanced,
    };

    let result =
        lifecycle::change_master_password(&change_req).expect("password change should succeed");

    // New recovery key must be valid.
    assert_eq!(
        result
            .recovery_key
            .formatted_key
            .chars()
            .filter(|c| *c == '-')
            .count(),
        6,
        "new recovery key must have 6 dashes"
    );

    // New password must unlock.
    let new_unlock = lifecycle::unlock_vault(&UnlockVaultRequest {
        password: new_password,
        vault_dir: tmp.path(),
    });
    assert!(new_unlock.is_ok(), "new password must unlock vault");
    drop(new_unlock);

    // Old password must fail.
    let old_unlock = lifecycle::unlock_vault(&UnlockVaultRequest {
        password: old_password,
        vault_dir: tmp.path(),
    });
    assert!(
        matches!(old_unlock, Err(VaultError::InvalidPassword)),
        "old password must not work after change, got: {old_unlock:?}"
    );
}

// ---------------------------------------------------------------------------
// Task 5.2: invalid current password fails with InvalidPassword
// ---------------------------------------------------------------------------

#[test]
fn change_master_password_wrong_old_password_fails() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"correct-password-2-11";

    let (_vault_result, _recovery_result, master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let calibrated = test_calibrated();
    let change_req = lifecycle::ChangeMasterPasswordRequest {
        old_password: b"wrong-password",
        new_password: b"doesnt-matter",
        vault_dir: tmp.path(),
        master_key: master_key.expose(),
        calibrated: &calibrated,
        preset: KdfPreset::Balanced,
    };

    let result = lifecycle::change_master_password(&change_req);
    assert!(
        matches!(result, Err(VaultError::InvalidPassword)),
        "wrong old password must return InvalidPassword, got: {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Task 5.3: password change creates backup file
// ---------------------------------------------------------------------------

#[test]
fn change_master_password_creates_backup() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"backup-test-2-11";

    let (_vault_result, _recovery_result, master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let calibrated = test_calibrated();
    let change_req = lifecycle::ChangeMasterPasswordRequest {
        old_password: password,
        new_password: b"new-password",
        vault_dir: tmp.path(),
        master_key: master_key.expose(),
        calibrated: &calibrated,
        preset: KdfPreset::Balanced,
    };

    lifecycle::change_master_password(&change_req).expect("password change should succeed");

    // Backup directory must exist.
    let backup_dir = tmp.path().join("backups");
    assert!(backup_dir.exists(), "backups directory must exist");

    // Should contain exactly one .verrou file.
    let backups: Vec<_> = std::fs::read_dir(&backup_dir)
        .expect("read backup dir")
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "verrou"))
        .collect();
    assert_eq!(backups.len(), 1, "must have exactly 1 backup file");

    // Backup must have content (not empty).
    let backup_bytes = std::fs::read(backups[0].path()).expect("read backup");
    assert!(!backup_bytes.is_empty(), "backup must not be empty");
    assert_eq!(&backup_bytes[..4], b"VROU", "backup must have VROU magic");
}

// ---------------------------------------------------------------------------
// Task 5.4: password change creates new password slot + new recovery key
// ---------------------------------------------------------------------------

#[test]
fn change_master_password_creates_new_slots_and_recovery_key() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"slot-test-2-11";

    let (vault_result, old_recovery, master_key) = create_vault_with_recovery(tmp.path(), password);

    let calibrated = test_calibrated();
    let change_req = lifecycle::ChangeMasterPasswordRequest {
        old_password: password,
        new_password: b"new-password-slots",
        vault_dir: tmp.path(),
        master_key: master_key.expose(),
        calibrated: &calibrated,
        preset: KdfPreset::Fast,
    };

    let result =
        lifecycle::change_master_password(&change_req).expect("password change should succeed");

    // New recovery key must differ from old.
    assert_ne!(
        result.recovery_key.formatted_key, old_recovery.formatted_key,
        "new recovery key must differ from old"
    );

    // Read updated header.
    let updated_bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
    let header = parse_header(&updated_bytes);

    // Must have exactly 2 slots (1 password + 1 recovery).
    assert_eq!(header.slot_count, 2, "must have 2 slots");
    assert_eq!(header.slots.len(), 2);
    assert_eq!(header.slots[0].slot_type, SlotType::Password);
    assert_eq!(header.slots[1].slot_type, SlotType::Recovery);

    // New recovery key must work.
    let recovery_session =
        lifecycle::unlock_vault_with_recovery_key(&result.recovery_key.formatted_key, tmp.path());
    assert!(recovery_session.is_ok(), "new recovery key must work");
    drop(recovery_session);
}

// ---------------------------------------------------------------------------
// Task 5.5: old password and recovery slots removed after change
// ---------------------------------------------------------------------------

#[test]
fn change_master_password_old_recovery_key_invalidated() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"invalidation-test-2-11";

    let (_vault_result, old_recovery, master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let calibrated = test_calibrated();
    let change_req = lifecycle::ChangeMasterPasswordRequest {
        old_password: password,
        new_password: b"new-password-invalidation",
        vault_dir: tmp.path(),
        master_key: master_key.expose(),
        calibrated: &calibrated,
        preset: KdfPreset::Balanced,
    };

    lifecycle::change_master_password(&change_req).expect("password change should succeed");

    // Old recovery key must not work.
    let old_recovery_result =
        lifecycle::unlock_vault_with_recovery_key(&old_recovery.formatted_key, tmp.path());
    assert!(
        matches!(old_recovery_result, Err(VaultError::InvalidRecoveryKey)),
        "old recovery key must not work after password change"
    );
}

// ---------------------------------------------------------------------------
// Task 5.6: master key unchanged — same data accessible after change
// ---------------------------------------------------------------------------

#[test]
fn change_master_password_master_key_unchanged() {
    let tmp = tempfile::tempdir().expect("tempdir should succeed");
    let password = b"masterkey-test-2-11";

    let (vault_result, _recovery_result, master_key) =
        create_vault_with_recovery(tmp.path(), password);

    let calibrated = test_calibrated();
    let change_req = lifecycle::ChangeMasterPasswordRequest {
        old_password: password,
        new_password: b"new-password-mk-test",
        vault_dir: tmp.path(),
        master_key: master_key.expose(),
        calibrated: &calibrated,
        preset: KdfPreset::Balanced,
    };

    lifecycle::change_master_password(&change_req).expect("password change should succeed");

    // Unlock with new password and verify master key is the same.
    let session = lifecycle::unlock_vault(&UnlockVaultRequest {
        password: b"new-password-mk-test",
        vault_dir: tmp.path(),
    })
    .expect("unlock with new password should succeed");

    assert_eq!(
        session.master_key.expose(),
        master_key.expose(),
        "master key must be unchanged after password change"
    );

    // Verify DB is still accessible with the same master key.
    let db = VaultDb::open(&vault_result.db_path, &master_key)
        .expect("DB should open with original master key");
    assert_eq!(db.schema_version().expect("schema_version"), 7);
}

// ---------------------------------------------------------------------------
// Proptest: random passwords + random presets produce valid vaults
// ---------------------------------------------------------------------------

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn random_passwords_produce_valid_vaults(
            password in prop::collection::vec(any::<u8>(), 1..128),
            preset_idx in 0..3u8,
        ) {
            let preset = match preset_idx {
                0 => KdfPreset::Fast,
                1 => KdfPreset::Balanced,
                _ => KdfPreset::Maximum,
            };

            let tmp = tempfile::tempdir().expect("tempdir should succeed");
            let result = create_test_vault(tmp.path(), &password, preset)
                .expect("create_vault should succeed for any password");

            prop_assert!(result.vault_path.exists());
            prop_assert!(result.db_path.exists());
            prop_assert_eq!(result.kdf_preset, preset);

            let bytes = std::fs::read(&result.vault_path).expect("read should succeed");
            prop_assert_eq!(&bytes[..4], b"VROU");

            // Verify the full roundtrip: password → master key → open DB.
            let master_key = recover_master_key_from_password(&bytes, &password);
            let db = VaultDb::open(&result.db_path, &master_key)
                .expect("VaultDb::open should succeed");
            prop_assert_eq!(db.schema_version().expect("schema_version"), 7);
        }
    }

    proptest! {
        /// Task 5.13: random recovery keys encode/decode roundtrip
        #[test]
        fn random_recovery_keys_encode_decode_roundtrip(
            entropy in prop::collection::vec(any::<u8>(), 16..=16),
        ) {
            let encoded = encode_recovery_key(&entropy);
            let decoded = decode_recovery_key(&encoded)
                .expect("decode should succeed for any valid encoding");
            prop_assert_eq!(decoded, entropy);
        }
    }

    proptest! {
        /// Task 5.14: random recovery keys create valid slots that unwrap correctly
        #[test]
        fn random_recovery_keys_create_valid_slots(
            password in prop::collection::vec(any::<u8>(), 1..64),
        ) {
            let tmp = tempfile::tempdir().expect("tempdir should succeed");
            let vault_result = create_test_vault(tmp.path(), &password, KdfPreset::Fast)
                .expect("create_vault should succeed");

            let verrou_bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
            let master_key = recover_master_key_from_password(&verrou_bytes, &password);

            let recovery_req = AddRecoverySlotRequest {
                vault_dir: tmp.path(),
                master_key: master_key.expose(),
            };
            let recovery_result = add_recovery_slot(&recovery_req)
                .expect("add_recovery_slot should succeed");

            // Verify the recovery key can decode.
            let decoded = decode_recovery_key(&recovery_result.formatted_key)
                .expect("decode should succeed");

            // Verify the recovery slot can unwrap to the correct master key.
            let updated_bytes = std::fs::read(&vault_result.vault_path).expect("read should succeed");
            let header = parse_header(&updated_bytes);

            let recovery_wrapping_key = verrou_crypto_core::kdf::derive(
                &decoded,
                &header.slot_salts[1],
                &header.sensitive_params,
            )
            .expect("derive should succeed");

            let recovered_mk = slots::unwrap_slot(&header.slots[1], recovery_wrapping_key.expose())
                .expect("unwrap should succeed");

            prop_assert_eq!(recovered_mk.expose(), master_key.expose().as_slice());
        }
    }
}

// ===========================================================================
// Story 2.12: Vault Integrity, Corruption Detection, and Automatic Backup
// ===========================================================================

// ---------------------------------------------------------------------------
// Task 7.1: verify_vault_integrity returns Ok for valid vault
// ---------------------------------------------------------------------------

#[test]
fn verify_integrity_ok_for_valid_vault() {
    let tmp = tempfile::tempdir().expect("tempdir");
    create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let report = lifecycle::verify_vault_integrity(tmp.path());
    assert_eq!(report.status, IntegrityStatus::Ok);
}

// ---------------------------------------------------------------------------
// Task 7.2: verify_vault_integrity detects corrupted magic bytes
// ---------------------------------------------------------------------------

#[test]
fn verify_integrity_detects_corrupted_magic() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    // Corrupt magic bytes.
    let mut data = std::fs::read(&result.vault_path).expect("read");
    data[0] = b'X';
    std::fs::write(&result.vault_path, &data).expect("write");

    let report = lifecycle::verify_vault_integrity(tmp.path());
    assert!(
        matches!(report.status, IntegrityStatus::HeaderCorrupted { .. }),
        "expected HeaderCorrupted, got {:?}",
        report.status
    );
    assert!(report.message.contains("corrupted or tampered"));
}

// ---------------------------------------------------------------------------
// Task 7.3: verify_vault_integrity detects missing .db file
// ---------------------------------------------------------------------------

#[test]
fn verify_integrity_detects_missing_db() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    // Delete the .db file.
    std::fs::remove_file(&result.db_path).expect("remove");

    let report = lifecycle::verify_vault_integrity(tmp.path());
    assert_eq!(report.status, IntegrityStatus::DatabaseMissing);
    assert!(report.message.contains("database file is missing"));
}

// ---------------------------------------------------------------------------
// Task 7.4: verify_vault_integrity detects slot_count mismatch
// ---------------------------------------------------------------------------

#[test]
fn verify_integrity_detects_slot_count_mismatch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    // Read, parse, and corrupt the header by changing slot_count.
    let data = std::fs::read(&result.vault_path).expect("read");
    let mut header = parse_header(&data);
    header.slot_count = 99; // Mismatch: header says 99 slots but only 1 exists

    // Re-serialize with the corrupted header.
    let mk = recover_master_key_from_password(&data, b"password");
    let new_data = vault_format::serialize(&header, &[], mk.expose()).expect("serialize");
    std::fs::write(&result.vault_path, &new_data).expect("write");

    let report = lifecycle::verify_vault_integrity(tmp.path());
    assert!(
        matches!(report.status, IntegrityStatus::HeaderCorrupted { .. }),
        "expected HeaderCorrupted, got {:?}",
        report.status
    );
}

// ---------------------------------------------------------------------------
// Task 7.5: verify_vault_integrity detects unsupported version
// ---------------------------------------------------------------------------

#[test]
fn verify_integrity_detects_unsupported_version() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    // Read, parse, and set version to 255 (future).
    let data = std::fs::read(&result.vault_path).expect("read");
    let mut header = parse_header(&data);
    header.version = 255;

    let mk = recover_master_key_from_password(&data, b"password");
    let new_data = vault_format::serialize(&header, &[], mk.expose()).expect("serialize");
    std::fs::write(&result.vault_path, &new_data).expect("write");

    let report = lifecycle::verify_vault_integrity(tmp.path());
    assert!(
        matches!(
            report.status,
            IntegrityStatus::VersionUnsupported { version: 255 }
        ),
        "expected VersionUnsupported(255), got {:?}",
        report.status
    );
    assert!(report.message.contains("newer version"));
}

// ---------------------------------------------------------------------------
// Task 7.6: list_backups returns empty for fresh vault
// ---------------------------------------------------------------------------

#[test]
fn list_backups_empty_for_fresh_vault() {
    let tmp = tempfile::tempdir().expect("tempdir");
    create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let backups = lifecycle::list_backups(tmp.path()).expect("list_backups");
    assert!(backups.is_empty());
}

// ---------------------------------------------------------------------------
// Task 7.7: create_backup + list_backups returns one entry
// ---------------------------------------------------------------------------

#[test]
fn create_backup_then_list_returns_one() {
    let tmp = tempfile::tempdir().expect("tempdir");
    create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let backup_path = lifecycle::create_backup(tmp.path()).expect("create_backup");
    assert!(backup_path.exists(), "backup file must exist");

    let backups = lifecycle::list_backups(tmp.path()).expect("list_backups");
    assert_eq!(backups.len(), 1);
    assert_eq!(backups[0].path, backup_path);
    assert!(backups[0].size_bytes > 0);
}

// ---------------------------------------------------------------------------
// Task 7.8: restore_backup replaces current vault file
// ---------------------------------------------------------------------------

#[test]
fn restore_backup_replaces_current_vault() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    // Create backup of the original vault.
    let backup_path = lifecycle::create_backup(tmp.path()).expect("backup");

    // Corrupt the current vault.
    std::fs::write(&result.vault_path, b"corrupted").expect("corrupt");

    // Verify it's corrupted.
    let report = lifecycle::verify_vault_integrity(tmp.path());
    assert!(matches!(
        report.status,
        IntegrityStatus::HeaderCorrupted { .. }
    ));

    // Restore from backup.
    lifecycle::restore_backup(tmp.path(), &backup_path).expect("restore");

    // Verify integrity is now OK.
    let report = lifecycle::verify_vault_integrity(tmp.path());
    assert_eq!(report.status, IntegrityStatus::Ok);
}

// ---------------------------------------------------------------------------
// Task 7.9: create_backup backs up both .verrou and .db files
// ---------------------------------------------------------------------------

#[test]
fn create_backup_backs_up_both_files() {
    let tmp = tempfile::tempdir().expect("tempdir");
    create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let backup_path = lifecycle::create_backup(tmp.path()).expect("backup");

    // The .verrou backup should exist.
    assert!(backup_path.exists());

    // The .db backup should also exist (same timestamp, .db extension).
    let db_backup = backup_path.with_extension("db");
    assert!(db_backup.exists(), "db backup must exist at {db_backup:?}");
}

// ---------------------------------------------------------------------------
// Task 7.10: unlock_vault fails with IntegrityFailure on corrupted file
// ---------------------------------------------------------------------------

#[test]
fn unlock_vault_fails_on_corrupted_vault() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    // Corrupt the .verrou file.
    let mut data = std::fs::read(&result.vault_path).expect("read");
    data[0] = b'X'; // corrupt magic
    std::fs::write(&result.vault_path, &data).expect("write");

    let unlock_result = lifecycle::unlock_vault(&UnlockVaultRequest {
        password: b"password",
        vault_dir: tmp.path(),
    });

    assert!(unlock_result.is_err());
    let err = unlock_result.expect_err("should fail on corrupted vault");
    assert!(
        matches!(err, VaultError::IntegrityFailure(_)),
        "expected IntegrityFailure, got {err:?}"
    );
}

// ===========================================================================
// Biometric slot management + biometric unlock (Story 9.1, Tasks 3 & 4)
// ===========================================================================

#[test]
fn has_biometric_slot_returns_false_initially() {
    let tmp = tempfile::tempdir().expect("tempdir");
    create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    assert!(
        !lifecycle::has_biometric_slot(tmp.path()).expect("has_biometric_slot"),
        "no biometric slot initially"
    );
}

#[test]
fn add_biometric_slot_then_has_biometric_slot() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    // Recover master key to add the biometric slot.
    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    // Generate a biometric token and add the slot.
    let token = [0xAA_u8; 32];
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add_biometric_slot");

    assert!(
        lifecycle::has_biometric_slot(tmp.path()).expect("has_biometric_slot"),
        "biometric slot should exist after add"
    );
}

#[test]
fn add_biometric_slot_is_idempotent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    let token = [0xBB_u8; 32];
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add 1");
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add 2 (idempotent)");

    // Should still have exactly one biometric slot.
    let updated_bytes = std::fs::read(&result.vault_path).expect("read");
    let header = parse_header(&updated_bytes);
    let bio_count = header
        .slots
        .iter()
        .filter(|s| s.slot_type == SlotType::Biometric)
        .count();
    assert_eq!(bio_count, 1, "should have exactly one biometric slot");
}

#[test]
fn remove_biometric_slot_succeeds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    let token = [0xCC_u8; 32];
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add");
    assert!(lifecycle::has_biometric_slot(tmp.path()).expect("has"));

    lifecycle::remove_biometric_slot(tmp.path(), mk.expose()).expect("remove");
    assert!(
        !lifecycle::has_biometric_slot(tmp.path()).expect("has"),
        "biometric slot should be removed"
    );
}

#[test]
fn remove_biometric_slot_when_none_returns_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    let err = lifecycle::remove_biometric_slot(tmp.path(), mk.expose())
        .expect_err("should fail with no biometric slot");
    assert!(
        matches!(err, VaultError::BiometricSlotNotFound),
        "expected BiometricSlotNotFound, got {err:?}"
    );
}

#[test]
fn biometric_unlock_roundtrip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    // Add biometric slot with a known token.
    let token = [0xDD_u8; 32];
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add");

    // Unlock with the same biometric token.
    let session =
        lifecycle::unlock_vault_with_biometric(&token, tmp.path()).expect("biometric unlock");

    // The master key from biometric unlock should match the original.
    assert_eq!(
        session.master_key.expose(),
        mk.expose(),
        "biometric unlock must recover the same master key"
    );
}

#[test]
fn biometric_unlock_with_wrong_token_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    let token = [0xEE_u8; 32];
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add");

    // Try to unlock with a different token.
    let wrong_token = [0xFF_u8; 32];
    let err = lifecycle::unlock_vault_with_biometric(&wrong_token, tmp.path())
        .expect_err("should fail with wrong token");
    assert!(
        matches!(err, VaultError::BiometricUnlockFailed),
        "expected BiometricUnlockFailed, got {err:?}"
    );
}

#[test]
fn biometric_unlock_increments_shared_attempt_counter() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    let token = [0xAB_u8; 32];
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add");

    // Fail biometric unlock.
    let wrong = [0xCD_u8; 32];
    let _ = lifecycle::unlock_vault_with_biometric(&wrong, tmp.path());

    // Check that unlock_attempts was incremented in the header.
    let updated_bytes = std::fs::read(&result.vault_path).expect("read");
    let header = parse_header(&updated_bytes);
    assert!(
        header.unlock_attempts >= 1,
        "shared attempt counter should be incremented after biometric failure"
    );
}

#[test]
fn biometric_unlock_without_slot_returns_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let token = [0x42_u8; 32];
    let err = lifecycle::unlock_vault_with_biometric(&token, tmp.path())
        .expect_err("should fail without biometric slot");
    assert!(
        matches!(err, VaultError::BiometricSlotNotFound),
        "expected BiometricSlotNotFound, got {err:?}"
    );
}

#[test]
fn biometric_unlock_resets_attempts_on_success() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    let token = [0x11_u8; 32];
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add");

    // Fail twice with wrong token to bump attempts.
    let wrong = [0x22_u8; 32];
    let _ = lifecycle::unlock_vault_with_biometric(&wrong, tmp.path());
    let _ = lifecycle::unlock_vault_with_biometric(&wrong, tmp.path());

    // Now succeed with correct token.
    let _session = lifecycle::unlock_vault_with_biometric(&token, tmp.path()).expect("unlock");

    // Attempts should be reset.
    let updated_bytes = std::fs::read(&result.vault_path).expect("read");
    let header = parse_header(&updated_bytes);
    assert_eq!(
        header.unlock_attempts, 0,
        "attempts should reset to 0 after successful biometric unlock"
    );
}

#[test]
fn password_unlock_still_works_after_biometric_slot_added() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let result = create_test_vault(tmp.path(), b"password", KdfPreset::Fast).expect("create");

    let verrou_bytes = std::fs::read(&result.vault_path).expect("read");
    let mk = recover_master_key_from_password(&verrou_bytes, b"password");

    let token = [0x33_u8; 32];
    lifecycle::add_biometric_slot(tmp.path(), mk.expose(), &token).expect("add");

    // Password unlock should still work.
    let session = lifecycle::unlock_vault(&UnlockVaultRequest {
        password: b"password",
        vault_dir: tmp.path(),
    })
    .expect("password unlock after biometric slot added");

    assert_eq!(
        session.master_key.expose(),
        mk.expose(),
        "password unlock must still recover the same master key"
    );
}
