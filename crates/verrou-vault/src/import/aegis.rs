//! Aegis Authenticator JSON vault export parser.
//!
//! Parses both plaintext and encrypted Aegis vault exports (`.json`).
//! The Aegis vault format stores entries in a `db.entries` array with
//! secrets already Base32-encoded (unlike Google Auth raw bytes).
//!
//! Encryption: scrypt KDF → AES-256-GCM (two-layer: slot key → master key → db).

use serde::Deserialize;
use zeroize::Zeroize;

use super::{ImportError, ImportedEntry, MalformedInfo, UnsupportedInfo};
use crate::entries::{Algorithm, EntryType};

// ---------------------------------------------------------------------------
// Aegis JSON deserialization structs
// ---------------------------------------------------------------------------

/// Top-level Aegis vault structure.
#[derive(Debug, Deserialize)]
pub struct AegisVault {
    /// Vault format version (expected: 1).
    pub version: u32,
    /// Encryption header (present for both encrypted and plaintext exports,
    /// but `slots` and `params` are null/empty for plaintext).
    #[serde(default)]
    pub header: Option<AegisHeader>,
    /// Database content — either a JSON object (plaintext) or a Base64 string (encrypted).
    pub db: serde_json::Value,
}

/// Encryption header containing key slots and crypto parameters.
#[derive(Debug, Deserialize)]
pub struct AegisHeader {
    /// Key slots (each slot wraps the master key).
    #[serde(default)]
    pub slots: Vec<AegisSlot>,
    /// Crypto parameters for decrypting the `db` payload.
    #[serde(default)]
    pub params: Option<AegisCryptoParams>,
}

/// A key slot — wraps the master key under a derived key.
#[derive(Debug, Deserialize)]
pub struct AegisSlot {
    /// Slot type (1 = password, 2 = biometric).
    #[serde(rename = "type")]
    pub slot_type: u32,
    /// The wrapped master key (hex-encoded).
    pub key: String,
    /// Crypto parameters for unwrapping the master key from this slot.
    pub key_params: AegisCryptoParams,
    // scrypt parameters (only for password slots, type=1)
    /// scrypt N parameter (CPU/memory cost).
    #[serde(default)]
    pub n: Option<u32>,
    /// scrypt r parameter (block size).
    #[serde(default)]
    pub r: Option<u32>,
    /// scrypt p parameter (parallelization).
    #[serde(default)]
    pub p: Option<u32>,
    /// Salt for scrypt (hex-encoded).
    #[serde(default)]
    pub salt: Option<String>,
}

/// AES-256-GCM parameters: nonce and authentication tag (hex-encoded).
#[derive(Debug, Deserialize)]
pub struct AegisCryptoParams {
    /// 96-bit nonce (hex-encoded, 24 hex chars).
    pub nonce: String,
    /// 128-bit authentication tag (hex-encoded, 32 hex chars).
    pub tag: String,
}

/// Plaintext database content.
#[derive(Debug, Deserialize)]
pub struct AegisDb {
    /// Database content version (expected: 1-3).
    pub version: u32,
    /// Array of OTP entries.
    #[serde(default)]
    pub entries: Vec<AegisEntry>,
}

/// A single Aegis vault entry.
#[derive(Debug, Deserialize)]
pub struct AegisEntry {
    /// Entry type: "totp", "hotp", "steam", "motp", "yandex".
    #[serde(rename = "type")]
    pub entry_type: String,
    /// Account name.
    #[serde(default)]
    pub name: String,
    /// Service issuer.
    #[serde(default)]
    pub issuer: String,
    /// OTP-specific parameters.
    pub info: AegisInfo,
}

/// OTP parameters within an Aegis entry.
#[derive(Debug, Deserialize)]
pub struct AegisInfo {
    /// Base32-encoded secret key.
    #[serde(default)]
    pub secret: String,
    /// Algorithm: "SHA1", "SHA256", "SHA512", "MD5".
    #[serde(default = "default_algo")]
    pub algo: String,
    /// Number of OTP digits.
    #[serde(default = "default_digits")]
    pub digits: u32,
    /// TOTP period in seconds.
    #[serde(default = "default_period")]
    pub period: u32,
    /// HOTP counter.
    #[serde(default)]
    pub counter: u64,
}

fn default_algo() -> String {
    "SHA1".to_string()
}

const fn default_digits() -> u32 {
    6
}

const fn default_period() -> u32 {
    30
}

// ---------------------------------------------------------------------------
// Parsing result types
// ---------------------------------------------------------------------------

/// Result of parsing a single Aegis entry.
pub enum ParsedEntry {
    /// Successfully parsed and validated.
    Valid(ImportedEntry),
    /// Entry uses an unsupported type or algorithm.
    Unsupported(UnsupportedInfo),
    /// Entry data is malformed.
    Malformed(MalformedInfo),
}

/// Result of parsing an Aegis vault export.
#[derive(Debug)]
pub struct ParseResult {
    /// Successfully parsed entries.
    pub entries: Vec<ImportedEntry>,
    /// Entries with unsupported types or algorithms.
    pub unsupported: Vec<UnsupportedInfo>,
    /// Entries with malformed data.
    pub malformed: Vec<MalformedInfo>,
    /// Aegis vault format version.
    pub vault_version: u32,
    /// Aegis database content version.
    pub db_version: u32,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect whether an Aegis vault export is encrypted.
///
/// Encrypted exports have `db` as a Base64 string; plaintext exports
/// have `db` as a JSON object.
///
/// # Errors
///
/// Returns `ImportError::InvalidFormat` if the JSON is unparseable.
pub fn is_encrypted(data: &str) -> Result<bool, ImportError> {
    let vault: AegisVault = serde_json::from_str(data)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid Aegis JSON: {e}")))?;
    Ok(vault.db.is_string())
}

/// Parse a plaintext Aegis JSON vault export.
///
/// # Errors
///
/// Returns `ImportError::InvalidFormat` if the JSON structure is invalid.
/// Returns `ImportError::Unsupported` if the vault or db version is unsupported.
pub fn parse_aegis_json(data: &str) -> Result<ParseResult, ImportError> {
    let vault: AegisVault = serde_json::from_str(data)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid Aegis JSON: {e}")))?;

    // Validate vault format version (FR45)
    if vault.version != 1 {
        return Err(ImportError::Unsupported(format!(
            "Aegis vault version {} is not supported (expected version 1)",
            vault.version
        )));
    }

    // The `db` field must be a JSON object for plaintext exports
    if vault.db.is_string() {
        return Err(ImportError::InvalidFormat(
            "Aegis export is encrypted. Use parse_aegis_encrypted() with a password.".to_string(),
        ));
    }

    let db: AegisDb = serde_json::from_value(vault.db)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid Aegis db structure: {e}")))?;

    parse_aegis_db(&db, vault.version)
}

/// Parse an encrypted Aegis JSON vault export.
///
/// Decrypts using the Aegis encryption scheme:
/// 1. scrypt KDF to derive slot key from password
/// 2. AES-256-GCM to unwrap master key from slot
/// 3. AES-256-GCM to decrypt db payload with master key
///
/// # Errors
///
/// Returns `ImportError::InvalidFormat` if the JSON structure or crypto params are invalid.
/// Returns `ImportError::Corrupted` if decryption fails (wrong password or tampered data).
pub fn parse_aegis_encrypted(data: &str, password: &[u8]) -> Result<ParseResult, ImportError> {
    let vault: AegisVault = serde_json::from_str(data)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid Aegis JSON: {e}")))?;

    // Validate vault format version (FR45)
    if vault.version != 1 {
        return Err(ImportError::Unsupported(format!(
            "Aegis vault version {} is not supported (expected version 1)",
            vault.version
        )));
    }

    // The `db` field must be a string (Base64-encoded ciphertext) for encrypted exports
    let db_b64 = vault.db.as_str().ok_or_else(|| {
        ImportError::InvalidFormat(
            "expected encrypted db (Base64 string), but got a JSON object".to_string(),
        )
    })?;

    // Decode Base64 db ciphertext
    let db_ciphertext = data_encoding::BASE64
        .decode(db_b64.as_bytes())
        .map_err(|e| ImportError::Encoding(format!("invalid Base64 in encrypted db: {e}")))?;

    // Extract header
    let header = vault
        .header
        .ok_or_else(|| ImportError::InvalidFormat("encrypted export missing header".to_string()))?;

    let header_params = header.params.ok_or_else(|| {
        ImportError::InvalidFormat("encrypted export missing header params".to_string())
    })?;

    // Find password slot (type=1)
    let slot = header
        .slots
        .iter()
        .find(|s| s.slot_type == 1)
        .ok_or_else(|| {
            ImportError::InvalidFormat(
                "no password slot (type=1) found in encrypted export".to_string(),
            )
        })?;

    // Extract scrypt params
    let n = slot.n.ok_or_else(|| {
        ImportError::InvalidFormat("password slot missing scrypt N parameter".to_string())
    })?;
    let r = slot.r.ok_or_else(|| {
        ImportError::InvalidFormat("password slot missing scrypt r parameter".to_string())
    })?;
    let p = slot.p.ok_or_else(|| {
        ImportError::InvalidFormat("password slot missing scrypt p parameter".to_string())
    })?;
    let salt_hex = slot
        .salt
        .as_deref()
        .ok_or_else(|| ImportError::InvalidFormat("password slot missing salt".to_string()))?;

    // Decode hex values
    let salt = decode_hex(salt_hex)?;
    let slot_key_nonce = decode_hex(&slot.key_params.nonce)?;
    let slot_key_tag = decode_hex(&slot.key_params.tag)?;
    let wrapped_master_key = decode_hex(&slot.key)?;
    let db_nonce = decode_hex(&header_params.nonce)?;
    let db_tag = decode_hex(&header_params.tag)?;

    // Step 1: Derive slot key from password via scrypt
    let mut slot_key = derive_scrypt(password, &salt, n, r, p)?;

    // Step 2: Decrypt master key from slot
    let mut master_key = aes_gcm_decrypt(
        &wrapped_master_key,
        &slot_key,
        &slot_key_nonce,
        &slot_key_tag,
    )
    .map_err(|_| {
        ImportError::Corrupted(
            "failed to decrypt master key — wrong password or corrupted slot".to_string(),
        )
    })?;
    slot_key.zeroize();

    // Step 3: Decrypt db payload with master key
    let mut db_json_bytes = aes_gcm_decrypt(&db_ciphertext, &master_key, &db_nonce, &db_tag)
        .map_err(|_| {
            ImportError::Corrupted("failed to decrypt vault database — corrupted data".to_string())
        })?;
    master_key.zeroize();

    // Step 4: Parse decrypted JSON
    let db_json = std::str::from_utf8(&db_json_bytes)
        .map_err(|e| ImportError::Corrupted(format!("decrypted data is not valid UTF-8: {e}")))?;

    let db: AegisDb = serde_json::from_str(db_json)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid Aegis db structure: {e}")))?;

    let result = parse_aegis_db(&db, vault.version);
    db_json_bytes.zeroize();
    result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse the plaintext `AegisDb` into a `ParseResult`.
fn parse_aegis_db(db: &AegisDb, vault_version: u32) -> Result<ParseResult, ImportError> {
    // Validate db content version (FR45)
    if db.version == 0 || db.version > 3 {
        return Err(ImportError::Unsupported(format!(
            "Aegis db version {} is not supported (expected 1-3)",
            db.version
        )));
    }

    let mut entries = Vec::new();
    let mut unsupported = Vec::new();
    let mut malformed = Vec::new();

    for (idx, entry) in db.entries.iter().enumerate() {
        match parse_single_entry(entry, idx) {
            ParsedEntry::Valid(imported) => entries.push(imported),
            ParsedEntry::Unsupported(info) => unsupported.push(info),
            ParsedEntry::Malformed(info) => malformed.push(info),
        }
    }

    Ok(ParseResult {
        entries,
        unsupported,
        malformed,
        vault_version,
        db_version: db.version,
    })
}

/// Parse a single Aegis entry into a categorized result.
fn parse_single_entry(entry: &AegisEntry, index: usize) -> ParsedEntry {
    // Map entry type
    let entry_type = match entry.entry_type.as_str() {
        "totp" => EntryType::Totp,
        "hotp" => EntryType::Hotp,
        "steam" | "motp" | "yandex" => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(entry),
                issuer: extract_issuer(entry),
                reason: format!("unsupported entry type: {}", entry.entry_type),
            });
        }
        other => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(entry),
                issuer: extract_issuer(entry),
                reason: format!("unknown entry type: {other}"),
            });
        }
    };

    // Map algorithm
    let algorithm = match entry.info.algo.as_str() {
        "SHA1" => Algorithm::SHA1,
        "SHA256" => Algorithm::SHA256,
        "SHA512" => Algorithm::SHA512,
        "MD5" => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(entry),
                issuer: extract_issuer(entry),
                reason: "MD5 algorithm not supported".to_string(),
            });
        }
        other => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(entry),
                issuer: extract_issuer(entry),
                reason: format!("unknown algorithm: {other}"),
            });
        }
    };

    // Validate secret (already Base32 in Aegis — just validate, don't re-encode)
    if let Err(reason) = super::validate_secret(&entry.info.secret) {
        return ParsedEntry::Malformed(MalformedInfo { index, reason });
    }

    // Validate OTP params (digits + period)
    if let Err(reason) = super::validate_otp_params(entry.info.digits, entry.info.period) {
        return ParsedEntry::Malformed(MalformedInfo { index, reason });
    }

    let name = extract_name(entry);
    let issuer = extract_issuer(entry);

    ParsedEntry::Valid(ImportedEntry {
        entry_type,
        name,
        issuer,
        secret: entry.info.secret.clone(),
        algorithm,
        digits: entry.info.digits,
        period: entry.info.period,
        counter: entry.info.counter,
    })
}

/// Extract a display name from an Aegis entry.
fn extract_name(entry: &AegisEntry) -> String {
    if entry.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        entry.name.clone()
    }
}

/// Extract an issuer from an Aegis entry.
fn extract_issuer(entry: &AegisEntry) -> Option<String> {
    if entry.issuer.is_empty() {
        None
    } else {
        Some(entry.issuer.clone())
    }
}

/// Decode a hex-encoded string to bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>, ImportError> {
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.as_bytes())
        .map_err(|e| ImportError::Encoding(format!("invalid hex encoding: {e}")))
}

/// Derive a 32-byte key using scrypt.
fn derive_scrypt(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
) -> Result<Vec<u8>, ImportError> {
    let params = scrypt::Params::new(log2(n)?, r, p, 32)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid scrypt params: {e}")))?;

    let mut key = vec![0u8; 32];
    scrypt::scrypt(password, salt, &params, &mut key)
        .map_err(|e| ImportError::Corrupted(format!("scrypt key derivation failed: {e}")))?;

    Ok(key)
}

/// Compute floor(log2(n)) for scrypt's `log_n` parameter.
///
/// Aegis stores N directly (e.g., 32768) but the `scrypt` crate expects
/// log2(N) (e.g., 15).
fn log2(n: u32) -> Result<u8, ImportError> {
    if n == 0 || (n & n.wrapping_sub(1)) != 0 {
        return Err(ImportError::InvalidFormat(format!(
            "scrypt N must be a power of 2, got {n}"
        )));
    }
    // Safe: n is validated as a power of 2 and u32, so trailing_zeros <= 31 fits u8.
    #[allow(clippy::cast_possible_truncation)]
    Ok(n.trailing_zeros() as u8)
}

/// AES-256-GCM decryption using ring (via verrou-crypto-core).
fn aes_gcm_decrypt(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, ImportError> {
    use verrou_crypto_core::symmetric::{SealedData, NONCE_LEN, TAG_LEN};

    if nonce.len() != NONCE_LEN {
        return Err(ImportError::InvalidFormat(format!(
            "invalid nonce length: {} (expected {NONCE_LEN})",
            nonce.len()
        )));
    }
    if tag.len() != TAG_LEN {
        return Err(ImportError::InvalidFormat(format!(
            "invalid tag length: {} (expected {TAG_LEN})",
            tag.len()
        )));
    }

    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);

    let sealed = SealedData {
        nonce: nonce_arr,
        ciphertext: ciphertext.to_vec(),
        tag: tag_arr,
    };

    // Aegis uses empty AAD for both slot and db decryption
    let secret_buf = verrou_crypto_core::decrypt(&sealed, key, &[])
        .map_err(|e| ImportError::Corrupted(format!("AES-256-GCM decryption failed: {e}")))?;

    Ok(secret_buf.expose().to_vec())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Build a single TOTP entry JSON value.
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

    // A valid Base32 secret for tests (encodes to "Hello!")
    const TEST_SECRET: &str = "JBSWY3DPEE======";

    #[test]
    fn parse_single_totp_entry() {
        let json = make_vault_json(&[make_totp_entry("user@example.com", "GitHub", TEST_SECRET)]);
        let result = parse_aegis_json(&json).expect("should parse");

        assert_eq!(result.entries.len(), 1);
        assert!(result.unsupported.is_empty());
        assert!(result.malformed.is_empty());
        assert_eq!(result.vault_version, 1);
        assert_eq!(result.db_version, 3);

        let entry = &result.entries[0];
        assert_eq!(entry.entry_type, EntryType::Totp);
        assert_eq!(entry.name, "user@example.com");
        assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
        assert_eq!(entry.secret, TEST_SECRET);
        assert_eq!(entry.algorithm, Algorithm::SHA1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
    }

    #[test]
    fn parse_hotp_entry() {
        let entry_json = serde_json::json!({
            "type": "hotp",
            "name": "hotp-account",
            "issuer": "Service",
            "info": {
                "secret": TEST_SECRET,
                "algo": "SHA256",
                "digits": 8,
                "period": 30,
                "counter": 42
            }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");

        assert_eq!(result.entries.len(), 1);
        let entry = &result.entries[0];
        assert_eq!(entry.entry_type, EntryType::Hotp);
        assert_eq!(entry.algorithm, Algorithm::SHA256);
        assert_eq!(entry.digits, 8);
        assert_eq!(entry.counter, 42);
    }

    #[test]
    fn parse_all_algorithms() {
        for (algo_str, expected) in [
            ("SHA1", Algorithm::SHA1),
            ("SHA256", Algorithm::SHA256),
            ("SHA512", Algorithm::SHA512),
        ] {
            let entry_json = serde_json::json!({
                "type": "totp",
                "name": "test",
                "issuer": "",
                "info": {
                    "secret": TEST_SECRET,
                    "algo": algo_str,
                    "digits": 6,
                    "period": 30
                }
            });
            let json = make_vault_json(&[entry_json]);
            let result = parse_aegis_json(&json).expect("should parse");
            assert_eq!(result.entries[0].algorithm, expected, "algo={algo_str}");
        }
    }

    #[test]
    fn unsupported_types_flagged() {
        for unsupported_type in ["steam", "motp", "yandex"] {
            let entry_json = serde_json::json!({
                "type": unsupported_type,
                "name": "test-account",
                "issuer": "TestService",
                "info": {
                    "secret": TEST_SECRET,
                    "algo": "SHA1",
                    "digits": 6,
                    "period": 30
                }
            });
            let json = make_vault_json(&[entry_json]);
            let result = parse_aegis_json(&json).expect("should parse");

            assert!(result.entries.is_empty(), "type={unsupported_type}");
            assert_eq!(result.unsupported.len(), 1, "type={unsupported_type}");
            assert!(
                result.unsupported[0].reason.contains(unsupported_type),
                "reason should mention type: {}",
                result.unsupported[0].reason
            );
        }
    }

    #[test]
    fn md5_algorithm_unsupported() {
        let entry_json = serde_json::json!({
            "type": "totp",
            "name": "md5-account",
            "issuer": "",
            "info": {
                "secret": TEST_SECRET,
                "algo": "MD5",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");

        assert!(result.entries.is_empty());
        assert_eq!(result.unsupported.len(), 1);
        assert!(result.unsupported[0].reason.contains("MD5"));
    }

    #[test]
    fn empty_secret_malformed() {
        let entry_json = serde_json::json!({
            "type": "totp",
            "name": "bad-account",
            "issuer": "",
            "info": {
                "secret": "",
                "algo": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");

        assert!(result.entries.is_empty());
        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("empty"));
    }

    #[test]
    fn invalid_base32_secret_malformed() {
        let entry_json = serde_json::json!({
            "type": "totp",
            "name": "bad-b32",
            "issuer": "",
            "info": {
                "secret": "not-valid-base32!!!",
                "algo": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");

        assert!(result.entries.is_empty());
        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("Base32"));
    }

    #[test]
    fn mixed_entries_categorized() {
        let entries = vec![
            // Valid TOTP
            make_totp_entry("good1", "Service1", TEST_SECRET),
            // Unsupported type (Steam)
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
        ];
        let json = make_vault_json(&entries);
        let result = parse_aegis_json(&json).expect("should parse");

        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.unsupported.len(), 1);
        assert_eq!(result.malformed.len(), 1);

        assert_eq!(result.unsupported[0].index, 1);
        assert_eq!(result.malformed[0].index, 3);
    }

    #[test]
    fn vault_version_validation() {
        let json = serde_json::json!({
            "version": 2,
            "header": null,
            "db": { "version": 3, "entries": [], "groups": [] }
        })
        .to_string();
        let err = parse_aegis_json(&json).unwrap_err();
        match err {
            ImportError::Unsupported(msg) => {
                assert!(msg.contains("version 2"), "msg: {msg}");
            }
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    #[test]
    fn db_version_validation() {
        // Version 0 (invalid)
        let json = serde_json::json!({
            "version": 1,
            "header": null,
            "db": { "version": 0, "entries": [], "groups": [] }
        })
        .to_string();
        assert!(matches!(
            parse_aegis_json(&json),
            Err(ImportError::Unsupported(_))
        ));

        // Version 4 (too high)
        let json = serde_json::json!({
            "version": 1,
            "header": null,
            "db": { "version": 4, "entries": [], "groups": [] }
        })
        .to_string();
        assert!(matches!(
            parse_aegis_json(&json),
            Err(ImportError::Unsupported(_))
        ));

        // Versions 1-3 (valid)
        for v in 1..=3 {
            let json = serde_json::json!({
                "version": 1,
                "header": null,
                "db": { "version": v, "entries": [], "groups": [] }
            })
            .to_string();
            assert!(
                parse_aegis_json(&json).is_ok(),
                "db version {v} should be valid"
            );
        }
    }

    #[test]
    fn invalid_json_error() {
        let err = parse_aegis_json("not json at all").unwrap_err();
        assert!(matches!(err, ImportError::InvalidFormat(_)));
    }

    #[test]
    fn encrypted_export_rejected_by_plaintext_parser() {
        let json = serde_json::json!({
            "version": 1,
            "header": {
                "slots": [],
                "params": { "nonce": "aabb", "tag": "ccdd" }
            },
            "db": "base64encodedciphertext"
        })
        .to_string();
        let err = parse_aegis_json(&json).unwrap_err();
        assert!(matches!(err, ImportError::InvalidFormat(_)));
    }

    #[test]
    fn is_encrypted_detection() {
        // Plaintext
        let plaintext = make_vault_json(&[]);
        assert!(!is_encrypted(&plaintext).unwrap());

        // Encrypted
        let encrypted = serde_json::json!({
            "version": 1,
            "header": null,
            "db": "base64string"
        })
        .to_string();
        assert!(is_encrypted(&encrypted).unwrap());
    }

    #[test]
    fn empty_name_defaults_to_unnamed() {
        let entry_json = serde_json::json!({
            "type": "totp",
            "name": "",
            "issuer": "Service",
            "info": { "secret": TEST_SECRET, "algo": "SHA1", "digits": 6, "period": 30 }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");
        assert_eq!(result.entries[0].name, "(unnamed)");
    }

    #[test]
    fn empty_issuer_becomes_none() {
        let entry_json = serde_json::json!({
            "type": "totp",
            "name": "test",
            "issuer": "",
            "info": { "secret": TEST_SECRET, "algo": "SHA1", "digits": 6, "period": 30 }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");
        assert!(result.entries[0].issuer.is_none());
    }

    #[test]
    fn missing_name_issuer_fields_use_defaults() {
        // Aegis entries without name/issuer fields should use serde defaults
        let entry_json = serde_json::json!({
            "type": "totp",
            "info": { "secret": TEST_SECRET, "algo": "SHA1", "digits": 6, "period": 30 }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");
        assert_eq!(result.entries[0].name, "(unnamed)");
        assert!(result.entries[0].issuer.is_none());
    }

    #[test]
    fn log2_valid_powers() {
        assert_eq!(log2(1).unwrap(), 0);
        assert_eq!(log2(2).unwrap(), 1);
        assert_eq!(log2(1024).unwrap(), 10);
        assert_eq!(log2(32768).unwrap(), 15);
    }

    #[test]
    fn log2_rejects_non_powers() {
        assert!(log2(0).is_err());
        assert!(log2(3).is_err());
        assert!(log2(5).is_err());
        assert!(log2(100).is_err());
    }

    #[test]
    fn empty_vault_parses_successfully() {
        let json = make_vault_json(&[]);
        let result = parse_aegis_json(&json).expect("should parse");
        assert!(result.entries.is_empty());
        assert!(result.unsupported.is_empty());
        assert!(result.malformed.is_empty());
    }

    #[test]
    fn unsupported_digits_malformed() {
        let entry_json = serde_json::json!({
            "type": "totp",
            "name": "test",
            "issuer": "",
            "info": { "secret": TEST_SECRET, "algo": "SHA1", "digits": 7, "period": 30 }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");
        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("digit"));
    }

    #[test]
    fn unsupported_period_malformed() {
        let entry_json = serde_json::json!({
            "type": "totp",
            "name": "test",
            "issuer": "",
            "info": { "secret": TEST_SECRET, "algo": "SHA1", "digits": 6, "period": 45 }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");
        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("period"));
    }

    #[test]
    fn encrypted_roundtrip() {
        // Create a known plaintext db, encrypt it, then decrypt and parse.
        use verrou_crypto_core::symmetric::encrypt as aes_encrypt;

        let db_json = serde_json::json!({
            "version": 2,
            "entries": [{
                "type": "totp",
                "name": "encrypted-test",
                "issuer": "SecureService",
                "info": {
                    "secret": TEST_SECRET,
                    "algo": "SHA256",
                    "digits": 6,
                    "period": 30
                }
            }],
            "groups": []
        });
        let db_plaintext = serde_json::to_string(&db_json).unwrap();

        // Generate a random master key
        let master_key = [0x42u8; 32];

        // Encrypt the db payload
        let db_sealed = aes_encrypt(db_plaintext.as_bytes(), &master_key, &[]).expect("encrypt db");

        // Encrypt the master key with a slot key (derived from password)
        let password = b"test-password";
        let salt = [0xAA; 32];

        // Derive slot key with scrypt (N=1024 for test speed)
        let scrypt_params = scrypt::Params::new(10, 8, 1, 32).unwrap(); // log2(1024)=10
        let mut slot_key = vec![0u8; 32];
        scrypt::scrypt(password, &salt, &scrypt_params, &mut slot_key).unwrap();

        let master_key_sealed =
            aes_encrypt(&master_key, &slot_key, &[]).expect("encrypt master key");

        // Build the encrypted vault JSON
        let vault_json = serde_json::json!({
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
        });

        let vault_str = serde_json::to_string(&vault_json).unwrap();

        // Verify it's detected as encrypted
        assert!(is_encrypted(&vault_str).unwrap());

        // Parse it
        let result = parse_aegis_encrypted(&vault_str, password).expect("should decrypt and parse");

        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].name, "encrypted-test");
        assert_eq!(result.entries[0].issuer.as_deref(), Some("SecureService"));
        assert_eq!(result.entries[0].algorithm, Algorithm::SHA256);
        assert_eq!(result.vault_version, 1);
        assert_eq!(result.db_version, 2);
    }

    #[test]
    fn encrypted_wrong_password_fails() {
        use verrou_crypto_core::symmetric::encrypt as aes_encrypt;

        let db_json = r#"{"version":1,"entries":[],"groups":[]}"#;
        let master_key = [0x42u8; 32];
        let db_sealed = aes_encrypt(db_json.as_bytes(), &master_key, &[]).unwrap();

        let password = b"correct-password";
        let salt = [0xBB; 32];
        let scrypt_params = scrypt::Params::new(10, 8, 1, 32).unwrap();
        let mut slot_key = vec![0u8; 32];
        scrypt::scrypt(password, &salt, &scrypt_params, &mut slot_key).unwrap();

        let master_key_sealed = aes_encrypt(&master_key, &slot_key, &[]).unwrap();

        let vault_json = serde_json::json!({
            "version": 1,
            "header": {
                "slots": [{
                    "type": 1,
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
        });

        let vault_str = serde_json::to_string(&vault_json).unwrap();
        let err = parse_aegis_encrypted(&vault_str, b"wrong-password").unwrap_err();
        assert!(matches!(err, ImportError::Corrupted(_)));
    }

    #[test]
    fn unknown_entry_type_flagged_unsupported() {
        let entry_json = serde_json::json!({
            "type": "foobar",
            "name": "unknown-type",
            "issuer": "",
            "info": { "secret": TEST_SECRET, "algo": "SHA1", "digits": 6, "period": 30 }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");
        assert_eq!(result.unsupported.len(), 1);
        assert!(result.unsupported[0].reason.contains("foobar"));
    }

    #[test]
    fn unknown_algorithm_flagged_unsupported() {
        let entry_json = serde_json::json!({
            "type": "totp",
            "name": "unknown-algo",
            "issuer": "",
            "info": { "secret": TEST_SECRET, "algo": "BLAKE3", "digits": 6, "period": 30 }
        });
        let json = make_vault_json(&[entry_json]);
        let result = parse_aegis_json(&json).expect("should parse");
        assert_eq!(result.unsupported.len(), 1);
        assert!(result.unsupported[0].reason.contains("BLAKE3"));
    }
}
