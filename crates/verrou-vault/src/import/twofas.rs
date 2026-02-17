//! 2FAS Authenticator JSON backup export parser.
//!
//! Parses both plaintext and encrypted 2FAS backup exports (`.json`).
//! The 2FAS format stores entries in a `services` array with secrets
//! as Base32-encoded strings in the top-level `secret` field.
//!
//! Encryption: PBKDF2-HMAC-SHA256 (10,000 iterations) → AES-256-GCM.

use serde::Deserialize;
use zeroize::Zeroize;

use super::{ImportError, ImportedEntry, MalformedInfo, UnsupportedInfo};
use crate::entries::{Algorithm, EntryType};

// ---------------------------------------------------------------------------
// 2FAS JSON deserialization structs
// ---------------------------------------------------------------------------

/// Top-level 2FAS backup structure.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwofasBackup {
    /// Array of service entries (plaintext export).
    #[serde(default)]
    pub services: Vec<TwofasService>,
    /// Encrypted services payload (colon-separated format).
    #[serde(default)]
    pub services_encrypted: Option<String>,
    /// Password verification reference (encrypted with same KDF).
    #[serde(default)]
    pub reference: Option<String>,
    /// Schema version (1-4 supported).
    #[serde(default)]
    pub schema_version: Option<u32>,
    // Note: `groups`, `updatedAt`, `appVersionCode` etc. are intentionally
    // omitted — serde silently ignores unknown fields by default.
}

/// A single 2FAS service entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwofasService {
    /// Service display name (e.g., "GitLab").
    #[serde(default)]
    pub name: String,
    /// Base32-encoded secret key.
    #[serde(default)]
    pub secret: String,
    /// OTP parameters.
    #[serde(default)]
    pub otp: Option<TwofasOtp>,
}

/// OTP parameters within a 2FAS service entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwofasOtp {
    /// Account name (e.g., "user@example.com").
    #[serde(default)]
    pub account: Option<String>,
    /// Service issuer (e.g., "GitLab").
    #[serde(default)]
    pub issuer: Option<String>,
    /// Token type: "TOTP", "HOTP", "STEAM".
    #[serde(default)]
    pub token_type: Option<String>,
    /// Hash algorithm: "SHA1", "SHA256", "SHA512", etc.
    #[serde(default)]
    pub algorithm: Option<String>,
    /// Number of OTP digits.
    #[serde(default)]
    pub digits: Option<u32>,
    /// TOTP period in seconds.
    #[serde(default)]
    pub period: Option<u32>,
    /// HOTP counter.
    #[serde(default)]
    pub counter: Option<u64>,
}

// ---------------------------------------------------------------------------
// Parsing result types
// ---------------------------------------------------------------------------

/// Result of parsing a single 2FAS entry.
pub enum ParsedEntry {
    /// Successfully parsed and validated.
    Valid(ImportedEntry),
    /// Entry uses an unsupported type or algorithm.
    Unsupported(UnsupportedInfo),
    /// Entry data is malformed.
    Malformed(MalformedInfo),
}

/// Result of parsing a 2FAS backup export.
#[derive(Debug)]
pub struct ParseResult {
    /// Successfully parsed entries.
    pub entries: Vec<ImportedEntry>,
    /// Entries with unsupported types or algorithms.
    pub unsupported: Vec<UnsupportedInfo>,
    /// Entries with malformed data.
    pub malformed: Vec<MalformedInfo>,
    /// 2FAS schema version.
    pub schema_version: u32,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// PBKDF2 iteration count used by 2FAS.
const PBKDF2_ITERATIONS: u32 = 10_000;

/// AES-256-GCM auth tag length (appended to ciphertext by Java JCE).
const GCM_TAG_LEN: usize = 16;

/// AES-256 key length in bytes.
const AES_KEY_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect whether a 2FAS backup export is encrypted.
///
/// Encrypted exports have a non-null, non-empty `servicesEncrypted` field.
///
/// # Errors
///
/// Returns `ImportError::InvalidFormat` if the JSON is unparseable.
pub fn is_encrypted(data: &str) -> Result<bool, ImportError> {
    let backup: TwofasBackup = serde_json::from_str(data)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid 2FAS JSON: {e}")))?;
    Ok(backup
        .services_encrypted
        .as_ref()
        .is_some_and(|s| !s.is_empty()))
}

/// Parse a plaintext 2FAS JSON backup export.
///
/// # Errors
///
/// Returns `ImportError::InvalidFormat` if the JSON structure is invalid.
/// Returns `ImportError::Unsupported` if the schema version is unsupported.
pub fn parse_twofas_json(data: &str) -> Result<ParseResult, ImportError> {
    let backup: TwofasBackup = serde_json::from_str(data)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid 2FAS JSON: {e}")))?;

    // Check if this is actually encrypted
    if backup
        .services_encrypted
        .as_ref()
        .is_some_and(|s| !s.is_empty())
    {
        return Err(ImportError::InvalidFormat(
            "2FAS export is encrypted. Use parse_twofas_encrypted() with a password.".to_string(),
        ));
    }

    let schema_version = validate_schema_version(backup.schema_version)?;
    Ok(parse_services(&backup.services, schema_version))
}

/// Parse an encrypted 2FAS JSON backup export.
///
/// Decrypts using the 2FAS encryption scheme:
/// 1. PBKDF2-HMAC-SHA256 to derive key from password (10,000 iterations)
/// 2. AES-256-GCM to decrypt the `servicesEncrypted` payload
///
/// # Errors
///
/// Returns `ImportError::InvalidFormat` if the JSON structure or crypto params are invalid.
/// Returns `ImportError::Corrupted` if decryption fails (wrong password or tampered data).
pub fn parse_twofas_encrypted(data: &str, password: &[u8]) -> Result<ParseResult, ImportError> {
    let backup: TwofasBackup = serde_json::from_str(data)
        .map_err(|e| ImportError::InvalidFormat(format!("invalid 2FAS JSON: {e}")))?;

    let schema_version = validate_schema_version(backup.schema_version)?;

    let encrypted_str = backup
        .services_encrypted
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ImportError::InvalidFormat(
                "expected encrypted export but servicesEncrypted is null or empty".to_string(),
            )
        })?;

    // Optionally verify password via reference field first
    if let Some(ref reference) = backup.reference {
        if !reference.is_empty() {
            verify_reference(reference, password)?;
        }
    }

    // Decrypt the services payload
    let mut decrypted = decrypt_payload(encrypted_str, password)?;

    // Parse decrypted JSON — zeroize on ALL exit paths (including errors)
    let result = std::str::from_utf8(&decrypted)
        .map_err(|e| ImportError::Corrupted(format!("decrypted data is not valid UTF-8: {e}")))
        .and_then(|decrypted_str| {
            let services: Vec<TwofasService> =
                serde_json::from_str(decrypted_str).map_err(|e| {
                    ImportError::InvalidFormat(format!("invalid decrypted services JSON: {e}"))
                })?;
            Ok(parse_services(&services, schema_version))
        });

    decrypted.zeroize();
    result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Validate the 2FAS schema version (FR45).
fn validate_schema_version(version: Option<u32>) -> Result<u32, ImportError> {
    let v = version.unwrap_or(1);
    if v == 0 || v > 4 {
        return Err(ImportError::Unsupported(format!(
            "2FAS schema version {v} is not supported (expected 1-4)"
        )));
    }
    Ok(v)
}

/// Parse a list of 2FAS services into a `ParseResult`.
fn parse_services(services: &[TwofasService], schema_version: u32) -> ParseResult {
    let mut entries = Vec::new();
    let mut unsupported = Vec::new();
    let mut malformed = Vec::new();

    for (idx, service) in services.iter().enumerate() {
        match parse_single_entry(service, idx) {
            ParsedEntry::Valid(imported) => entries.push(imported),
            ParsedEntry::Unsupported(info) => unsupported.push(info),
            ParsedEntry::Malformed(info) => malformed.push(info),
        }
    }

    ParseResult {
        entries,
        unsupported,
        malformed,
        schema_version,
    }
}

/// Parse a single 2FAS service entry into a categorized result.
fn parse_single_entry(service: &TwofasService, index: usize) -> ParsedEntry {
    let Some(otp) = &service.otp else {
        return ParsedEntry::Malformed(MalformedInfo {
            index,
            reason: "missing otp field".to_string(),
        });
    };

    // Map token type
    let token_type_str = otp.token_type.as_deref().unwrap_or("TOTP");
    let entry_type = match token_type_str {
        "TOTP" => EntryType::Totp,
        "HOTP" => EntryType::Hotp,
        "STEAM" => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(service),
                issuer: extract_issuer(service),
                reason: "STEAM token type not supported".to_string(),
            });
        }
        other => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(service),
                issuer: extract_issuer(service),
                reason: format!("unknown token type: {other}"),
            });
        }
    };

    // Map algorithm (default to SHA1 if null)
    let algo_str = otp.algorithm.as_deref().unwrap_or("SHA1");
    let algorithm = match algo_str {
        "SHA1" => Algorithm::SHA1,
        "SHA256" => Algorithm::SHA256,
        "SHA512" => Algorithm::SHA512,
        "SHA224" | "SHA384" => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(service),
                issuer: extract_issuer(service),
                reason: format!("{algo_str} algorithm not supported"),
            });
        }
        "MD5" => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(service),
                issuer: extract_issuer(service),
                reason: "MD5 algorithm not supported".to_string(),
            });
        }
        other => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(service),
                issuer: extract_issuer(service),
                reason: format!("unknown algorithm: {other}"),
            });
        }
    };

    // Strip whitespace from secret (known 2FAS quirk)
    let secret: String = service
        .secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    // Validate secret (already Base32 in 2FAS — just validate)
    if let Err(reason) = super::validate_secret(&secret) {
        return ParsedEntry::Malformed(MalformedInfo { index, reason });
    }

    // Apply defaults for nullable fields
    let digits = otp.digits.unwrap_or(6);
    let period = otp.period.unwrap_or(30);
    let counter = otp.counter.unwrap_or(0);

    // Validate OTP params (digits + period)
    if let Err(reason) = super::validate_otp_params(digits, period) {
        return ParsedEntry::Malformed(MalformedInfo { index, reason });
    }

    let name = extract_name(service);
    let issuer = extract_issuer(service);

    ParsedEntry::Valid(ImportedEntry {
        entry_type,
        name,
        issuer,
        secret,
        algorithm,
        digits,
        period,
        counter,
    })
}

/// Extract a display name from a 2FAS service entry.
///
/// Priority: `otp.account` → `name` → "(unnamed)".
fn extract_name(service: &TwofasService) -> String {
    if let Some(otp) = &service.otp {
        if let Some(account) = &otp.account {
            if !account.is_empty() {
                return account.clone();
            }
        }
    }
    if service.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        service.name.clone()
    }
}

/// Extract an issuer from a 2FAS service entry.
///
/// Priority: `otp.issuer` → `name` (if different from extracted name) → None.
fn extract_issuer(service: &TwofasService) -> Option<String> {
    if let Some(otp) = &service.otp {
        if let Some(issuer) = &otp.issuer {
            if !issuer.is_empty() {
                return Some(issuer.clone());
            }
        }
    }
    // Fallback: use top-level name as issuer if it differs from the extracted name
    let name = extract_name(service);
    if !service.name.is_empty() && service.name != name {
        Some(service.name.clone())
    } else {
        None
    }
}

/// Verify password using the 2FAS reference field.
///
/// The reference field is encrypted with the same KDF+cipher.
/// If decryption fails, the password is wrong (fail early).
fn verify_reference(reference: &str, password: &[u8]) -> Result<(), ImportError> {
    decrypt_payload(reference, password).map_or_else(
        |_| {
            Err(ImportError::Corrupted(
                "wrong password — reference verification failed".to_string(),
            ))
        },
        |mut decrypted| {
            decrypted.zeroize();
            Ok(())
        },
    )
}

/// Decrypt a 2FAS colon-separated encrypted payload.
///
/// Format: `<base64(ciphertext+tag)>:<base64(salt)>:<base64(iv)>`
///
/// Steps:
/// 1. Split on ':'
/// 2. Base64-decode each part
/// 3. Split ciphertext and appended 16-byte GCM auth tag
/// 4. Derive key via PBKDF2-HMAC-SHA256
/// 5. Decrypt via AES-256-GCM
fn decrypt_payload(encrypted: &str, password: &[u8]) -> Result<Vec<u8>, ImportError> {
    use verrou_crypto_core::symmetric::{SealedData, NONCE_LEN, TAG_LEN};

    // Step 1: Split on ':'
    let parts: Vec<&str> = encrypted.split(':').collect();
    if parts.len() != 3 {
        return Err(ImportError::InvalidFormat(format!(
            "expected 3 colon-separated parts in encrypted payload, got {}",
            parts.len()
        )));
    }

    // Step 2: Base64-decode each part
    let data_with_tag = data_encoding::BASE64
        .decode(parts[0].as_bytes())
        .map_err(|e| ImportError::Encoding(format!("invalid Base64 in encrypted data: {e}")))?;

    let salt = data_encoding::BASE64
        .decode(parts[1].as_bytes())
        .map_err(|e| ImportError::Encoding(format!("invalid Base64 in salt: {e}")))?;

    let iv = data_encoding::BASE64
        .decode(parts[2].as_bytes())
        .map_err(|e| ImportError::Encoding(format!("invalid Base64 in IV: {e}")))?;

    // Step 3: Split ciphertext and appended GCM auth tag (Java JCE format)
    if data_with_tag.len() < GCM_TAG_LEN {
        return Err(ImportError::Corrupted(
            "encrypted data too short to contain GCM auth tag".to_string(),
        ));
    }
    let tag_start = data_with_tag.len().saturating_sub(GCM_TAG_LEN);
    let ciphertext = &data_with_tag[..tag_start];
    let tag = &data_with_tag[tag_start..];

    // Validate nonce/tag lengths
    if iv.len() != NONCE_LEN {
        return Err(ImportError::InvalidFormat(format!(
            "invalid IV length: {} (expected {NONCE_LEN})",
            iv.len()
        )));
    }

    // Step 4: Derive key via PBKDF2-HMAC-SHA256
    let mut derived_key = [0u8; AES_KEY_LEN];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut derived_key);

    // Step 5: Decrypt via AES-256-GCM using verrou-crypto-core
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&iv);

    debug_assert_eq!(
        GCM_TAG_LEN, TAG_LEN,
        "GCM_TAG_LEN and crypto-core TAG_LEN must match"
    );
    let mut tag_arr = [0u8; TAG_LEN];
    tag_arr.copy_from_slice(tag);

    let sealed = SealedData {
        nonce: nonce_arr,
        ciphertext: ciphertext.to_vec(),
        tag: tag_arr,
    };

    let result = verrou_crypto_core::decrypt(&sealed, &derived_key, &[]).map_err(|_| {
        ImportError::Corrupted(
            "AES-256-GCM decryption failed — wrong password or corrupted data".to_string(),
        )
    });

    // Zeroize derived key on ALL paths (success and failure)
    derived_key.zeroize();

    result.map(|secret_buf| secret_buf.expose().to_vec())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn make_totp_service(
        name: &str,
        account: &str,
        issuer: &str,
        secret: &str,
    ) -> serde_json::Value {
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

    // A valid Base32 secret for tests (encodes to "Hello!")
    const TEST_SECRET: &str = "JBSWY3DPEE======";

    #[test]
    fn parse_single_totp_entry() {
        let json = make_backup_json(&[make_totp_service(
            "GitLab",
            "user@example.com",
            "GitLab",
            TEST_SECRET,
        )]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries.len(), 1);
        assert!(result.unsupported.is_empty());
        assert!(result.malformed.is_empty());
        assert_eq!(result.schema_version, 4);

        let entry = &result.entries[0];
        assert_eq!(entry.entry_type, EntryType::Totp);
        assert_eq!(entry.name, "user@example.com");
        assert_eq!(entry.issuer.as_deref(), Some("GitLab"));
        assert_eq!(entry.secret, TEST_SECRET);
        assert_eq!(entry.algorithm, Algorithm::SHA1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
    }

    #[test]
    fn parse_hotp_entry() {
        let service = serde_json::json!({
            "name": "Service",
            "secret": TEST_SECRET,
            "otp": {
                "account": "hotp-account",
                "issuer": "Service",
                "tokenType": "HOTP",
                "algorithm": "SHA256",
                "digits": 8,
                "period": 30,
                "counter": 42
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries.len(), 1);
        let entry = &result.entries[0];
        assert_eq!(entry.entry_type, EntryType::Hotp);
        assert_eq!(entry.algorithm, Algorithm::SHA256);
        assert_eq!(entry.digits, 8);
        assert_eq!(entry.counter, 42);
    }

    #[test]
    fn parse_all_supported_algorithms() {
        for (algo_str, expected) in [
            ("SHA1", Algorithm::SHA1),
            ("SHA256", Algorithm::SHA256),
            ("SHA512", Algorithm::SHA512),
        ] {
            let service = serde_json::json!({
                "name": "test",
                "secret": TEST_SECRET,
                "otp": {
                    "account": "test",
                    "issuer": "",
                    "tokenType": "TOTP",
                    "algorithm": algo_str,
                    "digits": 6,
                    "period": 30
                }
            });
            let json = make_backup_json(&[service]);
            let result = parse_twofas_json(&json).expect("should parse");
            assert_eq!(result.entries[0].algorithm, expected, "algo={algo_str}");
        }
    }

    #[test]
    fn steam_type_unsupported() {
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
        let result = parse_twofas_json(&json).expect("should parse");

        assert!(result.entries.is_empty());
        assert_eq!(result.unsupported.len(), 1);
        assert!(result.unsupported[0].reason.contains("STEAM"));
    }

    #[test]
    fn unsupported_algorithms_flagged() {
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
            let result = parse_twofas_json(&json).expect("should parse");

            assert!(result.entries.is_empty(), "algo={algo}");
            assert_eq!(result.unsupported.len(), 1, "algo={algo}");
            assert!(
                result.unsupported[0].reason.contains(algo),
                "reason should mention algo: {}",
                result.unsupported[0].reason
            );
        }
    }

    #[test]
    fn empty_secret_malformed() {
        let service = serde_json::json!({
            "name": "bad-account",
            "secret": "",
            "otp": {
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert!(result.entries.is_empty());
        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("empty"));
    }

    #[test]
    fn invalid_base32_secret_malformed() {
        let service = serde_json::json!({
            "name": "bad-b32",
            "secret": "not-valid-base32!!!",
            "otp": {
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert!(result.entries.is_empty());
        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("Base32"));
    }

    #[test]
    fn secret_whitespace_stripped() {
        // 2FAS quirk: some exports have spaces in secret
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
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].secret, TEST_SECRET);
    }

    #[test]
    fn null_algorithm_defaults_to_sha1() {
        let service = serde_json::json!({
            "name": "no-algo",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "TOTP",
                "algorithm": null,
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries[0].algorithm, Algorithm::SHA1);
    }

    #[test]
    fn null_digits_defaults_to_6() {
        let service = serde_json::json!({
            "name": "no-digits",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": null,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries[0].digits, 6);
    }

    #[test]
    fn null_period_defaults_to_30() {
        let service = serde_json::json!({
            "name": "no-period",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": null
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries[0].period, 30);
    }

    #[test]
    fn null_counter_defaults_to_0() {
        let service = serde_json::json!({
            "name": "no-counter",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "HOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
                "counter": null
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries[0].counter, 0);
    }

    #[test]
    fn missing_otp_field_malformed() {
        let service = serde_json::json!({
            "name": "no-otp",
            "secret": TEST_SECRET
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("otp"));
    }

    #[test]
    fn name_extraction_otp_account_preferred() {
        let service = serde_json::json!({
            "name": "ServiceName",
            "secret": TEST_SECRET,
            "otp": {
                "account": "user@example.com",
                "issuer": "ServiceName",
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries[0].name, "user@example.com");
        assert_eq!(result.entries[0].issuer.as_deref(), Some("ServiceName"));
    }

    #[test]
    fn name_extraction_fallback_to_name() {
        let service = serde_json::json!({
            "name": "ServiceName",
            "secret": TEST_SECRET,
            "otp": {
                "account": "",
                "issuer": "ServiceIssuer",
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries[0].name, "ServiceName");
        assert_eq!(result.entries[0].issuer.as_deref(), Some("ServiceIssuer"));
    }

    #[test]
    fn name_extraction_empty_becomes_unnamed() {
        let service = serde_json::json!({
            "name": "",
            "secret": TEST_SECRET,
            "otp": {
                "account": "",
                "issuer": "",
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries[0].name, "(unnamed)");
        assert!(result.entries[0].issuer.is_none());
    }

    #[test]
    fn issuer_fallback_to_name_when_different() {
        // When otp.issuer is empty but otp.account is used as name,
        // top-level name should be used as issuer if different
        let service = serde_json::json!({
            "name": "GitHub",
            "secret": TEST_SECRET,
            "otp": {
                "account": "user@example.com",
                "issuer": "",
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries[0].name, "user@example.com");
        assert_eq!(result.entries[0].issuer.as_deref(), Some("GitHub"));
    }

    #[test]
    fn schema_version_validation() {
        // Version 0 (invalid)
        let json = serde_json::json!({
            "services": [],
            "schemaVersion": 0
        })
        .to_string();
        assert!(matches!(
            parse_twofas_json(&json),
            Err(ImportError::Unsupported(_))
        ));

        // Version 5 (too high)
        let json = serde_json::json!({
            "services": [],
            "schemaVersion": 5
        })
        .to_string();
        assert!(matches!(
            parse_twofas_json(&json),
            Err(ImportError::Unsupported(_))
        ));

        // Versions 1-4 (valid)
        for v in 1..=4 {
            let json = serde_json::json!({
                "services": [],
                "schemaVersion": v
            })
            .to_string();
            assert!(
                parse_twofas_json(&json).is_ok(),
                "schema version {v} should be valid"
            );
        }
    }

    #[test]
    fn missing_schema_version_defaults_to_1() {
        let json = serde_json::json!({
            "services": []
        })
        .to_string();
        let result = parse_twofas_json(&json).expect("should parse");
        assert_eq!(result.schema_version, 1);
    }

    #[test]
    fn invalid_json_error() {
        let err = parse_twofas_json("not json at all").unwrap_err();
        assert!(matches!(err, ImportError::InvalidFormat(_)));
    }

    #[test]
    fn encrypted_export_rejected_by_plaintext_parser() {
        let json = serde_json::json!({
            "services": [],
            "servicesEncrypted": "some_encrypted_data",
            "schemaVersion": 4
        })
        .to_string();
        let err = parse_twofas_json(&json).unwrap_err();
        assert!(matches!(err, ImportError::InvalidFormat(_)));
    }

    #[test]
    fn is_encrypted_detection() {
        // Plaintext
        let plaintext = make_backup_json(&[]);
        assert!(!is_encrypted(&plaintext).unwrap());

        // Encrypted
        let encrypted = serde_json::json!({
            "services": [],
            "servicesEncrypted": "encrypted_payload",
            "schemaVersion": 4
        })
        .to_string();
        assert!(is_encrypted(&encrypted).unwrap());

        // Null servicesEncrypted
        let null_enc = serde_json::json!({
            "services": [],
            "servicesEncrypted": null,
            "schemaVersion": 4
        })
        .to_string();
        assert!(!is_encrypted(&null_enc).unwrap());

        // Empty servicesEncrypted
        let empty_enc = serde_json::json!({
            "services": [],
            "servicesEncrypted": "",
            "schemaVersion": 4
        })
        .to_string();
        assert!(!is_encrypted(&empty_enc).unwrap());
    }

    #[test]
    fn mixed_entries_categorized() {
        let services = vec![
            // Valid TOTP
            make_totp_service("GitHub", "good1@test.com", "GitHub", TEST_SECRET),
            // Unsupported type (Steam)
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
        ];
        let json = make_backup_json(&services);
        let result = parse_twofas_json(&json).expect("should parse");

        assert_eq!(result.entries.len(), 2);
        assert_eq!(result.unsupported.len(), 1);
        assert_eq!(result.malformed.len(), 1);

        assert_eq!(result.unsupported[0].index, 1);
        assert_eq!(result.malformed[0].index, 3);
    }

    #[test]
    fn empty_backup_parses_successfully() {
        let json = make_backup_json(&[]);
        let result = parse_twofas_json(&json).expect("should parse");
        assert!(result.entries.is_empty());
        assert!(result.unsupported.is_empty());
        assert!(result.malformed.is_empty());
    }

    #[test]
    fn unsupported_digits_malformed() {
        let service = serde_json::json!({
            "name": "test",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 7,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");
        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("digit"));
    }

    #[test]
    fn unsupported_period_malformed() {
        let service = serde_json::json!({
            "name": "test",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "TOTP",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 45
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");
        assert_eq!(result.malformed.len(), 1);
        assert!(result.malformed[0].reason.contains("period"));
    }

    #[test]
    fn encrypted_roundtrip() {
        // Create a known services JSON, encrypt it, then decrypt and parse.
        use verrou_crypto_core::symmetric::encrypt as aes_encrypt;

        let services_json = serde_json::json!([{
            "name": "EncryptedService",
            "secret": TEST_SECRET,
            "otp": {
                "account": "enc@test.com",
                "issuer": "EncryptedService",
                "tokenType": "TOTP",
                "algorithm": "SHA256",
                "digits": 6,
                "period": 30,
                "counter": 0
            }
        }]);
        let services_plaintext = serde_json::to_string(&services_json).unwrap();

        // Generate encryption params
        let password = b"test-password-2fas";
        let salt = [0xAA; 256]; // 2FAS uses 256-byte salt

        // Derive key via PBKDF2
        let mut derived_key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut derived_key);

        // Encrypt services
        let sealed = aes_encrypt(services_plaintext.as_bytes(), &derived_key, &[])
            .expect("encrypt services");

        // Build 2FAS colon-separated encrypted format:
        // <base64(ciphertext+tag)>:<base64(salt)>:<base64(iv)>
        let mut ciphertext_with_tag = sealed.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&sealed.tag);

        let encrypted_str = format!(
            "{}:{}:{}",
            data_encoding::BASE64.encode(&ciphertext_with_tag),
            data_encoding::BASE64.encode(&salt),
            data_encoding::BASE64.encode(&sealed.nonce),
        );

        let backup_json = serde_json::json!({
            "services": [],
            "servicesEncrypted": encrypted_str,
            "reference": null,
            "schemaVersion": 4
        });

        let backup_str = serde_json::to_string(&backup_json).unwrap();

        // Verify it's detected as encrypted
        assert!(is_encrypted(&backup_str).unwrap());

        // Parse it
        let result =
            parse_twofas_encrypted(&backup_str, password).expect("should decrypt and parse");

        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].name, "enc@test.com");
        assert_eq!(
            result.entries[0].issuer.as_deref(),
            Some("EncryptedService")
        );
        assert_eq!(result.entries[0].algorithm, Algorithm::SHA256);
        assert_eq!(result.schema_version, 4);
    }

    #[test]
    fn encrypted_wrong_password_fails() {
        use verrou_crypto_core::symmetric::encrypt as aes_encrypt;

        let services_json = "[]";
        let password = b"correct-password";
        let salt = [0xBB; 256];

        let mut derived_key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut derived_key);

        let sealed = aes_encrypt(services_json.as_bytes(), &derived_key, &[]).unwrap();

        let mut ciphertext_with_tag = sealed.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&sealed.tag);

        let encrypted_str = format!(
            "{}:{}:{}",
            data_encoding::BASE64.encode(&ciphertext_with_tag),
            data_encoding::BASE64.encode(&salt),
            data_encoding::BASE64.encode(&sealed.nonce),
        );

        let backup_json = serde_json::json!({
            "services": [],
            "servicesEncrypted": encrypted_str,
            "schemaVersion": 4
        });

        let backup_str = serde_json::to_string(&backup_json).unwrap();
        let err = parse_twofas_encrypted(&backup_str, b"wrong-password").unwrap_err();
        assert!(matches!(err, ImportError::Corrupted(_)));
    }

    #[test]
    fn encrypted_with_reference_verification() {
        use verrou_crypto_core::symmetric::encrypt as aes_encrypt;

        let password = b"ref-test-password";
        let salt = [0xCC; 256];
        let ref_salt = [0xDD; 256];

        // Derive keys
        let mut derived_key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &salt, PBKDF2_ITERATIONS, &mut derived_key);

        let mut ref_key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &ref_salt, PBKDF2_ITERATIONS, &mut ref_key);

        // Encrypt services
        let services_json = "[]";
        let sealed = aes_encrypt(services_json.as_bytes(), &derived_key, &[]).unwrap();

        // Encrypt reference
        let ref_plaintext = b"2fas-reference-constant";
        let ref_sealed = aes_encrypt(ref_plaintext, &ref_key, &[]).unwrap();

        // Build encrypted strings
        let build_encrypted = |s: &verrou_crypto_core::symmetric::SealedData, salt: &[u8]| {
            let mut ct_tag = s.ciphertext.clone();
            ct_tag.extend_from_slice(&s.tag);
            format!(
                "{}:{}:{}",
                data_encoding::BASE64.encode(&ct_tag),
                data_encoding::BASE64.encode(salt),
                data_encoding::BASE64.encode(&s.nonce),
            )
        };

        let backup_json = serde_json::json!({
            "services": [],
            "servicesEncrypted": build_encrypted(&sealed, &salt),
            "reference": build_encrypted(&ref_sealed, &ref_salt),
            "schemaVersion": 4
        });

        let backup_str = serde_json::to_string(&backup_json).unwrap();

        // Correct password works
        let result = parse_twofas_encrypted(&backup_str, password)
            .expect("should decrypt with correct password");
        assert!(result.entries.is_empty());

        // Wrong password fails on reference check
        let err = parse_twofas_encrypted(&backup_str, b"wrong-password").unwrap_err();
        assert!(matches!(err, ImportError::Corrupted(_)));
    }

    #[test]
    fn unknown_token_type_flagged_unsupported() {
        let service = serde_json::json!({
            "name": "unknown",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": "FOOBAR",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");
        assert_eq!(result.unsupported.len(), 1);
        assert!(result.unsupported[0].reason.contains("FOOBAR"));
    }

    #[test]
    fn null_token_type_defaults_to_totp() {
        let service = serde_json::json!({
            "name": "default-type",
            "secret": TEST_SECRET,
            "otp": {
                "tokenType": null,
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30
            }
        });
        let json = make_backup_json(&[service]);
        let result = parse_twofas_json(&json).expect("should parse");
        assert_eq!(result.entries[0].entry_type, EntryType::Totp);
    }
}
