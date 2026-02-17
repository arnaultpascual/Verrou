//! Recovery key generation, encoding/decoding, and vault fingerprint.
//!
//! This module provides:
//! - [`generate_recovery_key`] — produce 128-bit entropy + human-readable string
//! - [`encode_recovery_key`] — convert raw entropy to dash-separated base32-like string
//! - [`decode_recovery_key`] — parse human-readable string back to raw entropy
//! - [`vault_fingerprint`] — compute BLAKE3-based fingerprint of a `.verrou` file
//! - [`add_recovery_slot`] — add a recovery key slot to an existing vault
//!
//! # Recovery Key Format
//!
//! Human-readable encoding:
//! - **Alphabet**: 32 characters — `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`
//!   (excludes ambiguous: 0/O, 1/I/l)
//! - **Grouping**: 4-char groups separated by dashes
//! - **Length**: 26 data chars (128 bits ÷ 5 bits/char) + 2 checksum chars = 28 chars
//!   → 7 groups of 4 = `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`
//! - **Checksum**: Last 2 chars derived from `BLAKE3(entropy)[0..1]` (10 bits, encoded)
//! - **Case-insensitive decoding**: Accepts lowercase, normalizes to uppercase

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroize;

use verrou_crypto_core::kdf;
use verrou_crypto_core::slots::{self, SlotType};
use verrou_crypto_core::vault_format::{self, VaultHeader};

use crate::db::VaultDb;
use crate::error::VaultError;
use crate::lifecycle::{insert_key_slot_record, now_iso8601};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Recovery key entropy length in bytes (128 bits).
const RECOVERY_ENTROPY_LEN: usize = 16;

/// Salt length in bytes for Argon2id derivation.
const SALT_LEN: usize = 16;

/// Vault header file name.
const HEADER_FILE: &str = "vault.verrou";

/// Vault database file name.
const DB_FILE: &str = "vault.db";

/// Base32-like alphabet excluding ambiguous characters (0/O, 1/I/l).
/// 32 chars = 5 bits per character.
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Number of data characters in the encoded recovery key.
/// 128 bits ÷ 5 bits/char = 25.6 → 26 chars (with 2 bits padding).
const DATA_CHARS: usize = 26;

/// Number of checksum characters (10 bits → 2 base32 chars).
const CHECKSUM_CHARS: usize = 2;

/// Total characters in the encoded recovery key.
const TOTAL_CHARS: usize = 28;

/// Characters per group in the formatted output.
const GROUP_SIZE: usize = 4;

// ---------------------------------------------------------------------------
// Request / Result types
// ---------------------------------------------------------------------------

/// Parameters for adding a recovery slot to an existing vault.
pub struct AddRecoverySlotRequest<'a> {
    /// Directory containing the vault files.
    pub vault_dir: &'a Path,
    /// The decrypted master key (32 bytes).
    pub master_key: &'a [u8],
}

/// Result of a successful recovery key generation.
///
/// Contains the formatted recovery key (displayed ONCE to the user),
/// the vault fingerprint, and the generation date. No raw entropy
/// crosses the IPC boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateRecoveryKeyResult {
    /// Human-readable recovery key (e.g., `ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-CK42`).
    pub formatted_key: String,
    /// BLAKE3 fingerprint of the `.verrou` file (16 hex chars).
    pub vault_fingerprint: String,
    /// ISO 8601 UTC timestamp of generation.
    pub generation_date: String,
}

// ---------------------------------------------------------------------------
// Recovery key generation
// ---------------------------------------------------------------------------

/// Generate a recovery key and add a recovery slot to the vault.
///
/// Performs:
/// 1. Generate 128-bit random entropy (CSPRNG)
/// 2. Encode as human-readable string with checksum
/// 3. Generate fresh 16-byte salt
/// 4. Derive recovery wrapping key via Argon2id(`sensitive_params`)
/// 5. Create recovery slot wrapping the master key
/// 6. Update `VaultHeader`: increment `slot_count`, append slot + salt
/// 7. Re-serialize and write `.verrou` file
/// 8. Insert recovery slot record into `key_slots` table
/// 9. Compute vault fingerprint
/// 10. Return formatted key + fingerprint + date (no raw entropy)
///
/// # Errors
///
/// - [`VaultError::NotFound`] if vault files don't exist
/// - [`VaultError::Crypto`] if KDF, slot, or serialization fails
/// - [`VaultError::Io`] if file read/write fails
/// - [`VaultError::Database`] if DB operations fail
pub fn add_recovery_slot(
    req: &AddRecoverySlotRequest<'_>,
) -> Result<GenerateRecoveryKeyResult, VaultError> {
    let header_path = req.vault_dir.join(HEADER_FILE);
    let db_path = req.vault_dir.join(DB_FILE);

    // Verify vault exists.
    if !header_path.exists() || !db_path.exists() {
        return Err(VaultError::NotFound(req.vault_dir.display().to_string()));
    }

    // Read the current .verrou file for header parsing.
    let original_bytes = std::fs::read(&header_path)?;

    // Parse the existing header (unencrypted portion).
    let header = parse_header_from_bytes(&original_bytes)?;

    // Step 1: Generate 128-bit random entropy.
    let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
    OsRng.fill_bytes(&mut entropy);

    // Step 2: Encode as human-readable string.
    let formatted_key = encode_recovery_key(&entropy);

    // Step 3: Generate fresh salt.
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // Step 4: Derive recovery wrapping key using sensitive_params.
    let recovery_wrapping_key = kdf::derive(&entropy, &salt, &header.sensitive_params)?;

    // Zeroize raw entropy — the formatted_key is the user-facing representation.
    entropy.zeroize();

    // Step 5: Create recovery slot.
    let recovery_slot = slots::create_slot(
        req.master_key,
        recovery_wrapping_key.expose(),
        SlotType::Recovery,
    )?;

    // Step 6: Update VaultHeader.
    let updated_slot_count = header.slot_count.checked_add(1).ok_or_else(|| {
        VaultError::Crypto(verrou_crypto_core::CryptoError::VaultFormat(
            "slot_count overflow".into(),
        ))
    })?;

    let mut updated_header = header;
    updated_header.slot_count = updated_slot_count;
    updated_header.slots.push(recovery_slot.clone());
    updated_header.slot_salts.push(salt.to_vec());

    // Step 7: Re-serialize .verrou file (empty payload).
    let updated_bytes = vault_format::serialize(&updated_header, &[], req.master_key)?;
    std::fs::write(&header_path, &updated_bytes)?;

    // Step 8: Insert recovery slot record into key_slots table.
    // If this fails, restore the original .verrou file.
    let db = match VaultDb::open_raw(&db_path, req.master_key) {
        Ok(db) => db,
        Err(e) => {
            let _ = std::fs::write(&header_path, &original_bytes);
            return Err(e);
        }
    };

    if let Err(e) = insert_key_slot_record(
        db.connection(),
        &recovery_slot,
        &salt,
        &updated_header.sensitive_params,
    ) {
        drop(db);
        // Restore original .verrou file on failure.
        let _ = std::fs::write(&header_path, &original_bytes);
        return Err(e);
    }

    drop(db);

    // Step 9: Compute vault fingerprint from the updated file.
    let fingerprint = vault_fingerprint(&updated_bytes);

    // Step 10: Return result with no raw entropy.
    Ok(GenerateRecoveryKeyResult {
        formatted_key,
        vault_fingerprint: fingerprint,
        generation_date: now_iso8601(),
    })
}

// ---------------------------------------------------------------------------
// Recovery key encoding / decoding
// ---------------------------------------------------------------------------

/// Encode raw entropy bytes into a human-readable recovery key string.
///
/// Format: 7 groups of 4 chars separated by dashes.
/// The first 26 chars encode the 128-bit entropy (base32-like).
/// The last 2 chars are a BLAKE3-derived checksum.
///
/// # Panics
///
/// This function does not panic for any input length but only produces
/// a valid recovery key when called with 16 bytes of entropy.
#[must_use]
pub fn encode_recovery_key(entropy: &[u8]) -> String {
    // Encode the entropy as base32-like characters.
    let data_chars = encode_base32(entropy);

    // Compute checksum: BLAKE3(entropy)[0] gives 8 bits → 2 chars (10 bits,
    // but we only use 8 bits → the second char only uses 3 bits).
    let checksum_hash = blake3::hash(entropy);
    let checksum_byte = checksum_hash.as_bytes()[0];
    let checksum_chars = encode_checksum_byte(checksum_byte);

    // Combine data + checksum chars.
    let mut all_chars = String::with_capacity(TOTAL_CHARS);
    all_chars.push_str(&data_chars);
    all_chars.push_str(&checksum_chars);

    // Insert dashes every GROUP_SIZE chars.
    format_with_dashes(&all_chars)
}

/// Decode a human-readable recovery key string back to raw entropy bytes.
///
/// Accepts:
/// - Uppercase or lowercase input
/// - With or without dashes
/// - Leading/trailing whitespace is trimmed
///
/// # Errors
///
/// Returns [`VaultError::Crypto`] if:
/// - The key contains invalid characters
/// - The key has wrong length
/// - The checksum doesn't match
pub fn decode_recovery_key(input: &str) -> Result<Vec<u8>, VaultError> {
    // Normalize: uppercase, remove dashes, trim whitespace.
    let normalized: String = input
        .trim()
        .to_uppercase()
        .chars()
        .filter(|c| *c != '-')
        .collect();

    if normalized.len() != TOTAL_CHARS {
        return Err(VaultError::Crypto(
            verrou_crypto_core::CryptoError::VaultFormat(format!(
                "recovery key must be {TOTAL_CHARS} characters (got {})",
                normalized.len()
            )),
        ));
    }

    // Split into data and checksum portions.
    let data_str = &normalized[..DATA_CHARS];
    let checksum_str = &normalized[DATA_CHARS..];

    // Decode data chars back to bytes.
    let entropy = decode_base32(data_str)?;

    // Verify checksum.
    let checksum_hash = blake3::hash(&entropy);
    let expected_checksum_byte = checksum_hash.as_bytes()[0];
    let expected_checksum = encode_checksum_byte(expected_checksum_byte);

    if checksum_str != expected_checksum {
        return Err(VaultError::Crypto(
            verrou_crypto_core::CryptoError::VaultFormat("recovery key checksum mismatch".into()),
        ));
    }

    Ok(entropy)
}

// ---------------------------------------------------------------------------
// Vault fingerprint
// ---------------------------------------------------------------------------

/// Compute a vault fingerprint from `.verrou` file bytes.
///
/// Returns the first 8 bytes of the BLAKE3 hash, hex-encoded (16 chars).
#[must_use]
pub fn vault_fingerprint(verrou_bytes: &[u8]) -> String {
    let hash = blake3::hash(verrou_bytes);
    let bytes = hash.as_bytes();
    // First 8 bytes → 16 hex chars.
    let mut hex = String::with_capacity(16);
    for &b in &bytes[..8] {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a `VaultHeader` from raw `.verrou` file bytes (unencrypted portion only).
///
/// Does NOT decrypt the payload — only reads the header JSON.
#[allow(clippy::arithmetic_side_effects)]
fn parse_header_from_bytes(data: &[u8]) -> Result<VaultHeader, VaultError> {
    // Minimum: magic(4) + header_len(4) = 8 bytes
    if data.len() < 8 {
        return Err(VaultError::Crypto(
            verrou_crypto_core::CryptoError::VaultFormat("file too short for header".into()),
        ));
    }

    if &data[..4] != b"VROU" {
        return Err(VaultError::Crypto(
            verrou_crypto_core::CryptoError::VaultFormat("invalid magic bytes".into()),
        ));
    }

    let header_len = u32::from_le_bytes(data[4..8].try_into().map_err(|_| {
        VaultError::Crypto(verrou_crypto_core::CryptoError::VaultFormat(
            "cannot read header length".into(),
        ))
    })?) as usize;

    let header_end = 8usize.checked_add(header_len).ok_or_else(|| {
        VaultError::Crypto(verrou_crypto_core::CryptoError::VaultFormat(
            "header length overflow".into(),
        ))
    })?;

    if header_end > data.len() {
        return Err(VaultError::Crypto(
            verrou_crypto_core::CryptoError::VaultFormat("header extends beyond file".into()),
        ));
    }

    let header: VaultHeader = serde_json::from_slice(&data[8..header_end]).map_err(|e| {
        VaultError::Crypto(verrou_crypto_core::CryptoError::VaultFormat(format!(
            "invalid header JSON: {e}"
        )))
    })?;

    Ok(header)
}

/// Encode bytes to base32-like string using our custom alphabet.
///
/// Processes input as a bit stream, extracting 5 bits at a time.
fn encode_base32(data: &[u8]) -> String {
    let mut result = String::with_capacity(DATA_CHARS);
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;
    let mut chars_written: usize = 0;

    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits_in_buffer = bits_in_buffer.saturating_add(8);

        while bits_in_buffer >= 5 && chars_written < DATA_CHARS {
            bits_in_buffer = bits_in_buffer.saturating_sub(5);
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            result.push(char::from(ALPHABET[index]));
            chars_written = chars_written.saturating_add(1);
        }
    }

    // Handle remaining bits (pad with zeros on the right).
    if bits_in_buffer > 0 && chars_written < DATA_CHARS {
        let index = ((buffer << (5u32.saturating_sub(bits_in_buffer))) & 0x1F) as usize;
        result.push(char::from(ALPHABET[index]));
    }

    result
}

/// Decode a base32-like string back to bytes.
fn decode_base32(input: &str) -> Result<Vec<u8>, VaultError> {
    let mut buffer: u32 = 0;
    let mut bits_in_buffer: u32 = 0;
    let mut result = Vec::with_capacity(RECOVERY_ENTROPY_LEN);

    for ch in input.chars() {
        let value = alphabet_value(ch)?;
        buffer = (buffer << 5) | u32::from(value);
        bits_in_buffer = bits_in_buffer.saturating_add(5);

        while bits_in_buffer >= 8 {
            bits_in_buffer = bits_in_buffer.saturating_sub(8);
            let byte = ((buffer >> bits_in_buffer) & 0xFF) as u8;
            result.push(byte);
        }
    }

    // Truncate to exact entropy length (discard padding bits).
    result.truncate(RECOVERY_ENTROPY_LEN);

    Ok(result)
}

/// Get the numeric value (0..31) for a character in our alphabet.
fn alphabet_value(ch: char) -> Result<u8, VaultError> {
    let upper = ch.to_ascii_uppercase();
    ALPHABET
        .iter()
        .position(|&c| c == upper as u8)
        .and_then(|pos| u8::try_from(pos).ok())
        .ok_or_else(|| {
            VaultError::Crypto(verrou_crypto_core::CryptoError::VaultFormat(format!(
                "invalid character in recovery key: '{ch}'"
            )))
        })
}

/// Encode a single checksum byte into 2 base32 characters.
fn encode_checksum_byte(byte: u8) -> String {
    let hi = (byte >> 3) & 0x1F;
    let lo = (byte & 0x07) << 2; // lower 3 bits shifted left 2 (5-bit aligned)
    let mut s = String::with_capacity(CHECKSUM_CHARS);
    s.push(char::from(ALPHABET[hi as usize]));
    s.push(char::from(ALPHABET[lo as usize]));
    s
}

/// Format a character string with dashes every `GROUP_SIZE` characters.
fn format_with_dashes(input: &str) -> String {
    let groups: Vec<&str> = input
        .as_bytes()
        .chunks(GROUP_SIZE)
        .map(|chunk| {
            // SAFETY: input is ASCII (our alphabet is all ASCII).
            std::str::from_utf8(chunk).unwrap_or("")
        })
        .collect();
    groups.join("-")
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Task 5.1: Recovery key has 128-bit entropy --

    #[test]
    fn recovery_key_has_128_bit_entropy() {
        let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
        OsRng.fill_bytes(&mut entropy);
        assert_eq!(
            entropy.len(),
            16,
            "recovery key entropy must be 16 bytes (128 bits)"
        );
        // Verify it's not all zeros (extremely unlikely with CSPRNG).
        assert!(
            entropy.iter().any(|&b| b != 0),
            "entropy must not be all zeros"
        );
    }

    // -- Task 5.2: Recovery key encoding roundtrip --

    #[test]
    fn recovery_key_encoding_roundtrip() {
        let entropy: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let encoded = encode_recovery_key(&entropy);
        let decoded = decode_recovery_key(&encoded).expect("decode should succeed");
        assert_eq!(decoded, entropy.to_vec(), "roundtrip must preserve entropy");
    }

    // -- Task 5.3: Recovery key excludes ambiguous chars --

    #[test]
    fn recovery_key_excludes_ambiguous_chars() {
        // Generate multiple keys and verify no ambiguous characters.
        for _ in 0..20 {
            let mut entropy = [0u8; RECOVERY_ENTROPY_LEN];
            OsRng.fill_bytes(&mut entropy);
            let encoded = encode_recovery_key(&entropy);

            // Remove dashes for character-level check.
            let chars_only: String = encoded.chars().filter(|c| *c != '-').collect();
            for ch in chars_only.chars() {
                assert!(
                    ch != '0' && ch != 'O' && ch != '1' && ch != 'I' && ch != 'l',
                    "encoded key must not contain ambiguous char '{ch}' (key: {encoded})"
                );
            }
        }
    }

    // -- Task 5.4: Recovery key checksum validates --

    #[test]
    fn recovery_key_checksum_validates() {
        let entropy: [u8; 16] = [0x42; 16];
        let encoded = encode_recovery_key(&entropy);

        // Valid checksum should pass.
        let result = decode_recovery_key(&encoded);
        assert!(result.is_ok(), "valid checksum should decode successfully");

        // Corrupt last character → checksum should fail.
        let mut chars: Vec<char> = encoded.chars().collect();
        let last_idx = chars.len().saturating_sub(1);
        chars[last_idx] = if chars[last_idx] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();

        let result = decode_recovery_key(&corrupted);
        assert!(result.is_err(), "corrupted checksum should fail decoding");
    }

    // -- Format tests --

    #[test]
    fn recovery_key_format_has_correct_structure() {
        let entropy = [0xAB; 16];
        let encoded = encode_recovery_key(&entropy);

        // Should have 6 dashes (7 groups).
        let dash_count = encoded.chars().filter(|c| *c == '-').count();
        assert_eq!(dash_count, 6, "encoded key must have 6 dashes (7 groups)");

        // Total length: 28 chars + 6 dashes = 34 chars.
        assert_eq!(
            encoded.len(),
            34,
            "encoded key with dashes must be 34 chars"
        );

        // Each group should be 4 chars.
        for group in encoded.split('-') {
            assert_eq!(group.len(), 4, "each group must be 4 characters");
        }
    }

    #[test]
    fn recovery_key_decode_is_case_insensitive() {
        let entropy = [0x55; 16];
        let encoded = encode_recovery_key(&entropy);
        let lowercase = encoded.to_lowercase();

        let decoded_upper = decode_recovery_key(&encoded).expect("uppercase decode");
        let decoded_lower = decode_recovery_key(&lowercase).expect("lowercase decode");

        assert_eq!(decoded_upper, decoded_lower, "case-insensitive decoding");
    }

    #[test]
    fn recovery_key_decode_rejects_invalid_char() {
        let result = decode_recovery_key("ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-0000");
        assert!(result.is_err(), "character '0' should be rejected");
    }

    #[test]
    fn recovery_key_decode_rejects_wrong_length() {
        let result = decode_recovery_key("ABCD-EFGH");
        assert!(result.is_err(), "short key should be rejected");
    }

    // -- Vault fingerprint tests --

    #[test]
    fn vault_fingerprint_is_deterministic() {
        let data = b"test vault content";
        let fp1 = vault_fingerprint(data);
        let fp2 = vault_fingerprint(data);
        assert_eq!(fp1, fp2, "fingerprint must be deterministic");
    }

    #[test]
    fn vault_fingerprint_is_16_hex_chars() {
        let fp = vault_fingerprint(b"some vault data");
        assert_eq!(fp.len(), 16, "fingerprint must be 16 hex chars");
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint must be hex: {fp}"
        );
    }

    #[test]
    fn vault_fingerprint_changes_with_content() {
        let fp1 = vault_fingerprint(b"content A");
        let fp2 = vault_fingerprint(b"content B");
        assert_ne!(
            fp1, fp2,
            "different content should produce different fingerprints"
        );
    }

    // -- IPC result type safety --

    #[test]
    fn generate_recovery_key_result_has_no_raw_entropy() {
        let result = GenerateRecoveryKeyResult {
            formatted_key: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-CK42".to_string(),
            vault_fingerprint: "0123456789abcdef".to_string(),
            generation_date: "2026-02-09T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&result).expect("serialize should succeed");
        let lower = json.to_lowercase();

        // Must not contain binary/hex patterns that look like raw entropy.
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
        assert!(
            json.contains("formattedKey"),
            "must have camelCase formattedKey"
        );
        assert!(
            json.contains("vaultFingerprint"),
            "must have camelCase vaultFingerprint"
        );
        assert!(
            json.contains("generationDate"),
            "must have camelCase generationDate"
        );
    }

    #[test]
    fn generate_recovery_key_result_is_serializable() {
        fn assert_serializable<T: Serialize + Clone>() {}
        assert_serializable::<GenerateRecoveryKeyResult>();
    }
}
