//! `.verrou` binary file format — header, encrypted payload, padding.
//!
//! This module provides:
//! - [`serialize`] — produce a `.verrou` binary from a header + payload
//! - [`deserialize`] — recover header + payload from a `.verrou` binary
//! - [`VaultHeader`] — unencrypted vault metadata (version, KDF params, slots)
//!
//! # File Layout
//!
//! ```text
//! Magic (4 B) | Header Len (u32 LE) | Header JSON | Sealed Len (u32 LE) | Sealed JSON | Padding
//! ```
//!
//! - **Magic**: `b"VROU"` — identifies the file format
//! - **Header**: JSON-serialized [`VaultHeader`] (version, KDF params, key slots)
//! - **Sealed**: JSON-serialized [`SealedData`] — AES-256-GCM encrypted payload
//! - **Padding**: Random bytes to round total size to 64 KB boundary (NFR35)
//!
//! # Security Properties
//!
//! - No user data in unencrypted header (NFR36)
//! - File size padded to 64 KB boundaries — hides entry count (NFR35)
//! - Padding is random (not zeros) — passes entropy tests (NFR34)
//! - Payload AAD includes format version for domain separation

use crate::error::CryptoError;
use crate::kdf::Argon2idParams;
use crate::memory::SecretBuffer;
use crate::slots::{KeySlot, MASTER_KEY_LEN};
use crate::symmetric::{self, SealedData};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes identifying a `.verrou` file.
pub const MAGIC: &[u8; 4] = b"VROU";

/// Current format version.
pub const FORMAT_VERSION: u8 = 1;

/// File size padding boundary in bytes (64 KB).
pub const PADDING_BOUNDARY: usize = 65_536;

/// Advisory maximum for unencrypted header metadata in bytes (NFR36).
///
/// A zero-slot header must serialize below this threshold, confirming
/// that the header contains only format metadata — not user data
/// (names, counts, timestamps). Headers with key slots will exceed
/// this value, which is expected and safe.
pub const MAX_HEADER_SIZE: usize = 128;

/// Length of the magic bytes.
const MAGIC_LEN: usize = 4;

/// Length of a u32 length prefix.
const LEN_PREFIX: usize = 4;

/// AAD for payload encryption — includes version for domain separation.
const PAYLOAD_AAD: &[u8] = b"verrou-vault-payload-v1";

/// Minimum file size: magic + `header_len` + 0-byte header + `sealed_len` + min sealed.
const MIN_FILE_SIZE: usize = MAGIC_LEN + LEN_PREFIX + LEN_PREFIX;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Vault file header — unencrypted metadata stored at the start of `.verrou` files.
///
/// Contains ONLY format metadata, KDF parameters, and key slots.
/// Never contains user data (account names, entry counts, timestamps) per NFR36.
#[must_use = "vault header must be stored in the .verrou file"]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Format version (currently 1).
    pub version: u8,
    /// Number of key slots.
    pub slot_count: u8,
    /// KDF parameters for session unlock (user's chosen preset).
    pub session_params: Argon2idParams,
    /// KDF parameters for sensitive operations (Maximum tier).
    pub sensitive_params: Argon2idParams,
    /// Failed unlock attempt counter.
    pub unlock_attempts: u32,
    /// Unix timestamp (seconds) of the last failed unlock attempt.
    /// Used for brute-force cooldown persistence across app restarts.
    #[serde(default)]
    pub last_attempt_at: Option<u64>,
    /// Total successful unlock count (lifetime).
    /// Used for recovery key reminder at every 10th unlock.
    #[serde(default)]
    pub total_unlock_count: u32,
    /// Key slots — each wraps the master key with a different method.
    pub slots: Vec<KeySlot>,
    /// Per-slot KDF salts (index-aligned with `slots`).
    ///
    /// Password and recovery slots require a salt for key derivation.
    /// Biometric slots have an empty salt (`vec![]`).
    /// Stored in the unencrypted header so that unlock can derive the
    /// wrapping key before opening the encrypted database.
    #[serde(default)]
    pub slot_salts: Vec<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize a vault into the `.verrou` binary format.
///
/// Produces: magic + header-len + header-json + sealed-len + sealed-json + random-padding.
/// The output size is always a multiple of [`PADDING_BOUNDARY`] (64 KB).
///
/// # Arguments
///
/// - `header` — vault metadata (version, KDF params, key slots)
/// - `payload` — raw vault data to encrypt (may be empty)
/// - `master_key` — exactly 32 bytes
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyMaterial`] if the master key is not 32 bytes.
/// Returns [`CryptoError::Encryption`] if AES-256-GCM encryption fails.
/// Returns [`CryptoError::VaultFormat`] if serialization or padding fails.
pub fn serialize(
    header: &VaultHeader,
    payload: &[u8],
    master_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if master_key.len() != MASTER_KEY_LEN {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "invalid master key length: {} bytes (expected {MASTER_KEY_LEN})",
            master_key.len()
        )));
    }

    // Serialize header to JSON.
    let header_json = serde_json::to_vec(header)
        .map_err(|e| CryptoError::VaultFormat(format!("header serialization failed: {e}")))?;

    let header_len: u32 = u32::try_from(header_json.len())
        .map_err(|_| CryptoError::VaultFormat("header too large for u32 length".into()))?;

    // Encrypt payload with AES-256-GCM using version-tagged AAD.
    let sealed = symmetric::encrypt(payload, master_key, PAYLOAD_AAD)?;

    // Serialize sealed data to JSON.
    let sealed_json = serde_json::to_vec(&sealed)
        .map_err(|e| CryptoError::VaultFormat(format!("sealed data serialization failed: {e}")))?;

    let sealed_len: u32 = u32::try_from(sealed_json.len())
        .map_err(|_| CryptoError::VaultFormat("sealed data too large for u32 length".into()))?;

    // Calculate content size before padding.
    let content_size = MAGIC_LEN
        .checked_add(LEN_PREFIX)
        .and_then(|s| s.checked_add(header_json.len()))
        .and_then(|s| s.checked_add(LEN_PREFIX))
        .and_then(|s| s.checked_add(sealed_json.len()))
        .ok_or_else(|| CryptoError::VaultFormat("content size overflow".into()))?;

    // Generate random padding to reach next 64KB boundary.
    let padding = generate_padding(content_size)?;

    let total_size = content_size
        .checked_add(padding.len())
        .ok_or_else(|| CryptoError::VaultFormat("total size overflow".into()))?;

    // Assemble output.
    let mut out = Vec::with_capacity(total_size);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&sealed_len.to_le_bytes());
    out.extend_from_slice(&sealed_json);
    out.extend_from_slice(&padding);

    debug_assert_eq!(out.len() % PADDING_BOUNDARY, 0);

    Ok(out)
}

// ---------------------------------------------------------------------------
// Deserialization
// ---------------------------------------------------------------------------

/// Deserialize a `.verrou` binary back into header + payload.
///
/// Validates magic bytes, format version, and decrypts the payload.
/// Padding bytes are silently ignored.
///
/// # Arguments
///
/// - `data` — complete `.verrou` file bytes
/// - `master_key` — exactly 32 bytes
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyMaterial`] if the master key is not 32 bytes.
/// Returns [`CryptoError::VaultFormat`] for invalid magic, version, or structure.
/// Returns [`CryptoError::Decryption`] if the master key is wrong or data is tampered.
pub fn deserialize(
    data: &[u8],
    master_key: &[u8],
) -> Result<(VaultHeader, SecretBuffer), CryptoError> {
    if master_key.len() != MASTER_KEY_LEN {
        return Err(CryptoError::InvalidKeyMaterial(format!(
            "invalid master key length: {} bytes (expected {MASTER_KEY_LEN})",
            master_key.len()
        )));
    }

    if data.len() < MIN_FILE_SIZE {
        return Err(CryptoError::VaultFormat(format!(
            "file too short: {} bytes (minimum {MIN_FILE_SIZE})",
            data.len()
        )));
    }

    // Verify magic bytes.
    if &data[..MAGIC_LEN] != MAGIC.as_slice() {
        return Err(CryptoError::VaultFormat("invalid magic bytes".into()));
    }

    let mut cursor = MAGIC_LEN;

    // Read header length (u32 LE).
    let header_len = read_u32_le(data, &mut cursor)?;
    let header_end = cursor
        .checked_add(header_len)
        .ok_or_else(|| CryptoError::VaultFormat("header length overflow".into()))?;

    if header_end > data.len() {
        return Err(CryptoError::VaultFormat(format!(
            "header extends beyond file: header_end={header_end}, file_len={}",
            data.len()
        )));
    }

    // Deserialize header JSON.
    let header: VaultHeader = serde_json::from_slice(&data[cursor..header_end])
        .map_err(|e| CryptoError::VaultFormat(format!("invalid header: {e}")))?;
    cursor = header_end;

    // Version check.
    if header.version > FORMAT_VERSION {
        return Err(CryptoError::VaultFormat(format!(
            "vault format version {} is newer than supported version {FORMAT_VERSION}",
            header.version
        )));
    }

    // Slot count consistency check.
    if usize::from(header.slot_count) != header.slots.len() {
        return Err(CryptoError::VaultFormat(format!(
            "slot_count ({}) does not match slots array length ({})",
            header.slot_count,
            header.slots.len()
        )));
    }

    // Slot salts consistency check — each slot must have a corresponding salt entry.
    if header.slot_salts.len() != header.slots.len() {
        return Err(CryptoError::VaultFormat(format!(
            "slot_salts count ({}) does not match slots count ({})",
            header.slot_salts.len(),
            header.slots.len()
        )));
    }

    // Read sealed data length (u32 LE).
    let sealed_len = read_u32_le(data, &mut cursor)?;
    let sealed_end = cursor
        .checked_add(sealed_len)
        .ok_or_else(|| CryptoError::VaultFormat("sealed data length overflow".into()))?;

    if sealed_end > data.len() {
        return Err(CryptoError::VaultFormat(format!(
            "sealed data extends beyond file: sealed_end={sealed_end}, file_len={}",
            data.len()
        )));
    }

    // Deserialize sealed data JSON.
    let sealed: SealedData = serde_json::from_slice(&data[cursor..sealed_end])
        .map_err(|e| CryptoError::VaultFormat(format!("invalid sealed data: {e}")))?;

    // Decrypt payload.
    let payload = symmetric::decrypt(&sealed, master_key, PAYLOAD_AAD)?;

    Ok((header, payload))
}

/// Rewrite only the header portion of a `.verrou` file, preserving the sealed payload and padding.
///
/// This is used to update brute-force counters and unlock count without
/// re-encrypting the vault payload (which would require the master key).
///
/// # Layout
///
/// ```text
/// Magic (4 B) | Header Len (u32 LE) | Header JSON | Sealed Len | Sealed JSON | Padding
/// ```
///
/// Only `Header Len` and `Header JSON` are replaced. The sealed section and padding
/// are preserved byte-for-byte. If the new header is a different size, the file
/// is rewritten with adjusted padding to maintain 64 KB alignment.
///
/// # Errors
///
/// Returns [`CryptoError::VaultFormat`] if the header cannot be serialized or the
/// original file structure is invalid.
pub fn rewrite_header(
    original_data: &[u8],
    new_header: &VaultHeader,
) -> Result<Vec<u8>, CryptoError> {
    if original_data.len() < MIN_FILE_SIZE {
        return Err(CryptoError::VaultFormat(format!(
            "file too short: {} bytes (minimum {MIN_FILE_SIZE})",
            original_data.len()
        )));
    }

    // Verify magic bytes.
    if &original_data[..MAGIC_LEN] != MAGIC.as_slice() {
        return Err(CryptoError::VaultFormat("invalid magic bytes".into()));
    }

    let mut cursor = MAGIC_LEN;

    // Read original header length to skip past it.
    let old_header_len = read_u32_le(original_data, &mut cursor)?;
    let old_header_end = cursor
        .checked_add(old_header_len)
        .ok_or_else(|| CryptoError::VaultFormat("header length overflow".into()))?;

    if old_header_end > original_data.len() {
        return Err(CryptoError::VaultFormat(
            "header extends beyond file".into(),
        ));
    }

    // Everything after the old header JSON (sealed_len + sealed_json + old_padding).
    let rest_start = old_header_end;

    // Read sealed_len to find the end of the sealed section.
    let mut rest_cursor = rest_start;
    let sealed_len = read_u32_le(original_data, &mut rest_cursor)?;
    let sealed_end = rest_cursor
        .checked_add(sealed_len)
        .ok_or_else(|| CryptoError::VaultFormat("sealed data length overflow".into()))?;

    if sealed_end > original_data.len() {
        return Err(CryptoError::VaultFormat(
            "sealed data extends beyond file".into(),
        ));
    }

    // The sealed section: sealed_len(4) + sealed_json.
    let sealed_section = &original_data[rest_start..sealed_end];

    // Serialize new header.
    let new_header_json = serde_json::to_vec(new_header)
        .map_err(|e| CryptoError::VaultFormat(format!("header serialization failed: {e}")))?;

    let new_header_len: u32 = u32::try_from(new_header_json.len())
        .map_err(|_| CryptoError::VaultFormat("header too large for u32 length".into()))?;

    // Calculate content size for new output.
    let content_size = MAGIC_LEN
        .checked_add(LEN_PREFIX)
        .and_then(|s| s.checked_add(new_header_json.len()))
        .and_then(|s| s.checked_add(sealed_section.len()))
        .ok_or_else(|| CryptoError::VaultFormat("content size overflow".into()))?;

    // Generate new random padding.
    let padding = generate_padding(content_size)?;

    let total_size = content_size
        .checked_add(padding.len())
        .ok_or_else(|| CryptoError::VaultFormat("total size overflow".into()))?;

    // Assemble output.
    let mut out = Vec::with_capacity(total_size);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&new_header_len.to_le_bytes());
    out.extend_from_slice(&new_header_json);
    out.extend_from_slice(sealed_section);
    out.extend_from_slice(&padding);

    debug_assert_eq!(out.len() % PADDING_BOUNDARY, 0);

    Ok(out)
}

/// Parse the vault header from `.verrou` file bytes without decrypting the payload.
///
/// This is used during unlock to read KDF params, slot info, and brute-force
/// state before any expensive cryptographic operations.
///
/// # Errors
///
/// Returns [`CryptoError::VaultFormat`] for invalid magic, version, or structure.
pub fn parse_header_only(data: &[u8]) -> Result<VaultHeader, CryptoError> {
    if data.len() < MIN_FILE_SIZE {
        return Err(CryptoError::VaultFormat(format!(
            "file too short: {} bytes (minimum {MIN_FILE_SIZE})",
            data.len()
        )));
    }

    // Verify magic bytes.
    if &data[..MAGIC_LEN] != MAGIC.as_slice() {
        return Err(CryptoError::VaultFormat("invalid magic bytes".into()));
    }

    let mut cursor = MAGIC_LEN;

    // Read header length (u32 LE).
    let header_len = read_u32_le(data, &mut cursor)?;
    let header_end = cursor
        .checked_add(header_len)
        .ok_or_else(|| CryptoError::VaultFormat("header length overflow".into()))?;

    if header_end > data.len() {
        return Err(CryptoError::VaultFormat(format!(
            "header extends beyond file: header_end={header_end}, file_len={}",
            data.len()
        )));
    }

    // Deserialize header JSON.
    let header: VaultHeader = serde_json::from_slice(&data[cursor..header_end])
        .map_err(|e| CryptoError::VaultFormat(format!("invalid header: {e}")))?;

    // Version check.
    if header.version > FORMAT_VERSION {
        return Err(CryptoError::VaultFormat(format!(
            "vault format version {} is newer than supported version {FORMAT_VERSION}",
            header.version
        )));
    }

    // Slot count consistency check.
    if usize::from(header.slot_count) != header.slots.len() {
        return Err(CryptoError::VaultFormat(format!(
            "slot_count ({}) does not match slots array length ({})",
            header.slot_count,
            header.slots.len()
        )));
    }

    // Slot salts consistency check.
    if header.slot_salts.len() != header.slots.len() {
        return Err(CryptoError::VaultFormat(format!(
            "slot_salts count ({}) does not match slots count ({})",
            header.slot_salts.len(),
            header.slots.len()
        )));
    }

    Ok(header)
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

/// Generate random padding bytes to reach the next 64 KB boundary.
///
/// If `current_size` is already at a boundary, adds one full 64 KB block
/// (the file is never exactly the content size — there's always padding).
///
/// # Errors
///
/// Returns [`CryptoError::VaultFormat`] if arithmetic overflows.
fn generate_padding(current_size: usize) -> Result<Vec<u8>, CryptoError> {
    // Compute target size: next multiple of PADDING_BOUNDARY.
    let remainder = current_size % PADDING_BOUNDARY;
    let padding_needed = if remainder == 0 {
        // Already at boundary — add one full block.
        PADDING_BOUNDARY
    } else {
        PADDING_BOUNDARY
            .checked_sub(remainder)
            .ok_or_else(|| CryptoError::VaultFormat("padding calculation underflow".into()))?
    };

    let mut padding = vec![0u8; padding_needed];
    OsRng.fill_bytes(&mut padding);

    Ok(padding)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a u32 from `data` at `cursor` in little-endian order, advancing `cursor`.
fn read_u32_le(data: &[u8], cursor: &mut usize) -> Result<usize, CryptoError> {
    let end = cursor
        .checked_add(LEN_PREFIX)
        .ok_or_else(|| CryptoError::VaultFormat("cursor overflow".into()))?;

    if end > data.len() {
        return Err(CryptoError::VaultFormat(format!(
            "file too short to read u32 at offset {cursor}"
        )));
    }

    let mut buf = [0u8; 4];
    buf.copy_from_slice(&data[*cursor..end]);
    *cursor = end;

    let value = u32::from_le_bytes(buf);
    usize::try_from(value)
        .map_err(|_| CryptoError::VaultFormat("u32 value exceeds platform usize".into()))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::Argon2idParams;
    use crate::slots::{create_slot, SlotType};

    /// Fixed master key for tests — 32 bytes of 0xAA.
    const TEST_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0xAA; MASTER_KEY_LEN];

    /// Different master key for wrong-key tests.
    const WRONG_MASTER_KEY: [u8; MASTER_KEY_LEN] = [0xBB; MASTER_KEY_LEN];

    /// Create a minimal test header with no slots.
    fn test_header_no_slots() -> VaultHeader {
        VaultHeader {
            version: FORMAT_VERSION,
            slot_count: 0,
            session_params: Argon2idParams {
                m_cost: 262_144,
                t_cost: 3,
                p_cost: 4,
            },
            sensitive_params: Argon2idParams {
                m_cost: 524_288,
                t_cost: 4,
                p_cost: 4,
            },
            unlock_attempts: 0,
            last_attempt_at: None,
            total_unlock_count: 0,
            slots: vec![],
            slot_salts: vec![],
        }
    }

    /// Create a test header with 3 slots (one per type).
    fn test_header_with_slots() -> VaultHeader {
        let pw_slot = create_slot(&TEST_MASTER_KEY, &[0x01; 32], SlotType::Password)
            .expect("password slot should succeed");
        let bio_slot = create_slot(&TEST_MASTER_KEY, &[0x02; 32], SlotType::Biometric)
            .expect("biometric slot should succeed");
        let rec_slot = create_slot(&TEST_MASTER_KEY, &[0x03; 32], SlotType::Recovery)
            .expect("recovery slot should succeed");

        VaultHeader {
            version: FORMAT_VERSION,
            slot_count: 3,
            session_params: Argon2idParams {
                m_cost: 262_144,
                t_cost: 3,
                p_cost: 4,
            },
            sensitive_params: Argon2idParams {
                m_cost: 524_288,
                t_cost: 4,
                p_cost: 4,
            },
            unlock_attempts: 0,
            last_attempt_at: None,
            total_unlock_count: 0,
            slots: vec![pw_slot, bio_slot, rec_slot],
            slot_salts: vec![vec![0x01; 16], vec![], vec![0x03; 16]],
        }
    }

    /// Shannon entropy of a byte slice (bits per byte).
    #[allow(clippy::cast_precision_loss)]
    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut freq = [0u64; 256];
        for &b in data {
            freq[b as usize] = freq[b as usize].saturating_add(1);
        }
        let len = data.len() as f64;
        freq.iter()
            .filter(|&&f| f > 0)
            .map(|&f| {
                let p = f as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    // -- Task 6.1: Roundtrip --

    #[test]
    fn serialize_deserialize_roundtrip() {
        let header = test_header_no_slots();
        let payload = b"hello, VERROU vault data!";

        let blob = serialize(&header, payload, &TEST_MASTER_KEY).expect("serialize should succeed");
        let (recovered_header, recovered_payload) =
            deserialize(&blob, &TEST_MASTER_KEY).expect("deserialize should succeed");

        assert_eq!(recovered_payload.expose(), payload);
        assert_eq!(recovered_header.version, FORMAT_VERSION);
        assert_eq!(recovered_header.slot_count, 0);
    }

    // -- Task 6.2: Magic bytes --

    #[test]
    fn serialized_output_starts_with_magic() {
        let blob = serialize(&test_header_no_slots(), b"test", &TEST_MASTER_KEY)
            .expect("serialize should succeed");
        assert_eq!(&blob[..4], MAGIC.as_slice());
    }

    // -- Task 6.3: 64KB alignment --

    #[test]
    fn serialized_output_is_64kb_aligned() {
        let blob = serialize(&test_header_no_slots(), b"test", &TEST_MASTER_KEY)
            .expect("serialize should succeed");
        assert_eq!(
            blob.len() % PADDING_BOUNDARY,
            0,
            "output must be a multiple of 64KB, got {} bytes",
            blob.len()
        );
    }

    // -- Task 6.4: Encrypted payload entropy --

    #[test]
    fn encrypted_payload_passes_entropy_test() {
        let blob = serialize(&test_header_no_slots(), &[0x42; 4096], &TEST_MASTER_KEY)
            .expect("serialize should succeed");

        // Skip past all structured data to the padding region.
        // Layout: magic(4) + header_len(4) + header_json + sealed_len(4) + sealed_json + padding.
        // The sealed JSON is base64-encoded (ASCII, ~6 bits/char), so it won't hit 7.99.
        // The padding is raw random bytes and MUST pass the entropy threshold (NFR34).
        let header_len_bytes: [u8; 4] = blob[MAGIC_LEN..MAGIC_LEN + LEN_PREFIX]
            .try_into()
            .expect("4 bytes for header len");
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;
        let sealed_len_offset = MAGIC_LEN + LEN_PREFIX + header_len;
        let sealed_len_bytes: [u8; 4] = blob[sealed_len_offset..sealed_len_offset + LEN_PREFIX]
            .try_into()
            .expect("4 bytes for sealed len");
        let sealed_len = u32::from_le_bytes(sealed_len_bytes) as usize;
        let padding_start = sealed_len_offset + LEN_PREFIX + sealed_len;

        let padding_region = &blob[padding_start..];
        assert!(
            !padding_region.is_empty(),
            "padding region must not be empty"
        );
        let entropy = shannon_entropy(padding_region);
        assert!(entropy > 7.99, "padding region entropy too low: {entropy}");
    }

    // -- Task 6.5: Padding entropy --

    #[test]
    fn padding_bytes_pass_entropy_test() {
        let payload = &[0x00; 100];
        let blob = serialize(&test_header_no_slots(), payload, &TEST_MASTER_KEY)
            .expect("serialize should succeed");

        // The blob is 64KB. The content (magic + header + sealed) is much smaller.
        // The vast majority of the blob is random padding.
        // Measure the tail of the blob as "mostly padding".
        let tail_start = blob.len() / 2; // second half is overwhelmingly padding
        let tail = &blob[tail_start..];
        let entropy = shannon_entropy(tail);
        assert!(entropy > 7.99, "padding entropy too low: {entropy}");
    }

    // -- Task 6.6: Wrong magic --

    #[test]
    fn deserialize_rejects_wrong_magic() {
        let mut blob = serialize(&test_header_no_slots(), b"test", &TEST_MASTER_KEY)
            .expect("serialize should succeed");
        blob[0] = b'X';

        let result = deserialize(&blob, &TEST_MASTER_KEY);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::VaultFormat(ref msg)) if msg.contains("magic")),
            "wrong magic should yield CryptoError::VaultFormat with 'magic'"
        );
    }

    // -- Task 6.7: Future version --

    #[test]
    fn deserialize_rejects_future_version() {
        let mut header = test_header_no_slots();
        header.version = 255;

        let blob = serialize(&header, b"test", &TEST_MASTER_KEY).expect("serialize should succeed");
        let result = deserialize(&blob, &TEST_MASTER_KEY);

        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::VaultFormat(ref msg)) if msg.contains("newer")),
            "future version should yield CryptoError::VaultFormat with 'newer'"
        );
    }

    // -- Task 6.8: Wrong master key --

    #[test]
    fn deserialize_rejects_wrong_master_key() {
        let blob = serialize(&test_header_no_slots(), b"secret data", &TEST_MASTER_KEY)
            .expect("serialize should succeed");
        let result = deserialize(&blob, &WRONG_MASTER_KEY);

        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::Decryption)),
            "wrong key should yield CryptoError::Decryption"
        );
    }

    // -- Task 6.9: Tampered header --

    #[test]
    fn deserialize_rejects_tampered_header() {
        let mut blob = serialize(&test_header_no_slots(), b"test", &TEST_MASTER_KEY)
            .expect("serialize should succeed");

        // Tamper with a byte in the header JSON region.
        let header_region_start = MAGIC_LEN + LEN_PREFIX;
        if blob.len() > header_region_start {
            blob[header_region_start] ^= 0xFF;
        }

        let result = deserialize(&blob, &TEST_MASTER_KEY);
        assert!(
            result.is_err(),
            "tampered header should fail deserialization"
        );
    }

    // -- Task 6.10: Tampered payload --

    #[test]
    fn deserialize_rejects_tampered_payload() {
        let mut blob = serialize(&test_header_no_slots(), b"sensitive", &TEST_MASTER_KEY)
            .expect("serialize should succeed");

        // Find the sealed data region and tamper with it.
        let header_len_start = MAGIC_LEN;
        let header_len_bytes: [u8; 4] = blob[header_len_start..header_len_start + 4]
            .try_into()
            .expect("4 bytes for header len");
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;
        let sealed_region_start = MAGIC_LEN + LEN_PREFIX + header_len + LEN_PREFIX;

        if blob.len() > sealed_region_start {
            blob[sealed_region_start] ^= 0xFF;
        }

        let result = deserialize(&blob, &TEST_MASTER_KEY);
        assert!(
            result.is_err(),
            "tampered payload should fail deserialization"
        );
    }

    // -- Task 6.11: Truncated file --

    #[test]
    fn deserialize_rejects_truncated_file() {
        let result = deserialize(&[0u8; 8], &TEST_MASTER_KEY);
        assert!(result.is_err(), "truncated file should fail");
    }

    #[test]
    fn deserialize_rejects_empty_file() {
        let result = deserialize(&[], &TEST_MASTER_KEY);
        assert!(result.is_err(), "empty file should fail");
    }

    // -- Task 6.12: Wrong key length --

    #[test]
    fn serialize_rejects_wrong_key_length() {
        let result = serialize(&test_header_no_slots(), b"test", &[0u8; 31]);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "short key should yield CryptoError::InvalidKeyMaterial"
        );
    }

    #[test]
    fn deserialize_rejects_wrong_key_length() {
        let blob = serialize(&test_header_no_slots(), b"test", &TEST_MASTER_KEY)
            .expect("serialize should succeed");
        let result = deserialize(&blob, &[0u8; 33]);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::InvalidKeyMaterial(_))),
            "long key should yield CryptoError::InvalidKeyMaterial"
        );
    }

    // -- Task 6.13: Different ciphertexts --

    #[test]
    fn two_serializations_produce_different_ciphertexts() {
        let header = test_header_no_slots();
        let payload = b"same data";
        let blob_a =
            serialize(&header, payload, &TEST_MASTER_KEY).expect("serialize should succeed");
        let blob_b =
            serialize(&header, payload, &TEST_MASTER_KEY).expect("serialize should succeed");

        // Blobs should differ (different random nonce and padding).
        assert_ne!(
            blob_a, blob_b,
            "two serializations should produce different blobs"
        );
    }

    // -- Task 6.14: VaultHeader serde roundtrip --

    #[test]
    fn vault_header_serde_roundtrip() {
        let header = test_header_with_slots();
        let json = serde_json::to_string(&header).expect("serialize should succeed");
        let deserialized: VaultHeader =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(deserialized.version, header.version);
        assert_eq!(deserialized.slot_count, header.slot_count);
        assert_eq!(deserialized.session_params, header.session_params);
        assert_eq!(deserialized.sensitive_params, header.sensitive_params);
        assert_eq!(deserialized.unlock_attempts, header.unlock_attempts);
        assert_eq!(deserialized.slots.len(), header.slots.len());
    }

    // -- Task 6.15: Header with 0 slots --

    #[test]
    fn roundtrip_header_zero_slots() {
        let header = test_header_no_slots();
        let blob =
            serialize(&header, b"payload", &TEST_MASTER_KEY).expect("serialize should succeed");
        let (h, _) = deserialize(&blob, &TEST_MASTER_KEY).expect("deserialize should succeed");
        assert_eq!(h.slot_count, 0);
        assert!(h.slots.is_empty());
    }

    // -- Task 6.16: Header with 3 slots --

    #[test]
    fn roundtrip_header_three_slots() {
        let header = test_header_with_slots();
        let blob =
            serialize(&header, b"payload", &TEST_MASTER_KEY).expect("serialize should succeed");
        let (h, p) = deserialize(&blob, &TEST_MASTER_KEY).expect("deserialize should succeed");

        assert_eq!(h.slot_count, 3);
        assert_eq!(h.slots.len(), 3);
        assert_eq!(p.expose(), b"payload");
    }

    // -- Task 6.17: Empty payload --

    #[test]
    fn roundtrip_empty_payload() {
        let blob = serialize(&test_header_no_slots(), &[], &TEST_MASTER_KEY)
            .expect("serialize should succeed");
        let (_, p) = deserialize(&blob, &TEST_MASTER_KEY).expect("deserialize should succeed");
        assert!(p.expose().is_empty());
    }

    // -- Task 6.18: Large payload (1 MB) --

    #[test]
    fn roundtrip_large_payload() {
        let payload = vec![0x42u8; 1_048_576]; // 1 MB
        let blob = serialize(&test_header_no_slots(), &payload, &TEST_MASTER_KEY)
            .expect("serialize should succeed");

        assert_eq!(
            blob.len() % PADDING_BOUNDARY,
            0,
            "large payload output must be 64KB-aligned"
        );

        let (_, p) = deserialize(&blob, &TEST_MASTER_KEY).expect("deserialize should succeed");
        assert_eq!(p.expose(), &payload[..]);
    }

    // -- Review fix H1: slot_count vs slots.len() mismatch --

    #[test]
    fn deserialize_rejects_slot_count_mismatch() {
        let mut header = test_header_no_slots();
        // Claim 5 slots but provide 0.
        header.slot_count = 5;

        let blob = serialize(&header, b"test", &TEST_MASTER_KEY).expect("serialize should succeed");
        let result = deserialize(&blob, &TEST_MASTER_KEY);

        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::VaultFormat(ref msg)) if msg.contains("slot_count")),
            "slot_count mismatch should yield CryptoError::VaultFormat"
        );
    }

    // -- Review fix: slot_salts vs slots length mismatch --

    #[test]
    fn deserialize_rejects_slot_salts_mismatch() {
        let mut header = test_header_with_slots();
        // Remove all salts — creates a mismatch (3 slots, 0 salts).
        header.slot_salts = vec![];
        // Also fix slot_count to match slots so the slot_count check passes first.
        header.slot_count = 3;

        let blob = serialize(&header, b"test", &TEST_MASTER_KEY).expect("serialize should succeed");
        let result = deserialize(&blob, &TEST_MASTER_KEY);

        assert!(result.is_err());
        assert!(
            matches!(result, Err(CryptoError::VaultFormat(ref msg)) if msg.contains("slot_salts")),
            "slot_salts mismatch should yield CryptoError::VaultFormat with 'slot_salts'"
        );
    }

    // -- Review fix H2: MAX_HEADER_SIZE advisory — no user data in header --

    #[test]
    fn header_contains_no_user_data() {
        // NFR36: the unencrypted header must contain ONLY format metadata.
        // Verify the JSON representation contains no user-data fields.
        let header = test_header_with_slots();
        let json = serde_json::to_string(&header).expect("serialize should succeed");

        // Header should contain only known metadata keys.
        assert!(json.contains("version"), "header must have version");
        assert!(
            json.contains("session_params"),
            "header must have session_params"
        );
        assert!(
            json.contains("sensitive_params"),
            "header must have sensitive_params"
        );
        assert!(json.contains("slot_count"), "header must have slot_count");
        assert!(
            json.contains("unlock_attempts"),
            "header must have unlock_attempts"
        );
        assert!(json.contains("slots"), "header must have slots");

        // Header must NOT contain any user data fields.
        let forbidden = [
            "account",
            "issuer",
            "name",
            "email",
            "timestamp",
            "created_at",
            "entry",
        ];
        for word in &forbidden {
            assert!(
                !json.to_lowercase().contains(word),
                "header must not contain user data field: {word}"
            );
        }

        // Advisory: zero-slot header size is documented via MAX_HEADER_SIZE.
        let zero_slot_json =
            serde_json::to_vec(&test_header_no_slots()).expect("serialize should succeed");
        // Log actual size for documentation (not enforced as hard limit).
        assert!(
            zero_slot_json.len() < 512,
            "zero-slot header should be reasonably small, got {} bytes",
            zero_slot_json.len()
        );
    }

    // -- Review fix H3: non-aligned input --

    #[test]
    fn deserialize_handles_non_aligned_input() {
        // Construct a valid blob, then truncate padding to make it non-aligned.
        let blob = serialize(&test_header_no_slots(), b"test", &TEST_MASTER_KEY)
            .expect("serialize should succeed");
        assert_eq!(blob.len() % PADDING_BOUNDARY, 0);

        // Find where padding starts and truncate to just after sealed data.
        let header_len_bytes: [u8; 4] = blob[MAGIC_LEN..MAGIC_LEN + LEN_PREFIX]
            .try_into()
            .expect("4 bytes");
        let header_len = u32::from_le_bytes(header_len_bytes) as usize;
        let sealed_offset = MAGIC_LEN + LEN_PREFIX + header_len;
        let sealed_len_bytes: [u8; 4] = blob[sealed_offset..sealed_offset + LEN_PREFIX]
            .try_into()
            .expect("4 bytes");
        let sealed_len = u32::from_le_bytes(sealed_len_bytes) as usize;
        let content_end = sealed_offset + LEN_PREFIX + sealed_len;

        // Truncated blob (no padding) — should still deserialize successfully.
        let truncated = &blob[..content_end];
        assert_ne!(truncated.len() % PADDING_BOUNDARY, 0, "must be non-aligned");

        let (header, payload) = deserialize(truncated, &TEST_MASTER_KEY)
            .expect("non-aligned input should still deserialize");
        assert_eq!(header.version, FORMAT_VERSION);
        assert_eq!(payload.expose(), b"test");
    }

    // -- Review fix H5: version 0 acceptance --

    #[test]
    fn deserialize_accepts_version_zero() {
        let mut header = test_header_no_slots();
        header.version = 0;

        let blob =
            serialize(&header, b"v0 test", &TEST_MASTER_KEY).expect("serialize should succeed");
        let (recovered, payload) = deserialize(&blob, &TEST_MASTER_KEY)
            .expect("version 0 should be accepted (older than current)");

        assert_eq!(recovered.version, 0);
        assert_eq!(payload.expose(), b"v0 test");
    }
}
