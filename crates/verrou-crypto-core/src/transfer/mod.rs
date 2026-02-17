//! QR code desktop-to-desktop transfer encryption.
//!
//! Provides chunked AES-256-GCM encryption for air-gapped QR transfer.
//! A one-time verification phrase (4 EFF diceware words) derives a symmetric
//! key that encrypts the transfer payload chunk by chunk.
//!
//! # Protocol
//!
//! 1. Sender: [`generate_transfer_keypair`] → `(TransferKey, phrase)`
//! 2. Sender: [`chunk_payload`] → split serialized entries into chunks
//! 3. Sender: [`encrypt_chunk`] per chunk → encrypted QR data
//! 4. Receiver reads phrase from sender's screen
//! 5. Receiver: [`derive_transfer_key`] → derive same key from phrase
//! 6. Receiver: [`decrypt_chunk`] per scanned QR → `(index, total, plaintext)`
//! 7. Receiver: [`assemble_chunks`] → reconstruct full payload

use crate::error::CryptoError;
use crate::password::wordlist;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use ring::{aead, hkdf};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of the AES-256 transfer key in bytes.
pub const TRANSFER_KEY_LEN: usize = 32;

/// Number of EFF diceware words in the verification phrase.
pub const VERIFICATION_WORD_COUNT: usize = 4;

/// Default maximum plaintext size per chunk (bytes).
///
/// QR Version 40 with Error Correction M holds ~2331 bytes.
/// We target 1800 to leave margin for the 32-byte encryption
/// overhead (4-byte header + 12-byte nonce + 16-byte tag).
pub const DEFAULT_MAX_CHUNK_SIZE: usize = 1800;

/// Chunk header length: 2 bytes `chunk_index` + 2 bytes `total_chunks`.
const CHUNK_HEADER_LEN: usize = 4;

/// AES-256-GCM nonce length (96 bits).
const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length (128 bits).
const TAG_LEN: usize = 16;

/// Minimum encrypted chunk size: header + nonce + tag (empty plaintext).
const MIN_ENCRYPTED_CHUNK_LEN: usize = 32; // 4 + 12 + 16

/// HKDF salt for transfer key derivation.
const HKDF_SALT: &[u8] = b"verrou-qr-transfer-v1";

/// HKDF info for AES key expansion.
const HKDF_INFO: &[u8] = b"aes-key";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// 256-bit AES key for QR transfer encryption.
///
/// Securely zeroized on drop. Never logged or displayed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TransferKey {
    bytes: [u8; TRANSFER_KEY_LEN],
}

impl TransferKey {
    /// Expose the raw key bytes for cryptographic operations.
    #[must_use]
    pub const fn expose(&self) -> &[u8; TRANSFER_KEY_LEN] {
        &self.bytes
    }
}

// Safety: TransferKey contains secret key material — never log.
impl std::fmt::Debug for TransferKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransferKey(***)")
    }
}

/// `ring` HKDF output-length type for 32-byte AES keys.
struct TransferKeyType;

impl hkdf::KeyType for TransferKeyType {
    fn len(&self) -> usize {
        TRANSFER_KEY_LEN
    }
}

// ---------------------------------------------------------------------------
// Key generation and derivation
// ---------------------------------------------------------------------------

/// Generate a transfer key and verification phrase.
///
/// Returns `(TransferKey, phrase)` where `phrase` is 4 space-separated
/// EFF diceware words (~51 bits of entropy). The key is derived from the
/// phrase via HKDF-SHA256, so the receiver can reconstruct it by entering
/// the same phrase.
///
/// # Errors
///
/// Returns `CryptoError::TransferEncryption` if HKDF derivation fails.
pub fn generate_transfer_keypair() -> Result<(TransferKey, String), CryptoError> {
    let words = wordlist::eff_large();
    let word_count = words.len();
    let mut rng = OsRng;

    let phrase: String = (0..VERIFICATION_WORD_COUNT)
        .map(|_| {
            let idx = rng.gen_range(0..word_count);
            words[idx]
        })
        .collect::<Vec<&str>>()
        .join(" ");

    let key = derive_transfer_key(&phrase)?;
    Ok((key, phrase))
}

/// Derive a transfer key from a verification phrase.
///
/// Uses HKDF-SHA256 with a fixed salt (`verrou-qr-transfer-v1`) and info
/// (`aes-key`) to produce a deterministic 256-bit AES key from the phrase.
///
/// # Errors
///
/// Returns `CryptoError::TransferEncryption` if:
/// - The phrase does not contain exactly 4 space-separated words
/// - HKDF derivation fails
pub fn derive_transfer_key(phrase: &str) -> Result<TransferKey, CryptoError> {
    let word_count = phrase.split_whitespace().count();
    if word_count != VERIFICATION_WORD_COUNT {
        return Err(CryptoError::TransferEncryption(format!(
            "verification phrase must contain exactly {VERIFICATION_WORD_COUNT} words, got {word_count}"
        )));
    }

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, HKDF_SALT);
    let prk = salt.extract(phrase.as_bytes());
    let okm = prk
        .expand(&[HKDF_INFO], TransferKeyType)
        .map_err(|_| CryptoError::TransferEncryption("HKDF expansion failed".into()))?;

    let mut key_bytes = [0u8; TRANSFER_KEY_LEN];
    okm.fill(&mut key_bytes)
        .map_err(|_| CryptoError::TransferEncryption("HKDF fill failed".into()))?;

    Ok(TransferKey { bytes: key_bytes })
}

// ---------------------------------------------------------------------------
// Chunk encryption / decryption
// ---------------------------------------------------------------------------

/// Encrypt a data chunk for QR transfer.
///
/// Wire format of the output:
/// ```text
/// [2B chunk_index BE] [2B total_chunks BE] [12B nonce] [NB ciphertext] [16B tag]
/// ```
///
/// The nonce is constructed as `chunk_index (2B) || random (10B)`.
/// The chunk header (index + total) is authenticated via AAD to prevent
/// tampering.
///
/// # Errors
///
/// Returns `CryptoError::TransferEncryption` on encryption failure.
pub fn encrypt_chunk(
    data: &[u8],
    key: &TransferKey,
    chunk_index: u16,
    total_chunks: u16,
) -> Result<Vec<u8>, CryptoError> {
    // Build nonce: chunk_index (2 bytes BE) || random (10 bytes).
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes[..2].copy_from_slice(&chunk_index.to_be_bytes());
    OsRng.fill_bytes(&mut nonce_bytes[2..]);

    // AAD = chunk metadata — prevents index/total tampering.
    let mut aad_bytes = [0u8; CHUNK_HEADER_LEN];
    aad_bytes[..2].copy_from_slice(&chunk_index.to_be_bytes());
    aad_bytes[2..].copy_from_slice(&total_chunks.to_be_bytes());

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key.expose())
        .map_err(|_| CryptoError::TransferEncryption("failed to create AES key".into()))?;
    let less_safe = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let mut ciphertext = data.to_vec();
    let Ok(tag) =
        less_safe.seal_in_place_separate_tag(nonce, aead::Aad::from(&aad_bytes), &mut ciphertext)
    else {
        ciphertext.zeroize();
        return Err(CryptoError::TransferEncryption(
            "AES-256-GCM encryption failed".into(),
        ));
    };

    // Build output: header + nonce + ciphertext + tag.
    let output_len = CHUNK_HEADER_LEN
        .saturating_add(NONCE_LEN)
        .saturating_add(ciphertext.len())
        .saturating_add(TAG_LEN);
    let mut output = Vec::with_capacity(output_len);
    output.extend_from_slice(&aad_bytes);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(tag.as_ref());

    ciphertext.zeroize();
    Ok(output)
}

/// Decrypt a QR transfer chunk.
///
/// Parses the wire format, verifies the authentication tag, and returns
/// `(chunk_index, total_chunks, plaintext)`.
///
/// # Errors
///
/// Returns `CryptoError::TransferEncryption` if:
/// - The input is shorter than the minimum chunk size (32 bytes)
/// - Decryption fails (wrong key, tampered data, or tampered header)
pub fn decrypt_chunk(
    encrypted: &[u8],
    key: &TransferKey,
) -> Result<(u16, u16, Vec<u8>), CryptoError> {
    if encrypted.len() < MIN_ENCRYPTED_CHUNK_LEN {
        return Err(CryptoError::TransferEncryption(format!(
            "encrypted chunk too short: {} bytes (minimum {MIN_ENCRYPTED_CHUNK_LEN})",
            encrypted.len()
        )));
    }

    // Parse header.
    let chunk_index = u16::from_be_bytes([encrypted[0], encrypted[1]]);
    let total_chunks = u16::from_be_bytes([encrypted[2], encrypted[3]]);

    // Parse nonce (bytes 4..16).
    let nonce_end = CHUNK_HEADER_LEN.saturating_add(NONCE_LEN);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&encrypted[CHUNK_HEADER_LEN..nonce_end]);

    // Ciphertext + tag starts after header + nonce.
    let ct_tag = &encrypted[nonce_end..];

    // Rebuild AAD (must match encryption).
    let mut aad_bytes = [0u8; CHUNK_HEADER_LEN];
    aad_bytes[..2].copy_from_slice(&chunk_index.to_be_bytes());
    aad_bytes[2..].copy_from_slice(&total_chunks.to_be_bytes());

    let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key.expose())
        .map_err(|_| CryptoError::TransferEncryption("failed to create AES key".into()))?;
    let less_safe = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let mut ct_tag_buf = ct_tag.to_vec();
    let plaintext = less_safe
        .open_in_place(nonce, aead::Aad::from(&aad_bytes), &mut ct_tag_buf)
        .map_err(|_| {
            CryptoError::TransferEncryption(
                "chunk decryption failed (wrong key or tampered data)".into(),
            )
        })?;

    let result = plaintext.to_vec();
    ct_tag_buf.zeroize();
    Ok((chunk_index, total_chunks, result))
}

// ---------------------------------------------------------------------------
// Chunking / assembly
// ---------------------------------------------------------------------------

/// Split payload data into chunks of at most `max_chunk_size` bytes.
///
/// Each chunk is a standalone `Vec<u8>` suitable for individual encryption
/// via [`encrypt_chunk`]. An empty payload produces a single empty chunk.
///
/// # Errors
///
/// Returns `CryptoError::TransferEncryption` if `max_chunk_size` is zero.
pub fn chunk_payload(data: &[u8], max_chunk_size: usize) -> Result<Vec<Vec<u8>>, CryptoError> {
    if max_chunk_size == 0 {
        return Err(CryptoError::TransferEncryption(
            "max_chunk_size must be > 0".into(),
        ));
    }
    if data.is_empty() {
        return Ok(vec![Vec::new()]);
    }
    Ok(data.chunks(max_chunk_size).map(<[u8]>::to_vec).collect())
}

/// Reassemble decrypted chunks into the original payload.
///
/// Chunks are provided as `(chunk_index, plaintext)` pairs and are sorted
/// by index. Returns the concatenated payload if all chunks are present.
///
/// # Errors
///
/// Returns `CryptoError::TransferEncryption` if:
/// - `expected_total` is zero
/// - Any chunk index is out of range (`>= expected_total`)
/// - Any chunks are missing
pub fn assemble_chunks(
    chunks: &[(u16, Vec<u8>)],
    expected_total: u16,
) -> Result<Vec<u8>, CryptoError> {
    let total = usize::from(expected_total);
    if total == 0 {
        return Err(CryptoError::TransferEncryption(
            "expected_total must be > 0".into(),
        ));
    }

    let mut slots: Vec<Option<&[u8]>> = vec![None; total];

    for (idx, data) in chunks {
        let i = usize::from(*idx);
        if i >= total {
            return Err(CryptoError::TransferEncryption(format!(
                "chunk index {i} out of range (total {total})"
            )));
        }
        slots[i] = Some(data.as_slice());
    }

    let missing: Vec<usize> = slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.is_none())
        .map(|(i, _)| i)
        .collect();

    if !missing.is_empty() {
        return Err(CryptoError::TransferEncryption(format!(
            "missing chunks: {missing:?}"
        )));
    }

    let mut result = Vec::new();
    for data in slots.iter().flatten() {
        result.extend_from_slice(data);
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_transfer_keypair_returns_4_word_phrase() {
        let (_, phrase) = generate_transfer_keypair().unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), VERIFICATION_WORD_COUNT);
        for w in &words {
            assert!(!w.is_empty());
        }
    }

    #[test]
    fn derive_transfer_key_deterministic() {
        let phrase = "alpha bravo charlie delta";
        let key1 = derive_transfer_key(phrase).unwrap();
        let key2 = derive_transfer_key(phrase).unwrap();
        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn generate_derive_roundtrip() {
        let (key, phrase) = generate_transfer_keypair().unwrap();
        let derived = derive_transfer_key(&phrase).unwrap();
        assert_eq!(key.expose(), derived.expose());
    }

    #[test]
    fn derive_rejects_wrong_word_count() {
        assert!(derive_transfer_key("one two three").is_err());
        assert!(derive_transfer_key("one two three four five").is_err());
        assert!(derive_transfer_key("single").is_err());
        // Empty string has 0 words
        assert!(derive_transfer_key("").is_err());
    }

    #[test]
    fn different_phrases_produce_different_keys() {
        let key1 = derive_transfer_key("alpha bravo charlie delta").unwrap();
        let key2 = derive_transfer_key("echo foxtrot golf hotel").unwrap();
        assert_ne!(key1.expose(), key2.expose());
    }

    #[test]
    fn encrypt_chunk_output_format() {
        let key = derive_transfer_key("test word one two").unwrap();
        let data = b"hello world";
        let encrypted = encrypt_chunk(data, &key, 0, 1).unwrap();
        // header(4) + nonce(12) + ciphertext(11) + tag(16) = 43
        let expected_len = CHUNK_HEADER_LEN + NONCE_LEN + data.len() + TAG_LEN;
        assert_eq!(encrypted.len(), expected_len);
        // Verify header values
        assert_eq!(u16::from_be_bytes([encrypted[0], encrypted[1]]), 0);
        assert_eq!(u16::from_be_bytes([encrypted[2], encrypted[3]]), 1);
    }

    #[test]
    fn encrypt_decrypt_chunk_roundtrip() {
        let key = derive_transfer_key("test word one two").unwrap();
        let data = b"secret transfer data";
        let encrypted = encrypt_chunk(data, &key, 3, 10).unwrap();
        let (idx, total, plaintext) = decrypt_chunk(&encrypted, &key).unwrap();
        assert_eq!(idx, 3);
        assert_eq!(total, 10);
        assert_eq!(plaintext, data);
    }

    #[test]
    fn encrypt_decrypt_empty_chunk() {
        let key = derive_transfer_key("test word one two").unwrap();
        let encrypted = encrypt_chunk(&[], &key, 0, 1).unwrap();
        let (idx, total, plaintext) = decrypt_chunk(&encrypted, &key).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(total, 1);
        assert!(plaintext.is_empty());
    }

    #[test]
    fn decrypt_chunk_wrong_key_fails() {
        let key1 = derive_transfer_key("test word one two").unwrap();
        let key2 = derive_transfer_key("wrong key words here").unwrap();
        let encrypted = encrypt_chunk(b"data", &key1, 0, 1).unwrap();
        let result = decrypt_chunk(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_chunk_tampered_ciphertext_fails() {
        let key = derive_transfer_key("test word one two").unwrap();
        let mut encrypted = encrypt_chunk(b"data", &key, 0, 1).unwrap();
        // Tamper with ciphertext (after header + nonce = byte 16)
        if encrypted.len() > 17 {
            encrypted[17] ^= 0xFF;
        }
        assert!(decrypt_chunk(&encrypted, &key).is_err());
    }

    #[test]
    fn decrypt_chunk_tampered_header_fails() {
        let key = derive_transfer_key("test word one two").unwrap();
        let mut encrypted = encrypt_chunk(b"data", &key, 0, 1).unwrap();
        // Tamper with chunk_index in header — AAD mismatch
        encrypted[0] = 99;
        assert!(decrypt_chunk(&encrypted, &key).is_err());
    }

    #[test]
    fn decrypt_chunk_rejects_short_input() {
        let key = derive_transfer_key("test word one two").unwrap();
        assert!(decrypt_chunk(&[0u8; 10], &key).is_err());
    }

    #[test]
    fn chunk_payload_splits_correctly() {
        let data = vec![0u8; 100];
        let chunks = chunk_payload(&data, 30).unwrap();
        assert_eq!(chunks.len(), 4); // 30 + 30 + 30 + 10
        assert_eq!(chunks[0].len(), 30);
        assert_eq!(chunks[1].len(), 30);
        assert_eq!(chunks[2].len(), 30);
        assert_eq!(chunks[3].len(), 10);
    }

    #[test]
    fn chunk_payload_single_chunk() {
        let data = vec![0u8; 50];
        let chunks = chunk_payload(&data, 100).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 50);
    }

    #[test]
    fn chunk_payload_empty_data() {
        let chunks = chunk_payload(&[], 100).unwrap();
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].is_empty());
    }

    #[test]
    fn chunk_payload_zero_size_error() {
        let result = chunk_payload(&[1, 2, 3], 0);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("max_chunk_size must be > 0"));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn assemble_chunks_roundtrip() {
        let original = b"hello world, this is a test payload for assembly";
        let parts = chunk_payload(original, 15).unwrap();
        let total = parts.len() as u16;
        let indexed: Vec<(u16, Vec<u8>)> = parts
            .into_iter()
            .enumerate()
            .map(|(i, c)| (i as u16, c))
            .collect();
        let assembled = assemble_chunks(&indexed, total).unwrap();
        assert_eq!(assembled, original);
    }

    #[test]
    fn assemble_chunks_missing_chunk_error() {
        let parts = vec![(0u16, vec![1, 2, 3]), (2u16, vec![7, 8, 9])];
        let result = assemble_chunks(&parts, 3);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing"));
    }

    #[test]
    fn assemble_chunks_index_out_of_range() {
        let parts = vec![(5u16, vec![1, 2, 3])];
        let result = assemble_chunks(&parts, 3);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn assemble_chunks_zero_total_error() {
        let result = assemble_chunks(&[], 0);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn full_pipeline_chunk_encrypt_decrypt_assemble() {
        let (key, phrase) = generate_transfer_keypair().unwrap();
        let receiver_key = derive_transfer_key(&phrase).unwrap();

        let payload =
            b"This is a complete test of the full transfer pipeline with chunking and encryption.";
        let chunks = chunk_payload(payload, 20).unwrap();
        let total = chunks.len() as u16;

        // Encrypt all chunks.
        let encrypted: Vec<Vec<u8>> = chunks
            .iter()
            .enumerate()
            .map(|(i, c)| encrypt_chunk(c, &key, i as u16, total).unwrap())
            .collect();

        // Decrypt all chunks (using receiver's derived key).
        let decrypted: Vec<(u16, Vec<u8>)> = encrypted
            .iter()
            .map(|e| {
                let (idx, _, data) = decrypt_chunk(e, &receiver_key).unwrap();
                (idx, data)
            })
            .collect();

        let assembled = assemble_chunks(&decrypted, total).unwrap();
        assert_eq!(assembled, payload.as_slice());
    }

    #[test]
    fn two_generate_calls_produce_different_phrases() {
        let (_, phrase1) = generate_transfer_keypair().unwrap();
        let (_, phrase2) = generate_transfer_keypair().unwrap();
        // 7776^4 ≈ 3.6e15 — collision is astronomically unlikely.
        assert_ne!(phrase1, phrase2);
    }

    #[test]
    fn transfer_key_debug_masked() {
        let key = derive_transfer_key("test word one two").unwrap();
        let debug = format!("{key:?}");
        assert_eq!(debug, "TransferKey(***)");
    }
}
