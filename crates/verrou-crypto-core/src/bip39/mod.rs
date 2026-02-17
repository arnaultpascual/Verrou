//! BIP39 wordlist validation, checksum verification, and passphrase support.
//!
//! This module provides:
//! - [`validate_word`] — check if a word exists in a BIP39 wordlist
//! - [`validate_phrase`] — verify word count and SHA-256 checksum of a mnemonic
//! - [`suggest_words`] — prefix-match suggestions from a BIP39 wordlist
//! - [`word_index`] — get the 0-based index of a word in a wordlist
//! - [`Bip39Language`] — enum of all 10 official BIP39 languages
//!
//! # Architecture
//!
//! This module lives in `verrou-crypto-core` and provides pure BIP39 validation.
//! It does NOT handle secret storage, IPC, or UI — those are in `verrou-vault`
//! and `src-tauri` (Epic 6).

pub mod wordlists;

pub use wordlists::{get_wordlist, suggest_words, validate_word, word_index, WORDLIST_SIZE};

use crate::error::CryptoError;

// ── Types ──────────────────────────────────────────────────────────

/// Supported BIP39 wordlist languages.
///
/// All 10 official languages from the BIP39 specification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bip39Language {
    /// English (2048 words, alphabetically sorted).
    English,
    /// Japanese (2048 words, not alphabetically sorted).
    Japanese,
    /// Korean (2048 words, not alphabetically sorted).
    Korean,
    /// Spanish (2048 words, Unicode-sorted but not byte-order sorted).
    Spanish,
    /// Chinese Simplified (2048 words, not alphabetically sorted).
    ChineseSimplified,
    /// Chinese Traditional (2048 words, not alphabetically sorted).
    ChineseTraditional,
    /// French (2048 words, Unicode-sorted but not byte-order sorted).
    French,
    /// Italian (2048 words, alphabetically sorted).
    Italian,
    /// Czech (2048 words, Unicode-sorted but not byte-order sorted).
    Czech,
    /// Portuguese (2048 words, alphabetically sorted).
    Portuguese,
}

impl Bip39Language {
    /// Returns `true` if this language's wordlist is sorted by Rust's default
    /// `str` comparison (byte/Unicode code-point order), allowing binary search.
    ///
    /// Only English, Italian, and Portuguese wordlists are byte-order sorted.
    /// French, Czech, and Spanish contain accented characters that break
    /// byte-order sorting (e.g., "ábaco" sorts after "z" in byte order).
    #[must_use]
    pub const fn is_sorted_for_binary_search(self) -> bool {
        matches!(self, Self::English | Self::Italian | Self::Portuguese)
    }

    /// Returns all 10 BIP39 languages.
    #[must_use]
    pub const fn all() -> [Self; 10] {
        [
            Self::English,
            Self::Japanese,
            Self::Korean,
            Self::Spanish,
            Self::ChineseSimplified,
            Self::ChineseTraditional,
            Self::French,
            Self::Italian,
            Self::Czech,
            Self::Portuguese,
        ]
    }
}

// ── Constants ──────────────────────────────────────────────────────

/// Valid BIP39 mnemonic word counts.
pub const VALID_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

// ── Phrase Validation ──────────────────────────────────────────────

/// Validate a BIP39 mnemonic phrase: word count, word membership, and checksum.
///
/// # Arguments
///
/// * `words` — slice of words in the mnemonic (12, 15, 18, 21, or 24 words)
/// * `language` — the BIP39 language to validate against
///
/// # Returns
///
/// `Ok(())` if the phrase is valid (correct word count, all words in
/// wordlist, and SHA-256 checksum matches). Returns `CryptoError::Bip39`
/// with a descriptive message on failure.
///
/// # Errors
///
/// Returns `CryptoError::Bip39` if:
/// - Word count is not one of 12, 15, 18, 21, 24
/// - Any word is empty or not found in the wordlist
/// - The SHA-256 checksum does not match
pub fn validate_phrase(words: &[&str], language: Bip39Language) -> Result<(), CryptoError> {
    let word_count = words.len();

    // Validate word count.
    if !VALID_WORD_COUNTS.contains(&word_count) {
        return Err(CryptoError::Bip39(format!(
            "invalid word count: {word_count}, expected 12/15/18/21/24"
        )));
    }

    // Validate each word and collect 11-bit indices.
    let mut indices = Vec::with_capacity(word_count);
    for (i, word) in words.iter().enumerate() {
        if word.is_empty() {
            return Err(CryptoError::Bip39(format!("empty word at position {i}")));
        }
        match word_index(word, language) {
            Some(idx) => indices.push(idx),
            None => {
                return Err(CryptoError::Bip39(format!(
                    "word not found in wordlist at position {i}"
                )));
            }
        }
    }

    // Compute entropy + checksum bits.
    // Total bits = word_count * 11
    // Checksum bits = total_bits / 33  (equivalently: entropy_bits / 32)
    // Entropy bits = total_bits - checksum_bits
    //
    // word_count is one of [12, 15, 18, 21, 24] (validated above),
    // so these divisions are safe.
    #[allow(clippy::arithmetic_side_effects)]
    let total_bits = word_count * 11;
    #[allow(clippy::arithmetic_side_effects)]
    let checksum_bits = total_bits / 33;
    #[allow(clippy::arithmetic_side_effects)]
    let entropy_bits = total_bits - checksum_bits;
    #[allow(clippy::arithmetic_side_effects)]
    let entropy_bytes = entropy_bits / 8;

    // Build the concatenated bitstream from 11-bit indices.
    let bitstream = indices_to_bitstream(&indices, total_bits);

    // Split into entropy and checksum.
    let entropy = extract_bytes(&bitstream, 0, entropy_bits);
    let provided_checksum = extract_bits(&bitstream, entropy_bits, checksum_bits);

    // Compute expected checksum: first `checksum_bits` of SHA-256(entropy).
    let hash = ring::digest::digest(&ring::digest::SHA256, &entropy[..entropy_bytes]);
    let hash_bytes = hash.as_ref();
    let expected_checksum = extract_bits(hash_bytes, 0, checksum_bits);

    if provided_checksum != expected_checksum {
        return Err(CryptoError::Bip39("checksum mismatch".to_string()));
    }

    Ok(())
}

/// Validate a BIP39 passphrase (25th word).
///
/// The passphrase itself has no format constraints beyond being valid UTF-8
/// (which is guaranteed by Rust's `&str`). This function exists as a
/// validation entry point — passphrase storage and encryption are handled
/// by `verrou-vault` (Epic 6).
///
/// # Errors
///
/// Returns `CryptoError::Bip39` if the passphrase is empty.
pub fn validate_passphrase(passphrase: &str) -> Result<(), CryptoError> {
    if passphrase.is_empty() {
        return Err(CryptoError::Bip39(
            "passphrase must not be empty".to_string(),
        ));
    }
    Ok(())
}

// ── Bitstream Helpers ──────────────────────────────────────────────

/// Convert a slice of 11-bit word indices into a byte-aligned bitstream.
fn indices_to_bitstream(indices: &[u16], total_bits: usize) -> Vec<u8> {
    // Round up to full bytes.
    let byte_count = total_bits.div_ceil(8);
    let mut bitstream = vec![0u8; byte_count];

    let mut bit_pos: usize = 0;
    for &idx in indices {
        // Write 11 bits of `idx` into the bitstream at `bit_pos`.
        for bit_offset in (0u32..11).rev() {
            #[allow(clippy::arithmetic_side_effects)]
            let bit = (idx >> bit_offset) & 1;
            if bit == 1 {
                #[allow(clippy::arithmetic_side_effects)]
                let byte_idx = bit_pos / 8;
                #[allow(clippy::arithmetic_side_effects)]
                let shift = 7 - (bit_pos % 8);
                // byte_idx is within bounds: bit_pos < total_bits <= byte_count * 8.
                // shift is 0..=7 (safe for u8).
                #[allow(clippy::arithmetic_side_effects)]
                {
                    bitstream[byte_idx] |= 1u8 << shift;
                }
            }
            #[allow(clippy::arithmetic_side_effects)]
            {
                bit_pos += 1;
            }
        }
    }

    bitstream
}

/// Extract `num_bits` starting at `start_bit` from a byte slice, returning
/// complete bytes (zero-padded if `num_bits` is not a multiple of 8).
fn extract_bytes(data: &[u8], start_bit: usize, num_bits: usize) -> Vec<u8> {
    let byte_count = num_bits.div_ceil(8);
    let mut result = vec![0u8; byte_count];

    for i in 0..num_bits {
        #[allow(clippy::arithmetic_side_effects)]
        let src_byte = (start_bit + i) / 8;
        #[allow(clippy::arithmetic_side_effects)]
        let src_bit = 7 - ((start_bit + i) % 8);
        #[allow(clippy::arithmetic_side_effects)]
        let dst_byte = i / 8;
        #[allow(clippy::arithmetic_side_effects)]
        let dst_bit = 7 - (i % 8);

        #[allow(clippy::arithmetic_side_effects)]
        let bit = (data[src_byte] >> src_bit) & 1;
        if bit == 1 {
            #[allow(clippy::arithmetic_side_effects)]
            {
                result[dst_byte] |= 1u8 << dst_bit;
            }
        }
    }

    result
}

/// Extract `num_bits` from `data` starting at `start_bit`, returned as
/// a right-aligned `u8`. Only supports `num_bits` <= 8.
fn extract_bits(data: &[u8], start_bit: usize, num_bits: usize) -> u8 {
    debug_assert!(num_bits <= 8, "extract_bits only supports up to 8 bits");
    let mut result: u8 = 0;

    for i in 0..num_bits {
        #[allow(clippy::arithmetic_side_effects)]
        let byte_idx = (start_bit + i) / 8;
        #[allow(clippy::arithmetic_side_effects)]
        let bit_idx = 7 - ((start_bit + i) % 8);
        #[allow(clippy::arithmetic_side_effects)]
        let bit = (data[byte_idx] >> bit_idx) & 1;
        #[allow(clippy::arithmetic_side_effects)]
        let shift = (num_bits - 1) - i;
        #[allow(clippy::arithmetic_side_effects)]
        {
            result |= bit << shift;
        }
    }

    result
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_word tests ────────────────────────────────────────

    #[test]
    fn validate_word_known_english_words() {
        assert!(validate_word("abandon", Bip39Language::English));
        assert!(validate_word("zoo", Bip39Language::English));
        assert!(validate_word("ability", Bip39Language::English));
        assert!(validate_word("abstract", Bip39Language::English));
    }

    #[test]
    fn validate_word_rejects_non_bip39_words() {
        assert!(!validate_word("xyz123", Bip39Language::English));
        assert!(!validate_word("notaword", Bip39Language::English));
        assert!(!validate_word("", Bip39Language::English));
        assert!(!validate_word("ABANDON", Bip39Language::English)); // case sensitive
    }

    #[test]
    fn validate_word_all_languages_first_and_last() {
        for lang in Bip39Language::all() {
            let wordlist = get_wordlist(lang);
            let first = wordlist[0];
            #[allow(clippy::arithmetic_side_effects)]
            let last = wordlist[WORDLIST_SIZE - 1];
            assert!(
                validate_word(first, lang),
                "first word '{first}' not valid for {lang:?}"
            );
            assert!(
                validate_word(last, lang),
                "last word '{last}' not valid for {lang:?}"
            );
        }
    }

    // ── suggest_words tests ────────────────────────────────────────

    #[test]
    fn suggest_words_prefix_match() {
        let suggestions = suggest_words("aban", Bip39Language::English, 5);
        assert!(!suggestions.is_empty());
        assert!(suggestions.contains(&"abandon"));
        for s in &suggestions {
            assert!(
                s.starts_with("aban"),
                "suggestion '{s}' does not start with 'aban'"
            );
        }
    }

    #[test]
    fn suggest_words_empty_prefix_returns_first_n() {
        let suggestions = suggest_words("", Bip39Language::English, 3);
        assert_eq!(suggestions.len(), 3);
        let wordlist = get_wordlist(Bip39Language::English);
        assert_eq!(suggestions[0], wordlist[0]);
        assert_eq!(suggestions[1], wordlist[1]);
        assert_eq!(suggestions[2], wordlist[2]);
    }

    #[test]
    fn suggest_words_no_match_returns_empty() {
        let suggestions = suggest_words("zzzzzzz", Bip39Language::English, 10);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn suggest_words_respects_max() {
        let suggestions = suggest_words("a", Bip39Language::English, 2);
        assert!(suggestions.len() <= 2);
    }

    // ── word_index tests ───────────────────────────────────────────

    #[test]
    fn word_index_correct_for_known_words() {
        // "abandon" is the first word in English (index 0).
        assert_eq!(word_index("abandon", Bip39Language::English), Some(0));
        // "zoo" is the last word in English (index 2047).
        assert_eq!(word_index("zoo", Bip39Language::English), Some(2047));
    }

    #[test]
    fn word_index_returns_none_for_unknown() {
        assert_eq!(word_index("notaword", Bip39Language::English), None);
    }

    // ── validate_phrase tests ──────────────────────────────────────

    #[test]
    fn validate_phrase_valid_12_word_english() {
        // Known valid 12-word mnemonic from BIP39 test vectors (Trezor).
        let words: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .collect();
        let result = validate_phrase(&words, Bip39Language::English);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn validate_phrase_valid_24_word_english() {
        // Known valid 24-word mnemonic (all zeros entropy + correct checksum).
        let words: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
                .split_whitespace()
                .collect();
        let result = validate_phrase(&words, Bip39Language::English);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn validate_phrase_rejects_wrong_word_count() {
        let words_11: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
                .split_whitespace()
                .collect();
        let result = validate_phrase(&words_11, Bip39Language::English);
        assert!(result.is_err());
        let err = result.expect_err("expected error").to_string();
        assert!(
            err.contains("invalid word count"),
            "unexpected error: {err}"
        );

        // 13 words
        let words_13: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about zoo"
                .split_whitespace()
                .collect();
        let result = validate_phrase(&words_13, Bip39Language::English);
        assert!(result.is_err());
    }

    #[test]
    fn validate_phrase_rejects_invalid_checksum() {
        // Valid 12-word phrase with last word swapped to break checksum.
        let words: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
                .split_whitespace()
                .collect();
        let result = validate_phrase(&words, Bip39Language::English);
        assert!(result.is_err());
        let err = result.expect_err("expected error").to_string();
        assert!(err.contains("checksum mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn validate_phrase_rejects_non_bip39_word() {
        let words: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
                .split_whitespace()
                .collect();
        let result = validate_phrase(&words, Bip39Language::English);
        assert!(result.is_err());
        let err = result.expect_err("expected error").to_string();
        assert!(err.contains("word not found"), "unexpected error: {err}");
    }

    #[test]
    fn validate_phrase_rejects_empty_word() {
        let words: Vec<&str> = vec![
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "",
        ];
        let result = validate_phrase(&words, Bip39Language::English);
        assert!(result.is_err());
        let err = result.expect_err("expected error").to_string();
        assert!(err.contains("empty word"), "unexpected error: {err}");
    }

    // ── wordlist integrity tests ───────────────────────────────────

    #[test]
    fn all_wordlists_have_2048_entries() {
        for lang in Bip39Language::all() {
            let wordlist = get_wordlist(lang);
            assert_eq!(
                wordlist.len(),
                WORDLIST_SIZE,
                "{lang:?} wordlist has {} entries, expected {WORDLIST_SIZE}",
                wordlist.len()
            );
        }
    }

    #[test]
    fn sorted_wordlists_are_actually_sorted() {
        for lang in Bip39Language::all() {
            if lang.is_sorted_for_binary_search() {
                let wordlist = get_wordlist(lang);
                for i in 1..wordlist.len() {
                    assert!(
                        wordlist[i] > wordlist[i.wrapping_sub(1)],
                        "{lang:?} wordlist not sorted at index {i}: '{}' <= '{}'",
                        wordlist[i],
                        wordlist[i.wrapping_sub(1)]
                    );
                }
            }
        }
    }

    // ── passphrase tests ───────────────────────────────────────────

    #[test]
    fn validate_passphrase_accepts_valid() {
        assert!(validate_passphrase("my secret passphrase").is_ok());
        assert!(validate_passphrase("a").is_ok());
        assert!(validate_passphrase("日本語パスフレーズ").is_ok());
    }

    #[test]
    fn validate_passphrase_rejects_empty() {
        assert!(validate_passphrase("").is_err());
    }

    // ── performance test ───────────────────────────────────────────

    #[test]
    fn word_validation_performance() {
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = validate_word("abandon", Bip39Language::English);
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 1,
            "10000 word validations took {elapsed:?}, expected < 1s"
        );
    }

    #[test]
    fn phrase_validation_performance() {
        let words: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .collect();
        let start = std::time::Instant::now();
        for _ in 0..1_000 {
            let _ = validate_phrase(&words, Bip39Language::English);
        }
        let elapsed = start.elapsed();
        // 1000 validations should complete in < 1s (i.e., < 1ms each, well under 10ms budget).
        assert!(
            elapsed.as_secs() < 1,
            "1000 phrase validations took {elapsed:?}, expected < 1s"
        );
    }
}
