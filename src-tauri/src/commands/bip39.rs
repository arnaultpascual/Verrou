//! BIP39 validation IPC commands.
//!
//! These commands expose `verrou-crypto-core::bip39` functions to the frontend
//! for real-time word validation, autocomplete suggestions, and phrase checksum
//! verification. They NEVER send full wordlists to the frontend (NFR22).

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use verrou_crypto_core::bip39::{self, Bip39Language};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Result of validating a single BIP39 word.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bip39WordResult {
    /// Whether the word exists in the specified language's BIP39 wordlist.
    pub valid: bool,
}

/// Result of validating a complete BIP39 phrase (checksum verification).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bip39PhraseResult {
    /// Whether the phrase passes word count, word membership, and checksum.
    pub valid: bool,
    /// Human-readable error message if validation failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Language parser
// ---------------------------------------------------------------------------

/// Parse a language string to a `Bip39Language` enum value.
///
/// Accepts lowercase English names: `"english"`, `"japanese"`, `"korean"`,
/// `"spanish"`, `"chinese_simplified"`, `"chinese_traditional"`, `"french"`,
/// `"italian"`, `"czech"`, `"portuguese"`.
pub(crate) fn parse_language(s: &str) -> Result<Bip39Language, String> {
    match s {
        "english" => Ok(Bip39Language::English),
        "japanese" => Ok(Bip39Language::Japanese),
        "korean" => Ok(Bip39Language::Korean),
        "spanish" => Ok(Bip39Language::Spanish),
        "chinese_simplified" => Ok(Bip39Language::ChineseSimplified),
        "chinese_traditional" => Ok(Bip39Language::ChineseTraditional),
        "french" => Ok(Bip39Language::French),
        "italian" => Ok(Bip39Language::Italian),
        "czech" => Ok(Bip39Language::Czech),
        "portuguese" => Ok(Bip39Language::Portuguese),
        other => Err(format!(
            "Unknown BIP39 language: '{other}'. Expected one of: english, japanese, korean, \
             spanish, chinese_simplified, chinese_traditional, french, italian, czech, portuguese."
        )),
    }
}

// ---------------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------------

/// Validate a single word against a BIP39 wordlist.
///
/// Returns `{ valid: true }` if the word exists in the specified language
/// wordlist, `{ valid: false }` otherwise. The input word is zeroized after use.
///
/// # Errors
///
/// Returns a string error if the language is not supported.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn bip39_validate_word(mut word: String, language: String) -> Result<Bip39WordResult, String> {
    let lang = parse_language(&language)?;
    let valid = bip39::validate_word(&word, lang);
    word.zeroize();
    Ok(Bip39WordResult { valid })
}

/// Get autocomplete suggestions for a BIP39 word prefix.
///
/// Returns up to `max` words (default 5) from the specified language
/// wordlist that start with the given prefix. The prefix is zeroized after use.
///
/// # Errors
///
/// Returns a string error if the language is not supported.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn bip39_suggest_words(
    mut prefix: String,
    language: String,
    max: Option<usize>,
) -> Result<Vec<String>, String> {
    let lang = parse_language(&language)?;
    let limit = max.unwrap_or(5);
    let suggestions = bip39::suggest_words(&prefix, lang, limit);
    prefix.zeroize();
    Ok(suggestions.into_iter().map(String::from).collect())
}

/// Validate a complete BIP39 mnemonic phrase (word count + checksum).
///
/// Returns `{ valid: true }` if the phrase has a valid word count
/// (12/15/18/21/24), all words exist in the wordlist, and the SHA-256
/// checksum matches. Words are zeroized after validation.
///
/// # Errors
///
/// Returns a string error if the language is not supported.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn bip39_validate_phrase(
    mut words: Vec<String>,
    language: String,
) -> Result<Bip39PhraseResult, String> {
    let lang = parse_language(&language)?;

    // Convert to &str slice for crypto-core API.
    let word_refs: Vec<&str> = words.iter().map(String::as_str).collect();
    let result = bip39::validate_phrase(&word_refs, lang);

    // Zeroize all words after validation.
    for w in &mut words {
        w.zeroize();
    }

    match result {
        Ok(()) => Ok(Bip39PhraseResult {
            valid: true,
            error: None,
        }),
        Err(e) => Ok(Bip39PhraseResult {
            valid: false,
            error: Some(e.to_string()),
        }),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── bip39_validate_word tests ────────────────────────────────────

    #[test]
    fn validate_word_valid_english() {
        let result = bip39_validate_word("abandon".to_string(), "english".to_string());
        assert!(result.is_ok());
        assert!(result.unwrap().valid);
    }

    #[test]
    fn validate_word_valid_english_last() {
        let result = bip39_validate_word("zoo".to_string(), "english".to_string());
        assert!(result.is_ok());
        assert!(result.unwrap().valid);
    }

    #[test]
    fn validate_word_invalid_english() {
        let result = bip39_validate_word("xyz123".to_string(), "english".to_string());
        assert!(result.is_ok());
        assert!(!result.unwrap().valid);
    }

    #[test]
    fn validate_word_empty_string() {
        let result = bip39_validate_word(String::new(), "english".to_string());
        assert!(result.is_ok());
        assert!(!result.unwrap().valid);
    }

    #[test]
    fn validate_word_unknown_language() {
        let result = bip39_validate_word("abandon".to_string(), "klingon".to_string());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Unknown BIP39 language"));
    }

    #[test]
    fn validate_word_case_sensitive() {
        let result = bip39_validate_word("ABANDON".to_string(), "english".to_string());
        assert!(result.is_ok());
        assert!(!result.unwrap().valid); // BIP39 wordlists are lowercase
    }

    // ── bip39_suggest_words tests ────────────────────────────────────

    #[test]
    fn suggest_words_prefix_match() {
        let result = bip39_suggest_words("aban".to_string(), "english".to_string(), None);
        assert!(result.is_ok());
        let suggestions = result.unwrap();
        assert!(!suggestions.is_empty());
        assert!(suggestions.contains(&"abandon".to_string()));
        for s in &suggestions {
            assert!(
                s.starts_with("aban"),
                "suggestion '{s}' does not start with 'aban'"
            );
        }
    }

    #[test]
    fn suggest_words_respects_max_limit() {
        let result = bip39_suggest_words("a".to_string(), "english".to_string(), Some(2));
        assert!(result.is_ok());
        let suggestions = result.unwrap();
        assert!(suggestions.len() <= 2);
    }

    #[test]
    fn suggest_words_no_match() {
        let result = bip39_suggest_words("zzzzzzz".to_string(), "english".to_string(), None);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn suggest_words_default_max_is_five() {
        let result = bip39_suggest_words("a".to_string(), "english".to_string(), None);
        assert!(result.is_ok());
        let suggestions = result.unwrap();
        assert!(suggestions.len() <= 5);
    }

    #[test]
    fn suggest_words_unknown_language() {
        let result = bip39_suggest_words("aban".to_string(), "martian".to_string(), None);
        assert!(result.is_err());
    }

    // ── bip39_validate_phrase tests ────────────────────────────────────

    #[test]
    fn validate_phrase_valid_12_word() {
        let words: Vec<String> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .map(String::from)
                .collect();
        let result = bip39_validate_phrase(words, "english".to_string());
        assert!(result.is_ok());
        let phrase_result = result.unwrap();
        assert!(phrase_result.valid);
        assert!(phrase_result.error.is_none());
    }

    #[test]
    fn validate_phrase_valid_24_word() {
        let words: Vec<String> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
                .split_whitespace()
                .map(String::from)
                .collect();
        let result = bip39_validate_phrase(words, "english".to_string());
        assert!(result.is_ok());
        let phrase_result = result.unwrap();
        assert!(phrase_result.valid);
        assert!(phrase_result.error.is_none());
    }

    #[test]
    fn validate_phrase_checksum_mismatch() {
        let words: Vec<String> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo"
                .split_whitespace()
                .map(String::from)
                .collect();
        let result = bip39_validate_phrase(words, "english".to_string());
        assert!(result.is_ok());
        let phrase_result = result.unwrap();
        assert!(!phrase_result.valid);
        let err = phrase_result.error.unwrap();
        assert!(
            err.contains("checksum"),
            "expected checksum error, got: {err}"
        );
    }

    #[test]
    fn validate_phrase_invalid_word_count() {
        let words: Vec<String> = vec!["abandon".into(), "abandon".into(), "abandon".into()];
        let result = bip39_validate_phrase(words, "english".to_string());
        assert!(result.is_ok());
        let phrase_result = result.unwrap();
        assert!(!phrase_result.valid);
        let err = phrase_result.error.unwrap();
        assert!(
            err.contains("word count"),
            "expected word count error, got: {err}"
        );
    }

    #[test]
    fn validate_phrase_invalid_word_in_phrase() {
        let words: Vec<String> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
                .split_whitespace()
                .map(String::from)
                .collect();
        let result = bip39_validate_phrase(words, "english".to_string());
        assert!(result.is_ok());
        let phrase_result = result.unwrap();
        assert!(!phrase_result.valid);
        let err = phrase_result.error.unwrap();
        assert!(
            err.contains("word not found"),
            "expected word not found error, got: {err}"
        );
    }

    #[test]
    fn validate_phrase_unknown_language() {
        let words: Vec<String> = vec!["abandon".into(); 12];
        let result = bip39_validate_phrase(words, "elvish".to_string());
        assert!(result.is_err());
    }

    // ── parse_language tests ────────────────────────────────────────

    #[test]
    fn parse_all_ten_languages() {
        let langs = [
            "english",
            "japanese",
            "korean",
            "spanish",
            "chinese_simplified",
            "chinese_traditional",
            "french",
            "italian",
            "czech",
            "portuguese",
        ];
        for lang_str in &langs {
            let result = parse_language(lang_str);
            assert!(result.is_ok(), "failed to parse language: {lang_str}");
        }
    }

    // ── zeroization tests ────────────────────────────────────────────

    #[test]
    fn validate_word_zeroizes_input() {
        let word = "abandon".to_string();

        // Call the command — it takes ownership and zeroizes internally.
        // This test validates the zeroize code path runs without panic.
        let result = bip39_validate_word(word, "english".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn validate_phrase_zeroizes_words() {
        let words: Vec<String> = vec!["abandon".into(); 12];
        // Same as above — validates the zeroize path runs without panic.
        let _ = bip39_validate_phrase(words, "english".to_string());
    }
}
