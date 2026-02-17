//! Integration tests for BIP39 wordlist validation.
//!
//! Tests the full BIP39 lifecycle: word validation, phrase checksum,
//! suggestion → validation roundtrip, and cross-language behavior.

use verrou_crypto_core::bip39::validate_passphrase;
use verrou_crypto_core::bip39::{
    get_wordlist, suggest_words, validate_phrase, validate_word, word_index, Bip39Language,
};

/// Validate all words in a phrase individually, then validate the full phrase.
#[test]
fn validate_all_words_then_phrase() {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    // Each word individually valid.
    for word in &words {
        assert!(
            validate_word(word, Bip39Language::English),
            "word '{word}' should be valid"
        );
    }

    // Full phrase valid (checksum).
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

/// Same word index in different languages produces different strings but same index.
#[test]
fn cross_language_same_index_different_strings() {
    let idx = 42usize;
    let en_wordlist = get_wordlist(Bip39Language::English);
    let ja_wordlist = get_wordlist(Bip39Language::Japanese);

    let en_word = en_wordlist[idx];
    let ja_word = ja_wordlist[idx];

    // Different strings (English and Japanese are completely different scripts).
    assert_ne!(
        en_word, ja_word,
        "same-index words should differ between languages"
    );

    // Same index.
    assert_eq!(
        word_index(en_word, Bip39Language::English),
        Some(u16::try_from(idx).expect("index fits u16"))
    );
    assert_eq!(
        word_index(ja_word, Bip39Language::Japanese),
        Some(u16::try_from(idx).expect("index fits u16"))
    );
}

/// Suggest → validate roundtrip: get suggestion, validate it.
#[test]
fn suggest_then_validate_roundtrip() {
    let suggestions = suggest_words("aban", Bip39Language::English, 5);
    assert!(
        !suggestions.is_empty(),
        "should have suggestions for 'aban'"
    );

    for suggestion in &suggestions {
        assert!(
            validate_word(suggestion, Bip39Language::English),
            "suggestion '{suggestion}' should be a valid BIP39 word"
        );
    }
}

/// Change one word in a valid mnemonic to break checksum.
#[test]
fn invalid_modification_breaks_checksum() {
    let valid_words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split_whitespace()
            .collect();
    validate_phrase(&valid_words, Bip39Language::English).expect("valid phrase");

    // Change the last word to break checksum.
    let mut invalid_words = valid_words;
    invalid_words[11] = "abandon"; // was "about"
    let result = validate_phrase(&invalid_words, Bip39Language::English);
    assert!(result.is_err(), "modified phrase should fail checksum");
}

/// Validate 24-word phrase with all-ff entropy.
#[test]
fn validate_24_word_all_ff_entropy() {
    let words: Vec<&str> =
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

/// Validate 15-word phrase.
#[test]
fn validate_15_word_phrase() {
    let words: Vec<&str> =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor accident"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

/// Passphrase validation accepts non-empty UTF-8 strings and rejects empty.
#[test]
fn passphrase_validation_roundtrip() {
    validate_passphrase("my secret passphrase").expect("valid passphrase");
    validate_passphrase("日本語").expect("unicode passphrase");
    validate_passphrase("a").expect("single char passphrase");
    assert!(
        validate_passphrase("").is_err(),
        "empty passphrase should be rejected"
    );
}
