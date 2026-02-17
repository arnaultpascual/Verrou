#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Property-based tests for BIP39 wordlist validation.

use proptest::prelude::*;
use verrou_crypto_core::bip39::{
    get_wordlist, suggest_words, validate_word, word_index, Bip39Language, WORDLIST_SIZE,
};

/// Strategy for `Bip39Language`.
fn language_strategy() -> impl Strategy<Value = Bip39Language> {
    prop_oneof![
        Just(Bip39Language::English),
        Just(Bip39Language::Japanese),
        Just(Bip39Language::Korean),
        Just(Bip39Language::Spanish),
        Just(Bip39Language::ChineseSimplified),
        Just(Bip39Language::ChineseTraditional),
        Just(Bip39Language::French),
        Just(Bip39Language::Italian),
        Just(Bip39Language::Czech),
        Just(Bip39Language::Portuguese),
    ]
}

/// Strategy for a valid word index (0..2048).
fn index_strategy() -> impl Strategy<Value = usize> {
    0..WORDLIST_SIZE
}

proptest! {
    /// Every word in every wordlist validates as a valid word.
    #[test]
    fn all_wordlist_words_are_valid(
        lang in language_strategy(),
        idx in index_strategy(),
    ) {
        let wordlist = get_wordlist(lang);
        let word = wordlist[idx];
        prop_assert!(
            validate_word(word, lang),
            "word '{}' at index {} not valid for {:?}",
            word,
            idx,
            lang
        );
    }

    /// `suggest_words` always returns words that are valid BIP39 words.
    #[test]
    fn suggestions_are_valid_words(
        lang in language_strategy(),
        prefix_len in 1usize..4,
        idx in index_strategy(),
    ) {
        let wordlist = get_wordlist(lang);
        let word = wordlist[idx];
        // Use a prefix of the word.
        let prefix: String = word.chars().take(prefix_len).collect();
        let suggestions = suggest_words(&prefix, lang, 10);
        for s in &suggestions {
            prop_assert!(
                validate_word(s, lang),
                "suggestion '{}' is not a valid BIP39 word for {:?}",
                s,
                lang
            );
        }
    }

    /// `word_index` roundtrips: index → wordlist[index] → word_index == original.
    #[test]
    fn word_index_roundtrip(
        lang in language_strategy(),
        idx in index_strategy(),
    ) {
        let wordlist = get_wordlist(lang);
        let word = wordlist[idx];
        let found_idx = word_index(word, lang);
        prop_assert_eq!(
            found_idx,
            Some(u16::try_from(idx).expect("index fits u16")),
            "word_index roundtrip failed for '{}' at index {} in {:?}",
            word,
            idx,
            lang
        );
    }

    /// `validate_phrase` is deterministic.
    #[test]
    fn validate_phrase_is_deterministic(
        lang in Just(Bip39Language::English),
    ) {
        let words: Vec<&str> =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .split_whitespace()
                .collect();
        let r1 = verrou_crypto_core::bip39::validate_phrase(&words, lang);
        let r2 = verrou_crypto_core::bip39::validate_phrase(&words, lang);
        // Both should be Ok(()) — deterministic.
        prop_assert!(r1.is_ok(), "first call failed");
        prop_assert!(r2.is_ok(), "second call failed");
    }
}
