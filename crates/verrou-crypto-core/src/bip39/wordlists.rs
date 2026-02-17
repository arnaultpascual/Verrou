//! BIP39 wordlist loading and lookup.
//!
//! All 10 official BIP39 wordlists are embedded at compile time via `include_str!`.
//! Each wordlist is parsed once on first access using `OnceLock`.

use std::sync::OnceLock;

use super::Bip39Language;

/// Number of words in every BIP39 wordlist.
pub const WORDLIST_SIZE: usize = 2048;

// ── Embedded wordlist data ─────────────────────────────────────────

const ENGLISH_RAW: &str = include_str!("wordlists/english.txt");
const JAPANESE_RAW: &str = include_str!("wordlists/japanese.txt");
const KOREAN_RAW: &str = include_str!("wordlists/korean.txt");
const SPANISH_RAW: &str = include_str!("wordlists/spanish.txt");
const CHINESE_SIMPLIFIED_RAW: &str = include_str!("wordlists/chinese_simplified.txt");
const CHINESE_TRADITIONAL_RAW: &str = include_str!("wordlists/chinese_traditional.txt");
const FRENCH_RAW: &str = include_str!("wordlists/french.txt");
const ITALIAN_RAW: &str = include_str!("wordlists/italian.txt");
const CZECH_RAW: &str = include_str!("wordlists/czech.txt");
const PORTUGUESE_RAW: &str = include_str!("wordlists/portuguese.txt");

// ── Lazy-parsed wordlists ──────────────────────────────────────────

/// Parse a raw newline-delimited wordlist into a boxed slice of `&'static str`.
fn parse_wordlist(raw: &'static str) -> Box<[&'static str]> {
    let words: Vec<&'static str> = raw.lines().collect();
    debug_assert!(
        words.len() == WORDLIST_SIZE,
        "BIP39 wordlist must contain exactly {WORDLIST_SIZE} words, got {}",
        words.len()
    );
    words.into_boxed_slice()
}

macro_rules! wordlist_accessor {
    ($name:ident, $lock:ident, $raw:ident) => {
        static $lock: OnceLock<Box<[&'static str]>> = OnceLock::new();

        fn $name() -> &'static [&'static str] {
            $lock.get_or_init(|| parse_wordlist($raw))
        }
    };
}

wordlist_accessor!(english, ENGLISH_LOCK, ENGLISH_RAW);
wordlist_accessor!(japanese, JAPANESE_LOCK, JAPANESE_RAW);
wordlist_accessor!(korean, KOREAN_LOCK, KOREAN_RAW);
wordlist_accessor!(spanish, SPANISH_LOCK, SPANISH_RAW);
wordlist_accessor!(
    chinese_simplified,
    CHINESE_SIMPLIFIED_LOCK,
    CHINESE_SIMPLIFIED_RAW
);
wordlist_accessor!(
    chinese_traditional,
    CHINESE_TRADITIONAL_LOCK,
    CHINESE_TRADITIONAL_RAW
);
wordlist_accessor!(french, FRENCH_LOCK, FRENCH_RAW);
wordlist_accessor!(italian, ITALIAN_LOCK, ITALIAN_RAW);
wordlist_accessor!(czech, CZECH_LOCK, CZECH_RAW);
wordlist_accessor!(portuguese, PORTUGUESE_LOCK, PORTUGUESE_RAW);

// ── Public API ─────────────────────────────────────────────────────

/// Returns the parsed wordlist for the given language.
///
/// The wordlist is parsed lazily on first access and cached for the
/// lifetime of the process.
#[must_use]
pub fn get_wordlist(language: Bip39Language) -> &'static [&'static str] {
    match language {
        Bip39Language::English => english(),
        Bip39Language::Japanese => japanese(),
        Bip39Language::Korean => korean(),
        Bip39Language::Spanish => spanish(),
        Bip39Language::ChineseSimplified => chinese_simplified(),
        Bip39Language::ChineseTraditional => chinese_traditional(),
        Bip39Language::French => french(),
        Bip39Language::Italian => italian(),
        Bip39Language::Czech => czech(),
        Bip39Language::Portuguese => portuguese(),
    }
}

/// Check whether `word` exists in the BIP39 wordlist for `language`.
///
/// Uses binary search for byte-order sorted wordlists (English, Italian,
/// Portuguese). Falls back to linear scan for wordlists with accented
/// characters or non-Latin scripts (Japanese, Korean, Chinese, Spanish,
/// French, Czech).
#[must_use]
pub fn validate_word(word: &str, language: Bip39Language) -> bool {
    let wordlist = get_wordlist(language);
    if language.is_sorted_for_binary_search() {
        wordlist.binary_search(&word).is_ok()
    } else {
        wordlist.contains(&word)
    }
}

/// Returns the 0-based index of `word` in the BIP39 wordlist for `language`.
///
/// Returns `None` if the word is not found.
#[must_use]
pub fn word_index(word: &str, language: Bip39Language) -> Option<u16> {
    let wordlist = get_wordlist(language);
    if language.is_sorted_for_binary_search() {
        wordlist
            .binary_search(&word)
            .ok()
            .and_then(|i| u16::try_from(i).ok())
    } else {
        wordlist
            .iter()
            .position(|w| *w == word)
            .and_then(|i| u16::try_from(i).ok())
    }
}

/// Returns up to `max` words from the BIP39 wordlist for `language`
/// that start with `prefix`.
///
/// For alphabetically sorted wordlists, uses binary search to find the
/// prefix range efficiently. For others, uses linear scan.
#[must_use]
pub fn suggest_words(prefix: &str, language: Bip39Language, max: usize) -> Vec<&'static str> {
    let wordlist = get_wordlist(language);

    if prefix.is_empty() {
        return wordlist.iter().take(max).copied().collect();
    }

    if language.is_sorted_for_binary_search() {
        // Binary search to find the first word >= prefix.
        let start = wordlist.partition_point(|w| *w < prefix);
        wordlist[start..]
            .iter()
            .take_while(|w| w.starts_with(prefix))
            .take(max)
            .copied()
            .collect()
    } else {
        wordlist
            .iter()
            .filter(|w| w.starts_with(prefix))
            .take(max)
            .copied()
            .collect()
    }
}
