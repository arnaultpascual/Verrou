//! EFF diceware wordlist loading.
//!
//! The EFF large wordlist (7776 words) is embedded at compile time via `include_str!`.
//! It is parsed once on first access using `OnceLock`.

use std::sync::OnceLock;

/// Number of words in the EFF large diceware wordlist.
pub const EFF_WORDLIST_SIZE: usize = 7776;

const EFF_LARGE_RAW: &str = include_str!("wordlists/eff_large.txt");

static EFF_LARGE_LOCK: OnceLock<Box<[&'static str]>> = OnceLock::new();

/// Returns the parsed EFF large diceware wordlist (7776 words).
///
/// The wordlist is parsed lazily on first access and cached for the
/// lifetime of the process.
///
/// # Panics
///
/// Panics if the embedded wordlist does not contain exactly [`EFF_WORDLIST_SIZE`] words.
#[must_use]
pub fn eff_large() -> &'static [&'static str] {
    EFF_LARGE_LOCK.get_or_init(|| {
        let words: Vec<&'static str> = EFF_LARGE_RAW.lines().collect();
        assert!(
            words.len() == EFF_WORDLIST_SIZE,
            "EFF wordlist must contain exactly {EFF_WORDLIST_SIZE} words, got {}",
            words.len()
        );
        words.into_boxed_slice()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eff_list_has_7776_entries() {
        assert_eq!(eff_large().len(), EFF_WORDLIST_SIZE);
    }

    #[test]
    fn no_empty_words() {
        for (i, word) in eff_large().iter().enumerate() {
            assert!(!word.is_empty(), "word at index {i} is empty");
        }
    }

    #[test]
    fn all_lowercase() {
        for (i, word) in eff_large().iter().enumerate() {
            assert_eq!(
                *word,
                word.to_lowercase(),
                "word at index {i} ('{word}') is not lowercase"
            );
        }
    }
}
