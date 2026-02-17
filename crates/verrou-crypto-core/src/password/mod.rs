//! Cryptographic password and passphrase generation.
//!
//! Provides two generation modes:
//! - [`generate_random_password`] — character-based with configurable charsets
//! - [`generate_passphrase`] — word-based using the EFF large diceware wordlist
//!
//! Both use `OsRng` (OS-level CSPRNG) for all randomness.

pub mod wordlist;

use rand::seq::SliceRandom;
use rand::Rng;

use crate::error::CryptoError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum allowed password length.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// Maximum allowed password length.
pub const MAX_PASSWORD_LENGTH: usize = 128;

/// Default password length.
pub const DEFAULT_PASSWORD_LENGTH: usize = 20;

/// Minimum allowed passphrase word count.
pub const MIN_WORD_COUNT: usize = 3;

/// Maximum allowed passphrase word count.
pub const MAX_WORD_COUNT: usize = 10;

/// Default passphrase word count.
pub const DEFAULT_WORD_COUNT: usize = 5;

// Character sets
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:',.<>?/~";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Configuration for which character sets to include in a random password.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CharsetConfig {
    /// Include uppercase letters (A-Z).
    pub uppercase: bool,
    /// Include lowercase letters (a-z).
    pub lowercase: bool,
    /// Include digits (0-9).
    pub digits: bool,
    /// Include symbols (!@#$%^&*...).
    pub symbols: bool,
}

impl Default for CharsetConfig {
    fn default() -> Self {
        Self {
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
        }
    }
}

/// Separator between words in a passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PassphraseSeparator {
    /// Hyphen: `word-word-word`
    Hyphen,
    /// Space: `word word word`
    Space,
    /// Dot: `word.word.word`
    Dot,
    /// Underscore: `word_word_word`
    Underscore,
    /// No separator: `wordwordword`
    None,
}

impl PassphraseSeparator {
    /// Returns the string representation of this separator.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hyphen => "-",
            Self::Space => " ",
            Self::Dot => ".",
            Self::Underscore => "_",
            Self::None => "",
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a random password of the given `length` using the specified charsets.
///
/// At least one character from each enabled charset is guaranteed.
/// The remaining positions are filled randomly, then the whole password is
/// Fisher-Yates shuffled to avoid positional bias.
///
/// # Errors
///
/// Returns [`CryptoError::PasswordGeneration`] if:
/// - `length` is outside [`MIN_PASSWORD_LENGTH`]..=[`MAX_PASSWORD_LENGTH`]
/// - No charset is enabled
/// - `length` is less than the number of enabled charsets (can't guarantee one from each)
///
/// # Panics
///
/// Panics if the generated password bytes are not valid UTF-8 (should never happen
/// since all character sets are ASCII).
pub fn generate_random_password(
    length: usize,
    charsets: &CharsetConfig,
) -> Result<String, CryptoError> {
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&length) {
        return Err(CryptoError::PasswordGeneration(format!(
            "length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}, got {length}"
        )));
    }

    // Build the character pool and collect mandatory characters.
    let mut pool: Vec<u8> = Vec::new();
    let mut mandatory: Vec<u8> = Vec::new();
    let mut rng = rand::rngs::OsRng;

    if charsets.uppercase {
        pool.extend_from_slice(UPPERCASE);
        mandatory.push(UPPERCASE[rng.gen_range(0..UPPERCASE.len())]);
    }
    if charsets.lowercase {
        pool.extend_from_slice(LOWERCASE);
        mandatory.push(LOWERCASE[rng.gen_range(0..LOWERCASE.len())]);
    }
    if charsets.digits {
        pool.extend_from_slice(DIGITS);
        mandatory.push(DIGITS[rng.gen_range(0..DIGITS.len())]);
    }
    if charsets.symbols {
        pool.extend_from_slice(SYMBOLS);
        mandatory.push(SYMBOLS[rng.gen_range(0..SYMBOLS.len())]);
    }

    if pool.is_empty() {
        return Err(CryptoError::PasswordGeneration(
            "at least one charset must be enabled".to_string(),
        ));
    }

    if length < mandatory.len() {
        return Err(CryptoError::PasswordGeneration(format!(
            "length ({length}) must be at least {} to include one character from each enabled charset",
            mandatory.len()
        )));
    }

    // Fill the password: mandatory chars first, then random from the full pool.
    let mut chars: Vec<u8> = mandatory;
    for _ in chars.len()..length {
        chars.push(pool[rng.gen_range(0..pool.len())]);
    }

    // Fisher-Yates shuffle to eliminate positional bias.
    chars.shuffle(&mut rng);

    // Safety: all chars are ASCII.
    Ok(String::from_utf8(chars).expect("password chars are ASCII"))
}

/// Generate a passphrase from the EFF large diceware wordlist.
///
/// # Arguments
///
/// * `word_count` — Number of words (clamped to [`MIN_WORD_COUNT`]..=[`MAX_WORD_COUNT`]).
/// * `separator` — Separator between words.
/// * `capitalize` — Capitalize the first letter of each word.
/// * `append_digit` — Append a random digit (0-9) to the end.
///
/// # Errors
///
/// Returns [`CryptoError::PasswordGeneration`] if `word_count` is outside the allowed range.
pub fn generate_passphrase(
    word_count: usize,
    separator: PassphraseSeparator,
    capitalize: bool,
    append_digit: bool,
) -> Result<String, CryptoError> {
    if !(MIN_WORD_COUNT..=MAX_WORD_COUNT).contains(&word_count) {
        return Err(CryptoError::PasswordGeneration(format!(
            "word count must be between {MIN_WORD_COUNT} and {MAX_WORD_COUNT}, got {word_count}"
        )));
    }

    let wordlist = wordlist::eff_large();
    let mut rng = rand::rngs::OsRng;

    let words: Vec<String> = (0..word_count)
        .map(|_| {
            let word = wordlist[rng.gen_range(0..wordlist.len())];
            if capitalize {
                let mut chars = word.chars();
                chars.next().map_or_else(String::new, |c| {
                    c.to_uppercase().collect::<String>() + chars.as_str()
                })
            } else {
                word.to_string()
            }
        })
        .collect();

    let mut result = words.join(separator.as_str());

    if append_digit {
        const DIGIT_CHARS: &[u8] = b"0123456789";
        let digit = DIGIT_CHARS[rng.gen_range(0..DIGIT_CHARS.len())];
        result.push(char::from(digit));
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ── Random password tests ──────────────────────────────────────

    #[test]
    fn default_length_password() {
        let pw =
            generate_random_password(DEFAULT_PASSWORD_LENGTH, &CharsetConfig::default()).unwrap();
        assert_eq!(pw.len(), DEFAULT_PASSWORD_LENGTH);
    }

    #[test]
    fn min_length_password() {
        let pw = generate_random_password(MIN_PASSWORD_LENGTH, &CharsetConfig::default()).unwrap();
        assert_eq!(pw.len(), MIN_PASSWORD_LENGTH);
    }

    #[test]
    fn max_length_password() {
        let pw = generate_random_password(MAX_PASSWORD_LENGTH, &CharsetConfig::default()).unwrap();
        assert_eq!(pw.len(), MAX_PASSWORD_LENGTH);
    }

    #[test]
    fn below_min_rejected() {
        let result = generate_random_password(MIN_PASSWORD_LENGTH - 1, &CharsetConfig::default());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("length must be between"));
    }

    #[test]
    fn above_max_rejected() {
        let result = generate_random_password(MAX_PASSWORD_LENGTH + 1, &CharsetConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn no_charset_error() {
        let charsets = CharsetConfig {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
        };
        let result = generate_random_password(20, &charsets);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("at least one charset"));
    }

    #[test]
    fn contains_all_enabled_charsets() {
        // Generate 50 passwords and verify each contains at least one from each charset.
        for _ in 0..50 {
            let pw = generate_random_password(20, &CharsetConfig::default()).unwrap();
            assert!(
                pw.chars().any(|c| c.is_ascii_uppercase()),
                "missing uppercase in: {pw}"
            );
            assert!(
                pw.chars().any(|c| c.is_ascii_lowercase()),
                "missing lowercase in: {pw}"
            );
            assert!(
                pw.chars().any(|c| c.is_ascii_digit()),
                "missing digit in: {pw}"
            );
            assert!(
                pw.chars().any(|c| !c.is_ascii_alphanumeric()),
                "missing symbol in: {pw}"
            );
        }
    }

    #[test]
    fn uppercase_only() {
        let charsets = CharsetConfig {
            uppercase: true,
            lowercase: false,
            digits: false,
            symbols: false,
        };
        let pw = generate_random_password(20, &charsets).unwrap();
        assert!(
            pw.chars().all(|c| c.is_ascii_uppercase()),
            "not all uppercase: {pw}"
        );
    }

    #[test]
    fn lowercase_only() {
        let charsets = CharsetConfig {
            uppercase: false,
            lowercase: true,
            digits: false,
            symbols: false,
        };
        let pw = generate_random_password(20, &charsets).unwrap();
        assert!(
            pw.chars().all(|c| c.is_ascii_lowercase()),
            "not all lowercase: {pw}"
        );
    }

    #[test]
    fn digits_only() {
        let charsets = CharsetConfig {
            uppercase: false,
            lowercase: false,
            digits: true,
            symbols: false,
        };
        let pw = generate_random_password(20, &charsets).unwrap();
        assert!(
            pw.chars().all(|c| c.is_ascii_digit()),
            "not all digits: {pw}"
        );
    }

    #[test]
    fn symbols_only() {
        let charsets = CharsetConfig {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: true,
        };
        let pw = generate_random_password(20, &charsets).unwrap();
        let symbol_set: HashSet<u8> = SYMBOLS.iter().copied().collect();
        assert!(
            pw.bytes().all(|b| symbol_set.contains(&b)),
            "not all symbols: {pw}"
        );
    }

    #[test]
    fn uniqueness_random() {
        let passwords: HashSet<String> = (0..100)
            .map(|_| generate_random_password(20, &CharsetConfig::default()).unwrap())
            .collect();
        assert_eq!(passwords.len(), 100, "generated duplicate passwords");
    }

    // ── Passphrase tests ───────────────────────────────────────────

    #[test]
    fn default_passphrase() {
        let pp = generate_passphrase(
            DEFAULT_WORD_COUNT,
            PassphraseSeparator::Hyphen,
            false,
            false,
        )
        .unwrap();
        let word_count = pp.split('-').count();
        assert_eq!(word_count, DEFAULT_WORD_COUNT);
    }

    #[test]
    fn below_min_word_count_rejected() {
        let result = generate_passphrase(
            MIN_WORD_COUNT - 1,
            PassphraseSeparator::Hyphen,
            false,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn above_max_word_count_rejected() {
        let result = generate_passphrase(
            MAX_WORD_COUNT + 1,
            PassphraseSeparator::Hyphen,
            false,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn passphrase_capitalize() {
        let pp = generate_passphrase(5, PassphraseSeparator::Hyphen, true, false).unwrap();
        for word in pp.split('-') {
            let first = word.chars().next().unwrap();
            assert!(first.is_uppercase(), "word '{word}' is not capitalized");
        }
    }

    #[test]
    fn passphrase_append_digit() {
        let pp = generate_passphrase(5, PassphraseSeparator::Hyphen, false, true).unwrap();
        let last = pp.chars().last().unwrap();
        assert!(last.is_ascii_digit(), "last char '{last}' is not a digit");
    }

    #[test]
    fn passphrase_all_separators() {
        let cases = [
            (PassphraseSeparator::Hyphen, '-'),
            (PassphraseSeparator::Space, ' '),
            (PassphraseSeparator::Dot, '.'),
            (PassphraseSeparator::Underscore, '_'),
        ];
        for (sep, ch) in &cases {
            let pp = generate_passphrase(5, *sep, false, false).unwrap();
            assert!(
                pp.contains(*ch),
                "passphrase with {sep:?} separator missing '{ch}': {pp}"
            );
        }
    }

    #[test]
    fn passphrase_no_separator() {
        let pp = generate_passphrase(3, PassphraseSeparator::None, false, false).unwrap();
        // No separator — should be one continuous lowercase string.
        assert!(
            pp.chars().all(|c| c.is_ascii_lowercase()),
            "passphrase with no separator has unexpected chars: {pp}"
        );
    }

    #[test]
    fn uniqueness_passphrase() {
        let passphrases: HashSet<String> = (0..100)
            .map(|_| generate_passphrase(5, PassphraseSeparator::Hyphen, false, false).unwrap())
            .collect();
        assert_eq!(passphrases.len(), 100, "generated duplicate passphrases");
    }
}
