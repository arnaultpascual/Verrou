//! Password/passphrase generation IPC commands.
//!
//! Stateless crypto — no vault unlock required. Wraps
//! `verrou_crypto_core::password` for the frontend.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use verrou_crypto_core::password::{
    self, CharsetConfig, PassphraseSeparator, DEFAULT_PASSWORD_LENGTH, DEFAULT_WORD_COUNT,
};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Which generation mode the frontend requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PasswordMode {
    /// Character-based random password.
    Random,
    /// Word-based passphrase (EFF diceware).
    Passphrase,
}

/// Frontend request DTO for password generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratePasswordRequest {
    /// Generation mode.
    pub mode: PasswordMode,

    // ── Random mode options ──
    /// Password length (default: 20).
    pub length: Option<usize>,
    /// Include uppercase letters (default: true).
    pub uppercase: Option<bool>,
    /// Include lowercase letters (default: true).
    pub lowercase: Option<bool>,
    /// Include digits (default: true).
    pub digits: Option<bool>,
    /// Include symbols (default: true).
    pub symbols: Option<bool>,

    // ── Passphrase mode options ──
    /// Number of words (default: 5).
    pub word_count: Option<usize>,
    /// Separator between words (default: "hyphen").
    pub separator: Option<String>,
    /// Capitalize first letter of each word (default: false).
    pub capitalize: Option<bool>,
    /// Append a random digit to the end (default: false).
    pub append_digit: Option<bool>,
}

/// Result DTO returned to the frontend.
///
/// `Debug` is manually implemented to mask the generated value and prevent
/// accidental logging of secret material.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratePasswordResult {
    /// The generated password or passphrase.
    pub value: String,
}

impl std::fmt::Debug for GeneratePasswordResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratePasswordResult")
            .field("value", &"***")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a separator string from the frontend into a [`PassphraseSeparator`].
fn parse_separator(s: &str) -> Result<PassphraseSeparator, String> {
    match s {
        "hyphen" => Ok(PassphraseSeparator::Hyphen),
        "space" => Ok(PassphraseSeparator::Space),
        "dot" => Ok(PassphraseSeparator::Dot),
        "underscore" => Ok(PassphraseSeparator::Underscore),
        "none" => Ok(PassphraseSeparator::None),
        other => Err(format!(
            "Unknown separator: '{other}'. Expected one of: hyphen, space, dot, underscore, none."
        )),
    }
}

// ---------------------------------------------------------------------------
// IPC command
// ---------------------------------------------------------------------------

/// Generate a random password or passphrase.
///
/// This is a pure stateless operation — no vault unlock required.
/// Generated values are never logged.
///
/// # Errors
///
/// Returns a string error if the parameters are invalid.
#[allow(clippy::needless_pass_by_value)]
#[tauri::command]
pub fn generate_password(
    mut request: GeneratePasswordRequest,
) -> Result<GeneratePasswordResult, String> {
    let value = match request.mode {
        PasswordMode::Random => {
            let charsets = CharsetConfig {
                uppercase: request.uppercase.unwrap_or(true),
                lowercase: request.lowercase.unwrap_or(true),
                digits: request.digits.unwrap_or(true),
                symbols: request.symbols.unwrap_or(true),
            };
            let length = request.length.unwrap_or(DEFAULT_PASSWORD_LENGTH);
            password::generate_random_password(length, &charsets).map_err(|e| e.to_string())?
        }
        PasswordMode::Passphrase => {
            let word_count = request.word_count.unwrap_or(DEFAULT_WORD_COUNT);
            let separator = match &request.separator {
                Some(s) => parse_separator(s)?,
                None => PassphraseSeparator::Hyphen,
            };
            let capitalize = request.capitalize.unwrap_or(false);
            let append_digit = request.append_digit.unwrap_or(false);
            password::generate_passphrase(word_count, separator, capitalize, append_digit)
                .map_err(|e| e.to_string())?
        }
    };

    // Zeroize request separator string (only non-trivial field).
    if let Some(ref mut s) = request.separator {
        s.zeroize();
    }

    // Note: the `value` String in GeneratePasswordResult is serialized by Tauri's
    // IPC layer and then dropped. The same ephemeral-in-memory pattern is used by
    // generate_totp / generate_hotp. Full zeroization would require Zeroizing<String>
    // with serde support, tracked as future hardening (consistent with OTP pattern).
    Ok(GeneratePasswordResult { value })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_basic_success() {
        let request = GeneratePasswordRequest {
            mode: PasswordMode::Random,
            length: Some(24),
            uppercase: Some(true),
            lowercase: Some(true),
            digits: Some(true),
            symbols: Some(true),
            word_count: None,
            separator: None,
            capitalize: None,
            append_digit: None,
        };
        let result = generate_password(request);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value.len(), 24);
    }

    #[test]
    fn passphrase_basic_success() {
        let request = GeneratePasswordRequest {
            mode: PasswordMode::Passphrase,
            length: None,
            uppercase: None,
            lowercase: None,
            digits: None,
            symbols: None,
            word_count: Some(4),
            separator: Some("hyphen".to_string()),
            capitalize: Some(false),
            append_digit: Some(false),
        };
        let result = generate_password(request);
        assert!(result.is_ok());
        let value = result.unwrap().value;
        assert_eq!(value.split('-').count(), 4);
    }

    #[test]
    fn all_separators_parse() {
        let separators = ["hyphen", "space", "dot", "underscore", "none"];
        for sep_str in &separators {
            let result = parse_separator(sep_str);
            assert!(result.is_ok(), "failed to parse separator: {sep_str}");
        }
    }

    #[test]
    fn unknown_separator_error() {
        let result = parse_separator("banana");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("Unknown separator"));
    }
}
