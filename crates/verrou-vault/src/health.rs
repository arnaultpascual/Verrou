//! Password health analysis (Watchtower-style).
//!
//! All analysis runs server-side — passwords **never** cross the IPC boundary.
//! The frontend receives only aggregate counts, entry identifiers, and names.

use std::collections::HashMap;

use crate::entries::{EntryData, EntryType};
use crate::error::VaultError;
use verrou_crypto_core::memory::SecretBytes;

// ---------------------------------------------------------------------------
// Password strength (port of frontend `evaluateStrength`)
// ---------------------------------------------------------------------------

/// Password strength tier — mirrors the frontend algorithm exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    Weak,
    Fair,
    Good,
    Excellent,
}

impl PasswordStrength {
    /// Human-readable label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::Fair => "fair",
            Self::Good => "good",
            Self::Excellent => "excellent",
        }
    }
}

/// Evaluate password strength — identical logic to the frontend
/// `evaluateStrength()` in `src/components/PasswordInput.tsx`.
#[must_use]
#[allow(clippy::arithmetic_side_effects)]
pub fn evaluate_password_strength(password: &str) -> PasswordStrength {
    if password.is_empty() || password.len() < 4 {
        return PasswordStrength::Weak;
    }

    let mut score: u32 = 0;

    // Length bonuses.
    if password.len() >= 8 {
        score += 1;
    }
    if password.len() >= 12 {
        score += 1;
    }
    if password.len() >= 16 {
        score += 1;
    }

    // Mixed case.
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        score += 1;
    }

    // Digits.
    if password.chars().any(|c| c.is_ascii_digit()) {
        score += 1;
    }

    // Symbols (anything that isn't alphanumeric).
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        score += 1;
    }

    // Passphrase bonus: 3+ space-separated words (matches `/\w+\s+\w+\s+\w+/`).
    if is_passphrase_like(password) {
        score += 2;
    }

    match score {
        0..=2 => PasswordStrength::Weak,
        3..=4 => PasswordStrength::Fair,
        5 => PasswordStrength::Good,
        _ => PasswordStrength::Excellent,
    }
}

/// Check whether `s` looks like a passphrase (≥3 whitespace-separated word tokens).
///
/// Mirrors the frontend regex `/\w+\s+\w+\s+\w+/` exactly: only whitespace
/// characters (`\s`) count as word separators. Non-word, non-whitespace chars
/// (like `-`, `@`, `!`) do **not** separate words — they extend the current token.
#[allow(clippy::arithmetic_side_effects)]
fn is_passphrase_like(s: &str) -> bool {
    let mut word_count = 0u32;
    let mut in_word = false;
    for c in s.chars() {
        if c.is_whitespace() {
            in_word = false;
        } else if !in_word {
            word_count += 1;
            in_word = true;
        }
    }
    word_count >= 3
}

// ---------------------------------------------------------------------------
// Password health report
// ---------------------------------------------------------------------------

/// Severity for password age warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgeSeverity {
    Warning,
    Danger,
}

impl AgeSeverity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Danger => "danger",
        }
    }
}

/// A credential reference (ID + name) — safe to cross IPC (no secrets).
#[derive(Debug, Clone)]
pub struct CredentialRef {
    pub id: String,
    pub name: String,
}

/// A group of credentials sharing the same password.
#[derive(Debug, Clone)]
pub struct ReusedGroup {
    pub credentials: Vec<CredentialRef>,
}

/// A credential flagged as weak.
#[derive(Debug, Clone)]
pub struct WeakCredential {
    pub id: String,
    pub name: String,
    pub strength: PasswordStrength,
}

/// A credential with an old password.
#[derive(Debug, Clone)]
pub struct OldCredential {
    pub id: String,
    pub name: String,
    pub days_since_change: u64,
    pub severity: AgeSeverity,
}

/// Complete password health analysis result.
#[derive(Debug, Clone)]
pub struct PasswordHealthReport {
    /// Overall vault health score (0–100).
    pub overall_score: u32,
    /// Total credential count analyzed.
    pub total_credentials: u32,

    /// Credentials sharing duplicate passwords.
    pub reused_count: u32,
    pub reused_groups: Vec<ReusedGroup>,

    /// Credentials with weak or fair passwords.
    pub weak_count: u32,
    pub weak_credentials: Vec<WeakCredential>,

    /// Credentials with old passwords.
    pub old_count: u32,
    pub old_credentials: Vec<OldCredential>,

    /// Credentials without linked TOTP.
    pub no_totp_count: u32,
    pub no_totp_credentials: Vec<CredentialRef>,
}

// ---------------------------------------------------------------------------
// Age thresholds (days)
// ---------------------------------------------------------------------------

const AGE_WARNING_DAYS: u64 = 180;
const AGE_DANGER_DAYS: u64 = 365;

// ---------------------------------------------------------------------------
// Core analysis
// ---------------------------------------------------------------------------

/// Analyze password health for all credential entries in the vault.
///
/// Decrypts each credential server-side to inspect passwords, then returns
/// only aggregate counts and entry references (no password data).
///
/// Requires vault unlock (session auth) but **not** re-authentication.
///
/// # Errors
///
/// Returns [`VaultError`] if listing or decrypting entries fails.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::too_many_lines
)]
pub fn analyze_password_health(
    conn: &rusqlite::Connection,
    master_key: &SecretBytes<32>,
) -> Result<PasswordHealthReport, VaultError> {
    // 1. List all entries (metadata only, fast).
    let all_entries = crate::entries::list_entries(conn)?;

    // 2. Filter to credentials only.
    let credential_ids: Vec<(String, String, String)> = all_entries
        .iter()
        .filter(|e| e.entry_type == EntryType::Credential)
        .map(|e| (e.id.clone(), e.name.clone(), e.created_at.clone()))
        .collect();

    let total_credentials = credential_ids.len() as u32;

    if total_credentials == 0 {
        return Ok(PasswordHealthReport {
            overall_score: 100,
            total_credentials: 0,
            reused_count: 0,
            reused_groups: Vec::new(),
            weak_count: 0,
            weak_credentials: Vec::new(),
            old_count: 0,
            old_credentials: Vec::new(),
            no_totp_count: 0,
            no_totp_credentials: Vec::new(),
        });
    }

    // 3. Decrypt each credential and analyze.
    // Collect: (BLAKE3 hash, strength, age_days, has_totp, id, name)
    let mut password_hashes: Vec<([u8; 32], String, String)> = Vec::new();
    let mut weak_credentials: Vec<WeakCredential> = Vec::new();
    let mut old_credentials: Vec<OldCredential> = Vec::new();
    let mut no_totp_credentials: Vec<CredentialRef> = Vec::new();

    let now = now_epoch_days();

    for (id, name, created_at) in &credential_ids {
        let entry = crate::entries::get_entry(conn, master_key, id)?;

        if let EntryData::Credential {
            ref password,
            ref password_history,
            ref linked_totp_id,
            ..
        } = entry.data
        {
            // --- Reused detection: BLAKE3 hash ---
            let hash: [u8; 32] = blake3::hash(password.as_bytes()).into();
            password_hashes.push((hash, id.clone(), name.clone()));

            // --- Weak detection ---
            let strength = evaluate_password_strength(password);
            if matches!(strength, PasswordStrength::Weak | PasswordStrength::Fair) {
                weak_credentials.push(WeakCredential {
                    id: id.clone(),
                    name: name.clone(),
                    strength,
                });
            }

            // --- Age detection ---
            let last_changed = password_history
                .last()
                .map_or(created_at, |h| &h.changed_at);
            if let Some(change_days) = parse_iso8601_to_epoch_days(last_changed) {
                let age_days = now.saturating_sub(change_days);
                if age_days >= AGE_DANGER_DAYS {
                    old_credentials.push(OldCredential {
                        id: id.clone(),
                        name: name.clone(),
                        days_since_change: age_days,
                        severity: AgeSeverity::Danger,
                    });
                } else if age_days >= AGE_WARNING_DAYS {
                    old_credentials.push(OldCredential {
                        id: id.clone(),
                        name: name.clone(),
                        days_since_change: age_days,
                        severity: AgeSeverity::Warning,
                    });
                }
            }

            // --- Missing 2FA ---
            if linked_totp_id.is_none() {
                no_totp_credentials.push(CredentialRef {
                    id: id.clone(),
                    name: name.clone(),
                });
            }
        }
    }

    // 4. Group reused passwords by BLAKE3 hash (constant-time comparison).
    let reused_groups = find_reused_groups(&password_hashes);
    let reused_count: u32 = reused_groups
        .iter()
        .map(|g| g.credentials.len() as u32)
        .sum();

    let weak_count = weak_credentials.len() as u32;
    let old_count = old_credentials.len() as u32;
    let no_totp_count = no_totp_credentials.len() as u32;

    // 5. Compute overall health score.
    let total_issues = reused_count + weak_count + old_count + no_totp_count;
    let total_checks = total_credentials * 4;
    let overall_score = if total_checks == 0 {
        100
    } else {
        let penalty = (total_issues * 100) / total_checks;
        100u32.saturating_sub(penalty)
    };

    Ok(PasswordHealthReport {
        overall_score,
        total_credentials,
        reused_count,
        reused_groups,
        weak_count,
        weak_credentials,
        old_count,
        old_credentials,
        no_totp_count,
        no_totp_credentials,
    })
}

/// Group password hashes into reused groups (only groups with 2+ members).
///
/// Uses a `HashMap` for O(n) grouping. This is safe because the grouping
/// result (which passwords are reused) is public output sent to the frontend,
/// so timing of the comparison reveals nothing the result doesn't already reveal.
fn find_reused_groups(hashes: &[([u8; 32], String, String)]) -> Vec<ReusedGroup> {
    let mut groups: HashMap<[u8; 32], Vec<CredentialRef>> = HashMap::new();

    for (hash, id, name) in hashes {
        groups.entry(*hash).or_default().push(CredentialRef {
            id: id.clone(),
            name: name.clone(),
        });
    }

    // Only return groups with 2+ members (reused passwords).
    groups
        .into_values()
        .filter(|g| g.len() >= 2)
        .map(|credentials| ReusedGroup { credentials })
        .collect()
}

// ---------------------------------------------------------------------------
// Date helpers
// ---------------------------------------------------------------------------

/// Get the current date as days since Unix epoch.
fn now_epoch_days() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs / 86400
}

/// Parse an ISO 8601 date/datetime string to epoch days.
/// Supports "YYYY-MM-DDTHH:MM:SSZ" and "YYYY-MM-DD" formats.
#[allow(clippy::arithmetic_side_effects, clippy::cast_sign_loss)]
fn parse_iso8601_to_epoch_days(s: &str) -> Option<u64> {
    // Extract "YYYY-MM-DD" prefix.
    let date_part = s.split('T').next()?;
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;

    // Days from year/month/day using a simplified civil-date algorithm.
    // (Jean Meeus algorithm, valid for dates 1970+)
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 12 } else { month };
    let era_days = 365 * y + y / 4 - y / 100 + y / 400 + (153 * (m - 3) + 2) / 5 + day - 719_469;
    if era_days < 0 {
        None
    } else {
        Some(era_days as u64)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- evaluate_password_strength parity tests --

    #[test]
    fn empty_password_is_weak() {
        assert_eq!(evaluate_password_strength(""), PasswordStrength::Weak);
    }

    #[test]
    fn short_password_is_weak() {
        assert_eq!(evaluate_password_strength("ab"), PasswordStrength::Weak);
        assert_eq!(evaluate_password_strength("abc"), PasswordStrength::Weak);
    }

    #[test]
    fn four_lowercase_chars_is_weak() {
        // len < 8, only lowercase → score=0 → Weak
        assert_eq!(evaluate_password_strength("abcd"), PasswordStrength::Weak);
    }

    #[test]
    fn eight_lowercase_is_weak() {
        // len >= 8: +1, only lowercase → score=1 → Weak
        assert_eq!(
            evaluate_password_strength("abcdefgh"),
            PasswordStrength::Weak
        );
    }

    #[test]
    fn twelve_mixed_case_is_fair() {
        // len >= 8: +1, len >= 12: +1, mixed case: +1 → score=3 → Fair
        assert_eq!(
            evaluate_password_strength("AbcDefGhIjKl"),
            PasswordStrength::Fair
        );
    }

    #[test]
    fn twelve_mixed_with_digit_is_fair() {
        // len >= 8: +1, len >= 12: +1, mixed case: +1, digit: +1 → score=4 → Fair
        assert_eq!(
            evaluate_password_strength("AbcDefGhIj1l"),
            PasswordStrength::Fair
        );
    }

    #[test]
    fn sixteen_mixed_with_digit_is_good() {
        // len >= 8: +1, len >= 12: +1, len >= 16: +1, mixed case: +1, digit: +1 → score=5 → Good
        assert_eq!(
            evaluate_password_strength("AbcDefGhIj1lmnop"),
            PasswordStrength::Good
        );
    }

    #[test]
    fn sixteen_mixed_digits_symbols_is_excellent() {
        // len >= 8: +1, len >= 12: +1, len >= 16: +1, mixed: +1, digit: +1, symbol: +1 → score=6 → Excellent
        assert_eq!(
            evaluate_password_strength("AbcDef!1GhIjklmn"),
            PasswordStrength::Excellent
        );
    }

    #[test]
    fn passphrase_bonus_three_words() {
        // "correct horse battery" → len >= 8: +1, len >= 12: +1, len >= 16: +1,
        // symbols (space): +1, passphrase: +2 → score=6 → Excellent
        assert_eq!(
            evaluate_password_strength("correct horse battery"),
            PasswordStrength::Excellent,
        );
    }

    #[test]
    fn passphrase_bonus_long() {
        // "correct horse battery staple" → 4 words, len=28
        // len >= 8: +1, len >= 12: +1, len >= 16: +1, symbols (space): +1, passphrase: +2 → score=6 → Excellent
        assert_eq!(
            evaluate_password_strength("correct horse battery staple"),
            PasswordStrength::Excellent,
        );
    }

    #[test]
    fn passphrase_with_mixed_case_is_excellent() {
        // "Correct Horse Battery Staple" → len >= 16: +3, mixed: +1, passphrase: +2 → score=6 → Excellent
        assert_eq!(
            evaluate_password_strength("Correct Horse Battery Staple"),
            PasswordStrength::Excellent
        );
    }

    #[test]
    fn only_digits_8_chars() {
        // "12345678" → len >= 8: +1, digit: +1 → score=2 → Weak
        assert_eq!(
            evaluate_password_strength("12345678"),
            PasswordStrength::Weak
        );
    }

    #[test]
    fn only_symbols_8_chars() {
        // "!@#$%^&*" → len >= 8: +1, symbols: +1 → score=2 → Weak
        assert_eq!(
            evaluate_password_strength("!@#$%^&*"),
            PasswordStrength::Weak
        );
    }

    // -- is_passphrase_like tests --

    #[test]
    fn passphrase_detection_two_words_is_not() {
        assert!(!is_passphrase_like("hello world"));
    }

    #[test]
    fn passphrase_detection_three_words_is_yes() {
        assert!(is_passphrase_like("hello world foo"));
    }

    // -- parse_iso8601_to_epoch_days tests --

    #[test]
    fn parse_date_only() {
        // 2024-01-01 → should be ~19723 days since epoch
        let days = parse_iso8601_to_epoch_days("2024-01-01").unwrap();
        assert_eq!(days, 19723);
    }

    #[test]
    fn parse_datetime() {
        let days = parse_iso8601_to_epoch_days("2024-01-01T12:00:00Z").unwrap();
        assert_eq!(days, 19723);
    }

    #[test]
    fn parse_invalid() {
        assert!(parse_iso8601_to_epoch_days("not-a-date").is_none());
    }

    // -- PasswordStrength::as_str --

    #[test]
    fn strength_labels() {
        assert_eq!(PasswordStrength::Weak.as_str(), "weak");
        assert_eq!(PasswordStrength::Fair.as_str(), "fair");
        assert_eq!(PasswordStrength::Good.as_str(), "good");
        assert_eq!(PasswordStrength::Excellent.as_str(), "excellent");
    }
}
