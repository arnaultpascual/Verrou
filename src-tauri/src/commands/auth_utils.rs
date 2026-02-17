//! Shared authentication utilities used by IPC commands.

use super::vault::UnlockErrorResponse;

/// Constant-time comparison for key material.
///
/// The early return on length mismatch is acceptable because key
/// lengths (32 bytes) are public knowledge — the constant-time
/// property protects the *key value*.
#[must_use]
pub fn constant_time_key_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Format a structured error response as JSON string.
///
/// Tauri serializes command `Err` variants as plain strings, so we
/// produce JSON that the frontend can parse with `parseUnlockError()`.
#[must_use]
pub fn err_json(code: &str, message: &str) -> String {
    serde_json::to_string(&UnlockErrorResponse {
        code: code.into(),
        message: message.into(),
        remaining_ms: None,
    })
    .unwrap_or_else(|_| message.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matching_keys() {
        let key = [0x42u8; 32];
        assert!(constant_time_key_eq(&key, &key));
    }

    #[test]
    fn constant_time_eq_different_keys() {
        let a = [0x42u8; 32];
        let mut b = [0x42u8; 32];
        b[31] = 0x43;
        assert!(!constant_time_key_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_all_zeros() {
        let a = [0u8; 32];
        let b = [0u8; 32];
        assert!(constant_time_key_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 16];
        assert!(!constant_time_key_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_single_bit_difference() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[0] = 1;
        assert!(!constant_time_key_eq(&a, &b));
    }

    #[test]
    fn err_json_produces_valid_json() {
        let json = err_json("INVALID_PASSWORD", "Password is incorrect.");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["code"], "INVALID_PASSWORD");
        assert_eq!(parsed["message"], "Password is incorrect.");
    }
}
