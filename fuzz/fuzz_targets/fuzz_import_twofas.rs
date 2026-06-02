//! Fuzz target: 2FAS JSON import parser.
//!
//! Property under test: `parse_twofas_json` and `parse_twofas_encrypted` must
//! NEVER panic on arbitrary attacker-controlled bytes.
//!
//! A fixed dummy password ("fuzz") is used for the encrypted path so that all
//! error branches (wrong password, bad JSON, bad Base64, bad colon-separated
//! format, truncated GCM tag, …) are exercised without needing a valid key.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verrou_vault::import::twofas::{is_encrypted, parse_twofas_encrypted, parse_twofas_json};

fuzz_target!(|data: &[u8]| {
    // Only attempt UTF-8 conversion — reject pure binary early.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Plaintext path — must not panic.
    let _ = parse_twofas_json(s);

    // Encrypted path — must not panic regardless of password mismatch.
    let _ = parse_twofas_encrypted(s, b"fuzz");

    // Encryption-detection helper — must not panic.
    let _ = is_encrypted(s);
});
