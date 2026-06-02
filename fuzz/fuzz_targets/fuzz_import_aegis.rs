//! Fuzz target: Aegis JSON import parser.
//!
//! Property under test: `parse_aegis_json` and `parse_aegis_encrypted` must
//! NEVER panic on arbitrary attacker-controlled bytes.  They are permitted to
//! return `Err`, but must not crash, abort, or over-allocate.
//!
//! `parse_aegis_encrypted` requires a password; we use a fixed dummy password
//! ("fuzz") so the decryption path is exercised without needing a valid key.
//! The interesting property is that *all* error paths (wrong password, bad
//! JSON, bad Base64, bad scrypt params …) are handled gracefully.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verrou_vault::import::aegis::{is_encrypted, parse_aegis_encrypted, parse_aegis_json};

fuzz_target!(|data: &[u8]| {
    // Only attempt UTF-8 conversion — reject pure binary early so the fuzzer
    // spends more time on structurally interesting inputs.
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };

    // Plaintext path — must not panic.
    let _ = parse_aegis_json(s);

    // Encrypted path — must not panic regardless of password mismatch.
    let _ = parse_aegis_encrypted(s, b"fuzz");

    // Encryption-detection helper — must not panic.
    let _ = is_encrypted(s);
});
