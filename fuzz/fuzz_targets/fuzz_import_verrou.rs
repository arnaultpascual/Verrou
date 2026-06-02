//! Fuzz target: `.verrou` encrypted vault import parser.
//!
//! Property under test: the two lowest-level entry points that handle
//! untrusted file bytes must NEVER panic:
//!
//! 1. `verrou_crypto_core::vault_format::parse_header_only(&[u8])`
//!    Parses the fixed-size file header (magic, version, slot table, …)
//!    from raw bytes.  This is the first thing touched on any import.
//!
//! 2. `verrou_crypto_core::vault_format::deserialize(&[u8], key)`
//!    Parses the full binary file (header + encrypted payload) and
//!    decrypts it with a given master key.  We use a 32-byte all-zeros
//!    dummy key; the interesting property is that *all* error paths
//!    (truncated data, wrong magic, bad nonce length, AEAD auth failure,
//!    …) are handled gracefully without panicking.
//!
//! `validate_verrou_import` (the higher-level vault-layer function) is
//! intentionally NOT called here because it requires a live `rusqlite`
//! connection; testing it without a real database would require significant
//! scaffolding and is out of scope for a pure no-panic fuzz gate.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verrou_crypto_core::vault_format::{deserialize, parse_header_only};

/// Fixed dummy master key: all zeros, 32 bytes.
///
/// The goal is not to decrypt successfully (that would require a matching
/// password slot) but to exercise every error-handling branch — truncated
/// header, mismatched magic, bad AEAD tag, etc.
const DUMMY_KEY: [u8; 32] = [0u8; 32];

fuzz_target!(|data: &[u8]| {
    // Path 1: header-only parse — must not panic.
    let _ = parse_header_only(data);

    // Path 2: full deserialise with a known-wrong key — must not panic.
    // This exercises the AEAD decryption error path on every valid-looking
    // header, and the format-error path on garbage input.
    let _ = deserialize(data, &DUMMY_KEY);
});
