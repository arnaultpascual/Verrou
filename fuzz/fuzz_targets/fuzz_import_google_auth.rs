//! Fuzz target: Google Authenticator migration import parsers.
//!
//! Property under test: `parse_migration_payload` and `parse_migration_uri`
//! must NEVER panic on arbitrary attacker-controlled bytes.
//!
//! Two entry points are exercised:
//!
//! 1. `parse_migration_payload(&[u8])` — raw protobuf bytes path.
//!    This is the most critical target: protobuf parsing is the lowest-level
//!    entry point and handles arbitrary binary input directly.
//!
//! 2. `parse_migration_uri(&str)` — full URI path including URL-decode and
//!    Base64-decode steps.  We skip the UTF-8 check and call this on any
//!    valid UTF-8 slice so the URL decoder and Base64 decoder are fuzzed.
//!
//! Both functions must return `Err` (not crash) for all invalid inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use verrou_vault::import::google_auth::{parse_migration_payload, parse_migration_uri};

fuzz_target!(|data: &[u8]| {
    // Path 1: raw protobuf bytes — always call this regardless of UTF-8
    // validity, because protobuf decode accepts arbitrary bytes.
    let _ = parse_migration_payload(data);

    // Path 2: URI string — only attempt if the bytes are valid UTF-8.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_migration_uri(s);
    }
});
