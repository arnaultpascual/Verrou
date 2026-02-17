//! Fuzz target for Google Authenticator import parser.
//!
//! Feeds arbitrary bytes to `parse_migration_payload` — must never panic.
//!
//! # Usage
//!
//! ```sh
//! # Install cargo-fuzz (requires nightly Rust):
//! cargo +nightly install cargo-fuzz
//!
//! # Run from the verrou-vault crate directory:
//! cd crates/verrou-vault
//! cargo +nightly fuzz run google_auth_import -- -max_len=4096
//!
//! # Run for 24 hours (CI campaign):
//! cargo +nightly fuzz run google_auth_import -- -max_len=4096 -max_total_time=86400
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input.
    let _ = verrou_vault::import::google_auth::parse_migration_payload(data);

    // Also fuzz the URI parser with arbitrary strings
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = verrou_vault::import::google_auth::parse_migration_uri(s);
    }
});
