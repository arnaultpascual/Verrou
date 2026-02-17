//! Fuzz target for Aegis import parser.
//!
//! Feeds arbitrary strings to `parse_aegis_json` — must never panic.
//!
//! # Usage
//!
//! ```sh
//! # Install cargo-fuzz (requires nightly Rust):
//! cargo +nightly install cargo-fuzz
//!
//! # Run from the verrou-vault crate directory:
//! cd crates/verrou-vault
//! cargo +nightly fuzz run aegis_import -- -max_len=8192
//!
//! # Run for 24 hours (CI campaign):
//! cargo +nightly fuzz run aegis_import -- -max_len=8192 -max_total_time=86400
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = verrou_vault::import::aegis::parse_aegis_json(s);
        let _ = verrou_vault::import::aegis::is_encrypted(s);
    }
});
