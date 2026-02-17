#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    // Must never panic on arbitrary input
    let _ = verrou_vault::import::twofas::parse_twofas_json(data);
    let _ = verrou_vault::import::twofas::is_encrypted(data);
    let _ = verrou_vault::import::twofas::parse_twofas_encrypted(data, b"fuzz-password");
});
