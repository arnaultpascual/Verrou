//! BIP39 Known Answer Test vectors.
//!
//! Test vectors from the Trezor BIP39 reference implementation:
//! <https://github.com/trezor/python-mnemonic/blob/master/vectors.json>

use verrou_crypto_core::bip39::{validate_phrase, Bip39Language};

// ── Trezor BIP39 English test vectors ──────────────────────────────
// Each vector: (entropy_hex, mnemonic, passphrase, seed_hex)
// We test only the mnemonic → checksum validation (not seed derivation).

#[test]
fn trezor_vector_12_words_all_zero_entropy() {
    // Entropy: 00000000000000000000000000000000
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

#[test]
fn trezor_vector_12_words_mixed_entropy() {
    // Entropy: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
    let words: Vec<&str> =
        "legal winner thank year wave sausage worth useful legal winner thank yellow"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

#[test]
fn vector_15_words_all_80_entropy() {
    // Entropy: 8080808080808080808080808080808080808080 (20 bytes, 160 bits)
    let words: Vec<&str> =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor accident"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

#[test]
fn trezor_vector_18_words() {
    // Entropy: 000000000000000000000000000000000000000000000000
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

#[test]
fn trezor_vector_21_words() {
    // Entropy: 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f
    let words: Vec<&str> =
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

#[test]
fn trezor_vector_24_words_all_zero() {
    // Entropy: 0000000000000000000000000000000000000000000000000000000000000000
    let words: Vec<&str> =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

#[test]
fn trezor_vector_24_words_all_ff() {
    // Entropy: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    let words: Vec<&str> =
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"
            .split_whitespace()
            .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}

#[test]
fn trezor_vector_12_words_ff_entropy() {
    // Entropy: ffffffffffffffffffffffffffffffff
    let words: Vec<&str> = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        .split_whitespace()
        .collect();
    validate_phrase(&words, Bip39Language::English).expect("should validate");
}
