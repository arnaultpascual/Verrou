//! `verrou-crypto-core` — Pure cryptographic primitives for VERROU.
//!
//! This crate is the audit target: zero network, zero async, zero Tauri dependencies.
//! Must remain < 30 direct dependencies and < 10,000 LOC.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::arithmetic_side_effects))]

pub mod error;
pub mod memory;

pub mod kdf;
pub mod symmetric;

pub mod kem;

pub mod signing;

pub mod vault_format;

pub mod slots;

pub mod totp;

pub mod bip39;

pub mod password;

pub mod transfer;

pub mod biometric;

pub mod hardware_key;

pub use biometric::{derive_biometric_wrapping_key, generate_biometric_enrollment_token};
pub use bip39::{
    suggest_words, validate_passphrase, validate_phrase, validate_word, word_index, Bip39Language,
};
pub use error::CryptoError;
pub use hardware_key::{derive_hardware_wrapping_key, generate_hardware_token};
pub use kdf::{calibrate, derive, Argon2idParams, CalibratedPresets, KdfPreset};
pub use kem::{
    decapsulate, encapsulate, generate_keypair, HybridCiphertext, HybridKeyPair, HybridPublicKey,
};
pub use memory::{disable_core_dumps, LockedRegion, SecretBuffer, SecretBytes};
pub use password::{
    generate_passphrase, generate_random_password, CharsetConfig, PassphraseSeparator,
    DEFAULT_PASSWORD_LENGTH, DEFAULT_WORD_COUNT,
};
pub use signing::{
    generate_signing_keypair, sign, verify, HybridSignature, HybridSigningKeyPair,
    HybridSigningPublicKey,
};
pub use slots::{create_slot, unwrap_slot, KeySlot, SlotType, MASTER_KEY_LEN, WRAPPING_KEY_LEN};
pub use symmetric::{decrypt, encrypt, SealedData};
pub use totp::{generate_hotp, generate_totp, validate_totp, OtpAlgorithm, OtpDigits};
pub use transfer::{
    assemble_chunks, chunk_payload, decrypt_chunk, derive_transfer_key, encrypt_chunk,
    generate_transfer_keypair, TransferKey, DEFAULT_MAX_CHUNK_SIZE, VERIFICATION_WORD_COUNT,
};
pub use vault_format::{
    deserialize, serialize, VaultHeader, FORMAT_VERSION, MAGIC, PADDING_BOUNDARY,
};
