//! Cryptographic error types for `verrou-crypto-core`.

use thiserror::Error;

/// Errors produced by cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key derivation failed (Argon2id parameter validation, memory allocation).
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// Symmetric encryption/decryption failure (AES-256-GCM).
    #[error("encryption error: {0}")]
    Encryption(String),

    /// Authentication tag verification failed — ciphertext tampered or wrong key.
    #[error("decryption failed: authentication tag mismatch")]
    Decryption,

    /// Key encapsulation/decapsulation failure (hybrid KEM).
    #[error("key encapsulation error: {0}")]
    KeyEncapsulation(String),

    /// Digital signature creation or verification failure.
    #[error("signature error: {0}")]
    Signature(String),

    /// Invalid key material (wrong length, corrupted bytes).
    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),

    /// TOTP/HOTP generation or validation error.
    #[error("OTP error: {0}")]
    Otp(String),

    /// BIP39 mnemonic validation failure.
    #[error("BIP39 error: {0}")]
    Bip39(String),

    /// Secure memory allocation failure (mlock, guard pages).
    #[error("secure memory error: {0}")]
    SecureMemory(String),

    /// Vault file format parsing or serialization error.
    #[error("vault format error: {0}")]
    VaultFormat(String),

    /// Password/passphrase generation failure (invalid parameters).
    #[error("password generation error: {0}")]
    PasswordGeneration(String),

    /// QR code transfer encryption/decryption failure.
    #[error("transfer encryption error: {0}")]
    TransferEncryption(String),

    /// Biometric key derivation or enrollment failure.
    #[error("biometric error: {0}")]
    Biometric(String),

    /// Hardware security key derivation failure.
    #[error("hardware key error: {0}")]
    HardwareKey(String),
}
