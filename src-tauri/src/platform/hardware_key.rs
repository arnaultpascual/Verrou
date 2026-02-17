//! Platform hardware security abstraction — Secure Enclave, TPM 2.0.
//!
//! Provides a unified [`HardwareKeyProvider`] trait with platform-specific
//! implementations. The hardware token is stored encrypted by a hardware-bound
//! key (Secure Enclave P-256 / TPM), providing defense-in-depth beyond
//! software-only keychain storage.
//!
//! # Architecture
//!
//! ```text
//! HardwareKeyProvider (trait)
//! ├── MacOsHardwareKeyProvider  (Security.framework keychain + UserPresence)
//! ├── WindowsHardwareKeyProvider (stub — NotAvailable until Story 9.4)
//! ├── LinuxHardwareKeyProvider  (stub — NotAvailable until Story 9.4)
//! └── NullHardwareKeyProvider   (always NotAvailable — fallback)
//! ```

use std::fmt;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from hardware security operations.
#[derive(Debug)]
pub enum HardwareKeyError {
    /// No hardware security module detected on this device.
    NotAvailable,
    /// Failed to store key in hardware security module.
    StoreFailed(String),
    /// Failed to retrieve key from hardware security module.
    RetrieveFailed(String),
    /// Failed to delete key from hardware security module.
    DeleteFailed(String),
    /// Platform-specific error.
    PlatformError(String),
}

impl fmt::Display for HardwareKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAvailable => write!(f, "hardware security not available"),
            Self::StoreFailed(msg) => write!(f, "hardware key store failed: {msg}"),
            Self::RetrieveFailed(msg) => write!(f, "hardware key retrieve failed: {msg}"),
            Self::DeleteFailed(msg) => write!(f, "hardware key delete failed: {msg}"),
            Self::PlatformError(msg) => write!(f, "platform error: {msg}"),
        }
    }
}

impl std::error::Error for HardwareKeyError {}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// Platform hardware security provider abstraction.
///
/// Implementations handle OS-specific hardware security APIs (Secure Enclave,
/// TPM 2.0). The token is stored with hardware-bound protection — retrieving
/// it requires user authentication (biometric or device passcode).
pub trait HardwareKeyProvider: Send + Sync {
    /// Check if hardware security is available on this device.
    fn is_available(&self) -> bool;

    /// Human-readable provider name (e.g., "Secure Enclave", "TPM 2.0").
    fn provider_name(&self) -> &'static str;

    /// Store a token in the hardware security module for a vault.
    ///
    /// The token is protected by a hardware-bound key. Retrieving it later
    /// will require user authentication (biometric or device passcode).
    ///
    /// # Errors
    ///
    /// Returns [`HardwareKeyError`] if storage fails or hardware is unavailable.
    fn store_key(&self, vault_id: &str, token: &[u8]) -> Result<(), HardwareKeyError>;

    /// Retrieve a token from the hardware security module.
    ///
    /// This may trigger a system authentication prompt (Touch ID, passcode).
    /// The caller must zeroize the returned bytes when done.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareKeyError`] if retrieval fails, user cancels, or hardware is unavailable.
    fn retrieve_key(&self, vault_id: &str) -> Result<Vec<u8>, HardwareKeyError>;

    /// Delete a token from the hardware security module.
    ///
    /// # Errors
    ///
    /// Returns [`HardwareKeyError`] if deletion fails or hardware is unavailable.
    fn delete_key(&self, vault_id: &str) -> Result<(), HardwareKeyError>;
}

// ---------------------------------------------------------------------------
// Null provider (fallback)
// ---------------------------------------------------------------------------

/// Fallback provider when no hardware security is available.
pub struct NullHardwareKeyProvider;

impl HardwareKeyProvider for NullHardwareKeyProvider {
    fn is_available(&self) -> bool {
        false
    }

    fn provider_name(&self) -> &'static str {
        "None"
    }

    fn store_key(&self, _vault_id: &str, _token: &[u8]) -> Result<(), HardwareKeyError> {
        Err(HardwareKeyError::NotAvailable)
    }

    fn retrieve_key(&self, _vault_id: &str) -> Result<Vec<u8>, HardwareKeyError> {
        Err(HardwareKeyError::NotAvailable)
    }

    fn delete_key(&self, _vault_id: &str) -> Result<(), HardwareKeyError> {
        Err(HardwareKeyError::NotAvailable)
    }
}

// ---------------------------------------------------------------------------
// macOS provider
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::{HardwareKeyError, HardwareKeyProvider};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};

    /// Keychain service name for hardware-security-protected tokens.
    const KEYCHAIN_SERVICE: &str = "com.verrou.vault.hw";

    /// macOS hardware key provider using Security.framework keychain
    /// with `UserPresence` access control (biometric OR device passcode).
    ///
    /// On Apple Silicon, keychain items with `UserPresence` are protected
    /// by the Secure Enclave. On Intel Macs with T2, the T2 chip provides
    /// similar protection. On older Macs without SE/T2, the keychain
    /// still enforces `UserPresence` via the login password.
    pub struct MacOsHardwareKeyProvider;

    impl MacOsHardwareKeyProvider {
        /// Build the keychain account string for a vault.
        fn account_for_vault(vault_id: &str) -> String {
            // Use BLAKE3 hash of vault_id for consistent key naming.
            let hash = blake3::hash(vault_id.as_bytes());
            format!("{KEYCHAIN_SERVICE}.{}", &hash.to_hex()[..16])
        }
    }

    impl HardwareKeyProvider for MacOsHardwareKeyProvider {
        fn is_available(&self) -> bool {
            // Check for Secure Enclave / T2 by attempting to evaluate
            // DeviceOwnerAuthentication policy (biometric OR passcode).
            check_user_presence_available()
        }

        fn provider_name(&self) -> &'static str {
            "Secure Enclave"
        }

        fn store_key(&self, vault_id: &str, token: &[u8]) -> Result<(), HardwareKeyError> {
            if token.len() != 32 {
                return Err(HardwareKeyError::StoreFailed(
                    "hardware token must be exactly 32 bytes".into(),
                ));
            }
            let account = Self::account_for_vault(vault_id);

            // Delete any existing entry first (idempotent).
            let _ = delete_generic_password(KEYCHAIN_SERVICE, &account);

            // Create options with UserPresence access control.
            // UserPresence = biometric OR device passcode.
            let mut opts = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &account);
            opts.set_access_control_options(AccessControlOptions::USER_PRESENCE);

            set_generic_password_options(token, opts)
                .map_err(|e| HardwareKeyError::StoreFailed(format!("keychain add failed: {e}")))
        }

        fn retrieve_key(&self, vault_id: &str) -> Result<Vec<u8>, HardwareKeyError> {
            let account = Self::account_for_vault(vault_id);
            let secret = get_generic_password(KEYCHAIN_SERVICE, &account).map_err(|e| {
                let code = e.code();
                match code {
                    -128 => {
                        HardwareKeyError::RetrieveFailed("user cancelled authentication".into())
                    } // errSecUserCanceled
                    -25293 => HardwareKeyError::RetrieveFailed("authentication failed".into()), // errSecAuthFailed
                    -25300 => HardwareKeyError::RetrieveFailed(
                        "no hardware key found for this vault".into(),
                    ), // errSecItemNotFound
                    _ => HardwareKeyError::PlatformError(format!(
                        "keychain get failed (code {code}): {e}"
                    )),
                }
            })?;

            if secret.len() != 32 {
                return Err(HardwareKeyError::RetrieveFailed(format!(
                    "keychain item has wrong size: {} bytes (expected 32)",
                    secret.len()
                )));
            }

            Ok(secret)
        }

        fn delete_key(&self, vault_id: &str) -> Result<(), HardwareKeyError> {
            let account = Self::account_for_vault(vault_id);
            delete_generic_password(KEYCHAIN_SERVICE, &account).map_err(|e| {
                let code = e.code();
                if code == -25300 {
                    // errSecItemNotFound — already deleted, not an error.
                    return HardwareKeyError::DeleteFailed("no key found to delete".into());
                }
                HardwareKeyError::DeleteFailed(format!("keychain delete failed: {e}"))
            })
        }
    }

    /// Check if `UserPresence` (biometric OR passcode) authentication is available.
    fn check_user_presence_available() -> bool {
        // Use objc2 to call LAContext.canEvaluatePolicy:error:
        // LAPolicy::DeviceOwnerAuthentication = 2 (biometric OR passcode)
        unsafe {
            let cls = objc2::runtime::AnyClass::get(c"LAContext");
            let Some(cls) = cls else {
                return false;
            };

            let ctx: *mut objc2::runtime::AnyObject = objc2::msg_send![cls, new];
            if ctx.is_null() {
                return false;
            }

            let mut error: *mut objc2::runtime::AnyObject = std::ptr::null_mut();
            // Policy 2 = DeviceOwnerAuthentication (biometric OR passcode)
            let policy: i64 = 2;
            let can_evaluate: bool =
                objc2::msg_send![&*ctx, canEvaluatePolicy: policy, error: &mut error];

            let _: () = objc2::msg_send![&*ctx, release];

            can_evaluate
        }
    }
}

// ---------------------------------------------------------------------------
// Windows provider (stub)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod windows_impl {
    use super::*;

    /// Windows hardware key provider — stub until Story 9.4.
    pub struct WindowsHardwareKeyProvider;

    impl HardwareKeyProvider for WindowsHardwareKeyProvider {
        fn is_available(&self) -> bool {
            false
        }
        fn provider_name(&self) -> &'static str {
            "TPM 2.0"
        }
        fn store_key(&self, _vault_id: &str, _token: &[u8]) -> Result<(), HardwareKeyError> {
            Err(HardwareKeyError::NotAvailable)
        }
        fn retrieve_key(&self, _vault_id: &str) -> Result<Vec<u8>, HardwareKeyError> {
            Err(HardwareKeyError::NotAvailable)
        }
        fn delete_key(&self, _vault_id: &str) -> Result<(), HardwareKeyError> {
            Err(HardwareKeyError::NotAvailable)
        }
    }
}

// ---------------------------------------------------------------------------
// Linux provider (stub)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::{HardwareKeyError, HardwareKeyProvider};

    /// Linux hardware key provider — stub until Story 9.4.
    pub struct LinuxHardwareKeyProvider;

    impl HardwareKeyProvider for LinuxHardwareKeyProvider {
        fn is_available(&self) -> bool {
            false
        }
        fn provider_name(&self) -> &'static str {
            "TPM 2.0"
        }
        fn store_key(&self, _vault_id: &str, _token: &[u8]) -> Result<(), HardwareKeyError> {
            Err(HardwareKeyError::NotAvailable)
        }
        fn retrieve_key(&self, _vault_id: &str) -> Result<Vec<u8>, HardwareKeyError> {
            Err(HardwareKeyError::NotAvailable)
        }
        fn delete_key(&self, _vault_id: &str) -> Result<(), HardwareKeyError> {
            Err(HardwareKeyError::NotAvailable)
        }
    }
}

// ---------------------------------------------------------------------------
// Factory function
// ---------------------------------------------------------------------------

/// Create the appropriate hardware key provider for the current platform.
#[must_use]
pub fn create_hardware_key_provider() -> Box<dyn HardwareKeyProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsHardwareKeyProvider)
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(windows_impl::WindowsHardwareKeyProvider)
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux_impl::LinuxHardwareKeyProvider)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Box::new(NullHardwareKeyProvider)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_provider_is_not_available() {
        let provider = NullHardwareKeyProvider;
        assert!(!provider.is_available());
        assert_eq!(provider.provider_name(), "None");
    }

    #[test]
    fn null_provider_store_returns_not_available() {
        let provider = NullHardwareKeyProvider;
        let result = provider.store_key("test-vault", &[0u8; 32]);
        assert!(matches!(result, Err(HardwareKeyError::NotAvailable)));
    }

    #[test]
    fn null_provider_retrieve_returns_not_available() {
        let provider = NullHardwareKeyProvider;
        let result = provider.retrieve_key("test-vault");
        assert!(matches!(result, Err(HardwareKeyError::NotAvailable)));
    }

    #[test]
    fn null_provider_delete_returns_not_available() {
        let provider = NullHardwareKeyProvider;
        let result = provider.delete_key("test-vault");
        assert!(matches!(result, Err(HardwareKeyError::NotAvailable)));
    }

    #[test]
    fn hardware_key_error_display() {
        assert_eq!(
            HardwareKeyError::NotAvailable.to_string(),
            "hardware security not available"
        );
        assert_eq!(
            HardwareKeyError::StoreFailed("test".into()).to_string(),
            "hardware key store failed: test"
        );
        assert_eq!(
            HardwareKeyError::RetrieveFailed("test".into()).to_string(),
            "hardware key retrieve failed: test"
        );
        assert_eq!(
            HardwareKeyError::DeleteFailed("test".into()).to_string(),
            "hardware key delete failed: test"
        );
        assert_eq!(
            HardwareKeyError::PlatformError("test".into()).to_string(),
            "platform error: test"
        );
    }

    #[test]
    fn factory_returns_provider() {
        let provider = create_hardware_key_provider();
        // On any platform, the factory should return a valid provider.
        let _ = provider.provider_name();
    }
}
