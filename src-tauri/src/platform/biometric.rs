//! Platform biometric abstraction — Touch ID, Windows Hello, Linux fingerprint.
//!
//! Provides a unified [`BiometricProvider`] trait with platform-specific
//! implementations. The biometric secret is stored in the OS keychain with
//! biometric access control; retrieving it triggers the native biometric prompt.
//!
//! # Architecture
//!
//! ```text
//! BiometricProvider (trait)
//! ├── MacOsBiometricProvider  (Security.framework keychain + LAContext)
//! ├── WindowsBiometricProvider (stub — NotAvailable until Story 9.4)
//! ├── LinuxBiometricProvider  (stub — NotAvailable until Story 9.4)
//! └── NullBiometricProvider   (always NotAvailable — fallback)
//! ```

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from biometric operations.
#[derive(Debug)]
pub enum BiometricError {
    /// No biometric hardware detected on this device.
    NotAvailable,
    /// Biometric hardware exists but no enrollment found for this vault.
    NotEnrolled,
    /// User cancelled the biometric prompt.
    UserCancelled,
    /// Biometric verification failed (wrong finger, too many attempts).
    AuthenticationFailed(String),
    /// Platform-specific error (keychain, API failure).
    PlatformError(String),
}

impl fmt::Display for BiometricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAvailable => write!(f, "biometric hardware not available"),
            Self::NotEnrolled => write!(f, "biometric not enrolled for this vault"),
            Self::UserCancelled => write!(f, "biometric verification cancelled"),
            Self::AuthenticationFailed(msg) => {
                write!(f, "biometric authentication failed: {msg}")
            }
            Self::PlatformError(msg) => write!(f, "platform error: {msg}"),
        }
    }
}

impl std::error::Error for BiometricError {}

// ---------------------------------------------------------------------------
// Biometric token
// ---------------------------------------------------------------------------

/// Secret bytes retrieved from the OS keychain after biometric verification.
///
/// Wraps 32 bytes of key material. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct BiometricToken {
    bytes: [u8; 32],
}

impl BiometricToken {
    /// Create a token from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Expose the raw bytes for key derivation.
    #[must_use]
    pub const fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for BiometricToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BiometricToken(***)")
    }
}

// ---------------------------------------------------------------------------
// Capability detection result
// ---------------------------------------------------------------------------

/// Result of biometric capability detection.
#[derive(Debug, Clone)]
pub struct BiometricCapability {
    /// Whether biometric hardware is available on this device.
    pub available: bool,
    /// Human-readable provider name (e.g., "Touch ID", "Windows Hello").
    pub provider_name: String,
    /// Whether biometric is enrolled for the current vault.
    pub enrolled: bool,
}

// ---------------------------------------------------------------------------
// Provider trait
// ---------------------------------------------------------------------------

/// Platform biometric provider abstraction.
///
/// Implementations handle OS-specific biometric APIs. The biometric secret
/// is stored in the OS keychain with biometric access control; retrieving
/// it triggers the native biometric prompt.
pub trait BiometricProvider: Send + Sync {
    /// Check if biometric hardware is available on this device.
    fn is_available(&self) -> bool;

    /// Human-readable provider name (e.g., "Touch ID", "Windows Hello").
    fn provider_name(&self) -> &'static str;

    /// Authenticate via biometric and return the stored secret.
    ///
    /// This retrieves the biometric secret from the OS keychain, which
    /// triggers the native biometric prompt (Touch ID dialog, etc.).
    ///
    /// # Errors
    ///
    /// Returns [`BiometricError`] if authentication fails, is cancelled,
    /// or biometric hardware is not available.
    fn authenticate(&self, vault_id: &str) -> Result<BiometricToken, BiometricError>;

    /// Enroll biometric for a vault by storing a secret in the OS keychain.
    ///
    /// # Errors
    ///
    /// Returns [`BiometricError`] if enrollment fails or biometric
    /// hardware is not available.
    fn enroll(&self, vault_id: &str, secret: &[u8]) -> Result<(), BiometricError>;

    /// Check if biometric is enrolled for a specific vault.
    fn is_enrolled(&self, vault_id: &str) -> bool;

    /// Revoke biometric enrollment by deleting the keychain entry.
    ///
    /// # Errors
    ///
    /// Returns [`BiometricError`] if revocation fails or biometric
    /// hardware is not available.
    fn revoke(&self, vault_id: &str) -> Result<(), BiometricError>;
}

// ---------------------------------------------------------------------------
// Null provider (fallback)
// ---------------------------------------------------------------------------

/// Fallback provider when no biometric hardware is available.
pub struct NullBiometricProvider;

impl BiometricProvider for NullBiometricProvider {
    fn is_available(&self) -> bool {
        false
    }

    fn provider_name(&self) -> &'static str {
        "None"
    }

    fn authenticate(&self, _vault_id: &str) -> Result<BiometricToken, BiometricError> {
        Err(BiometricError::NotAvailable)
    }

    fn enroll(&self, _vault_id: &str, _secret: &[u8]) -> Result<(), BiometricError> {
        Err(BiometricError::NotAvailable)
    }

    fn is_enrolled(&self, _vault_id: &str) -> bool {
        false
    }

    fn revoke(&self, _vault_id: &str) -> Result<(), BiometricError> {
        Err(BiometricError::NotAvailable)
    }
}

// ---------------------------------------------------------------------------
// macOS provider
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use super::{BiometricError, BiometricProvider, BiometricToken, Zeroize};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::{AccessControlOptions, PasswordOptions};

    /// Keychain service name for biometric secrets.
    const KEYCHAIN_SERVICE: &str = "com.verrou.vault.biometric";

    /// macOS biometric provider using Security.framework keychain
    /// with biometric access control (Touch ID / Face ID).
    pub struct MacOsBiometricProvider;

    impl MacOsBiometricProvider {
        /// Build the keychain account string for a vault.
        fn account_for_vault(vault_id: &str) -> String {
            format!("{KEYCHAIN_SERVICE}.{vault_id}")
        }
    }

    impl BiometricProvider for MacOsBiometricProvider {
        fn is_available(&self) -> bool {
            check_biometric_hardware_available()
        }

        fn provider_name(&self) -> &'static str {
            "Touch ID"
        }

        fn authenticate(&self, vault_id: &str) -> Result<BiometricToken, BiometricError> {
            let account = Self::account_for_vault(vault_id);
            // Retrieving a biometric-protected keychain item triggers Touch ID.
            let secret = get_generic_password(KEYCHAIN_SERVICE, &account).map_err(|e| {
                let code = e.code();
                match code {
                    -128 => BiometricError::UserCancelled, // errSecUserCanceled
                    -25293 => BiometricError::AuthenticationFailed(
                        "biometric authentication failed".into(),
                    ), // errSecAuthFailed
                    -25300 => BiometricError::NotEnrolled, // errSecItemNotFound
                    _ => BiometricError::PlatformError(format!(
                        "keychain get failed (code {code}): {e}"
                    )),
                }
            })?;

            if secret.len() != 32 {
                return Err(BiometricError::PlatformError(format!(
                    "keychain item has wrong size: {} bytes (expected 32)",
                    secret.len()
                )));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&secret);
            let token = BiometricToken::new(bytes);
            bytes.zeroize();
            Ok(token)
        }

        fn enroll(&self, vault_id: &str, secret: &[u8]) -> Result<(), BiometricError> {
            if secret.len() != 32 {
                return Err(BiometricError::PlatformError(
                    "enrollment secret must be exactly 32 bytes".into(),
                ));
            }
            let account = Self::account_for_vault(vault_id);

            // Delete any existing entry first (idempotent).
            let _ = delete_generic_password(KEYCHAIN_SERVICE, &account);

            // Create options with biometric access control.
            let mut opts = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &account);
            opts.set_access_control_options(AccessControlOptions::BIOMETRY_CURRENT_SET);

            set_generic_password_options(secret, opts)
                .map_err(|e| BiometricError::PlatformError(format!("keychain add failed: {e}")))
        }

        fn is_enrolled(&self, vault_id: &str) -> bool {
            let account = Self::account_for_vault(vault_id);
            // Try to look up without accessing data (won't trigger biometric).
            // Note: get_generic_password will trigger biometric. For a
            // non-interactive check, we use the keychain query existence check.
            // Unfortunately security_framework doesn't expose a non-data query,
            // so we check if delete would succeed without actually deleting.
            // A simpler approach: just try to get and catch the error.
            // For enrollment detection, we can accept that this may trigger
            // biometric on some macOS versions. In practice, the IPC command
            // will also check the vault header for a biometric slot.
            get_generic_password(KEYCHAIN_SERVICE, &account).is_ok()
        }

        fn revoke(&self, vault_id: &str) -> Result<(), BiometricError> {
            let account = Self::account_for_vault(vault_id);
            delete_generic_password(KEYCHAIN_SERVICE, &account).map_err(|e| {
                let code = e.code();
                if code == -25300 {
                    // errSecItemNotFound — already deleted, not an error.
                    return BiometricError::NotEnrolled;
                }
                BiometricError::PlatformError(format!("keychain delete failed: {e}"))
            })
        }
    }

    /// Check if biometric hardware is available using `LAContext`.
    fn check_biometric_hardware_available() -> bool {
        // Use objc2 to call LAContext.canEvaluatePolicy:error:
        // LAPolicy::DeviceOwnerAuthenticationWithBiometrics = 1
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
            let policy: i64 = 1; // LAPolicyDeviceOwnerAuthenticationWithBiometrics
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

    /// Windows biometric provider — stub until Story 9.4.
    pub struct WindowsBiometricProvider;

    impl BiometricProvider for WindowsBiometricProvider {
        fn is_available(&self) -> bool {
            false
        }
        fn provider_name(&self) -> &'static str {
            "Windows Hello"
        }
        fn authenticate(&self, _vault_id: &str) -> Result<BiometricToken, BiometricError> {
            Err(BiometricError::NotAvailable)
        }
        fn enroll(&self, _vault_id: &str, _secret: &[u8]) -> Result<(), BiometricError> {
            Err(BiometricError::NotAvailable)
        }
        fn is_enrolled(&self, _vault_id: &str) -> bool {
            false
        }
        fn revoke(&self, _vault_id: &str) -> Result<(), BiometricError> {
            Err(BiometricError::NotAvailable)
        }
    }
}

// ---------------------------------------------------------------------------
// Linux provider (stub)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::{BiometricError, BiometricProvider, BiometricToken};

    /// Linux biometric provider — stub until Story 9.4.
    pub struct LinuxBiometricProvider;

    impl BiometricProvider for LinuxBiometricProvider {
        fn is_available(&self) -> bool {
            false
        }
        fn provider_name(&self) -> &'static str {
            "Fingerprint"
        }
        fn authenticate(&self, _vault_id: &str) -> Result<BiometricToken, BiometricError> {
            Err(BiometricError::NotAvailable)
        }
        fn enroll(&self, _vault_id: &str, _secret: &[u8]) -> Result<(), BiometricError> {
            Err(BiometricError::NotAvailable)
        }
        fn is_enrolled(&self, _vault_id: &str) -> bool {
            false
        }
        fn revoke(&self, _vault_id: &str) -> Result<(), BiometricError> {
            Err(BiometricError::NotAvailable)
        }
    }
}

// ---------------------------------------------------------------------------
// Factory function
// ---------------------------------------------------------------------------

/// Create the appropriate biometric provider for the current platform.
#[must_use]
pub fn create_biometric_provider() -> Box<dyn BiometricProvider> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsBiometricProvider)
    }

    #[cfg(target_os = "windows")]
    {
        Box::new(windows_impl::WindowsBiometricProvider)
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux_impl::LinuxBiometricProvider)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Box::new(NullBiometricProvider)
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
        let provider = NullBiometricProvider;
        assert!(!provider.is_available());
        assert_eq!(provider.provider_name(), "None");
    }

    #[test]
    fn null_provider_authenticate_returns_not_available() {
        let provider = NullBiometricProvider;
        let result = provider.authenticate("test-vault");
        assert!(matches!(result, Err(BiometricError::NotAvailable)));
    }

    #[test]
    fn null_provider_enroll_returns_not_available() {
        let provider = NullBiometricProvider;
        let result = provider.enroll("test-vault", &[0u8; 32]);
        assert!(matches!(result, Err(BiometricError::NotAvailable)));
    }

    #[test]
    fn null_provider_is_not_enrolled() {
        let provider = NullBiometricProvider;
        assert!(!provider.is_enrolled("test-vault"));
    }

    #[test]
    fn null_provider_revoke_returns_not_available() {
        let provider = NullBiometricProvider;
        let result = provider.revoke("test-vault");
        assert!(matches!(result, Err(BiometricError::NotAvailable)));
    }

    #[test]
    fn biometric_token_debug_is_masked() {
        let token = BiometricToken::new([0xAA; 32]);
        let debug = format!("{token:?}");
        assert_eq!(debug, "BiometricToken(***)");
        assert!(!debug.contains("AA"));
    }

    #[test]
    fn biometric_token_expose_returns_bytes() {
        let bytes = [0x42_u8; 32];
        let token = BiometricToken::new(bytes);
        assert_eq!(token.expose(), &bytes);
    }

    #[test]
    fn biometric_error_display() {
        assert_eq!(
            BiometricError::NotAvailable.to_string(),
            "biometric hardware not available"
        );
        assert_eq!(
            BiometricError::UserCancelled.to_string(),
            "biometric verification cancelled"
        );
        assert_eq!(
            BiometricError::NotEnrolled.to_string(),
            "biometric not enrolled for this vault"
        );
    }

    #[test]
    fn factory_returns_provider() {
        let provider = create_biometric_provider();
        let _ = provider.provider_name();
        let _ = provider.is_available();
    }
}
