//! Platform-specific integrations — tray, hotkeys, clipboard, biometric, hardware key, autostart.

pub mod autostart;
pub mod biometric;
pub mod clipboard;
pub mod hardware_key;
pub mod hotkeys;
pub mod tray;

use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// OsType
// ---------------------------------------------------------------------------

/// Detected operating system type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    MacOS,
    Windows,
    Linux,
    Unknown,
}

impl OsType {
    /// String representation for IPC serialization.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MacOS => "macos",
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for OsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Detect the current OS type at compile time.
#[must_use]
const fn detect_os_type() -> OsType {
    #[cfg(target_os = "macos")]
    {
        OsType::MacOS
    }
    #[cfg(target_os = "windows")]
    {
        OsType::Windows
    }
    #[cfg(target_os = "linux")]
    {
        OsType::Linux
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        OsType::Unknown
    }
}

// ---------------------------------------------------------------------------
// PlatformCapabilities
// ---------------------------------------------------------------------------

/// Session-level platform capabilities — detected once at startup, immutable.
///
/// Represents hardware availability for biometric and hardware security.
/// Vault-specific enrollment status is NOT included here (queried live
/// per-component because it can change during a session).
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    /// Detected OS type.
    pub os_type: OsType,
    /// Whether biometric hardware is available on this device.
    pub biometric_available: bool,
    /// Human-readable biometric provider name (e.g., "Touch ID", "None").
    pub biometric_provider_name: String,
    /// Whether hardware security is available on this device.
    pub hardware_security_available: bool,
    /// Human-readable hardware security provider name (e.g., "Secure Enclave", "None").
    pub hardware_security_provider_name: String,
}

/// Managed Tauri state: immutable after initialization (no Mutex needed).
pub type ManagedPlatformCapabilities = Arc<PlatformCapabilities>;

/// Detect platform capabilities for the current device.
///
/// Wraps each provider's `is_available()` call in `catch_unwind()` to
/// prevent panics from FFI calls (e.g., in VMs or stripped OS images)
/// from crashing the application. Any panic is treated as "not available".
#[must_use]
pub fn detect_platform_capabilities() -> PlatformCapabilities {
    let os_type = detect_os_type();

    // Detect biometric availability — catch_unwind for VM safety.
    let (biometric_available, biometric_provider_name) = std::panic::catch_unwind(|| {
        let provider = biometric::create_biometric_provider();
        let available = provider.is_available();
        let name = provider.provider_name().to_string();
        (available, name)
    })
    .unwrap_or_else(|_| {
        tracing::warn!("Biometric detection panicked — treating as unavailable");
        (false, "None".to_string())
    });

    // Detect hardware security availability — catch_unwind for VM safety.
    let (hardware_security_available, hardware_security_provider_name) =
        std::panic::catch_unwind(|| {
            let provider = hardware_key::create_hardware_key_provider();
            let available = provider.is_available();
            let name = provider.provider_name().to_string();
            (available, name)
        })
        .unwrap_or_else(|_| {
            tracing::warn!("Hardware security detection panicked — treating as unavailable");
            (false, "None".to_string())
        });

    tracing::info!(
        os = %os_type,
        biometric = biometric_available,
        biometric_provider = %biometric_provider_name,
        hardware_security = hardware_security_available,
        hardware_security_provider = %hardware_security_provider_name,
        "Platform capabilities detected"
    );

    PlatformCapabilities {
        os_type,
        biometric_available,
        biometric_provider_name,
        hardware_security_available,
        hardware_security_provider_name,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_type_as_str() {
        assert_eq!(OsType::MacOS.as_str(), "macos");
        assert_eq!(OsType::Windows.as_str(), "windows");
        assert_eq!(OsType::Linux.as_str(), "linux");
        assert_eq!(OsType::Unknown.as_str(), "unknown");
    }

    #[test]
    fn os_type_display() {
        assert_eq!(format!("{}", OsType::MacOS), "macos");
        assert_eq!(format!("{}", OsType::Windows), "windows");
        assert_eq!(format!("{}", OsType::Linux), "linux");
        assert_eq!(format!("{}", OsType::Unknown), "unknown");
    }

    #[test]
    fn detect_os_type_returns_known_variant() {
        let os = detect_os_type();
        // On any CI/dev machine, should not be Unknown.
        assert_ne!(os.as_str(), "");
    }

    #[test]
    fn detect_platform_capabilities_returns_valid_struct() {
        let caps = detect_platform_capabilities();
        // OS type should be detected correctly for the current platform.
        assert!(!caps.os_type.as_str().is_empty());
        // Provider names should never be empty.
        assert!(!caps.biometric_provider_name.is_empty());
        assert!(!caps.hardware_security_provider_name.is_empty());
    }

    #[test]
    fn platform_capabilities_is_clone() {
        let caps = detect_platform_capabilities();
        let cloned = caps.clone();
        assert_eq!(caps.os_type, cloned.os_type);
        assert_eq!(caps.biometric_available, cloned.biometric_available);
    }

    #[test]
    fn managed_platform_capabilities_is_arc() {
        let caps = detect_platform_capabilities();
        let managed: ManagedPlatformCapabilities = Arc::new(caps);
        assert!(!managed.biometric_provider_name.is_empty());
    }
}
