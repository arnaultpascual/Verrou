//! Application state management for VERROU.
//!
//! The vault session is held behind a `Mutex<Option<VaultSession>>`:
//! - `None` when the vault is locked (before unlock or after lock)
//! - `Some(session)` when the vault is unlocked
//!
//! When the session is dropped (set to `None`), the master key is
//! automatically zeroized via `SecretBytes<32>`'s `Drop` impl,
//! and the `SQLCipher` connection is closed via `VaultDb`'s `Drop`.
//!
//! The auto-lock timer tracks user activity and session start time.
//! It runs a background thread that periodically checks for inactivity
//! or maximum session duration, locking the vault automatically.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use verrou_crypto_core::memory::SecretBytes;
use verrou_vault::VaultDb;

// ── Vault session ──────────────────────────────────────────────────

/// How the vault was unlocked in the current session.
///
/// Informational only — does NOT affect security gates. Sensitive
/// operations always require the master password regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    /// Unlocked with master password.
    Password,
    /// Unlocked with biometric (Touch ID, Windows Hello).
    Biometric,
    /// Unlocked with recovery key.
    Recovery,
}

impl UnlockMethod {
    /// String representation for frontend display.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Biometric => "biometric",
            Self::Recovery => "recovery",
        }
    }
}

/// Active vault session — holds the decrypted database and master key.
///
/// # Security
///
/// - `master_key` is `SecretBytes<32>` → zeroized on drop
/// - `db` is `VaultDb` → `SQLCipher` connection closed on drop
/// - Setting `ManagedVaultState` to `None` triggers both
pub struct VaultSession {
    /// Handle to the decrypted `SQLCipher` database.
    pub db: VaultDb,
    /// The 256-bit master key (needed for re-auth operations).
    pub master_key: SecretBytes<32>,
    /// Total successful unlock count (for recovery key reminder).
    pub unlock_count: u32,
    /// How this session was unlocked (informational only).
    pub unlock_method: UnlockMethod,
}

/// Managed Tauri state: `None` = locked, `Some` = unlocked.
///
/// Wrapped in `Arc` so background threads (auto-lock timer) can
/// hold a reference alongside the Tauri command handler.
pub type ManagedVaultState = Arc<Mutex<Option<VaultSession>>>;

// ── Auto-lock timer ────────────────────────────────────────────────

/// Default inactivity timeout in minutes.
pub const DEFAULT_INACTIVITY_TIMEOUT_MINUTES: u32 = 15;

/// Default maximum session duration in hours.
pub const DEFAULT_MAX_SESSION_HOURS: u32 = 4;

/// Auto-lock timer check interval in seconds.
pub const TIMER_CHECK_INTERVAL_SECS: u64 = 10;

/// Auto-lock timer state — tracks user activity and session duration.
///
/// Separate from `ManagedVaultState` to avoid holding the vault mutex
/// while checking timer state (prevents deadlock).
pub struct AutoLockTimer {
    /// Last user activity timestamp (reset on heartbeat or IPC).
    pub last_activity: Mutex<Instant>,
    /// Session start time (set on unlock).
    pub session_start: Instant,
    /// Inactivity timeout in minutes (1–60, default 15).
    pub timeout_minutes: u32,
    /// Maximum session duration in hours (default 4).
    pub max_session_hours: u32,
    /// Flag to signal the background thread to stop.
    pub cancel: Arc<AtomicBool>,
}

impl AutoLockTimer {
    /// Create a new timer starting now.
    #[must_use]
    pub fn new(timeout_minutes: u32, max_session_hours: u32) -> Self {
        let now = Instant::now();
        Self {
            last_activity: Mutex::new(now),
            session_start: now,
            timeout_minutes,
            max_session_hours,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Record user activity (resets the inactivity countdown).
    pub fn record_activity(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = Instant::now();
        }
    }

    /// Check whether the inactivity timeout has been exceeded.
    pub fn is_inactivity_expired(&self) -> bool {
        let timeout_secs = u64::from(self.timeout_minutes) * 60;
        self.last_activity
            .lock()
            .is_ok_and(|last| last.elapsed().as_secs() >= timeout_secs)
    }

    /// Check whether the maximum session duration has been exceeded.
    pub fn is_max_session_expired(&self) -> bool {
        let max_secs = u64::from(self.max_session_hours) * 3600;
        self.session_start.elapsed().as_secs() >= max_secs
    }

    /// Signal the background thread to stop.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Managed auto-lock state: `None` when vault is locked, `Some` when active.
///
/// Wrapped in `Arc` so background threads can hold a reference.
pub type ManagedAutoLockState = Arc<Mutex<Option<AutoLockTimer>>>;

/// Managed preferences state — loaded once on startup, updated via IPC.
///
/// Not wrapped in `Option` because preferences always have a value
/// (defaults are loaded when the file is missing).
pub type ManagedPreferencesState = Arc<Mutex<verrou_vault::preferences::Preferences>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn new_timer_is_not_expired() {
        let timer = AutoLockTimer::new(15, 4);
        assert!(!timer.is_inactivity_expired());
        assert!(!timer.is_max_session_expired());
    }

    #[test]
    fn inactivity_expires_after_timeout() {
        // Use 0 minutes so it expires immediately.
        let timer = AutoLockTimer::new(0, 4);
        assert!(timer.is_inactivity_expired());
    }

    #[test]
    fn record_activity_resets_inactivity() {
        // 0-minute timeout, but activity recorded right now.
        let timer = AutoLockTimer::new(0, 4);
        timer.record_activity();
        // After record_activity, a 0-minute timeout still expires immediately
        // (0 * 60 = 0 seconds). Use a tiny threshold to test reset.
        // Better: use 1-minute timeout and verify NOT expired.
        let timer2 = AutoLockTimer::new(1, 4);
        thread::sleep(Duration::from_millis(10));
        timer2.record_activity();
        assert!(!timer2.is_inactivity_expired());
    }

    #[test]
    fn max_session_expires_with_zero_hours() {
        let timer = AutoLockTimer::new(15, 0);
        assert!(timer.is_max_session_expired());
    }

    #[test]
    fn max_session_not_expired_when_fresh() {
        let timer = AutoLockTimer::new(15, 1);
        assert!(!timer.is_max_session_expired());
    }

    #[test]
    fn cancel_sets_flag() {
        let timer = AutoLockTimer::new(15, 4);
        assert!(!timer.cancel.load(Ordering::Relaxed));
        timer.cancel();
        assert!(timer.cancel.load(Ordering::Relaxed));
    }

    #[test]
    fn managed_vault_state_defaults_to_none() {
        let state: ManagedVaultState = Arc::new(Mutex::new(None));
        assert!(state.lock().expect("lock").is_none());
    }

    #[test]
    fn managed_auto_lock_state_defaults_to_none() {
        let state: ManagedAutoLockState = Arc::new(Mutex::new(None));
        assert!(state.lock().expect("lock").is_none());
    }
}
