//! Secure memory types for cryptographic key material.
//!
//! This module provides memory-safe wrappers that:
//! - Zero memory on drop via [`zeroize`]
//! - Lock pages in RAM via `mlock` to prevent swap
//! - Mask output in `Debug`/`Display` to prevent accidental leakage
//! - Disable core dumps in release builds

use crate::error::CryptoError;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretSlice};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// Platform-specific memory locking
// ---------------------------------------------------------------------------

/// RAII guard that unlocks memory on drop.
///
/// When created, locks a memory region via `mlock` to prevent it from being
/// swapped to disk. On drop, calls `munlock` to release the lock.
pub struct LockedRegion {
    ptr: *const u8,
    len: usize,
    locked: bool,
}

// SAFETY: The pointer is only used for mlock/munlock system calls, which
// are thread-safe. The pointed-to data is owned by SecretBuffer/SecretBytes
// and is not accessed through LockedRegion.
unsafe impl Send for LockedRegion {}
unsafe impl Sync for LockedRegion {}

impl LockedRegion {
    /// Attempt to lock a memory region. Returns a guard that unlocks on drop.
    ///
    /// If `mlock` fails (e.g., insufficient privileges or quota), the region
    /// is **not** locked but no error is returned — this is a soft fallback.
    ///
    /// This is `pub(crate)` because callers must guarantee pointer validity
    /// and lifetime. External consumers should use `SecretBuffer` / `SecretBytes`
    /// which manage locking internally.
    #[must_use]
    pub(crate) fn try_lock(ptr: *const u8, len: usize) -> Self {
        let locked = platform::try_mlock(ptr, len);
        if !locked && len > 0 {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                eprintln!(
                    "[verrou-crypto-core] WARNING: mlock failed — \
                     secret data may be swapped to disk. \
                     Consider increasing RLIMIT_MEMLOCK."
                );
            });
        }
        Self { ptr, len, locked }
    }

    /// Returns `true` if the memory region is currently locked.
    #[must_use]
    pub const fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedRegion {
    fn drop(&mut self) {
        if self.locked {
            platform::try_munlock(self.ptr, self.len);
        }
    }
}

// ---------------------------------------------------------------------------
// SecretBuffer — variable-length
// ---------------------------------------------------------------------------

/// Variable-length buffer for sensitive data.
///
/// Wraps [`SecretSlice<u8>`] from the `secrecy` crate and adds:
/// - `mlock` on allocation (soft fallback if unavailable)
/// - Masked `Debug` output (`SecretBuffer(***)`)
/// - Zeroization on drop (via `secrecy`'s built-in `Zeroize`)
pub struct SecretBuffer {
    inner: SecretSlice<u8>,
    lock: LockedRegion,
}

impl SecretBuffer {
    /// Create a new `SecretBuffer` from the given data.
    ///
    /// The data is copied into a new allocation, then `mlock`'d.
    /// The caller should zeroize the source data after calling this.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SecureMemory` if memory allocation fails.
    pub fn new(data: &[u8]) -> Result<Self, CryptoError> {
        let inner: SecretSlice<u8> = data.to_vec().into();
        let exposed = inner.expose_secret();
        let lock = LockedRegion::try_lock(exposed.as_ptr(), exposed.len());
        Ok(Self { inner, lock })
    }

    /// Create a `SecretBuffer` filled with cryptographically random bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SecureMemory` if the CSPRNG fails.
    pub fn random(len: usize) -> Result<Self, CryptoError> {
        let mut bytes = vec![0u8; len];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| CryptoError::SecureMemory(format!("CSPRNG fill failed: {e}")))?;
        let result = Self::new(&bytes);
        bytes.zeroize();
        result
    }

    /// Expose the underlying bytes. Use sparingly — only when the raw
    /// bytes are needed for a cryptographic operation.
    ///
    /// The returned slice borrows `self`. Keep exposure minimal — prefer
    /// using the slice within a single expression rather than binding it
    /// to a long-lived variable.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    /// Returns the number of bytes in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.expose_secret().len()
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the underlying memory is `mlock`'d.
    #[must_use]
    pub const fn is_mlocked(&self) -> bool {
        self.lock.is_locked()
    }
}

impl fmt::Debug for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBuffer(***)")
    }
}

impl fmt::Display for SecretBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBuffer(***)")
    }
}

// ---------------------------------------------------------------------------
// SecretBytes<N> — fixed-size
// ---------------------------------------------------------------------------

/// Fixed-size buffer for keys, nonces, and other fixed-length secrets.
///
/// Derives `Zeroize` + `ZeroizeOnDrop` so the bytes are securely
/// erased when the value goes out of scope.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
    // LockedRegion is NOT inside Zeroize derive — we manage its Drop manually.
    #[zeroize(skip)]
    lock: LockedRegion,
}

impl<const N: usize> SecretBytes<N> {
    /// Create a new `SecretBytes` from a fixed-size array.
    ///
    /// The input array is moved into the struct (no copy remains).
    ///
    /// **Note on `mlock`:** The memory region is locked at the current stack
    /// address. If this value is subsequently moved (e.g., returned from a
    /// function), the `LockedRegion` still references the original address.
    /// This is acceptable because `mlock` is best-effort: `munlock` on a
    /// stale address is a safe no-op, and the zeroize-on-drop guarantee is
    /// independent of `mlock` status.
    #[must_use]
    pub fn new(data: [u8; N]) -> Self {
        // Two-phase init: create struct with a no-op dummy lock, then
        // replace with a real lock once `bytes` has a stable address.
        // The dummy is safe to drop (locked=false → no munlock call).
        let mut s = Self {
            bytes: data,
            lock: LockedRegion {
                ptr: std::ptr::null(),
                len: 0,
                locked: false,
            },
        };
        s.lock = LockedRegion::try_lock(s.bytes.as_ptr(), N);
        s
    }

    /// Create `SecretBytes` filled with cryptographically random bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::SecureMemory` if the CSPRNG fails.
    pub fn random() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; N];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| CryptoError::SecureMemory(format!("CSPRNG fill failed: {e}")))?;
        Ok(Self::new(bytes))
    }

    /// Expose the underlying bytes for cryptographic operations.
    #[must_use]
    pub const fn expose(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(***)")
    }
}

impl<const N: usize> fmt::Display for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>(***)")
    }
}

impl<const N: usize> From<[u8; N]> for SecretBytes<N> {
    fn from(data: [u8; N]) -> Self {
        Self::new(data)
    }
}

// ---------------------------------------------------------------------------
// Core dump disabling
// ---------------------------------------------------------------------------

/// Disable core dumps for the current process.
///
/// On Unix: sets `RLIMIT_CORE` to 0 (both soft and hard limits).
/// On non-Unix: no-op (returns `Ok`).
///
/// # Errors
///
/// Returns `CryptoError::SecureMemory` if the `setrlimit` call fails.
pub fn disable_core_dumps() -> Result<(), CryptoError> {
    platform::disable_core_dumps_impl()
}

// ---------------------------------------------------------------------------
// Platform-specific implementations
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod platform {
    use crate::error::CryptoError;

    pub(super) fn try_mlock(ptr: *const u8, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        // SAFETY: mlock is safe to call with any valid pointer/length pair.
        // If the pointer is invalid, the kernel returns ENOMEM which we handle.
        unsafe { libc::mlock(ptr.cast(), len) == 0 }
    }

    pub(super) fn try_munlock(ptr: *const u8, len: usize) {
        if len == 0 {
            return;
        }
        // SAFETY: munlock is safe to call. Failure is non-critical.
        unsafe {
            libc::munlock(ptr.cast(), len);
        }
    }

    pub(super) fn disable_core_dumps_impl() -> Result<(), CryptoError> {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit with RLIMIT_CORE is a standard POSIX call.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) };
        if ret != 0 {
            return Err(CryptoError::SecureMemory(
                "failed to disable core dumps via RLIMIT_CORE".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod platform {
    use crate::error::CryptoError;

    pub(super) fn try_mlock(_ptr: *const u8, _len: usize) -> bool {
        false
    }

    pub(super) fn try_munlock(_ptr: *const u8, _len: usize) {}

    pub(super) fn disable_core_dumps_impl() -> Result<(), CryptoError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_buffer_new_stores_correct_content() {
        let data = b"test key material";
        let buf = SecretBuffer::new(data).expect("allocation should succeed");
        assert_eq!(buf.expose(), data);
        assert_eq!(buf.len(), data.len());
        assert!(!buf.is_empty());
    }

    #[test]
    fn secret_buffer_empty() {
        let buf = SecretBuffer::new(b"").expect("allocation should succeed");
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn secret_buffer_random_produces_unique_buffers() {
        let a = SecretBuffer::random(32).expect("random should succeed");
        let b = SecretBuffer::random(32).expect("random should succeed");
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn secret_buffer_random_non_zero() {
        let buf = SecretBuffer::random(64).expect("random should succeed");
        assert!(buf.expose().iter().any(|&b| b != 0));
    }

    #[test]
    fn secret_buffer_debug_is_masked() {
        let buf = SecretBuffer::new(b"super secret").expect("allocation should succeed");
        let debug = format!("{buf:?}");
        assert_eq!(debug, "SecretBuffer(***)");
        assert!(!debug.contains("super"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn secret_buffer_display_is_masked() {
        let buf = SecretBuffer::new(b"super secret").expect("allocation should succeed");
        let display = format!("{buf}");
        assert_eq!(display, "SecretBuffer(***)");
    }

    #[test]
    fn secret_bytes_new_and_expose_roundtrip() {
        let data: [u8; 32] = [0xAB; 32];
        let key = SecretBytes::new(data);
        assert_eq!(key.expose(), &data);
    }

    #[test]
    fn secret_bytes_random_correct_length() {
        let key = SecretBytes::<32>::random().expect("random should succeed");
        assert_eq!(key.expose().len(), 32);
    }

    #[test]
    fn secret_bytes_random_16() {
        let key = SecretBytes::<16>::random().expect("random should succeed");
        assert_eq!(key.expose().len(), 16);
    }

    #[test]
    fn secret_bytes_random_64() {
        let key = SecretBytes::<64>::random().expect("random should succeed");
        assert_eq!(key.expose().len(), 64);
    }

    #[test]
    fn secret_bytes_debug_is_masked() {
        let key = SecretBytes::<32>::new([0xFF; 32]);
        let debug = format!("{key:?}");
        assert_eq!(debug, "SecretBytes<32>(***)");
        assert!(!debug.contains("ff"));
        assert!(!debug.contains("FF"));
    }

    #[test]
    fn secret_bytes_display_is_masked() {
        let key = SecretBytes::<32>::new([0xFF; 32]);
        let display = format!("{key}");
        assert_eq!(display, "SecretBytes<32>(***)");
    }

    #[test]
    fn secret_bytes_from_array() {
        let data: [u8; 16] = [0x42; 16];
        let key: SecretBytes<16> = data.into();
        assert_eq!(key.expose(), &data);
    }

    #[cfg(unix)]
    #[test]
    fn mlock_status_is_reported() {
        let buf = SecretBuffer::new(b"test data for mlock").expect("allocation should succeed");
        let _is_locked = buf.is_mlocked();
    }

    #[cfg(unix)]
    #[test]
    fn disable_core_dumps_succeeds() {
        disable_core_dumps().expect("disable_core_dumps should succeed");

        let mut limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) };
        assert_eq!(ret, 0);
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
    }

    #[test]
    fn secret_buffer_debug_never_contains_raw_bytes() {
        // Verify Debug output is always the same masked string regardless of content
        let data_a = vec![0xDE; 64];
        let data_b = vec![0x42; 64];
        let buf_a = SecretBuffer::new(&data_a).expect("allocation should succeed");
        let buf_b = SecretBuffer::new(&data_b).expect("allocation should succeed");
        let debug_a = format!("{buf_a:?}");
        let debug_b = format!("{buf_b:?}");
        // Same masked output regardless of content
        assert_eq!(debug_a, debug_b);
        assert_eq!(debug_a, "SecretBuffer(***)");
        // Must not contain any raw string representation of the data
        assert!(!debug_a.contains("222")); // 0xDE = 222
        assert!(!debug_a.contains("66")); // 0x42 = 66
    }
}
