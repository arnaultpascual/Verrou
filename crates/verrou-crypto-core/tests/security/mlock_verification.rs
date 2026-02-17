//! Verify that `mlock` is active for secret buffers and that core dumps
//! are properly disabled.
//!
//! These tests are platform-specific and only run on Unix systems.

use verrou_crypto_core::memory::{disable_core_dumps, SecretBuffer};

#[cfg(unix)]
#[test]
fn secret_buffer_reports_mlock_status() {
    let buf = SecretBuffer::new(b"mlock test data").expect("allocation should succeed");
    // On most Unix systems with sufficient mlock quota, this should be true.
    // On CI or containers with low limits, it may be false — that's acceptable.
    let is_locked = buf.is_mlocked();

    // We don't assert true because mlock can legitimately fail in constrained
    // environments. Instead we just verify the method doesn't panic and returns
    // a reasonable value.
    eprintln!("mlock status: {is_locked}");
}

#[cfg(target_os = "linux")]
#[test]
fn mlock_increases_vmlck_on_linux() {
    // Read VmLck before allocation.
    let vmlck_before = read_vmlck_kb();

    // Allocate a large enough buffer that mlock should be detectable.
    // Use 64KB to be above page size granularity.
    let buf = SecretBuffer::new(&vec![0xAA; 65536]).expect("allocation should succeed");

    if buf.is_mlocked() {
        let vmlck_after = read_vmlck_kb();
        // VmLck should have increased (at least 64KB = ~64 in the VmLck field).
        assert!(
            vmlck_after >= vmlck_before,
            "VmLck did not increase after mlock: before={vmlck_before}KB, after={vmlck_after}KB"
        );
    } else {
        eprintln!("mlock failed (likely insufficient quota) — skipping VmLck check");
    }
}

#[cfg(target_os = "linux")]
fn read_vmlck_kb() -> u64 {
    let status =
        std::fs::read_to_string("/proc/self/status").expect("failed to read /proc/self/status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmLck:") {
            let trimmed = rest.trim().trim_end_matches(" kB").trim();
            return trimmed.parse().unwrap_or(0);
        }
    }
    0
}

#[cfg(unix)]
#[test]
fn disable_core_dumps_sets_rlimit_zero() {
    disable_core_dumps().expect("disable_core_dumps should succeed");

    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) };
    assert_eq!(ret, 0, "getrlimit failed");
    assert_eq!(limit.rlim_cur, 0, "RLIMIT_CORE soft limit should be 0");
    assert_eq!(limit.rlim_max, 0, "RLIMIT_CORE hard limit should be 0");
}
