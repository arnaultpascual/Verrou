//! Verify that `SecretBuffer` and `SecretBytes` actually zero memory after drop.
//!
//! These tests use unsafe pointer inspection to verify that the zeroize
//! mechanism works correctly. This is security-critical validation.
//!
//! **Note on heap-allocated buffers:** After `SecretSlice<u8>` zeroes its
//! `Box<[u8]>` and deallocates, the allocator may write metadata (free-list
//! pointers, etc.) into the freed block. Therefore we verify using sentinel
//! pattern scanning rather than asserting all-zeros, which is the correct
//! security test: an attacker scanning memory should not find recognizable
//! secret patterns.
//!
//! **UB caveat:** Reading freed memory is technically undefined behavior.
//! These tests are best-effort smoke tests that work reliably under the
//! **debug** profile (default `cargo test`). In release builds with
//! aggressive optimizations, the compiler may elide the post-free reads.
//! Run these tests in debug mode only.

use verrou_crypto_core::kdf::{derive, KdfPreset};
use verrou_crypto_core::kem::{generate_keypair, HybridKeyPair, HybridPrivateKey};
use verrou_crypto_core::memory::{SecretBuffer, SecretBytes};
use verrou_crypto_core::signing::{generate_signing_keypair, HybridSigningKeyPair};

/// Sentinel pattern used to verify zeroization — easily identifiable in memory.
const SENTINEL: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];

#[test]
fn secret_buffer_sentinel_not_found_after_drop() {
    // Fill a large buffer with a distinctive sentinel pattern.
    let sentinel_data: Vec<u8> = SENTINEL.iter().copied().cycle().take(512).collect();

    let data_ptr: *const u8;
    let data_len: usize;

    {
        let buf = SecretBuffer::new(&sentinel_data).expect("allocation should succeed");
        let exposed = buf.expose();
        data_ptr = exposed.as_ptr();
        data_len = exposed.len();
        // Verify the sentinel is actually present before drop.
        assert_eq!(&exposed[..4], &SENTINEL);
    }
    // `buf` is now dropped — secrecy zeroes the Box<[u8]> before deallocation.

    // SAFETY: We're reading memory that was just freed. This is intentionally
    // undefined behavior for testing purposes only. On most systems with
    // standard allocators, the memory is still mapped and readable immediately
    // after free. The sentinel pattern should NOT be present if zeroize worked.
    //
    // Note: This test may produce false negatives if the allocator has already
    // reclaimed and overwritten the memory. We accept this for best-effort.
    let sentinel_found = unsafe {
        let slice = std::slice::from_raw_parts(data_ptr, data_len);
        slice.windows(4).any(|w| w == SENTINEL)
    };

    assert!(
        !sentinel_found,
        "Sentinel pattern [0xDE, 0xAD, 0xBE, 0xEF] found in memory after SecretBuffer drop"
    );
}

#[test]
fn secret_buffer_large_allocation_sentinel_cleared() {
    // Use a larger allocation (64KB) to be above common allocator thresholds.
    let sentinel_data: Vec<u8> = SENTINEL.iter().copied().cycle().take(65536).collect();

    let data_ptr: *const u8;
    let data_len: usize;

    {
        let buf = SecretBuffer::new(&sentinel_data).expect("allocation should succeed");
        let exposed = buf.expose();
        data_ptr = exposed.as_ptr();
        data_len = exposed.len();
    }

    let sentinel_found = unsafe {
        let slice = std::slice::from_raw_parts(data_ptr, data_len);
        slice.windows(4).any(|w| w == SENTINEL)
    };

    assert!(
        !sentinel_found,
        "Sentinel pattern found in 64KB SecretBuffer after drop"
    );
}

#[test]
fn secret_bytes_zeroed_after_drop() {
    // SecretBytes<N> stores data inline (stack/struct), so zeroize-on-drop
    // should reliably produce all-zeros at the same memory location.
    let data_ptr: *const u8;

    {
        let key = SecretBytes::<32>::new([0xAB; 32]);
        data_ptr = key.expose().as_ptr();
        assert_eq!(key.expose()[0], 0xAB);
    }
    // `key` is now dropped — ZeroizeOnDrop zeroes the [u8; 32] in place.

    // SAFETY: For stack-allocated data, the memory location is still valid
    // (same stack frame). The bytes should be zeroed by ZeroizeOnDrop.
    let zeroed = unsafe {
        let slice = std::slice::from_raw_parts(data_ptr, 32);
        slice.iter().all(|&b| b == 0)
    };

    assert!(
        zeroed,
        "SecretBytes<32> memory was NOT zeroed after drop — ZeroizeOnDrop may be broken"
    );
}

#[test]
fn secret_bytes_sentinel_not_found_after_drop() {
    let data_ptr: *const u8;

    {
        let key = SecretBytes::<32>::new([0xAB; 32]);
        data_ptr = key.expose().as_ptr();
    }

    // No 0xAB bytes should remain.
    let sentinel_found = unsafe {
        let slice = std::slice::from_raw_parts(data_ptr, 32);
        slice.contains(&0xAB)
    };

    assert!(
        !sentinel_found,
        "Sentinel byte 0xAB found in SecretBytes<32> memory after drop"
    );
}

// ── Composite struct zeroize-on-drop tests ──────────────────────────

/// Verify that `HybridPrivateKey` (inside `HybridKeyPair`) implements Drop.
///
/// Since `HybridPrivateKey` wraps two `SecretBuffer` fields (`x25519` and
/// `ml_kem`), Rust's default Drop will call Drop on each field. This test
/// verifies the type-level guarantee that Drop exists and the struct contains
/// non-trivial key material.
#[test]
fn hybrid_private_key_needs_drop_and_nontrivial() {
    // Type-level: Drop impl chain must exist.
    assert!(
        std::mem::needs_drop::<HybridPrivateKey>(),
        "HybridPrivateKey must implement Drop (via SecretBuffer fields)"
    );

    // Structural: Verify the struct is non-trivially sized (contains actual data).
    assert!(
        std::mem::size_of::<HybridKeyPair>() > 64,
        "HybridKeyPair should contain non-trivial key material"
    );

    // Functional: Generate a real keypair and drop it — must not panic.
    let kp = generate_keypair().expect("keypair generation should succeed");
    drop(kp);
}

/// Verify that `HybridSigningKeyPair` implements Drop via `SecretBuffer` fields.
#[test]
fn hybrid_signing_key_pair_needs_drop_and_nontrivial() {
    assert!(
        std::mem::needs_drop::<HybridSigningKeyPair>(),
        "HybridSigningKeyPair must implement Drop (via SecretBuffer fields)"
    );

    assert!(
        std::mem::size_of::<HybridSigningKeyPair>() > 64,
        "HybridSigningKeyPair should contain non-trivial key material"
    );

    // Generate and drop — must not panic.
    let kp = generate_signing_keypair().expect("signing keypair generation should succeed");
    drop(kp);
}

/// Verify that KDF-derived `SecretBuffer` is zeroed after drop.
///
/// We capture the first 8 bytes of the KDF output as a "fingerprint",
/// then verify that this exact byte sequence doesn't appear in the freed
/// memory region. This uses the same sentinel-absence approach as the
/// existing `SecretBuffer` tests.
#[test]
fn kdf_output_sentinel_not_found_after_drop() {
    let password = b"test-password-for-zeroize";
    let salt = b"0123456789abcdef"; // 16 bytes minimum
    let params = KdfPreset::Fast.default_params();

    let data_ptr: *const u8;
    let data_len: usize;
    let fingerprint: [u8; 8];

    {
        let key = derive(password, salt, &params).expect("KDF derivation should succeed");
        let exposed = key.expose();
        data_ptr = exposed.as_ptr();
        data_len = exposed.len();
        // Capture first 8 bytes as our sentinel fingerprint.
        fingerprint = [
            exposed[0], exposed[1], exposed[2], exposed[3], exposed[4], exposed[5], exposed[6],
            exposed[7],
        ];
        // Verify the buffer contains non-zero key material before drop.
        assert!(
            exposed.iter().any(|&b| b != 0),
            "KDF output should contain non-zero bytes"
        );
    }
    // `key` is now dropped — SecretBuffer zeroes the Box<[u8]> before deallocation.

    // SAFETY: Reading freed memory (UB) — best-effort smoke test, debug mode only.
    // After zeroize + dealloc, the allocator may write free-list pointers, but
    // the original key fingerprint should not survive.
    let sentinel_found = unsafe {
        let slice = std::slice::from_raw_parts(data_ptr, data_len);
        slice.windows(8).any(|w| w == fingerprint)
    };

    assert!(
        !sentinel_found,
        "KDF output fingerprint found in memory after drop — zeroize may have failed"
    );
}
