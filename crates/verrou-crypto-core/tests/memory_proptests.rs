#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Property-based tests for secure memory types.

use proptest::prelude::*;
use verrou_crypto_core::memory::{SecretBuffer, SecretBytes};

proptest! {
    /// SecretBuffer roundtrip: new(data).expose() == data
    #[test]
    fn secret_buffer_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let buf = SecretBuffer::new(&data).expect("allocation should succeed");
        prop_assert_eq!(buf.expose(), data.as_slice());
    }

    /// SecretBuffer length is preserved
    #[test]
    fn secret_buffer_length_preserved(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let buf = SecretBuffer::new(&data).expect("allocation should succeed");
        prop_assert_eq!(buf.len(), data.len());
        prop_assert_eq!(buf.is_empty(), data.is_empty());
    }

    /// SecretBuffer Debug output never contains any byte from the input data
    /// represented as a decimal string.
    #[test]
    fn secret_buffer_debug_never_leaks(data in proptest::collection::vec(any::<u8>(), 1..256)) {
        let buf = SecretBuffer::new(&data).expect("allocation should succeed");
        let debug = format!("{buf:?}");
        // The debug output must always be exactly this masked string.
        prop_assert_eq!(debug.as_str(), "SecretBuffer(***)");
    }
}

/// `SecretBytes<16>` roundtrip.
#[test]
fn secret_bytes_16_random_length() {
    let key = SecretBytes::<16>::random().expect("random should succeed");
    assert_eq!(key.expose().len(), 16);
}

/// `SecretBytes<32>` roundtrip.
#[test]
fn secret_bytes_32_random_length() {
    let key = SecretBytes::<32>::random().expect("random should succeed");
    assert_eq!(key.expose().len(), 32);
}

/// `SecretBytes<64>` roundtrip.
#[test]
fn secret_bytes_64_random_length() {
    let key = SecretBytes::<64>::random().expect("random should succeed");
    assert_eq!(key.expose().len(), 64);
}
