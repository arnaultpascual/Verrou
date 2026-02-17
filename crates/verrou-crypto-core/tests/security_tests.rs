#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

//! Security validation test suite for verrou-crypto-core.
//!
//! These integration tests verify security-critical properties:
//! - Memory zeroization on drop (Layer 1)
//! - mlock status verification and core dump disabling (Layer 2)
//! - CSPRNG entropy quality via Shannon entropy (Layer 4)
//! - Constant-time comparison via Welch's t-test (Layer 5)

mod security;
