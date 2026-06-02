//! Known-Answer-Test vectors for deterministic hybrid keypair derivation.
//!
//! These vectors PIN the derived PUBLIC keys for a fixed `ikm` + `context`,
//! proving that `kem::derive_keypair` and `signing::derive_signing_keypair`
//! are deterministic and stable across builds. Any change to the HKDF
//! derivation (labels, split layout, algorithm) breaks these assertions.
//!
//! The X25519 and Ed25519 public keys (32 bytes each) are pinned in full.
//! The large post-quantum public keys (ML-KEM-1024 = 1568 bytes, ML-DSA-65 =
//! 1952 bytes) are pinned via a 128-bit FNV-1a fingerprint computed inline
//! (no extra dependencies) — a fingerprint match over every byte proves the
//! entire public key is byte-stable.

use std::fmt::Write as _;
use verrou_crypto_core::kem;
use verrou_crypto_core::signing;

/// Fixed input key material used by all KAT vectors in this file.
const KAT_IKM: &[u8] = b"VERROU-KAT-deterministic-ikm-v1!";

/// Fixed derivation context used by all KAT vectors in this file.
const KAT_CONTEXT: &[u8] = b"verrou://kat-context-v1";

/// Lowercase hex encoding of a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
}

/// 128-bit FNV-1a fingerprint over every byte, rendered as lowercase hex.
///
/// Used only as a compact, stable digest for KAT pinning of large public
/// keys. Not used for any security purpose — it merely detects byte changes.
fn fingerprint(bytes: &[u8]) -> String {
    // FNV-1a, 128-bit parameters (digit separators for readability).
    const OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= u128::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:032x}")
}

/// Pinned KEM derivation vector: X25519 public key (full) + ML-KEM public key
/// (FNV-1a fingerprint). Proves `kem::derive_keypair` is deterministic and
/// stable.
#[test]
fn derive_kem_keypair_pinned_public_key() {
    let kp = kem::derive_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");

    // Sanity: lengths are correct per FIPS 203 / RFC 7748.
    assert_eq!(
        kp.public.x25519.len(),
        32,
        "X25519 public key must be 32 bytes"
    );
    assert_eq!(
        kp.public.ml_kem.len(),
        1568,
        "ML-KEM-1024 public key must be 1568 bytes"
    );

    let x25519_hex = hex(&kp.public.x25519);
    let ml_kem_fp = fingerprint(&kp.public.ml_kem);

    assert_eq!(
        x25519_hex, "c8f01c6c091ff9ecf470a7e3b89bb957ac8d902dbd0d0a33e631766bcfba4205",
        "derived X25519 public key must match pinned KAT value"
    );
    assert_eq!(
        ml_kem_fp, "763a04e45f66f7663c101eee45a4faeb",
        "derived ML-KEM public key fingerprint must match pinned KAT value"
    );
}

/// Pinned signing derivation vector: Ed25519 public key (full) + ML-DSA
/// verification key (FNV-1a fingerprint). Proves
/// `signing::derive_signing_keypair` is deterministic and stable.
#[test]
fn derive_signing_keypair_pinned_public_key() {
    let kp = signing::derive_signing_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");

    assert_eq!(
        kp.public.ed25519.len(),
        32,
        "Ed25519 public key must be 32 bytes"
    );
    assert_eq!(
        kp.public.ml_dsa.len(),
        1952,
        "ML-DSA-65 verification key must be 1952 bytes"
    );

    let ed25519_hex = hex(&kp.public.ed25519);
    let ml_dsa_fp = fingerprint(&kp.public.ml_dsa);

    assert_eq!(
        ed25519_hex, "88257a53ddf5c5f3a00ba61c0c2854274f27fd97790b1edd3c2ed2fc98e24cd8",
        "derived Ed25519 public key must match pinned KAT value"
    );
    assert_eq!(
        ml_dsa_fp, "ecb61941529c2d092f89362c3ca08452",
        "derived ML-DSA verification key fingerprint must match pinned KAT value"
    );
}

/// A second derivation with the same inputs must be byte-identical (full
/// public key comparison, not just digests).
#[test]
fn derive_keypairs_second_derivation_is_byte_identical() {
    let kem_a = kem::derive_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");
    let kem_b = kem::derive_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");
    assert_eq!(kem_a.public.x25519, kem_b.public.x25519);
    assert_eq!(kem_a.public.ml_kem, kem_b.public.ml_kem);

    let sign_a =
        signing::derive_signing_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");
    let sign_b =
        signing::derive_signing_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");
    assert_eq!(sign_a.public.ed25519, sign_b.public.ed25519);
    assert_eq!(sign_a.public.ml_dsa, sign_b.public.ml_dsa);
}

/// A different context must yield different derived public keys for both the
/// KEM and signing key pairs.
#[test]
fn derive_keypairs_different_context_differs() {
    let kem_a = kem::derive_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");
    let kem_b =
        kem::derive_keypair(KAT_IKM, b"verrou://other-context").expect("derive should succeed");
    assert_ne!(kem_a.public.x25519, kem_b.public.x25519);
    assert_ne!(kem_a.public.ml_kem, kem_b.public.ml_kem);

    let sign_a =
        signing::derive_signing_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");
    let sign_b = signing::derive_signing_keypair(KAT_IKM, b"verrou://other-context")
        .expect("derive should succeed");
    assert_ne!(sign_a.public.ed25519, sign_b.public.ed25519);
    assert_ne!(sign_a.public.ml_dsa, sign_b.public.ml_dsa);
}

/// Full round-trips using DERIVED key pairs: encap/decap for the KEM and
/// sign/verify for the signer.
#[test]
fn derived_keypairs_roundtrip() {
    let kem_kp = kem::derive_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");
    let (ct, ss_enc) = kem::encapsulate(&kem_kp.public).expect("encapsulate should succeed");
    let ss_dec = kem::decapsulate(&ct, &kem_kp.private).expect("decapsulate should succeed");
    assert_eq!(
        ss_enc.expose(),
        ss_dec.expose(),
        "derived KEM key pair must round-trip encap/decap"
    );

    let sign_kp =
        signing::derive_signing_keypair(KAT_IKM, KAT_CONTEXT).expect("derive should succeed");
    let message = b"KAT round-trip message for derived signer";
    let sig = signing::sign(message, &sign_kp).expect("signing should succeed");
    signing::verify(message, &sig, &sign_kp.public).expect("verification should succeed");
}
