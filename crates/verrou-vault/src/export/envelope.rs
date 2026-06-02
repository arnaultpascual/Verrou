//! Post-quantum export **envelope** (`PQ-B`).
//!
//! Wraps the existing `vault_format` blob (produced by
//! [`crate::export::verrou_format::export_vault`]) in a binary envelope that
//! adds two post-quantum guarantees on top of the password-based inner format:
//!
//! 1. **Hybrid KEM key-wrapping** (X25519 + ML-KEM-1024): the fresh export
//!    content key (CEK) is encapsulated to the *source vault's* KEM public key
//!    so the same vault can re-import without the export password.
//! 2. **Hybrid signature** (Ed25519 + ML-DSA-65) over the entire envelope —
//!    verified **fail-closed** at import time *before* any decryption.
//!
//! The inner `vault_format` blob is unchanged: an envelope is a strict superset.
//! Old `.verrou` files (raw `vault_format`, no envelope) remain importable via
//! the password path.
//!
//! # Wire Format
//!
//! All length prefixes are unsigned 32-bit **big-endian** (`u32 BE`). Hand-rolled
//! framing — no external dependency.
//!
//! ```text
//! Offset  Field
//! ------  ------------------------------------------------------------------
//! 0       MAGIC                "VRENV1"                       (6 bytes)
//! 6       VERSION              0x01                           (1 byte)
//! 7       len(kem_ct)          u32 BE                         (4 bytes)
//! 11      kem_ct               JSON(HybridCiphertext)         (len bytes)
//! ..      len(wrapped_cek)     u32 BE                         (4 bytes)
//! ..      wrapped_cek          SealedData::to_bytes           (len bytes)
//! ..      len(sign_pub)        u32 BE                         (4 bytes)
//! ..      sign_pub             JSON(HybridSigningPublicKey)   (len bytes)
//! ..      len(inner)           u32 BE                         (4 bytes)
//! ..      inner                vault_format blob              (len bytes)
//! ------  ------------------------------------------------------------------  <- signed portion ends here
//! ..      signature            JSON(HybridSignature)          (to end)
//! ```
//!
//! The **signed portion** is every byte from `MAGIC` through the end of the
//! inner blob (i.e. everything preceding the trailing signature). The signature
//! itself is the only field outside the signed portion.

use serde::Serialize;
use verrou_crypto_core::kem::HybridCiphertext;
use verrou_crypto_core::signing::{HybridSignature, HybridSigningPublicKey};
use verrou_crypto_core::symmetric::SealedData;

use crate::error::VaultError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Envelope magic bytes. Distinct from the inner `vault_format` magic (`VROU`)
/// so the two formats can never be confused: `MAGIC[..4]` is `VREN` != `VROU`.
pub const ENVELOPE_MAGIC: &[u8; 6] = b"VRENV1";

/// Current envelope format version.
pub const ENVELOPE_VERSION: u8 = 1;

/// HKDF context for deriving the vault's KEM key pair from the master key.
///
/// Must match the live session derivation exactly so a vault can decrypt its
/// own exports.
pub const VAULT_KEM_CONTEXT: &[u8] = b"verrou-vault-kem-v1";

/// HKDF context for deriving the vault's signing key pair from the master key.
///
/// Must match the live session derivation exactly.
pub const VAULT_SIGN_CONTEXT: &[u8] = b"verrou-vault-sign-v1";

/// AAD binding the KEM-wrapped content key to its purpose (domain separation).
pub const KEM_CEK_AAD: &[u8] = b"verrou-export-kem-cek";

/// Width of a `u32` length prefix, in bytes.
const LEN_PREFIX: usize = 4;

/// Upper bound for any single length-prefixed field (16 MiB).
///
/// Generous relative to all legitimate envelope fields (the largest is the
/// inner blob, padded to 64 KiB boundaries) while preventing a crafted prefix
/// from triggering a huge allocation before the bytes are even present.
const MAX_FIELD_LEN: usize = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Magic detection
// ---------------------------------------------------------------------------

/// Return `true` if `data` begins with the envelope magic.
///
/// Used by the import path to route between the new envelope flow and the
/// legacy raw-`vault_format` password flow.
#[must_use]
pub fn has_envelope_magic(data: &[u8]) -> bool {
    data.len() >= ENVELOPE_MAGIC.len() && &data[..ENVELOPE_MAGIC.len()] == ENVELOPE_MAGIC
}

// ---------------------------------------------------------------------------
// Length-prefix framing helpers
// ---------------------------------------------------------------------------

/// Append a `u32` big-endian length prefix followed by `field` to `out`.
///
/// # Errors
///
/// Returns [`VaultError::Export`] if `field` exceeds [`MAX_FIELD_LEN`] or does
/// not fit in a `u32` (defensive — legitimate fields never approach this).
fn push_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), VaultError> {
    if field.len() > MAX_FIELD_LEN {
        return Err(VaultError::Export(
            "export envelope field exceeds maximum size".into(),
        ));
    }
    let len = u32::try_from(field.len())
        .map_err(|_| VaultError::Export("export envelope field length overflow".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// Cursor over an in-memory envelope, reading length-prefixed fields.
struct FieldReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> FieldReader<'a> {
    const fn new(data: &'a [u8], start: usize) -> Self {
        Self { data, pos: start }
    }

    /// Read one `u32 BE`-prefixed field and advance the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Import`] if the buffer is truncated or the declared
    /// length exceeds [`MAX_FIELD_LEN`]. Never panics on malformed input.
    fn read_field(&mut self) -> Result<&'a [u8], VaultError> {
        let prefix_end = self.pos.checked_add(LEN_PREFIX).ok_or_else(|| {
            VaultError::Import("malformed export envelope: length overflow".into())
        })?;
        if prefix_end > self.data.len() {
            return Err(VaultError::Import(
                "malformed export envelope: truncated length prefix".into(),
            ));
        }

        let mut len_bytes = [0u8; LEN_PREFIX];
        len_bytes.copy_from_slice(&self.data[self.pos..prefix_end]);
        let field_len = u32::from_be_bytes(len_bytes) as usize;

        if field_len > MAX_FIELD_LEN {
            return Err(VaultError::Import(
                "malformed export envelope: field exceeds maximum size".into(),
            ));
        }

        let field_end = prefix_end.checked_add(field_len).ok_or_else(|| {
            VaultError::Import("malformed export envelope: length overflow".into())
        })?;
        if field_end > self.data.len() {
            return Err(VaultError::Import(
                "malformed export envelope: truncated field".into(),
            ));
        }

        self.pos = field_end;
        Ok(&self.data[prefix_end..field_end])
    }

    /// Current cursor offset (used to delimit the signed portion).
    const fn position(&self) -> usize {
        self.pos
    }

    /// Remaining unread bytes (the trailing signature occupies these).
    fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

// ---------------------------------------------------------------------------
// Assembly (export side)
// ---------------------------------------------------------------------------

/// The four KEM/signature fields plus the inner blob, ready to be signed.
///
/// `assemble_signed_portion` builds the `magic..inner` byte range; the caller
/// then signs it and appends the signature via [`finish_envelope`].
pub struct EnvelopeParts<'a> {
    /// Hybrid KEM ciphertext encapsulating the content key.
    pub kem_ciphertext: &'a HybridCiphertext,
    /// Content key sealed under the KEM shared secret.
    pub wrapped_cek: &'a SealedData,
    /// Signer's hybrid public key (embedded for verification).
    pub signing_public: &'a HybridSigningPublicKey,
    /// The inner `vault_format` blob being wrapped.
    pub inner_blob: &'a [u8],
}

/// Serialize a serde value to JSON bytes, mapping failures to an export error.
fn json_field<T: Serialize>(value: &T, what: &str) -> Result<Vec<u8>, VaultError> {
    serde_json::to_vec(value)
        .map_err(|e| VaultError::Export(format!("failed to serialize {what}: {e}")))
}

/// Build the **signed portion** of the envelope: `MAGIC | VERSION | fields | inner`.
///
/// This is the exact byte sequence that must be signed and, at import time,
/// re-derived and passed to signature verification.
///
/// # Errors
///
/// Returns [`VaultError::Export`] if any field fails to serialize or exceeds
/// the field-size limit.
pub fn assemble_signed_portion(parts: &EnvelopeParts<'_>) -> Result<Vec<u8>, VaultError> {
    let kem_ct_bytes = json_field(parts.kem_ciphertext, "KEM ciphertext")?;
    let wrapped_cek_bytes = parts.wrapped_cek.to_bytes();
    let sign_pub_bytes = json_field(parts.signing_public, "signing public key")?;

    let mut out = Vec::new();
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.push(ENVELOPE_VERSION);
    push_field(&mut out, &kem_ct_bytes)?;
    push_field(&mut out, &wrapped_cek_bytes)?;
    push_field(&mut out, &sign_pub_bytes)?;
    push_field(&mut out, parts.inner_blob)?;
    Ok(out)
}

/// Append the trailing signature to a signed portion, producing the final
/// envelope bytes.
///
/// # Errors
///
/// Returns [`VaultError::Export`] if the signature fails to serialize.
pub fn finish_envelope(
    mut signed_portion: Vec<u8>,
    signature: &HybridSignature,
) -> Result<Vec<u8>, VaultError> {
    let sig_bytes = json_field(signature, "signature")?;
    // The signature is the only field *outside* the signed portion, so it is
    // appended directly (its presence/length does not need to be authenticated).
    signed_portion.extend_from_slice(&sig_bytes);
    Ok(signed_portion)
}

// ---------------------------------------------------------------------------
// Parsing (import side)
// ---------------------------------------------------------------------------

/// Borrowed view over a parsed envelope's components.
///
/// `signed_portion` is the `magic..inner` byte range that must be handed to
/// signature verification. `signature` is the trailing hybrid signature.
pub struct ParsedEnvelope<'a> {
    /// Hybrid KEM ciphertext (encapsulates the content key).
    pub kem_ciphertext: HybridCiphertext,
    /// Content key sealed under the KEM shared secret.
    pub wrapped_cek: SealedData,
    /// Embedded signer public key used to verify [`Self::signature`].
    pub signing_public: HybridSigningPublicKey,
    /// The inner `vault_format` blob.
    pub inner_blob: &'a [u8],
    /// Exact bytes that were signed (`magic..inner`).
    pub signed_portion: &'a [u8],
    /// Trailing hybrid signature over [`Self::signed_portion`].
    pub signature: HybridSignature,
}

/// Parse an envelope's structure **without** verifying the signature or
/// decrypting anything.
///
/// The caller is responsible for verifying [`ParsedEnvelope::signature`] over
/// [`ParsedEnvelope::signed_portion`] before trusting any other field
/// (fail-closed). All untrusted-length reads are bounds-checked; this function
/// never panics on malformed input.
///
/// # Errors
///
/// Returns [`VaultError::Import`] if the magic/version is wrong, the framing is
/// truncated, or any embedded structure fails to deserialize.
pub fn parse_envelope(data: &[u8]) -> Result<ParsedEnvelope<'_>, VaultError> {
    if !has_envelope_magic(data) {
        return Err(VaultError::Import(
            "not a post-quantum export envelope".into(),
        ));
    }

    // MAGIC (6) + VERSION (1).
    let version_pos = ENVELOPE_MAGIC.len();
    let header_end = version_pos
        .checked_add(1)
        .ok_or_else(|| VaultError::Import("malformed export envelope: header overflow".into()))?;
    if header_end > data.len() {
        return Err(VaultError::Import(
            "malformed export envelope: truncated header".into(),
        ));
    }
    let version = data[version_pos];
    if version != ENVELOPE_VERSION {
        return Err(VaultError::Import(format!(
            "unsupported export envelope version: {version}"
        )));
    }

    let mut reader = FieldReader::new(data, header_end);

    let kem_ct_bytes = reader.read_field()?;
    let wrapped_cek_bytes = reader.read_field()?;
    let sign_pub_bytes = reader.read_field()?;
    let inner_blob = reader.read_field()?;

    // Everything from the start through the end of the inner blob is signed.
    let signed_end = reader.position();
    let signed_portion = &data[..signed_end];

    // The remainder is the trailing signature.
    let signature_bytes = reader.remaining();
    if signature_bytes.is_empty() {
        return Err(VaultError::Import(
            "malformed export envelope: missing signature".into(),
        ));
    }

    let kem_ciphertext: HybridCiphertext = serde_json::from_slice(kem_ct_bytes)
        .map_err(|e| VaultError::Import(format!("invalid envelope KEM ciphertext: {e}")))?;
    let wrapped_cek = SealedData::from_bytes(wrapped_cek_bytes)
        .map_err(|_| VaultError::Import("invalid envelope wrapped content key".into()))?;
    let signing_public: HybridSigningPublicKey = serde_json::from_slice(sign_pub_bytes)
        .map_err(|e| VaultError::Import(format!("invalid envelope signing key: {e}")))?;
    let signature: HybridSignature = serde_json::from_slice(signature_bytes)
        .map_err(|e| VaultError::Import(format!("invalid envelope signature: {e}")))?;

    Ok(ParsedEnvelope {
        kem_ciphertext,
        wrapped_cek,
        signing_public,
        inner_blob,
        signed_portion,
        signature,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use verrou_crypto_core::kem;
    use verrou_crypto_core::signing;
    use verrou_crypto_core::symmetric;

    /// Deterministic master key used to derive vault keypairs in tests.
    const TEST_MASTER_KEY: [u8; 32] = [0x42; 32];

    /// Build a full, signed envelope around a given inner blob using a
    /// master-key-derived KEM + signing keypair (mirrors the real export flow).
    fn build_test_envelope(inner: &[u8]) -> Vec<u8> {
        let kem_kp = kem::derive_keypair(&TEST_MASTER_KEY, VAULT_KEM_CONTEXT).expect("kem derive");
        let sign_kp =
            signing::derive_signing_keypair(&TEST_MASTER_KEY, VAULT_SIGN_CONTEXT).expect("sign");

        let cek = [0x11u8; 32];
        let (kem_ct, shared) = kem::encapsulate(&kem_kp.public).expect("encapsulate");
        let wrapped = symmetric::encrypt(&cek, shared.expose(), KEM_CEK_AAD).expect("wrap");

        let parts = EnvelopeParts {
            kem_ciphertext: &kem_ct,
            wrapped_cek: &wrapped,
            signing_public: &sign_kp.public,
            inner_blob: inner,
        };
        let signed = assemble_signed_portion(&parts).expect("assemble");
        let sig = signing::sign(&signed, &sign_kp).expect("sign");
        finish_envelope(signed, &sig).expect("finish")
    }

    #[test]
    fn magic_detection_distinguishes_from_inner_format() {
        // Envelope magic detected.
        assert!(has_envelope_magic(b"VRENV1\x01rest"));
        // Inner vault_format magic (VROU) must NOT be detected as an envelope.
        assert!(!has_envelope_magic(b"VROU\x00\x00"));
        // Too short.
        assert!(!has_envelope_magic(b"VR"));
    }

    #[test]
    fn roundtrip_parse_recovers_all_fields_and_verifies() {
        let inner = b"inner vault_format blob bytes";
        let envelope = build_test_envelope(inner);

        let parsed = parse_envelope(&envelope).expect("parse should succeed");
        assert_eq!(parsed.inner_blob, inner);

        // Signature must verify over the signed portion with the embedded key.
        signing::verify(
            parsed.signed_portion,
            &parsed.signature,
            &parsed.signing_public,
        )
        .expect("signature should verify");

        // CEK recovery: decapsulate then decrypt the wrapped CEK.
        let kem_kp = kem::derive_keypair(&TEST_MASTER_KEY, VAULT_KEM_CONTEXT).expect("derive");
        let shared = kem::decapsulate(&parsed.kem_ciphertext, &kem_kp.private).expect("decap");
        let cek = symmetric::decrypt(&parsed.wrapped_cek, shared.expose(), KEM_CEK_AAD)
            .expect("unwrap cek");
        assert_eq!(cek.expose(), &[0x11u8; 32]);
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let inner = b"payload";
        let mut envelope = build_test_envelope(inner);
        // Flip the last byte (inside the trailing signature).
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;

        // Parsing may or may not still succeed (JSON), but verification must
        // fail. A parse error after the tamper is also acceptable (fail-closed).
        if let Ok(parsed) = parse_envelope(&envelope) {
            let result = signing::verify(
                parsed.signed_portion,
                &parsed.signature,
                &parsed.signing_public,
            );
            assert!(result.is_err(), "tampered signature must not verify");
        }
    }

    #[test]
    fn tampered_body_fails_verification() {
        let inner = b"original-inner-blob-contents-here";
        let mut envelope = build_test_envelope(inner);

        // Locate the inner blob precisely: it is the last signed field, so it
        // occupies `[signed_end - inner.len() .. signed_end)`. Flip a byte there
        // so the *structure* still parses but the signature must reject it.
        let signed_end = parse_envelope(&envelope)
            .expect("structure parses before tamper")
            .signed_portion
            .len();
        let flip_at = signed_end - inner.len() + (inner.len() / 2);
        envelope[flip_at] ^= 0xFF;

        let parsed = parse_envelope(&envelope).expect("structure still parses");
        let result = signing::verify(
            parsed.signed_portion,
            &parsed.signature,
            &parsed.signing_public,
        );
        assert!(result.is_err(), "tampered body must not verify");
    }

    #[test]
    fn truncated_envelope_is_rejected_without_panic() {
        let envelope = build_test_envelope(b"data");
        // Cut off mid-field.
        let truncated = &envelope[..envelope.len() / 2];
        let result = parse_envelope(truncated);
        assert!(matches!(result, Err(VaultError::Import(_))));
    }

    #[test]
    fn oversized_length_prefix_is_rejected() {
        // MAGIC + VERSION + a u32 prefix claiming 0xFFFFFFFF bytes.
        let mut data = Vec::new();
        data.extend_from_slice(ENVELOPE_MAGIC);
        data.push(ENVELOPE_VERSION);
        data.extend_from_slice(&u32::MAX.to_be_bytes());
        data.extend_from_slice(b"short");
        let result = parse_envelope(&data);
        assert!(matches!(result, Err(VaultError::Import(_))));
    }

    #[test]
    fn missing_signature_is_rejected() {
        // Build an envelope but drop the trailing signature entirely.
        let kem_kp = kem::derive_keypair(&TEST_MASTER_KEY, VAULT_KEM_CONTEXT).expect("derive");
        let sign_kp =
            signing::derive_signing_keypair(&TEST_MASTER_KEY, VAULT_SIGN_CONTEXT).expect("sign");
        let cek = [0x11u8; 32];
        let (kem_ct, shared) = kem::encapsulate(&kem_kp.public).expect("encapsulate");
        let wrapped = symmetric::encrypt(&cek, shared.expose(), KEM_CEK_AAD).expect("wrap");
        let parts = EnvelopeParts {
            kem_ciphertext: &kem_ct,
            wrapped_cek: &wrapped,
            signing_public: &sign_kp.public,
            inner_blob: b"inner",
        };
        let signed = assemble_signed_portion(&parts).expect("assemble");
        // No signature appended.
        let result = parse_envelope(&signed);
        assert!(matches!(result, Err(VaultError::Import(_))));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut envelope = build_test_envelope(b"data");
        envelope[ENVELOPE_MAGIC.len()] = 0xEE; // bogus version
        let result = parse_envelope(&envelope);
        assert!(matches!(result, Err(VaultError::Import(_))));
    }
}
