//! Google Authenticator migration QR code parser.
//!
//! Parses `otpauth-migration://offline?data=<url-encoded-base64>` URIs
//! into `ImportedEntry` structs. Uses `prost` derive macros for protobuf
//! deserialization (no `.proto` file or build script required).

use prost::Message;
use zeroize::Zeroize;

use super::{ImportError, ImportedEntry, MalformedInfo, UnsupportedInfo};
use crate::entries::{Algorithm, EntryType};

// ---------------------------------------------------------------------------
// Protobuf message structs (Google Authenticator migration format)
// ---------------------------------------------------------------------------

/// Top-level migration payload.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct MigrationPayload {
    #[prost(message, repeated, tag = "1")]
    pub otp_parameters: Vec<OtpParameters>,
    #[prost(int32, tag = "2")]
    pub version: i32,
    #[prost(int32, tag = "3")]
    pub batch_size: i32,
    #[prost(int32, tag = "4")]
    pub batch_index: i32,
    #[prost(int32, tag = "5")]
    pub batch_id: i32,
}

/// Individual OTP account parameters.
#[derive(Clone, PartialEq, Eq, Message)]
pub struct OtpParameters {
    #[prost(bytes = "vec", tag = "1")]
    pub secret: Vec<u8>,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub issuer: String,
    #[prost(int32, tag = "4")]
    pub algorithm: i32,
    #[prost(int32, tag = "5")]
    pub digits: i32,
    #[prost(int32, tag = "6")]
    pub otp_type: i32,
    #[prost(int64, tag = "7")]
    pub counter: i64,
}

// Google Authenticator protobuf enum values.
const GA_ALGO_UNSPECIFIED: i32 = 0;
const GA_ALGO_SHA1: i32 = 1;
const GA_ALGO_SHA256: i32 = 2;
const GA_ALGO_SHA512: i32 = 3;
const GA_ALGO_MD5: i32 = 4;

const GA_DIGITS_UNSPECIFIED: i32 = 0;
const GA_DIGITS_SIX: i32 = 1;
const GA_DIGITS_EIGHT: i32 = 2;

const GA_TYPE_UNSPECIFIED: i32 = 0;
const GA_TYPE_HOTP: i32 = 1;
const GA_TYPE_TOTP: i32 = 2;

// ---------------------------------------------------------------------------
// Parsing result for individual entries
// ---------------------------------------------------------------------------

/// Result of parsing a single OTP entry from a migration payload.
///
/// Categorizes each entry as valid, unsupported, or malformed.
pub enum ParsedEntry {
    /// Successfully parsed and validated.
    Valid(ImportedEntry),
    /// Entry uses an unsupported algorithm or type.
    Unsupported(UnsupportedInfo),
    /// Entry data is malformed (empty secret, etc.).
    Malformed(MalformedInfo),
}

/// Result of parsing an entire migration payload.
#[derive(Debug)]
pub struct ParseResult {
    /// Successfully parsed entries.
    pub entries: Vec<ImportedEntry>,
    /// Entries with unsupported algorithms or types.
    pub unsupported: Vec<UnsupportedInfo>,
    /// Entries with malformed data.
    pub malformed: Vec<MalformedInfo>,
    /// Batch metadata.
    pub version: i32,
    pub batch_size: i32,
    pub batch_index: i32,
    pub batch_id: i32,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a Google Authenticator migration URI.
///
/// URI format: `otpauth-migration://offline?data=<url-encoded-base64>`
///
/// # Errors
///
/// Returns `ImportError::InvalidFormat` if the URI scheme or structure is wrong.
/// Returns `ImportError::Encoding` if URL-decoding or Base64-decoding fails.
/// Returns `ImportError::Corrupted` if the protobuf payload is invalid.
pub fn parse_migration_uri(uri: &str) -> Result<ParseResult, ImportError> {
    // Step 1: Validate URI scheme
    let data_part = uri
        .strip_prefix("otpauth-migration://offline?data=")
        .ok_or_else(|| {
            ImportError::InvalidFormat(
                "expected URI starting with 'otpauth-migration://offline?data='".to_string(),
            )
        })?;

    // Step 2: URL-decode the data parameter
    let url_decoded = url_decode(data_part)
        .map_err(|e| ImportError::Encoding(format!("URL decode failed: {e}")))?;

    // Step 3: Base64-decode
    let bytes = data_encoding::BASE64
        .decode(url_decoded.as_bytes())
        .map_err(|e| ImportError::Encoding(format!("Base64 decode failed: {e}")))?;

    // Step 4: Parse protobuf
    parse_migration_payload(&bytes)
}

/// Parse a raw protobuf migration payload.
///
/// This is the lower-level entry point — use `parse_migration_uri` for
/// full URI handling.
///
/// # Errors
///
/// Returns `ImportError::Corrupted` if the protobuf bytes are invalid.
pub fn parse_migration_payload(bytes: &[u8]) -> Result<ParseResult, ImportError> {
    let payload = MigrationPayload::decode(bytes)
        .map_err(|e| ImportError::Corrupted(format!("protobuf decode failed: {e}")))?;

    // Validate format version (FR45). Google Authenticator uses version 0 (unset)
    // or 1. Reject unknown future versions with a clear error.
    if payload.version > 1 {
        return Err(ImportError::Unsupported(format!(
            "migration payload version {} is not supported (expected version 0 or 1)",
            payload.version
        )));
    }

    let mut entries = Vec::new();
    let mut unsupported = Vec::new();
    let mut malformed = Vec::new();

    for (idx, otp) in payload.otp_parameters.iter().enumerate() {
        match parse_single_entry(otp, idx) {
            ParsedEntry::Valid(entry) => entries.push(entry),
            ParsedEntry::Unsupported(info) => unsupported.push(info),
            ParsedEntry::Malformed(info) => malformed.push(info),
        }
    }

    Ok(ParseResult {
        entries,
        unsupported,
        malformed,
        version: payload.version,
        batch_size: payload.batch_size,
        batch_index: payload.batch_index,
        batch_id: payload.batch_id,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse a single `OtpParameters` into a categorized result.
fn parse_single_entry(otp: &OtpParameters, index: usize) -> ParsedEntry {
    // Validate secret is non-empty
    if otp.secret.is_empty() {
        return ParsedEntry::Malformed(MalformedInfo {
            index,
            reason: "empty secret field".to_string(),
        });
    }

    // Map algorithm
    let algorithm = match otp.algorithm {
        GA_ALGO_UNSPECIFIED | GA_ALGO_SHA1 => Algorithm::SHA1,
        GA_ALGO_SHA256 => Algorithm::SHA256,
        GA_ALGO_SHA512 => Algorithm::SHA512,
        GA_ALGO_MD5 => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(otp),
                issuer: extract_issuer(otp),
                reason: "MD5 algorithm not supported".to_string(),
            });
        }
        other => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(otp),
                issuer: extract_issuer(otp),
                reason: format!("unknown algorithm value: {other}"),
            });
        }
    };

    // Map OTP type
    let entry_type = match otp.otp_type {
        GA_TYPE_UNSPECIFIED | GA_TYPE_TOTP => EntryType::Totp,
        GA_TYPE_HOTP => EntryType::Hotp,
        other => {
            return ParsedEntry::Unsupported(UnsupportedInfo {
                index,
                name: extract_name(otp),
                issuer: extract_issuer(otp),
                reason: format!("unknown OTP type value: {other}"),
            });
        }
    };

    // Map digit count
    let digits = match otp.digits {
        GA_DIGITS_UNSPECIFIED | GA_DIGITS_SIX => 6,
        GA_DIGITS_EIGHT => 8,
        other => {
            return ParsedEntry::Malformed(MalformedInfo {
                index,
                reason: format!("unknown digit count value: {other}"),
            });
        }
    };

    // Encode raw secret bytes to Base32 (RFC 4648, uppercase, with padding)
    let mut secret_bytes = otp.secret.clone();
    let secret_b32 = data_encoding::BASE32.encode(&secret_bytes);
    secret_bytes.zeroize();

    // Extract name and issuer.
    // Google Auth sometimes puts "issuer:name" in the name field.
    let (name, issuer) = split_name_issuer(otp);

    // HOTP counter (cast i64 → u64; clamp negatives to 0)
    #[allow(clippy::cast_sign_loss)]
    let counter = if otp.counter >= 0 {
        otp.counter as u64
    } else {
        0
    };

    // Default period: 30s for TOTP, 30 for HOTP (ignored but stored)
    let period = 30;

    ParsedEntry::Valid(ImportedEntry {
        entry_type,
        name,
        issuer,
        secret: secret_b32,
        algorithm,
        digits,
        period,
        counter,
    })
}

/// Extract a display name from `OtpParameters`.
fn extract_name(otp: &OtpParameters) -> String {
    if otp.name.is_empty() {
        "(unnamed)".to_string()
    } else {
        otp.name.clone()
    }
}

/// Extract an issuer from `OtpParameters`.
fn extract_issuer(otp: &OtpParameters) -> Option<String> {
    if otp.issuer.is_empty() {
        None
    } else {
        Some(otp.issuer.clone())
    }
}

/// Split the name field and issuer field intelligently.
///
/// Google Auth often encodes names as "issuer:account" in the `name` field
/// while also providing a separate `issuer` field. This function:
/// 1. Uses the explicit `issuer` field if present
/// 2. Falls back to splitting `name` on `:` if no issuer is set
fn split_name_issuer(otp: &OtpParameters) -> (String, Option<String>) {
    let explicit_issuer = if otp.issuer.is_empty() {
        None
    } else {
        Some(otp.issuer.clone())
    };

    let name = if otp.name.is_empty() {
        "(unnamed)".to_string()
    } else if let Some(ref issuer) = explicit_issuer {
        // If the name starts with "issuer:" strip it to avoid duplication
        let prefix = format!("{issuer}:");
        if otp.name.starts_with(&prefix) {
            otp.name[prefix.len()..].trim().to_string()
        } else {
            otp.name.clone()
        }
    } else if let Some(colon_pos) = otp.name.find(':') {
        // No explicit issuer — split name on first ':'
        let inferred_issuer = otp.name[..colon_pos].trim().to_string();
        #[allow(clippy::arithmetic_side_effects)]
        let account = otp.name[colon_pos + 1..].trim().to_string();
        return (
            if account.is_empty() {
                otp.name.clone()
            } else {
                account
            },
            Some(inferred_issuer),
        );
    } else {
        otp.name.clone()
    };

    // Ensure name is not empty after stripping issuer prefix
    let final_name = if name.is_empty() {
        otp.name.clone()
    } else {
        name
    };

    (final_name, explicit_issuer)
}

/// Simple percent-decoding for URL-encoded strings.
///
/// Handles `%XX` hex sequences and `+` as space (form encoding).
/// Collects raw bytes first, then validates UTF-8, so multi-byte
/// percent-encoded sequences (e.g., `%C3%A9` for `é`) decode correctly.
fn url_decode(input: &str) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut iter = input.bytes();

    while let Some(b) = iter.next() {
        match b {
            b'%' => {
                let hi = iter
                    .next()
                    .ok_or_else(|| "incomplete percent-encoding".to_string())?;
                let lo = iter
                    .next()
                    .ok_or_else(|| "incomplete percent-encoding".to_string())?;
                bytes.push(hex_byte(hi, lo)?);
            }
            b'+' => bytes.push(b' '),
            _ => bytes.push(b),
        }
    }

    String::from_utf8(bytes).map_err(|e| format!("invalid UTF-8 in URL-decoded data: {e}"))
}

/// Convert two hex ASCII bytes to a single byte value.
#[allow(clippy::arithmetic_side_effects)]
fn hex_byte(hi: u8, lo: u8) -> Result<u8, String> {
    let h = hex_nibble(hi)?;
    let l = hex_nibble(lo)?;
    Ok((h << 4) | l)
}

/// Convert a single hex ASCII character to its nibble value.
#[allow(clippy::arithmetic_side_effects)]
fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode("hello%20world").unwrap(), "hello world");
        assert_eq!(url_decode("a+b").unwrap(), "a b");
        assert_eq!(url_decode("no%2Fslash").unwrap(), "no/slash");
    }

    #[test]
    fn url_decode_passthrough() {
        assert_eq!(url_decode("abc123").unwrap(), "abc123");
    }

    #[test]
    fn url_decode_incomplete_percent() {
        assert!(url_decode("abc%2").is_err());
        assert!(url_decode("abc%").is_err());
    }

    #[test]
    fn url_decode_multibyte_utf8() {
        // é = U+00E9 = UTF-8 bytes C3 A9
        assert_eq!(url_decode("%C3%A9").unwrap(), "é");
        // ü = U+00FC = UTF-8 bytes C3 BC
        assert_eq!(url_decode("f%C3%BCr").unwrap(), "für");
    }

    #[test]
    fn url_decode_invalid_utf8() {
        // 0xFF is not valid UTF-8
        assert!(url_decode("%FF").is_err());
    }

    #[test]
    fn split_name_issuer_explicit_issuer() {
        let otp = OtpParameters {
            name: "GitHub:user@example.com".into(),
            issuer: "GitHub".into(),
            secret: vec![1, 2, 3],
            algorithm: GA_ALGO_SHA1,
            digits: GA_DIGITS_SIX,
            otp_type: GA_TYPE_TOTP,
            counter: 0,
        };
        let (name, issuer) = split_name_issuer(&otp);
        assert_eq!(name, "user@example.com");
        assert_eq!(issuer.as_deref(), Some("GitHub"));
    }

    #[test]
    fn split_name_issuer_no_issuer_with_colon() {
        let otp = OtpParameters {
            name: "Slack:alice@corp.com".into(),
            issuer: String::new(),
            secret: vec![1, 2, 3],
            algorithm: GA_ALGO_SHA1,
            digits: GA_DIGITS_SIX,
            otp_type: GA_TYPE_TOTP,
            counter: 0,
        };
        let (name, issuer) = split_name_issuer(&otp);
        assert_eq!(name, "alice@corp.com");
        assert_eq!(issuer.as_deref(), Some("Slack"));
    }

    #[test]
    fn split_name_issuer_plain_name() {
        let otp = OtpParameters {
            name: "myaccount".into(),
            issuer: String::new(),
            secret: vec![1, 2, 3],
            algorithm: GA_ALGO_SHA1,
            digits: GA_DIGITS_SIX,
            otp_type: GA_TYPE_TOTP,
            counter: 0,
        };
        let (name, issuer) = split_name_issuer(&otp);
        assert_eq!(name, "myaccount");
        assert!(issuer.is_none());
    }

    #[test]
    fn parse_single_entry_valid_totp() {
        let otp = OtpParameters {
            secret: b"Hello!".to_vec(),
            name: "user@example.com".into(),
            issuer: "GitHub".into(),
            algorithm: GA_ALGO_SHA1,
            digits: GA_DIGITS_SIX,
            otp_type: GA_TYPE_TOTP,
            counter: 0,
        };
        match parse_single_entry(&otp, 0) {
            ParsedEntry::Valid(entry) => {
                assert_eq!(entry.entry_type, EntryType::Totp);
                assert_eq!(entry.name, "user@example.com");
                assert_eq!(entry.issuer.as_deref(), Some("GitHub"));
                assert_eq!(entry.algorithm, Algorithm::SHA1);
                assert_eq!(entry.digits, 6);
                assert_eq!(entry.period, 30);
                assert_eq!(entry.counter, 0);
                // Verify Base32 encoding of b"Hello!"
                assert_eq!(entry.secret, data_encoding::BASE32.encode(b"Hello!"));
            }
            other => panic!(
                "expected Valid, got {:?}",
                match other {
                    ParsedEntry::Unsupported(u) => format!("Unsupported: {}", u.reason),
                    ParsedEntry::Malformed(m) => format!("Malformed: {}", m.reason),
                    ParsedEntry::Valid(_) => "Valid".to_string(),
                }
            ),
        }
    }

    #[test]
    fn parse_single_entry_md5_unsupported() {
        let otp = OtpParameters {
            secret: vec![1, 2, 3],
            name: "test".into(),
            issuer: String::new(),
            algorithm: GA_ALGO_MD5,
            digits: GA_DIGITS_SIX,
            otp_type: GA_TYPE_TOTP,
            counter: 0,
        };
        match parse_single_entry(&otp, 0) {
            ParsedEntry::Unsupported(info) => {
                assert!(info.reason.contains("MD5"));
            }
            _ => panic!("expected Unsupported"),
        }
    }

    #[test]
    fn parse_single_entry_empty_secret_malformed() {
        let otp = OtpParameters {
            secret: vec![],
            name: "test".into(),
            issuer: String::new(),
            algorithm: GA_ALGO_SHA1,
            digits: GA_DIGITS_SIX,
            otp_type: GA_TYPE_TOTP,
            counter: 0,
        };
        match parse_single_entry(&otp, 0) {
            ParsedEntry::Malformed(info) => {
                assert!(info.reason.contains("empty secret"));
            }
            _ => panic!("expected Malformed"),
        }
    }

    #[test]
    fn parse_single_entry_hotp_with_counter() {
        let otp = OtpParameters {
            secret: vec![1, 2, 3, 4, 5],
            name: "hotp-test".into(),
            issuer: String::new(),
            algorithm: GA_ALGO_SHA1,
            digits: GA_DIGITS_EIGHT,
            otp_type: GA_TYPE_HOTP,
            counter: 42,
        };
        match parse_single_entry(&otp, 0) {
            ParsedEntry::Valid(entry) => {
                assert_eq!(entry.entry_type, EntryType::Hotp);
                assert_eq!(entry.digits, 8);
                assert_eq!(entry.counter, 42);
            }
            _ => panic!("expected Valid"),
        }
    }

    #[test]
    fn parse_migration_payload_valid() {
        // Build a test payload with prost encoding
        let payload = MigrationPayload {
            otp_parameters: vec![
                OtpParameters {
                    secret: b"test-secret-1".to_vec(),
                    name: "GitHub:user@test.com".into(),
                    issuer: "GitHub".into(),
                    algorithm: GA_ALGO_SHA1,
                    digits: GA_DIGITS_SIX,
                    otp_type: GA_TYPE_TOTP,
                    counter: 0,
                },
                OtpParameters {
                    secret: b"test-secret-2".to_vec(),
                    name: "AWS:admin".into(),
                    issuer: "AWS".into(),
                    algorithm: GA_ALGO_SHA256,
                    digits: GA_DIGITS_EIGHT,
                    otp_type: GA_TYPE_TOTP,
                    counter: 0,
                },
            ],
            version: 1,
            batch_size: 1,
            batch_index: 0,
            batch_id: 100,
        };

        let bytes = payload.encode_to_vec();
        let result = parse_migration_payload(&bytes).expect("should parse");

        assert_eq!(result.entries.len(), 2);
        assert!(result.unsupported.is_empty());
        assert!(result.malformed.is_empty());
        assert_eq!(result.version, 1);
        assert_eq!(result.batch_id, 100);

        assert_eq!(result.entries[0].name, "user@test.com");
        assert_eq!(result.entries[0].issuer.as_deref(), Some("GitHub"));
        assert_eq!(result.entries[0].algorithm, Algorithm::SHA1);
        assert_eq!(result.entries[0].digits, 6);

        assert_eq!(result.entries[1].name, "admin");
        assert_eq!(result.entries[1].issuer.as_deref(), Some("AWS"));
        assert_eq!(result.entries[1].algorithm, Algorithm::SHA256);
        assert_eq!(result.entries[1].digits, 8);
    }

    #[test]
    fn parse_migration_payload_mixed() {
        let payload = MigrationPayload {
            otp_parameters: vec![
                // Valid
                OtpParameters {
                    secret: b"good-secret".to_vec(),
                    name: "Good".into(),
                    issuer: String::new(),
                    algorithm: GA_ALGO_SHA1,
                    digits: GA_DIGITS_SIX,
                    otp_type: GA_TYPE_TOTP,
                    counter: 0,
                },
                // Unsupported (MD5)
                OtpParameters {
                    secret: b"md5-secret".to_vec(),
                    name: "MD5Account".into(),
                    issuer: String::new(),
                    algorithm: GA_ALGO_MD5,
                    digits: GA_DIGITS_SIX,
                    otp_type: GA_TYPE_TOTP,
                    counter: 0,
                },
                // Malformed (empty secret)
                OtpParameters {
                    secret: vec![],
                    name: "EmptySecret".into(),
                    issuer: String::new(),
                    algorithm: GA_ALGO_SHA1,
                    digits: GA_DIGITS_SIX,
                    otp_type: GA_TYPE_TOTP,
                    counter: 0,
                },
            ],
            version: 1,
            batch_size: 1,
            batch_index: 0,
            batch_id: 200,
        };

        let bytes = payload.encode_to_vec();
        let result = parse_migration_payload(&bytes).expect("should parse");

        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.unsupported.len(), 1);
        assert_eq!(result.malformed.len(), 1);
        assert_eq!(result.unsupported[0].index, 1);
        assert_eq!(result.malformed[0].index, 2);
    }

    #[test]
    fn parse_migration_payload_empty() {
        let payload = MigrationPayload {
            otp_parameters: vec![],
            version: 1,
            batch_size: 1,
            batch_index: 0,
            batch_id: 300,
        };

        let bytes = payload.encode_to_vec();
        let result = parse_migration_payload(&bytes).expect("should parse");
        assert!(result.entries.is_empty());
    }

    #[test]
    fn parse_migration_payload_corrupted() {
        let result = parse_migration_payload(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_migration_payload_unsupported_version() {
        let payload = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                secret: b"test".to_vec(),
                name: "test".into(),
                issuer: String::new(),
                algorithm: GA_ALGO_SHA1,
                digits: GA_DIGITS_SIX,
                otp_type: GA_TYPE_TOTP,
                counter: 0,
            }],
            version: 2,
            batch_size: 1,
            batch_index: 0,
            batch_id: 0,
        };

        let bytes = payload.encode_to_vec();
        let result = parse_migration_payload(&bytes);
        assert!(result.is_err());
        match result.unwrap_err() {
            ImportError::Unsupported(msg) => {
                assert!(msg.contains("version 2"), "should mention version: {msg}");
            }
            other => panic!("expected Unsupported, got: {other}"),
        }
    }

    #[test]
    fn parse_migration_payload_version_zero_accepted() {
        let payload = MigrationPayload {
            otp_parameters: vec![],
            version: 0,
            batch_size: 0,
            batch_index: 0,
            batch_id: 0,
        };

        let bytes = payload.encode_to_vec();
        assert!(parse_migration_payload(&bytes).is_ok());
    }

    #[test]
    fn parse_migration_uri_full_roundtrip() {
        let payload = MigrationPayload {
            otp_parameters: vec![OtpParameters {
                secret: b"roundtrip-secret".to_vec(),
                name: "Test:user".into(),
                issuer: "Test".into(),
                algorithm: GA_ALGO_SHA512,
                digits: GA_DIGITS_SIX,
                otp_type: GA_TYPE_TOTP,
                counter: 0,
            }],
            version: 1,
            batch_size: 1,
            batch_index: 0,
            batch_id: 400,
        };

        let bytes = payload.encode_to_vec();
        let b64 = data_encoding::BASE64.encode(&bytes);
        // URL-encode the base64 (replace + with %2B, / with %2F, = with %3D)
        let url_encoded = b64
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let uri = format!("otpauth-migration://offline?data={url_encoded}");

        let result = parse_migration_uri(&uri).expect("should parse");
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].name, "user");
        assert_eq!(result.entries[0].issuer.as_deref(), Some("Test"));
        assert_eq!(result.entries[0].algorithm, Algorithm::SHA512);
    }

    #[test]
    fn parse_migration_uri_invalid_scheme() {
        let result = parse_migration_uri("https://example.com/data=abc");
        assert!(result.is_err());
        match result.unwrap_err() {
            ImportError::InvalidFormat(msg) => {
                assert!(msg.contains("otpauth-migration"));
            }
            other => panic!("expected InvalidFormat, got: {other}"),
        }
    }

    #[test]
    fn parse_migration_uri_invalid_base64() {
        let result = parse_migration_uri("otpauth-migration://offline?data=not-valid-b64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn parse_single_entry_sha256_sha512() {
        for (algo_val, expected) in [
            (GA_ALGO_SHA256, Algorithm::SHA256),
            (GA_ALGO_SHA512, Algorithm::SHA512),
        ] {
            let otp = OtpParameters {
                secret: vec![10, 20, 30],
                name: "test".into(),
                issuer: String::new(),
                algorithm: algo_val,
                digits: GA_DIGITS_SIX,
                otp_type: GA_TYPE_TOTP,
                counter: 0,
            };
            match parse_single_entry(&otp, 0) {
                ParsedEntry::Valid(entry) => assert_eq!(entry.algorithm, expected),
                _ => panic!("expected Valid for algo {algo_val}"),
            }
        }
    }

    #[test]
    fn parse_single_entry_negative_counter_clamped() {
        let otp = OtpParameters {
            secret: vec![1, 2, 3],
            name: "test".into(),
            issuer: String::new(),
            algorithm: GA_ALGO_SHA1,
            digits: GA_DIGITS_SIX,
            otp_type: GA_TYPE_HOTP,
            counter: -5,
        };
        match parse_single_entry(&otp, 0) {
            ParsedEntry::Valid(entry) => assert_eq!(entry.counter, 0),
            _ => panic!("expected Valid"),
        }
    }

    #[test]
    fn parse_single_entry_unspecified_defaults() {
        let otp = OtpParameters {
            secret: vec![1, 2, 3],
            name: "test".into(),
            issuer: String::new(),
            algorithm: GA_ALGO_UNSPECIFIED,
            digits: GA_DIGITS_UNSPECIFIED,
            otp_type: GA_TYPE_UNSPECIFIED,
            counter: 0,
        };
        match parse_single_entry(&otp, 0) {
            ParsedEntry::Valid(entry) => {
                assert_eq!(entry.algorithm, Algorithm::SHA1);
                assert_eq!(entry.digits, 6);
                assert_eq!(entry.entry_type, EntryType::Totp);
            }
            _ => panic!("expected Valid"),
        }
    }
}
