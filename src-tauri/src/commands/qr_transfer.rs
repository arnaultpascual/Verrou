//! QR desktop-to-desktop transfer IPC commands.
//!
//! Two commands form the transfer protocol:
//! - `prepare_qr_transfer` (sender): serializes entries, encrypts, chunks, returns base64 QR data
//! - `receive_qr_transfer` (receiver): decrypts chunks, reassembles, imports entries
//!
//! Seed phrases and recovery codes require re-authentication (sensitive tier).
//! TOTP, credentials, and notes use session auth only (already unlocked).

#![allow(
    clippy::significant_drop_tightening,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use std::io::Write;

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};
use zeroize::Zeroize;

use super::auth_utils::{constant_time_key_eq, err_json};
use crate::state::ManagedVaultState;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Request to prepare a QR transfer on the sending device.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrTransferPrepareRequest {
    /// IDs of entries to transfer.
    pub entry_ids: Vec<String>,
    /// Master password — required if any `seed_phrase` or `recovery_code`
    /// entries are selected (re-auth for sensitive data). `None` when only
    /// TOTP/credentials/notes are selected.
    pub password: Option<String>,
}

/// Result of preparing a QR transfer (sent to frontend for QR display).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrTransferPrepareResult {
    /// Base64-encoded encrypted chunks (each becomes one QR code).
    pub chunks: Vec<String>,
    /// Human-readable verification phrase (4 EFF words).
    pub verification_code: String,
    /// Number of entries included.
    pub total_entries: usize,
    /// Whether any sensitive entries (seed/recovery) are included.
    pub has_sensitive: bool,
}

/// Request to receive a QR transfer on the receiving device.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrTransferReceiveRequest {
    /// Base64-encoded encrypted chunks scanned from QR codes.
    pub chunks: Vec<String>,
    /// Verification phrase entered by the user (4 words).
    pub verification_code: String,
}

/// Result of receiving a QR transfer.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QrTransferReceiveResult {
    /// Number of entries successfully imported.
    pub imported_count: usize,
}

// ---------------------------------------------------------------------------
// Sender command
// ---------------------------------------------------------------------------

/// Prepare entries for QR transfer.
///
/// 1. Check if any selected entries are sensitive (seed/recovery) → require password
/// 2. If password provided, re-authenticate via vault header
/// 3. Serialize selected entries
/// 4. Generate transfer key + verification phrase
/// 5. Chunk the payload, encrypt each chunk
/// 6. Return base64-encoded chunks + verification phrase
#[tauri::command]
pub fn prepare_qr_transfer(
    mut request: QrTransferPrepareRequest,
    app: tauri::AppHandle,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<QrTransferPrepareResult, String> {
    // Step 1: Check vault is unlocked, determine if sensitive entries are selected.
    let has_sensitive = {
        let state = vault_state
            .lock()
            .map_err(|_| err_json("INTERNAL_ERROR", "Failed to acquire vault lock"))?;
        let session = state
            .as_ref()
            .ok_or_else(|| err_json("VAULT_LOCKED", "Vault is locked."))?;

        let mut sensitive = false;
        for entry_id in &request.entry_ids {
            let entry_type = verrou_vault::get_entry_type(session.db.connection(), entry_id)
                .map_err(|e| err_json("INTERNAL_ERROR", &format!("Entry lookup failed: {e}")))?;
            if matches!(
                entry_type,
                verrou_vault::EntryType::SeedPhrase | verrou_vault::EntryType::RecoveryCode
            ) {
                sensitive = true;
                break;
            }
        }
        sensitive
    };

    // Step 2: Re-authenticate if sensitive entries are selected.
    if has_sensitive {
        let password = request.password.as_deref().ok_or_else(|| {
            err_json(
                "AUTH_REQUIRED",
                "Password required to transfer seed phrases or recovery codes.",
            )
        })?;

        verify_password_for_transfer(password, &app, &vault_state)?;
    }

    // Zeroize password immediately after re-auth — not needed beyond this point.
    if let Some(ref mut pw) = request.password {
        pw.zeroize();
    }

    // Step 3: Serialize entries.
    let (payload_bytes, total_entries) = {
        let state = vault_state
            .lock()
            .map_err(|_| err_json("INTERNAL_ERROR", "Failed to acquire vault lock"))?;
        let session = state
            .as_ref()
            .ok_or_else(|| err_json("VAULT_LOCKED", "Vault is locked."))?;

        let data = verrou_vault::serialize_entries_for_transfer(
            session.db.connection(),
            &session.master_key,
            &request.entry_ids,
        )
        .map_err(|e| err_json("INTERNAL_ERROR", &format!("Serialization failed: {e}")))?;

        let count = request.entry_ids.len();
        (data, count)
    };

    // Step 4: Generate transfer key + verification phrase.
    let (transfer_key, verification_code) = verrou_crypto_core::generate_transfer_keypair()
        .map_err(|e| {
            err_json(
                "INTERNAL_ERROR",
                &format!("Transfer key generation failed: {e}"),
            )
        })?;

    // Step 5: Chunk the payload.
    let raw_chunks = verrou_crypto_core::chunk_payload(
        &payload_bytes,
        verrou_crypto_core::DEFAULT_MAX_CHUNK_SIZE,
    )
    .map_err(|e| err_json("INTERNAL_ERROR", &format!("Chunking failed: {e}")))?;

    #[allow(clippy::cast_possible_truncation)]
    let total_chunks = raw_chunks.len() as u16;

    // Step 6: Encrypt each chunk and base64-encode.
    let mut encoded_chunks = Vec::with_capacity(raw_chunks.len());
    for (i, chunk) in raw_chunks.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let index = i as u16;
        let encrypted =
            verrou_crypto_core::encrypt_chunk(chunk, &transfer_key, index, total_chunks).map_err(
                |e| err_json("INTERNAL_ERROR", &format!("Chunk encryption failed: {e}")),
            )?;
        encoded_chunks.push(BASE64.encode(&encrypted));
    }

    Ok(QrTransferPrepareResult {
        chunks: encoded_chunks,
        verification_code,
        total_entries,
        has_sensitive,
    })
}

// ---------------------------------------------------------------------------
// Receiver command
// ---------------------------------------------------------------------------

/// Receive entries from a QR transfer.
///
/// 1. Derive transfer key from verification phrase
/// 2. Decode and decrypt each chunk
/// 3. Reassemble the payload
/// 4. Import entries into the vault
#[tauri::command]
pub fn receive_qr_transfer(
    request: QrTransferReceiveRequest,
    vault_state: State<'_, ManagedVaultState>,
) -> Result<QrTransferReceiveResult, String> {
    // Step 1: Derive transfer key from verification phrase.
    let transfer_key = verrou_crypto_core::derive_transfer_key(&request.verification_code)
        .map_err(|e| err_json("INVALID_CODE", &format!("Invalid verification code: {e}")))?;

    // Step 2: Decode and decrypt each chunk.
    let mut decrypted_chunks: Vec<(u16, Vec<u8>)> = Vec::with_capacity(request.chunks.len());
    let mut total_chunks: u16 = 0;

    for (i, chunk_b64) in request.chunks.iter().enumerate() {
        let encrypted = BASE64
            .decode(chunk_b64.as_bytes())
            .map_err(|e| err_json("INVALID_DATA", &format!("Invalid base64 in chunk {i}: {e}")))?;

        let (index, total, plaintext) =
            verrou_crypto_core::decrypt_chunk(&encrypted, &transfer_key).map_err(|e| {
                err_json(
                    "DECRYPTION_FAILED",
                    &format!("Chunk {i} decryption failed: {e}"),
                )
            })?;

        total_chunks = total;
        decrypted_chunks.push((index, plaintext));
    }

    // Step 3: Reassemble the payload.
    let payload = verrou_crypto_core::assemble_chunks(&decrypted_chunks, total_chunks)
        .map_err(|e| err_json("INCOMPLETE_TRANSFER", &format!("{e}")))?;

    // Step 4: Import entries into the vault.
    let state = vault_state
        .lock()
        .map_err(|_| err_json("INTERNAL_ERROR", "Failed to acquire vault lock"))?;
    let session = state
        .as_ref()
        .ok_or_else(|| err_json("VAULT_LOCKED", "Vault is locked."))?;

    let imported_count = verrou_vault::import_transfer_entries(
        session.db.connection(),
        &session.master_key,
        &payload,
    )
    .map_err(|e| err_json("IMPORT_FAILED", &format!("Import failed: {e}")))?;

    Ok(QrTransferReceiveResult { imported_count })
}

// ---------------------------------------------------------------------------
// Re-auth helper
// ---------------------------------------------------------------------------

/// Verify password by unwrapping the vault header's password slot.
fn verify_password_for_transfer(
    password: &str,
    app: &tauri::AppHandle,
    vault_state: &State<'_, ManagedVaultState>,
) -> Result<(), String> {
    // Copy master key for comparison.
    let mut master_key_copy = [0u8; 32];
    {
        let state = vault_state
            .lock()
            .map_err(|_| err_json("INTERNAL_ERROR", "Failed to acquire vault lock"))?;
        let session = state
            .as_ref()
            .ok_or_else(|| err_json("VAULT_LOCKED", "Vault is locked."))?;
        master_key_copy.copy_from_slice(session.master_key.expose());
    }

    // Read vault header.
    let vault_path = app.path().app_data_dir().map_err(|_| {
        master_key_copy.zeroize();
        err_json("INTERNAL_ERROR", "Failed to resolve vault directory.")
    })?;
    let header_path = vault_path.join("vault.verrou");

    let file_data = std::fs::read(&header_path).map_err(|_| {
        master_key_copy.zeroize();
        err_json("IO_ERROR", "Failed to read vault header.")
    })?;

    let header = verrou_crypto_core::vault_format::parse_header_only(&file_data).map_err(|_| {
        master_key_copy.zeroize();
        err_json("INTERNAL_ERROR", "Failed to parse vault header.")
    })?;

    // Find password slot.
    let (slot_index, password_slot) = header
        .slots
        .iter()
        .enumerate()
        .find(|(_, s)| s.slot_type == verrou_crypto_core::slots::SlotType::Password)
        .ok_or_else(|| {
            master_key_copy.zeroize();
            err_json("INTERNAL_ERROR", "No password slot found.")
        })?;

    let password_slot = password_slot.clone();

    let salt = header
        .slot_salts
        .get(slot_index)
        .ok_or_else(|| {
            master_key_copy.zeroize();
            err_json("INTERNAL_ERROR", "Missing salt for password slot.")
        })?
        .clone();

    // Derive wrapping key and unwrap slot.
    let wrapping_key =
        verrou_crypto_core::kdf::derive(password.as_bytes(), &salt, &header.session_params)
            .map_err(|_| {
                master_key_copy.zeroize();
                err_json("INTERNAL_ERROR", "Key derivation failed.")
            })?;

    let recovered_key =
        verrou_crypto_core::slots::unwrap_slot(&password_slot, wrapping_key.expose()).map_err(
            |_| {
                master_key_copy.zeroize();
                err_json("INVALID_PASSWORD", "Incorrect password.")
            },
        )?;

    // Constant-time comparison.
    if !constant_time_key_eq(recovered_key.expose(), &master_key_copy) {
        master_key_copy.zeroize();
        return Err(err_json("INVALID_PASSWORD", "Incorrect password."));
    }

    master_key_copy.zeroize();
    Ok(())
}

// ---------------------------------------------------------------------------
// Screen capture protection
// ---------------------------------------------------------------------------

/// Enable or disable OS-level screen capture protection.
///
/// - **macOS**: Sets `NSWindow.sharingType` to `.none` (blocks screen recording).
///   Note: macOS 15+ `ScreenCaptureKit` may bypass this — documented limitation.
/// - **Windows**: Calls `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`.
/// - **Linux**: No-op — no OS-level screen capture protection available.
///
/// Returns `true` if protection was applied, `false` if unavailable on this platform.
#[allow(clippy::needless_pass_by_value, unused_variables)]
#[tauri::command]
pub fn set_screen_capture_protection(
    window: tauri::WebviewWindow,
    enabled: bool,
) -> Result<bool, String> {
    set_screen_capture_impl(&window, enabled)
}

#[cfg(target_os = "macos")]
fn set_screen_capture_impl(window: &tauri::WebviewWindow, enabled: bool) -> Result<bool, String> {
    set_screen_capture_macos(window, enabled)?;
    Ok(true)
}

#[cfg(target_os = "windows")]
fn set_screen_capture_impl(window: &tauri::WebviewWindow, enabled: bool) -> Result<bool, String> {
    set_screen_capture_windows(window, enabled)?;
    Ok(true)
}

#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_wraps, clippy::missing_const_for_fn)]
fn set_screen_capture_impl(_window: &tauri::WebviewWindow, _enabled: bool) -> Result<bool, String> {
    // No OS-level screen capture protection available on Linux.
    // Signature must match other platform impls which can fail.
    Ok(false)
}

/// macOS: Set `NSWindow.sharingType` via `objc2` message send.
///
/// `NSWindowSharingNone` (0) = block screen recording.
/// `NSWindowSharingReadOnly` (1) = default, allow sharing.
#[cfg(target_os = "macos")]
fn set_screen_capture_macos(window: &tauri::WebviewWindow, enabled: bool) -> Result<(), String> {
    window
        .with_webview(move |webview| {
            unsafe {
                let ns_window: *mut objc2::runtime::AnyObject = webview.ns_window().cast();
                if ns_window.is_null() {
                    return;
                }
                // NSWindowSharingNone = 0, NSWindowSharingReadOnly = 1
                let sharing_type: usize = usize::from(!enabled);
                let _: () = objc2::msg_send![&*ns_window, setSharingType: sharing_type];
            }
        })
        .map_err(|e| format!("Failed to set screen capture protection: {e}"))
}

/// Windows: Call `SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE`.
///
/// `WDA_NONE` (0) = default, allow capture.
/// `WDA_EXCLUDEFROMCAPTURE` (0x11) = exclude from screen capture (Win10 v2004+).
#[cfg(target_os = "windows")]
fn set_screen_capture_windows(window: &tauri::WebviewWindow, enabled: bool) -> Result<(), String> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    extern "system" {
        fn SetWindowDisplayAffinity(hwnd: isize, dw_affinity: u32) -> i32;
    }

    const WDA_NONE: u32 = 0x0000_0000;
    const WDA_EXCLUDEFROMCAPTURE: u32 = 0x0000_0011;

    let handle = window
        .window_handle()
        .map_err(|e| format!("Failed to get window handle: {e}"))?;

    if let RawWindowHandle::Win32(win32) = handle.as_ref() {
        let hwnd = win32.hwnd.get() as isize;
        let affinity = if enabled {
            WDA_EXCLUDEFROMCAPTURE
        } else {
            WDA_NONE
        };
        let result = unsafe { SetWindowDisplayAffinity(hwnd, affinity) };
        if result == 0 {
            return Err("SetWindowDisplayAffinity failed".to_string());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// File-based transfer (alternative for desktops without webcam)
// ---------------------------------------------------------------------------

/// On-disk transfer file format.
#[derive(Serialize, Deserialize)]
struct TransferFile {
    /// Format version.
    version: u8,
    /// Base64-encoded encrypted chunks (same as QR data).
    chunks: Vec<String>,
}

/// Write encrypted transfer chunks to a `.verrou-transfer` file.
///
/// The verification code is NOT stored in the file — it must be
/// communicated out-of-band (verbally, different channel, etc.).
#[tauri::command]
pub fn save_transfer_file(path: String, chunks: Vec<String>) -> Result<(), String> {
    let file = TransferFile { version: 1, chunks };
    let json = serde_json::to_vec_pretty(&file)
        .map_err(|e| format!("Failed to serialize transfer file: {e}"))?;

    let mut f = std::fs::File::create(&path).map_err(|e| format!("Failed to create file: {e}"))?;
    f.write_all(&json)
        .map_err(|e| format!("Failed to write file: {e}"))?;

    Ok(())
}

/// Read encrypted transfer chunks from a `.verrou-transfer` file.
#[tauri::command]
pub fn load_transfer_file(path: String) -> Result<Vec<String>, String> {
    let data = std::fs::read(&path).map_err(|e| format!("Failed to read file: {e}"))?;

    let file: TransferFile = serde_json::from_slice(&data).map_err(|_| {
        "Invalid transfer file format. Expected a .verrou-transfer file.".to_string()
    })?;

    if file.version != 1 {
        return Err(format!(
            "Unsupported transfer file version: {}. Expected version 1.",
            file.version
        ));
    }

    if file.chunks.is_empty() {
        return Err("Transfer file contains no data.".to_string());
    }

    Ok(file.chunks)
}
