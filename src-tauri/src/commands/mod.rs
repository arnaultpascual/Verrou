//! IPC command handlers for VERROU.
//!
//! Each submodule defines Tauri `#[command]` functions that form the
//! IPC boundary between the `SolidJS` frontend and the Rust backend.
//! All commands return dedicated DTOs — never domain entities.

pub mod attachments;
pub mod auth_utils;
pub mod biometric;
pub mod bip39;
pub mod clipboard;
pub mod entries;
pub mod export;
pub mod folders;
pub mod hardware_key;
pub mod import;
pub mod onboarding;
pub mod paper_backup;
pub mod password_generator;
pub mod platform;
pub mod preferences;
pub mod qr_transfer;
pub mod vault;
