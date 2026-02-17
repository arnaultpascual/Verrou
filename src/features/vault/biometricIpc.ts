/**
 * Biometric IPC service.
 * Wraps Tauri invoke() calls for biometric operations (check, unlock, enroll, revoke).
 * Falls back to mocks in browser dev mode.
 */

import { getVaultDir, type UnlockVaultResult } from "./ipc";

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs
// ---------------------------------------------------------------------------

export interface BiometricCapability {
  /** Whether biometric hardware is available on this device. */
  available: boolean;
  /** Human-readable provider name (e.g., "Touch ID", "Windows Hello"). */
  providerName: string;
  /** Whether biometric is enrolled for the current vault. */
  enrolled: boolean;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// Biometric check
// ---------------------------------------------------------------------------

/** Check biometric availability and enrollment for the current vault. */
export async function checkBiometricAvailability(): Promise<BiometricCapability> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<BiometricCapability>("check_biometric_availability", {
      vaultDir: getVaultDir(),
    });
  }

  // Mock fallback: biometric not available.
  return { available: false, providerName: "None", enrolled: false };
}

// ---------------------------------------------------------------------------
// Biometric unlock
// ---------------------------------------------------------------------------

/**
 * Unlock the vault with biometric authentication.
 * Triggers the native biometric prompt (Touch ID, Windows Hello, etc.).
 */
export async function unlockVaultBiometric(): Promise<UnlockVaultResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<UnlockVaultResult>("unlock_vault_biometric", {
      vaultDir: getVaultDir(),
    });
  }

  // Mock fallback.
  await delay(500);
  return { unlockCount: 1 };
}

// ---------------------------------------------------------------------------
// Biometric enrollment
// ---------------------------------------------------------------------------

/**
 * Enroll biometric for the current vault.
 * Requires the master password for re-authentication.
 */
export async function enrollBiometric(password: string): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("enroll_biometric", {
      password,
      vaultDir: getVaultDir(),
    });
  }

  // Mock fallback.
  await delay(1000);
  if (password === "wrong") {
    throw JSON.stringify({
      code: "INVALID_PASSWORD",
      message: "Incorrect password. Please try again.",
    });
  }
}

// ---------------------------------------------------------------------------
// Biometric revocation
// ---------------------------------------------------------------------------

/**
 * Revoke biometric enrollment for the current vault.
 * Requires the master password for re-authentication.
 */
export async function revokeBiometric(password: string): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("revoke_biometric", {
      password,
      vaultDir: getVaultDir(),
    });
  }

  // Mock fallback.
  await delay(1000);
  if (password === "wrong") {
    throw JSON.stringify({
      code: "INVALID_PASSWORD",
      message: "Incorrect password. Please try again.",
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
