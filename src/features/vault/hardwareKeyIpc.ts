/**
 * Hardware security IPC service.
 * Wraps Tauri invoke() call for hardware security status check.
 * Falls back to mocks in browser dev mode.
 */

import { getVaultDir } from "./ipc";

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs
// ---------------------------------------------------------------------------

export interface HardwareSecurityStatus {
  /** Whether hardware security is available on this device. */
  available: boolean;
  /** Human-readable provider name (e.g., "Secure Enclave", "TPM 2.0"). */
  providerName: string;
  /** Whether a hardware security slot is enabled for the current vault. */
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// Hardware security check
// ---------------------------------------------------------------------------

/** Check hardware security availability and enrollment for the current vault. */
export async function checkHardwareSecurity(): Promise<HardwareSecurityStatus> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<HardwareSecurityStatus>("check_hardware_security", {
      vaultDir: getVaultDir(),
    });
  }

  // Mock fallback: hardware security not available.
  return { available: false, providerName: "None", enabled: false };
}
