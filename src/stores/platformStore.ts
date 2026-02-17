/**
 * Platform capabilities store — session-level cache.
 *
 * Detected once at app startup via IPC, immutable for the session.
 * Components read from this store for hardware availability (instant,
 * no IPC) and separately query vault-specific enrollment status.
 */

import { createSignal } from "solid-js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PlatformCapabilities {
  osType: string;
  biometricAvailable: boolean;
  biometricProviderName: string;
  hardwareSecurityAvailable: boolean;
  hardwareSecurityProviderName: string;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

const [capabilities, setCapabilities] =
  createSignal<PlatformCapabilities | null>(null);

// Track whether init has been called to prevent duplicate IPC calls.
let initCalled = false;

// ---------------------------------------------------------------------------
// Accessors
// ---------------------------------------------------------------------------

/** Raw platform capabilities (null until initialized). */
export const platformCapabilities = capabilities;

/** Whether platform capabilities have been loaded. */
export const platformLoaded = (): boolean => capabilities() !== null;

/** Whether biometric hardware is available on this device. */
export const isBiometricAvailable = (): boolean =>
  capabilities()?.biometricAvailable ?? false;

/** Whether hardware security is available on this device. */
export const isHardwareSecurityAvailable = (): boolean =>
  capabilities()?.hardwareSecurityAvailable ?? false;

/** Human-readable biometric provider name. */
export const biometricProviderName = (): string =>
  capabilities()?.biometricProviderName ?? "None";

/** Human-readable hardware security provider name. */
export const hardwareSecurityProviderName = (): string =>
  capabilities()?.hardwareSecurityProviderName ?? "None";

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/**
 * Fetch platform capabilities from the backend (once per session).
 * Subsequent calls are no-ops. Safe to call from multiple components.
 */
export async function initPlatformCapabilities(): Promise<void> {
  if (initCalled) return;
  initCalled = true;

  try {
    if (IS_TAURI) {
      const { invoke } = await import("@tauri-apps/api/core");
      const caps = await invoke<PlatformCapabilities>(
        "get_platform_capabilities",
      );
      setCapabilities(caps);
    } else {
      // Browser dev mode — all unavailable.
      setCapabilities({
        osType: "unknown",
        biometricAvailable: false,
        biometricProviderName: "None",
        hardwareSecurityAvailable: false,
        hardwareSecurityProviderName: "None",
      });
    }
  } catch {
    // Detection failed — default to all unavailable.
    setCapabilities({
      osType: "unknown",
      biometricAvailable: false,
      biometricProviderName: "None",
      hardwareSecurityAvailable: false,
      hardwareSecurityProviderName: "None",
    });
  }
}

/**
 * Reset the store (for testing only).
 * @internal
 */
export function _resetPlatformStore(): void {
  setCapabilities(null);
  initCalled = false;
}
