/**
 * Onboarding IPC service.
 * Wraps Tauri invoke() calls for KDF calibration, vault creation,
 * and recovery key generation. Falls back to mocks in browser dev mode.
 */

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs exactly
// ---------------------------------------------------------------------------

export interface Argon2idParams {
  mCost: number;
  tCost: number;
  pCost: number;
}

export interface CalibratedPresets {
  fast: Argon2idParams;
  balanced: Argon2idParams;
  maximum: Argon2idParams;
}

export interface CreateVaultResult {
  vaultPath: string;
  dbPath: string;
  kdfPreset: string;
}

export interface RecoveryKeyResult {
  formattedKey: string;
  vaultFingerprint: string;
  generationDate: string;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

/** Benchmark host hardware and return calibrated KDF presets. */
export async function benchmarkKdf(): Promise<CalibratedPresets> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<CalibratedPresets>("benchmark_kdf");
  }

  // Mock fallback for browser dev/test.
  await delay(200);
  return {
    fast: { mCost: 262144, tCost: 2, pCost: 4 },
    balanced: { mCost: 524288, tCost: 3, pCost: 4 },
    maximum: { mCost: 524288, tCost: 4, pCost: 4 },
  };
}

/** Create a new vault and unlock it. */
export async function createVault(
  password: string,
  preset: string,
): Promise<CreateVaultResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<CreateVaultResult>("create_vault", { password, preset });
  }

  // Mock fallback for browser dev/test.
  await delay(2000);
  return {
    vaultPath: "~/.verrou/vault.verrou",
    dbPath: "~/.verrou/vault.db",
    kdfPreset: preset,
  };
}

/** Generate a recovery key for the currently unlocked vault. */
export async function getRecoveryKey(): Promise<RecoveryKeyResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<RecoveryKeyResult>("generate_recovery_key");
  }

  // Mock fallback for browser dev/test.
  await delay(100);
  return {
    formattedKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-CK42",
    vaultFingerprint: "a1b2c3d4e5f67890",
    generationDate: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
