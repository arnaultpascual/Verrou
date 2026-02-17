/**
 * Vault IPC service.
 * Wraps Tauri invoke() calls for vault operations (unlock, lock, recovery,
 * integrity, backups). Falls back to mocks in browser dev mode.
 */

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs exactly
// ---------------------------------------------------------------------------

export interface VaultStatusResult {
  state: "no-vault" | "locked" | "unlocked";
  vaultDir: string;
}

export interface UnlockVaultResult {
  unlockCount: number;
}

export interface UnlockErrorResponse {
  code: string;
  message: string;
  remainingMs?: number;
}

export interface PasswordChangeResponse {
  formattedKey: string;
  vaultFingerprint: string;
  generationDate: string;
}

export interface IntegrityReport {
  status: IntegrityStatus;
  message: string;
}

export type IntegrityStatus =
  | { kind: "ok" }
  | { kind: "fileNotFound" }
  | { kind: "headerCorrupted"; detail: string }
  | { kind: "databaseMissing" }
  | { kind: "versionUnsupported"; version: number };

export interface BackupInfoDto {
  path: string;
  timestamp: string;
  sizeBytes: number;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// Vault directory cache
// ---------------------------------------------------------------------------

let _vaultDir = "";

/** Store the resolved vault directory (set from checkVaultStatus result). */
export function setVaultDir(dir: string): void {
  _vaultDir = dir;
}

/** Get the cached vault directory path. */
export function getVaultDir(): string {
  return _vaultDir;
}

// ---------------------------------------------------------------------------
// Error parsing
// ---------------------------------------------------------------------------

/** Parse a structured error from the IPC error string. */
export function parseUnlockError(errorStr: string): UnlockErrorResponse {
  try {
    return JSON.parse(errorStr) as UnlockErrorResponse;
  } catch {
    return {
      code: "UNKNOWN",
      message: errorStr || "An unexpected error occurred.",
    };
  }
}

// ---------------------------------------------------------------------------
// Vault status (NEW — used by startup flow)
// ---------------------------------------------------------------------------

/** Check vault existence and lock state. */
export async function checkVaultStatus(): Promise<VaultStatusResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<VaultStatusResult>("check_vault_status");
  }

  // Mock fallback: treat as locked vault.
  return { state: "locked", vaultDir: "/mock/app-data" };
}

// ---------------------------------------------------------------------------
// Unlock / lock
// ---------------------------------------------------------------------------

/** Unlock the vault with a master password. */
export async function unlockVault(
  password: string,
  vaultDir?: string,
): Promise<UnlockVaultResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<UnlockVaultResult>("unlock_vault", {
      password,
      vaultDir: vaultDir ?? _vaultDir,
    });
  }

  // Mock fallback.
  await delay(1500);
  if (password === "wrong") {
    throw JSON.stringify({
      code: "INVALID_PASSWORD",
      message: "Incorrect password. Please try again.",
    });
  }
  return { unlockCount: 1 };
}

/** Lock the vault (zeroize master key, close DB). */
export async function lockVault(): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("lock_vault");
  }

  await delay(100);
}

/** Record user activity to reset the inactivity timer. */
export async function heartbeat(): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("heartbeat");
  }
}

/** Check if the vault is currently unlocked. */
export async function isVaultUnlocked(): Promise<boolean> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<boolean>("is_vault_unlocked");
  }

  return false;
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/** Unlock the vault with a recovery key. */
export async function recoverVault(
  recoveryKey: string,
  vaultDir?: string,
): Promise<UnlockVaultResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<UnlockVaultResult>("recover_vault", {
      recoveryKey,
      vaultDir: vaultDir ?? _vaultDir,
    });
  }

  // Mock fallback.
  await delay(3000);
  if (recoveryKey.replace(/-/g, "").length !== 28) {
    throw JSON.stringify({
      code: "INVALID_RECOVERY_KEY",
      message: "Invalid recovery key. Please check for typos and try again.",
    });
  }
  if (recoveryKey.startsWith("XXXX")) {
    throw JSON.stringify({
      code: "INVALID_RECOVERY_KEY",
      message: "Invalid recovery key. Please check for typos and try again.",
    });
  }
  return { unlockCount: 1 };
}

/** Change password after recovery key unlock (mandatory operation). */
export async function changePasswordAfterRecovery(
  newPassword: string,
  vaultDir?: string,
  preset?: string,
): Promise<PasswordChangeResponse> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<PasswordChangeResponse>("change_password_after_recovery", {
      newPassword,
      vaultDir: vaultDir ?? _vaultDir,
      preset: preset ?? "balanced",
    });
  }

  // Mock fallback.
  await delay(2000);
  return {
    formattedKey: "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345",
    vaultFingerprint: "a1b2c3d4e5f6g7h8",
    generationDate: new Date().toISOString(),
  };
}

/** Change master password from Settings (vault already unlocked). */
export async function changeMasterPassword(
  oldPassword: string,
  newPassword: string,
  preset?: string,
): Promise<PasswordChangeResponse> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<PasswordChangeResponse>("change_master_password", {
      oldPassword,
      newPassword,
      preset: preset ?? "balanced",
      vaultDir: _vaultDir,
    });
  }

  // Mock fallback.
  await delay(3500);
  if (oldPassword === "wrong") {
    throw JSON.stringify({
      code: "INVALID_PASSWORD",
      message: "Current password is incorrect. Please try again.",
    });
  }
  return {
    formattedKey: "MNPQ-RSTU-VWXY-Z234-5678-ABCD-EFGH",
    vaultFingerprint: "f8e7d6c5b4a39281",
    generationDate: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Integrity & backup
// ---------------------------------------------------------------------------

/** Check vault integrity before unlock. */
export async function checkVaultIntegrity(
  vaultDir?: string,
): Promise<IntegrityReport> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<IntegrityReport>("check_vault_integrity", {
      vaultDir: vaultDir ?? _vaultDir,
    });
  }

  await delay(100);
  return {
    status: { kind: "ok" },
    message: "Vault integrity check passed.",
  };
}

/** List available vault backups, newest first. */
export async function listVaultBackups(
  vaultDir?: string,
): Promise<BackupInfoDto[]> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<BackupInfoDto[]>("list_vault_backups", {
      vaultDir: vaultDir ?? _vaultDir,
    });
  }

  await delay(200);
  return [
    {
      path: "/mock/backups/vault-2026-02-10T12-30-00Z.verrou",
      timestamp: "2026-02-10T12:30:00Z",
      sizeBytes: 65536,
    },
    {
      path: "/mock/backups/vault-2026-02-09T08-15-00Z.verrou",
      timestamp: "2026-02-09T08:15:00Z",
      sizeBytes: 65536,
    },
  ];
}

/** Restore a vault from a selected backup. */
export async function restoreVaultBackup(
  backupPath: string,
  vaultDir?: string,
): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("restore_vault_backup", {
      vaultDir: vaultDir ?? _vaultDir,
      backupPath,
    });
  }

  await delay(1000);
}

// ---------------------------------------------------------------------------
// Vault deletion
// ---------------------------------------------------------------------------

/** Permanently delete the vault after password re-authentication. */
export async function deleteVault(
  password: string,
  vaultDir?: string,
): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("delete_vault", {
      password,
      vaultDir: vaultDir ?? _vaultDir,
    });
  }

  // Mock fallback.
  await delay(1000);
  if (password === "wrong") {
    throw JSON.stringify({
      code: "INVALID_PASSWORD",
      message: "Incorrect password. Vault was not deleted.",
    });
  }
}

// ---------------------------------------------------------------------------
// Event listener
// ---------------------------------------------------------------------------

/**
 * Listen for the `verrou://vault-locked` backend event.
 * Returns an unlisten function to remove the listener.
 */
export function onVaultLocked(callback: () => void): () => void {
  if (IS_TAURI) {
    let unlisten: (() => void) | undefined;
    import("@tauri-apps/api/event").then(({ listen }) => {
      listen("verrou://vault-locked", () => callback()).then((fn) => {
        unlisten = fn;
      });
    });
    return () => unlisten?.();
  }

  // Mock: DOM event fallback for tests.
  const handler = () => callback();
  window.addEventListener("verrou://vault-locked", handler);
  return () => window.removeEventListener("verrou://vault-locked", handler);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
