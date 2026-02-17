/**
 * Recovery code IPC service.
 * Wraps Tauri invoke() calls for recovery code reveal and stats.
 * Function signatures match the Rust DTO types for seamless swap.
 */

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs exactly
// ---------------------------------------------------------------------------

/** Recovery code display DTO returned after re-authentication. */
export interface RecoveryCodeDisplay {
  codes: string[];
  used: number[];
  totalCodes: number;
  remainingCodes: number;
  linkedEntryId?: string;
  hasLinkedEntry: boolean;
}

/** Recovery stats for display on TOTP entry cards (no secrets). */
export interface RecoveryStats {
  total: number;
  remaining: number;
}

/** Batch recovery stats entry (one per linked TOTP/HOTP entry). */
export interface RecoveryStatEntry {
  entryId: string;
  total: number;
  remaining: number;
}

/** Map of TOTP entry ID → recovery stats for batch rendering. */
export type RecoveryStatsMap = Map<string, RecoveryStats>;

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

/**
 * Reveal recovery codes after re-authenticating with the master password.
 * Requires the vault to be unlocked. The password is verified server-side
 * via KDF re-derivation and slot unwrapping.
 */
export async function revealRecoveryCodes(
  entryId: string,
  password: string,
): Promise<RecoveryCodeDisplay> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<RecoveryCodeDisplay>("reveal_recovery_codes", {
      entryId,
      password,
    });
  }

  // Mock: return sample recovery codes after simulated delay
  await delay(50);
  return {
    codes: [
      "abcd-1234-efgh-5678",
      "ijkl-9012-mnop-3456",
      "qrst-7890-uvwx-1234",
      "yzab-5678-cdef-9012",
      "ghij-3456-klmn-7890",
    ],
    used: [1],
    totalCodes: 5,
    remainingCodes: 4,
    hasLinkedEntry: false,
  };
}

/**
 * Get recovery code statistics for a TOTP/HOTP entry.
 * Returns total and remaining counts without exposing the actual codes.
 * No re-auth required — stats only.
 */
export async function getRecoveryStats(
  entryId: string,
): Promise<RecoveryStats> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<RecoveryStats>("get_recovery_stats", { entryId });
  }

  // Mock: return sample stats
  await delay(20);
  return { total: 5, remaining: 4 };
}

/**
 * Get recovery code statistics for ALL linked entries in a single scan.
 * Returns a Map keyed by TOTP/HOTP entry ID with total/remaining counts.
 * This is the batch alternative to calling getRecoveryStats per entry.
 */
export async function getAllRecoveryStats(): Promise<RecoveryStatsMap> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    const entries = await invoke<RecoveryStatEntry[]>("get_all_recovery_stats");
    const map: RecoveryStatsMap = new Map();
    for (const entry of entries) {
      map.set(entry.entryId, { total: entry.total, remaining: entry.remaining });
    }
    return map;
  }

  // Mock: return sample batch stats
  await delay(30);
  const map: RecoveryStatsMap = new Map();
  map.set("b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e", { total: 5, remaining: 4 });
  return map;
}

/**
 * Toggle a recovery code's used/unused status.
 * Requires re-authentication. Returns the updated RecoveryCodeDisplay
 * with the toggled `used` vec so the caller can update local state.
 */
export async function toggleRecoveryCodeUsed(
  entryId: string,
  codeIndex: number,
  password: string,
): Promise<RecoveryCodeDisplay> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<RecoveryCodeDisplay>("toggle_recovery_code_used", {
      entryId,
      codeIndex,
      password,
    });
  }

  // Mock: simulate toggle
  await delay(50);
  const mockUsed = [1];
  const idx = mockUsed.indexOf(codeIndex);
  if (idx >= 0) {
    mockUsed.splice(idx, 1);
  } else {
    mockUsed.push(codeIndex);
  }
  return {
    codes: [
      "abcd-1234-efgh-5678",
      "ijkl-9012-mnop-3456",
      "qrst-7890-uvwx-1234",
      "yzab-5678-cdef-9012",
      "ghij-3456-klmn-7890",
    ],
    used: mockUsed,
    totalCodes: 5,
    remainingCodes: 5 - mockUsed.length,
    hasLinkedEntry: false,
  };
}

/**
 * Update recovery codes: add new codes and/or remove codes by index.
 * Requires re-authentication. Returns the updated RecoveryCodeDisplay.
 */
export async function updateRecoveryCodes(
  entryId: string,
  codesToAdd: string[],
  indexesToRemove: number[],
  password: string,
): Promise<RecoveryCodeDisplay> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<RecoveryCodeDisplay>("update_recovery_codes", {
      entryId,
      codesToAdd,
      indexesToRemove,
      password,
    });
  }

  // Mock: simulate update
  await delay(50);
  const mockCodes = [
    "abcd-1234-efgh-5678",
    "ijkl-9012-mnop-3456",
    "qrst-7890-uvwx-1234",
  ];
  // Simulate removing and adding
  const remaining = mockCodes.filter((_, i) => !indexesToRemove.includes(i));
  const updated = [...remaining, ...codesToAdd];
  return {
    codes: updated,
    used: [],
    totalCodes: updated.length,
    remainingCodes: updated.length,
    hasLinkedEntry: false,
  };
}

/**
 * Get the count of recovery code entries linked to a given TOTP/HOTP entry.
 * Used to display cascade deletion warnings.
 */
export async function getLinkedRecoveryCount(
  entryId: string,
): Promise<number> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<number>("get_linked_recovery_count", { entryId });
  }

  // Mock: return 0 (no linked recovery codes)
  await delay(20);
  return 0;
}

/**
 * Delete a recovery code entry after re-authenticating with the master password.
 * Wraps the generalized `delete_entry_with_auth` Rust command which checks
 * entry type internally — RecoveryCode requires re-auth.
 */
export async function deleteRecoveryCodeEntry(
  entryId: string,
  password: string,
): Promise<void> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<void>("delete_entry_with_auth", { entryId, password });
  }

  // Mock: simulate authenticated deletion with delay
  await delay(50);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
