/**
 * Paper backup IPC service.
 * Wraps Tauri invoke() calls for generating paper backup data.
 * Falls back to mocks in browser dev mode.
 */

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/** A single seed phrase entry for paper backup. */
export interface SeedBackupEntry {
  name: string;
  issuer?: string;
  words: string[];
  wordCount: number;
  hasPassphrase: boolean;
}

/** A single recovery code entry for paper backup. */
export interface RecoveryBackupEntry {
  name: string;
  issuer?: string;
  codes: string[];
  used: number[];
  totalCodes: number;
  remainingCodes: number;
}

/** Complete paper backup data DTO. */
export interface PaperBackupData {
  seeds: SeedBackupEntry[];
  recoveryCodes: RecoveryBackupEntry[];
  generatedAt: string;
  vaultFingerprint: string;
  contentChecksum: string;
}

// ---------------------------------------------------------------------------
// Tauri detection
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

// ---------------------------------------------------------------------------
// IPC functions
// ---------------------------------------------------------------------------

/**
 * Generate paper backup data after re-authenticating with the master password.
 * Returns all seed phrases and recovery codes with integrity metadata.
 */
export async function generatePaperBackupData(
  password: string,
): Promise<PaperBackupData> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<PaperBackupData>("generate_paper_backup_data", { password });
  }

  // Mock for browser dev mode
  await new Promise((r) => setTimeout(r, 2000));
  return {
    seeds: [
      {
        name: "Bitcoin Wallet",
        issuer: undefined,
        words: [
          "abandon", "ability", "able", "about", "above", "absent",
          "absorb", "abstract", "absurd", "abuse", "access", "accident",
          "account", "accuse", "achieve", "acid", "acoustic", "acquire",
          "across", "act", "action", "actor", "actress", "zoo",
        ],
        wordCount: 24,
        hasPassphrase: true,
      },
      {
        name: "Ethereum Wallet",
        issuer: undefined,
        words: [
          "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
          "abandon", "abandon", "abandon", "abandon", "abandon", "about",
        ],
        wordCount: 12,
        hasPassphrase: false,
      },
    ],
    recoveryCodes: [
      {
        name: "Google Account",
        issuer: "google.com",
        codes: [
          "ABCD-1234-EFGH",
          "IJKL-5678-MNOP",
          "QRST-9012-UVWX",
          "YZAB-3456-CDEF",
        ],
        used: [0, 2],
        totalCodes: 4,
        remainingCodes: 2,
      },
      {
        name: "GitHub",
        issuer: "github.com",
        codes: [
          "abc12-def34",
          "ghi56-jkl78",
          "mno90-pqr12",
          "stu34-vwx56",
          "yza78-bcd90",
        ],
        used: [],
        totalCodes: 5,
        remainingCodes: 5,
      },
    ],
    generatedAt: new Date().toISOString(),
    vaultFingerprint: "a1b2c3d4e5f6a7b8",
    contentChecksum:
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  };
}
