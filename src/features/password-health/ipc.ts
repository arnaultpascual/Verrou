/**
 * Password health IPC service.
 * Mirrors Rust PasswordHealthDto from src-tauri/src/commands/entries.rs.
 */

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs exactly
// ---------------------------------------------------------------------------

export interface CredentialRef {
  id: string;
  name: string;
}

export interface ReusedGroup {
  credentials: CredentialRef[];
}

export interface WeakCredential {
  id: string;
  name: string;
  strength: string;
}

export interface OldCredential {
  id: string;
  name: string;
  daysSinceChange: number;
  severity: "warning" | "danger";
}

export interface PasswordHealthReport {
  overallScore: number;
  totalCredentials: number;
  reusedCount: number;
  reusedGroups: ReusedGroup[];
  weakCount: number;
  weakCredentials: WeakCredential[];
  oldCount: number;
  oldCredentials: OldCredential[];
  noTotpCount: number;
  noTotpCredentials: CredentialRef[];
}

// ---------------------------------------------------------------------------
// IPC invoke
// ---------------------------------------------------------------------------

const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export async function getPasswordHealth(): Promise<PasswordHealthReport> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<PasswordHealthReport>("get_password_health");
  }
  // Mock for development/tests.
  return MOCK_REPORT;
}

// ---------------------------------------------------------------------------
// Mock data (realistic for 5 credential entries)
// ---------------------------------------------------------------------------

const MOCK_REPORT: PasswordHealthReport = {
  overallScore: 65,
  totalCredentials: 5,
  reusedCount: 2,
  reusedGroups: [
    {
      credentials: [
        { id: "cred-1", name: "GitHub" },
        { id: "cred-2", name: "GitLab" },
      ],
    },
  ],
  weakCount: 1,
  weakCredentials: [{ id: "cred-3", name: "Old Forum", strength: "weak" }],
  oldCount: 2,
  oldCredentials: [
    {
      id: "cred-4",
      name: "Legacy Service",
      daysSinceChange: 400,
      severity: "danger",
    },
    {
      id: "cred-3",
      name: "Old Forum",
      daysSinceChange: 200,
      severity: "warning",
    },
  ],
  noTotpCount: 3,
  noTotpCredentials: [
    { id: "cred-3", name: "Old Forum" },
    { id: "cred-4", name: "Legacy Service" },
    { id: "cred-5", name: "Personal Blog" },
  ],
};
