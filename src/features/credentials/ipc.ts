/**
 * IPC service for password generation commands.
 * Wraps Tauri invoke() with mock fallback for tests/dev.
 */

// ---------------------------------------------------------------------------
// DTOs — mirror Rust camelCase DTOs exactly
// ---------------------------------------------------------------------------

export type PasswordMode = "random" | "passphrase";

export type SeparatorType = "hyphen" | "space" | "dot" | "underscore" | "none";

/** Request DTO for the `generate_password` IPC command. */
export interface GeneratePasswordRequest {
  mode: PasswordMode;

  // Random mode options
  length?: number;
  uppercase?: boolean;
  lowercase?: boolean;
  digits?: boolean;
  symbols?: boolean;

  // Passphrase mode options
  wordCount?: number;
  separator?: SeparatorType;
  capitalize?: boolean;
  appendDigit?: boolean;
}

/** Result DTO returned by `generate_password`. */
export interface GeneratePasswordResult {
  value: string;
}

// ---------------------------------------------------------------------------
// IPC
// ---------------------------------------------------------------------------

/** Whether we're running inside a Tauri webview (vs. test/browser). */
const IS_TAURI =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/**
 * Generate a random password or passphrase.
 *
 * In production (Tauri): invokes the Rust `generate_password` command.
 * In tests: uses a basic JS-based mock.
 */
export async function generatePassword(
  request: GeneratePasswordRequest,
): Promise<GeneratePasswordResult> {
  if (IS_TAURI) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<GeneratePasswordResult>("generate_password", { request });
  }
  return mockGeneratePassword(request);
}

// ---------------------------------------------------------------------------
// Mock (test/dev only)
// ---------------------------------------------------------------------------

function mockGeneratePassword(
  request: GeneratePasswordRequest,
): GeneratePasswordResult {
  if (request.mode === "passphrase") {
    const count = request.wordCount ?? 5;
    const sampleWords = [
      "correct", "horse", "battery", "staple", "purple",
      "monkey", "river", "cloud", "garden", "window",
    ];
    const words = sampleWords.slice(0, count).map((w) =>
      request.capitalize ? w.charAt(0).toUpperCase() + w.slice(1) : w,
    );
    const sep =
      request.separator === "space" ? " "
      : request.separator === "dot" ? "."
      : request.separator === "underscore" ? "_"
      : request.separator === "none" ? ""
      : "-";
    let value = words.join(sep);
    if (request.appendDigit) value += String(Math.floor(Math.random() * 10));
    return { value };
  }

  // Random mode mock
  const len = request.length ?? 20;
  const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const lower = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const symbols = "!@#$%^&*()-_=+[]{}|;:',.<>?/~";
  let pool = "";
  if (request.uppercase !== false) pool += upper;
  if (request.lowercase !== false) pool += lower;
  if (request.digits !== false) pool += digits;
  if (request.symbols !== false) pool += symbols;
  if (!pool) pool = lower;

  let value = "";
  for (let i = 0; i < len; i++) {
    value += pool[Math.floor(Math.random() * pool.length)];
  }
  return { value };
}
