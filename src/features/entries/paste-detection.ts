/**
 * Smart paste detection: otpauth:// URI → raw Base32 → unknown.
 */

import type { ParsedOtpAuth } from "./otpauth";
import { parseOtpAuthUri } from "./otpauth";
import { isValidBase32 } from "./validation";

export type PasteResult =
  | { type: "uri"; parsed: ParsedOtpAuth }
  | { type: "base32"; secret: string }
  | { type: "unknown" };

/** Detect whether pasted input is an otpauth URI, a raw Base32 key, or unknown. */
export function detectPasteType(input: string): PasteResult {
  const trimmed = input.trim();
  if (!trimmed) return { type: "unknown" };

  // Priority 1: otpauth:// URI
  if (trimmed.startsWith("otpauth://")) {
    const parsed = parseOtpAuthUri(trimmed);
    if (parsed) return { type: "uri", parsed };
    return { type: "unknown" };
  }

  // Priority 2: raw Base32 key
  if (isValidBase32(trimmed)) {
    const secret = trimmed.replace(/\s/g, "").toUpperCase();
    return { type: "base32", secret };
  }

  return { type: "unknown" };
}
