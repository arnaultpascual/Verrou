/**
 * Entry form validation utilities.
 * Base32 key validation + full form validation.
 */

import type { OtpAlgorithm, OtpDigits, OtpPeriod } from "./otpauth";

export interface AddEntryFormState {
  secret: string;
  name: string;
  issuer: string;
  algorithm: OtpAlgorithm;
  digits: OtpDigits;
  period: OtpPeriod;
  pasteInput: string;
  pasteDetected: "uri" | "base32" | "manual" | null;
  showManualForm: boolean;
  showAdvanced: boolean;
  isSubmitting: boolean;
  errors: Record<string, string>;
}

export type ValidationErrors = Record<string, string>;

const BASE32_CHARS = /^[A-Z2-7]+=*$/;

/**
 * Check if a string is valid Base32 (A-Z, 2-7, optional trailing = padding).
 * Tolerates spaces (common in copy-paste) and case-insensitive input.
 */
export function isValidBase32(secret: string): boolean {
  const stripped = secret.replace(/\s/g, "").toUpperCase();
  if (!stripped) return false;
  return BASE32_CHARS.test(stripped);
}

/** Validate the full add-entry form. Returns errors keyed by field name. */
export function validateEntryForm(form: AddEntryFormState): ValidationErrors {
  const errors: ValidationErrors = {};

  const trimmedName = form.name.trim();
  if (!trimmedName) {
    errors.name = "Account name is required.";
  } else if (trimmedName.length > 100) {
    errors.name = "Account name too long (max 100 characters).";
  }

  if (form.issuer && form.issuer.length > 100) {
    errors.issuer = "Issuer too long (max 100 characters).";
  }

  if (!isValidBase32(form.secret)) {
    errors.secret = "Secret must be valid Base32 (A-Z, 2-7).";
  }

  return errors;
}
