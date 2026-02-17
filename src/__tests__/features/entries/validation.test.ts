import { describe, it, expect } from "vitest";
import {
  isValidBase32,
  validateEntryForm,
  type AddEntryFormState,
} from "../../../features/entries/validation";

function makeFormState(overrides: Partial<AddEntryFormState> = {}): AddEntryFormState {
  return {
    secret: "JBSWY3DPEHPK3PXP",
    name: "My Account",
    issuer: "",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pasteInput: "",
    pasteDetected: null,
    showManualForm: false,
    showAdvanced: false,
    isSubmitting: false,
    errors: {},
    ...overrides,
  };
}

describe("isValidBase32", () => {
  it("accepts valid uppercase Base32", () => {
    expect(isValidBase32("JBSWY3DPEHPK3PXP")).toBe(true);
  });

  it("accepts lowercase (normalizes to uppercase)", () => {
    expect(isValidBase32("jbswy3dpehpk3pxp")).toBe(true);
  });

  it("accepts mixed case", () => {
    expect(isValidBase32("JbSwY3DpEhPk3PxP")).toBe(true);
  });

  it("accepts with trailing padding", () => {
    expect(isValidBase32("MFRA====")).toBe(true);
  });

  it("accepts short valid keys", () => {
    expect(isValidBase32("ME")).toBe(true);
  });

  it("rejects empty string", () => {
    expect(isValidBase32("")).toBe(false);
  });

  it("rejects whitespace-only", () => {
    expect(isValidBase32("   ")).toBe(false);
  });

  it("rejects invalid characters (0, 1, 8, 9)", () => {
    expect(isValidBase32("JBSWY01")).toBe(false);
  });

  it("rejects special characters", () => {
    expect(isValidBase32("JBSWY+/=")).toBe(false);
  });

  it("rejects padding in the middle", () => {
    expect(isValidBase32("MF==RA")).toBe(false);
  });

  it("accepts key with spaces (trims them)", () => {
    expect(isValidBase32("  JBSWY3DPEHPK3PXP  ")).toBe(true);
  });

  it("accepts key with internal spaces (common copy-paste)", () => {
    expect(isValidBase32("JBSW Y3DP EHPK 3PXP")).toBe(true);
  });
});

describe("validateEntryForm", () => {
  it("returns no errors for valid complete form", () => {
    const errors = validateEntryForm(makeFormState());
    expect(Object.keys(errors)).toHaveLength(0);
  });

  it("returns error for empty name", () => {
    const errors = validateEntryForm(makeFormState({ name: "" }));
    expect(errors.name).toBe("Account name is required.");
  });

  it("returns error for whitespace-only name", () => {
    const errors = validateEntryForm(makeFormState({ name: "   " }));
    expect(errors.name).toBe("Account name is required.");
  });

  it("returns error for name exceeding 100 chars", () => {
    const errors = validateEntryForm(makeFormState({ name: "A".repeat(101) }));
    expect(errors.name).toBe("Account name too long (max 100 characters).");
  });

  it("returns error for issuer exceeding 100 chars", () => {
    const errors = validateEntryForm(makeFormState({ issuer: "I".repeat(101) }));
    expect(errors.issuer).toBe("Issuer too long (max 100 characters).");
  });

  it("accepts empty issuer (optional)", () => {
    const errors = validateEntryForm(makeFormState({ issuer: "" }));
    expect(errors.issuer).toBeUndefined();
  });

  it("returns error for empty secret", () => {
    const errors = validateEntryForm(makeFormState({ secret: "" }));
    expect(errors.secret).toBe("Secret must be valid Base32 (A-Z, 2-7).");
  });

  it("returns error for invalid Base32 secret", () => {
    const errors = validateEntryForm(makeFormState({ secret: "NOT-VALID!" }));
    expect(errors.secret).toBe("Secret must be valid Base32 (A-Z, 2-7).");
  });

  it("collects multiple errors", () => {
    const errors = validateEntryForm(
      makeFormState({ name: "", secret: "", issuer: "I".repeat(101) }),
    );
    expect(Object.keys(errors).length).toBe(3);
    expect(errors.name).toBeDefined();
    expect(errors.secret).toBeDefined();
    expect(errors.issuer).toBeDefined();
  });
});
