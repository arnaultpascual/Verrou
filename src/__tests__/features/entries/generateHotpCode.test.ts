import { describe, expect, it, beforeEach } from "vitest";
import {
  generateHotpCode,
  getEntry,
  _resetMockStore,
} from "../../../features/entries/ipc";

// Mock HOTP entry from the ipc mock store: "Legacy VPN", counter 42, 6 digits.
const HOTP_ID = "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80";
// A TOTP entry to assert the type guard.
const TOTP_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

beforeEach(() => {
  _resetMockStore();
});

describe("generateHotpCode", () => {
  it("returns a HotpCodeDto with code and counter", async () => {
    const result = await generateHotpCode(HOTP_ID);
    expect(result).toHaveProperty("code");
    expect(result).toHaveProperty("counter");
  });

  it("returns a 6-digit code", async () => {
    const result = await generateHotpCode(HOTP_ID);
    expect(result.code).toMatch(/^\d{6}$/);
  });

  it("returns the counter the code was generated from (pre-advance)", async () => {
    const result = await generateHotpCode(HOTP_ID);
    // Mock entry starts at counter 42.
    expect(result.counter).toBe(42);
  });

  it("advances and persists the counter by exactly one per call", async () => {
    await generateHotpCode(HOTP_ID);
    const after = await getEntry(HOTP_ID);
    expect(after.counter).toBe(43);
  });

  it("produces different codes on successive calls (counter moves forward)", async () => {
    const first = await generateHotpCode(HOTP_ID);
    const second = await generateHotpCode(HOTP_ID);
    expect(first.counter).toBe(42);
    expect(second.counter).toBe(43);
    // RFC 4226: consecutive counters yield independent codes.
    expect(first.code).not.toBe(second.code);
  });

  it("is deterministic for a given counter (RFC 4226 KAT-style stability)", async () => {
    const first = await generateHotpCode(HOTP_ID);
    // Reset so the counter is back to 42, then regenerate.
    _resetMockStore();
    const again = await generateHotpCode(HOTP_ID);
    expect(again.counter).toBe(first.counter);
    expect(again.code).toBe(first.code);
  });

  it("throws for a non-existent entry", async () => {
    await expect(generateHotpCode("nonexistent-id")).rejects.toBe(
      "Entry not found. It may have been deleted.",
    );
  });

  it("throws for a non-HOTP (TOTP) entry", async () => {
    await expect(generateHotpCode(TOTP_ID)).rejects.toBe(
      "Entry is not a HOTP entry.",
    );
  });

  it("does not advance the counter when the entry is not HOTP", async () => {
    await expect(generateHotpCode(TOTP_ID)).rejects.toBeDefined();
    const totp = await getEntry(TOTP_ID);
    // TOTP counter stays 0 — the guard runs before any persist.
    expect(totp.counter).toBe(0);
  });
});
