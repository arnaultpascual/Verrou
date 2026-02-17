import { describe, expect, it, beforeEach } from "vitest";
import { generateTotpCode, _resetMockStore } from "../../../features/entries/ipc";

beforeEach(() => {
  _resetMockStore();
});

describe("generateTotpCode", () => {
  it("returns a TotpCodeDto with code and remainingSeconds", async () => {
    const result = await generateTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    expect(result).toHaveProperty("code");
    expect(result).toHaveProperty("remainingSeconds");
  });

  it("returns a 6-digit code for 6-digit TOTP entry", async () => {
    const result = await generateTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    expect(result.code).toMatch(/^\d{6}$/);
  });

  it("returns an 8-digit code for 8-digit TOTP entry", async () => {
    const result = await generateTotpCode("c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f");
    expect(result.code).toMatch(/^\d{8}$/);
  });

  it("remainingSeconds is between 1 and period", async () => {
    const result = await generateTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    expect(result.remainingSeconds).toBeGreaterThanOrEqual(1);
    expect(result.remainingSeconds).toBeLessThanOrEqual(30);
  });

  it("generates deterministic code for same time window", async () => {
    const result1 = await generateTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    const result2 = await generateTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    expect(result1.code).toBe(result2.code);
  });

  it("throws for non-existent entry", async () => {
    await expect(generateTotpCode("nonexistent-id")).rejects.toBe(
      "Entry not found. It may have been deleted.",
    );
  });

  it("throws for non-TOTP entry", async () => {
    await expect(
      generateTotpCode("d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f80"),
    ).rejects.toBe("Entry is not a TOTP entry.");
  });

  it("generates different codes for different entries", async () => {
    const github = await generateTotpCode("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d");
    const google = await generateTotpCode("b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e");
    // Different secrets → different codes (with overwhelming probability)
    expect(github.code).not.toBe(google.code);
  });
});
