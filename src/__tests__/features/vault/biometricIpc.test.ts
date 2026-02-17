import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the Tauri invoke module.
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

// These tests verify the mock fallback (no Tauri runtime in test).
// IS_TAURI is false in vitest, so all functions use mock fallback.

describe("biometricIpc (mock fallback)", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("checkBiometricAvailability returns not-available mock", async () => {
    const { checkBiometricAvailability } = await import(
      "../../../features/vault/biometricIpc"
    );
    const result = await checkBiometricAvailability();
    expect(result).toEqual({
      available: false,
      providerName: "None",
      enrolled: false,
    });
  });

  it("unlockVaultBiometric returns mock unlock result", async () => {
    const { unlockVaultBiometric } = await import(
      "../../../features/vault/biometricIpc"
    );
    const result = await unlockVaultBiometric();
    expect(result).toEqual({ unlockCount: 1 });
  });

  it("enrollBiometric resolves for correct password", async () => {
    const { enrollBiometric } = await import(
      "../../../features/vault/biometricIpc"
    );
    await expect(enrollBiometric("correct")).resolves.toBeUndefined();
  });

  it("enrollBiometric rejects for wrong password", async () => {
    const { enrollBiometric } = await import(
      "../../../features/vault/biometricIpc"
    );
    await expect(enrollBiometric("wrong")).rejects.toContain("INVALID_PASSWORD");
  });

  it("revokeBiometric resolves for correct password", async () => {
    const { revokeBiometric } = await import(
      "../../../features/vault/biometricIpc"
    );
    await expect(revokeBiometric("correct")).resolves.toBeUndefined();
  });

  it("revokeBiometric rejects for wrong password", async () => {
    const { revokeBiometric } = await import(
      "../../../features/vault/biometricIpc"
    );
    await expect(revokeBiometric("wrong")).rejects.toContain("INVALID_PASSWORD");
  });
});
