import { describe, it, expect, vi } from "vitest";

// Ensure we're in non-Tauri env for mock fallback
vi.stubGlobal("window", {});

describe("hardwareKeyIpc mock fallback", () => {
  it("checkHardwareSecurity returns unavailable in browser mode", async () => {
    // Dynamic import after window stub (no __TAURI_INTERNALS__)
    const { checkHardwareSecurity } = await import(
      "../../../features/vault/hardwareKeyIpc"
    );

    const result = await checkHardwareSecurity();
    expect(result).toEqual({
      available: false,
      providerName: "None",
      enabled: false,
    });
  });
});
